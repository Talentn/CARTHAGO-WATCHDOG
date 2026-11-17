package pipeline

import (
	"context"
	"strings"
	"testing"
	"time"

	pb "carthago/backend/gen/carthago/v1"
	"carthago/backend/internal/knowledge/synth"
	"carthago/backend/internal/store"
	"carthago/backend/internal/toxicity"
)

// spoiledMatch is an eight-minute match of ten honest players in which the game server's
// events for the last slot are those of a player who feeds, shoots teammates, stands idle
// and leaves. It returns the batches and that slot's player.
func spoiledMatch(id string) ([]*pb.GameplayBatch, synth.PlayerSpec) {
	mode := pb.GameMode_GAME_MODE_COMPETITIVE_SHOOTER
	ps := synth.DefaultPlayers(mode, 1, nil)
	for i := range ps {
		ps[i].SessionID = "sess-" + ps[i].PlayerHash
	}
	me := ps[len(ps)-1]
	var mates, enemies []uint32
	for _, p := range ps[:len(ps)-1] {
		if p.Team == me.Team {
			mates = append(mates, p.Slot)
		} else {
			enemies = append(enemies, p.Slot)
		}
	}
	bs := synth.Batches(synth.Spec{MatchID: id, Mode: mode, TickRate: 64, Seconds: 480, Seed: 18, Players: ps})
	synth.Spoil(bs, 64, me.Slot, mates, enemies)
	return bs, me
}

func behaviourOf(t *testing.T, st *store.Memory, tenant string, f store.ToxicityFilter) map[string]store.ToxicityFinding {
	t.Helper()
	rows, err := st.ListToxicityFindings(context.Background(), tenant, f)
	if err != nil {
		t.Fatal(err)
	}
	out := map[string]store.ToxicityFinding{}
	for _, r := range rows {
		if _, twice := out[r.Kind+"/"+r.PlayerHash]; twice {
			t.Fatalf("%s found twice for %s in one match", r.Kind, r.PlayerHash)
		}
		out[r.Kind+"/"+r.PlayerHash] = r
	}
	return out
}

func TestBehaviourFindingsAreAdviceOnly(t *testing.T) {
	p, st, k := newTest(t, Config{})
	ctx := context.Background()
	bs, me := spoiledMatch("tox-1")
	sess := session(st, me.SessionID, "t1", "spoiler")
	feed(t, p, "t1", bs)
	flush(p)

	got := behaviourOf(t, st, "t1", store.ToxicityFilter{MatchID: "tox-1"})
	if len(got) != len(toxicity.Kinds) {
		t.Fatalf("findings: %+v", got)
	}
	for kind, at := range map[string][2]int64{
		toxicity.KindFeeding: {170_000, 171_000}, toxicity.KindTeamDamage: {210_000, 211_000}, toxicity.KindTeamKill: {218_000, 219_000},
		toxicity.KindAFK: {223_000, 226_000}, toxicity.KindLeftEarly: {329_000, 330_000},
	} {
		// The verified session names the player, as it does for evidence.
		r, ok := got[kind+"/spoiler"]
		if !ok || r.SessionID != sess.SessionID || r.Slot != me.Slot || r.Bot || r.MatchMs < at[0] || r.MatchMs > at[1] || r.Summary == "" || r.Count == 0 {
			t.Errorf("%s: %+v", kind, r)
		}
	}

	// Nothing of it reaches the anti-cheat side: no evidence, no kick, no ban.
	ev, err := st.ListEvidence(ctx, "t1", store.EvidenceFilter{Limit: 1000})
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range ev {
		if e.PlayerHash == "spoiler" || e.SessionID == sess.SessionID {
			t.Errorf("behaviour made evidence: %+v", e)
		}
		for _, kind := range toxicity.Kinds {
			if strings.Contains(e.Rule, kind) {
				t.Errorf("a behaviour kind among the evidence: %+v", e)
			}
		}
	}
	if r := k.reason(sess.SessionID); r != "" {
		t.Errorf("the player was kicked: %q", r)
	}
	if bans, _ := st.ListBans(ctx, "t1", 0); len(bans) != 0 {
		t.Errorf("bans: %+v", bans)
	}
	if rows, _ := st.ListToxicityFindings(ctx, "t2", store.ToxicityFilter{}); len(rows) != 0 {
		t.Errorf("another studio reads the findings: %+v", rows)
	}
}

func TestBehaviourWithoutASessionUsesTheGameServersName(t *testing.T) {
	p, st, _ := newTest(t, Config{})
	bs, me := spoiledMatch("tox-2")
	feed(t, p, "t1", bs)
	flush(p)
	got := behaviourOf(t, st, "t1", store.ToxicityFilter{PlayerHash: me.PlayerHash})
	if r := got[toxicity.KindTeamKill+"/"+me.PlayerHash]; len(got) != len(toxicity.Kinds) || r.SessionID != "" || r.MatchID != "tox-2" {
		t.Fatalf("findings: %+v", got)
	}
}

func TestBehaviourLimitsAreTheStudiosOwn(t *testing.T) {
	p, st, _ := newTest(t, Config{})
	ctx := context.Background()
	// One studio only wants to hear about team kills, from the first; another turned all off.
	only := toxicity.Limits{TeamKills: 1}
	if err := st.SetToxicityLimits(ctx, "t1", only.Encode(), time.Now()); err != nil {
		t.Fatal(err)
	}
	if err := st.SetToxicityLimits(ctx, "t2", toxicity.Limits{}.Encode(), time.Now()); err != nil {
		t.Fatal(err)
	}
	bs, me := spoiledMatch("tox-3")
	feed(t, p, "t1", bs)
	feed(t, p, "t2", bs)
	feed(t, p, "t3", bs)
	flush(p)
	got := behaviourOf(t, st, "t1", store.ToxicityFilter{})
	if r := got[toxicity.KindTeamKill+"/"+me.PlayerHash]; len(got) != 1 || r.Count != 1 || !strings.Contains(r.Summary, "limit 1") {
		t.Fatalf("the studio with its own limits: %+v", got)
	}
	if got := behaviourOf(t, st, "t2", store.ToxicityFilter{}); len(got) != 0 {
		t.Fatalf("the studio that turned behaviour off: %+v", got)
	}
	if got := behaviourOf(t, st, "t3", store.ToxicityFilter{}); len(got) != len(toxicity.Kinds) {
		t.Fatalf("the studio on the defaults: %+v", got)
	}
}

func TestHonestMatchesHaveNoBehaviourFindings(t *testing.T) {
	p, st, _ := newTest(t, Config{})
	feed(t, p, "t1", synth.Batches(leakMatch("tox-honest", 300)))
	// A match without teams, positions or shots, as a v1 game server sends it.
	if ok, _, err := p.Gameplay(context.Background(), "t1", cheaterBatch(1, nil, true)); !ok || err != nil {
		t.Fatalf("v1 batch: %v %v", ok, err)
	}
	flush(p)
	if rows, _ := st.ListToxicityFindings(context.Background(), "t1", store.ToxicityFilter{}); len(rows) != 0 {
		t.Fatalf("findings in matches nobody spoiled: %+v", rows)
	}
}

func TestBehaviourFindingsArePruned(t *testing.T) {
	now := time.Now()
	p, st, _ := newTest(t, Config{Now: func() time.Time { return now }, ToxicityRetention: 24 * time.Hour})
	ctx := context.Background()
	if err := st.AddToxicityFindings(ctx, []store.ToxicityFinding{
		{TenantID: "t1", PlayerHash: "old", MatchID: "m", Kind: toxicity.KindAFK, ObservedAt: now.Add(-25 * time.Hour)},
		{TenantID: "t1", PlayerHash: "new", MatchID: "m", Kind: toxicity.KindAFK, ObservedAt: now.Add(-23 * time.Hour)},
	}); err != nil {
		t.Fatal(err)
	}
	p.prune()
	rows, _ := st.ListToxicityFindings(ctx, "t1", store.ToxicityFilter{})
	if len(rows) != 1 || rows[0].PlayerHash != "new" {
		t.Fatalf("after the prune: %+v", rows)
	}
}
