package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	pb "carthago/backend/gen/carthago/v1"
	"carthago/backend/internal/bans"
	"carthago/backend/internal/learning"
	"carthago/backend/internal/store"
)

// matchSize is how many players the simulated matchmaker puts in a match.
const matchSize = 4

type sim struct {
	ctx    context.Context
	out    io.Writer
	local  *local
	api    string
	ws     string
	key    string
	period time.Duration

	// queue is every account that signed in, in that order; pcs is the PC of each.
	queue []*player
	pcs   map[string]deviceKey
	// expect is what the simulation itself knows each account to be. The matchmaker
	// never reads it: it asks the gateway. The scenes compare the two.
	expect map[string]string
}

func (s *sim) say(format string, a ...any) { fmt.Fprintf(s.out, "   "+format+"\n", a...) }

// call is the studio's backend calling the game-server API under its server key.
func (s *sim) call(method, path string, body, into any) error {
	var rd io.Reader
	if body != nil {
		raw, _ := json.Marshal(body)
		rd = bytes.NewReader(raw)
	}
	req, err := http.NewRequestWithContext(s.ctx, method, s.api+path, rd)
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+s.key)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("%s %s: HTTP %d %s", method, path, resp.StatusCode, strings.TrimSpace(string(raw)))
	}
	return json.Unmarshal(raw, into)
}

// statuses asks for many players at once: POST /v1/shadow/status.
func (s *sim) statuses(names []string) (map[string]string, error) {
	var out struct {
		Players []struct{ Player, Status string }
	}
	if err := s.call("POST", "/v1/shadow/status", map[string]any{"players": names}, &out); err != nil {
		return nil, err
	}
	got := map[string]string{}
	for _, p := range out.Players {
		got[p.Player] = p.Status
	}
	for _, n := range names {
		if got[n] != bans.StatusNormal && got[n] != bans.StatusShadow {
			return nil, fmt.Errorf("no status for %s in the answer", n)
		}
	}
	return got, nil
}

// pool lists the pool: GET /v1/shadow/pool. The value is when each player's ban takes
// effect.
func (s *sim) pool() (map[string]time.Time, error) {
	var out struct {
		Players []struct {
			Player  string
			UntilMS int64 `json:"until_ms"`
		}
	}
	if err := s.call("GET", "/v1/shadow/pool", nil, &out); err != nil {
		return nil, err
	}
	got := map[string]time.Time{}
	for _, p := range out.Players {
		got[p.Player] = time.UnixMilli(p.UntilMS)
	}
	return got, nil
}

// signIn starts a client for an account on a PC; an empty pc is a PC of its own.
func (s *sim) signIn(name, pc string) (*player, error) {
	if pc == "" {
		pc = name
	}
	dk, ok := s.pcs[pc]
	if !ok {
		dk = newDeviceKey()
		s.pcs[pc] = dk
	}
	p, every, err := signIn(s.ctx, s.ws, demoTenant, name, s.local.identity, dk)
	if err != nil {
		return nil, err
	}
	s.pcs[name] = dk
	p.play(s.ctx, every)
	s.queue = append(s.queue, p)
	if s.expect[name] == "" {
		s.expect[name] = bans.StatusNormal
	}
	return p, nil
}

func (s *sim) signInAll(names ...string) error {
	for _, n := range names {
		if _, err := s.signIn(n, ""); err != nil {
			return fmt.Errorf("%s signs in: %w", n, err)
		}
	}
	return nil
}

func (s *sim) player(name string) *player {
	for i := len(s.queue) - 1; i >= 0; i-- {
		if s.queue[i].name == name {
			return s.queue[i]
		}
	}
	return nil
}

// wait polls until ok, for at most d.
func (s *sim) wait(d time.Duration, ok func() bool) bool {
	deadline := time.Now().Add(d)
	for !ok() {
		if time.Now().After(deadline) || s.ctx.Err() != nil {
			return false
		}
		time.Sleep(50 * time.Millisecond)
	}
	return true
}

type match struct {
	kind    string
	players []string
}

// round is one pass of the matchmaker over the players who are online.
type round struct {
	matches []match
	waiting map[string][]string
	status  map[string]string
}

// matchmake is the studio's matchmaker: it asks the gateway for the status of everybody
// in the queue, then fills matches from the normal players and from the pool
// separately. It knows nothing else about anybody.
func (s *sim) matchmake() (*round, error) {
	var names []string
	for _, p := range s.queue {
		if p.online() {
			names = append(names, p.name)
		}
	}
	status, err := s.statuses(names)
	if err != nil {
		return nil, err
	}
	r := &round{status: status, waiting: map[string][]string{}}
	for _, kind := range []string{bans.StatusNormal, bans.StatusShadow} {
		var q []string
		for _, n := range names {
			if status[n] == kind {
				q = append(q, n)
			}
		}
		for len(q) >= matchSize {
			r.matches = append(r.matches, match{kind, q[:matchSize]})
			q = q[matchSize:]
		}
		r.waiting[kind] = q
	}
	return r, nil
}

func (s *sim) show(r *round) {
	n := map[string]int{}
	for _, st := range r.status {
		n[st]++
	}
	s.say("matchmaker asks POST /v1/shadow/status for %d players online: %d normal, %d shadow", len(r.status), n[bans.StatusNormal], n[bans.StatusShadow])
	for _, m := range r.matches {
		s.say("  match (%s): %s", m.kind, strings.Join(m.players, " "))
	}
	if w := r.waiting[bans.StatusNormal]; len(w) > 0 {
		s.say("  waiting for the next normal match: %s", strings.Join(w, " "))
	}
	if w := r.waiting[bans.StatusShadow]; len(w) > 0 {
		s.say("  waiting in the pool for %d more: %s (filling a short match with bots is the studio's choice)", matchSize-len(w), strings.Join(w, " "))
	}
}

// check compares a round with what the simulation knows: every account that is online
// has the status it should have, and no match holds players of both kinds.
func (s *sim) check(r *round) error {
	for n, got := range r.status {
		if got != s.expect[n] {
			return fmt.Errorf("the gateway says %s is %s, and it is %s", n, got, s.expect[n])
		}
	}
	for _, m := range r.matches {
		for _, n := range m.players {
			if s.expect[n] != m.kind {
				return fmt.Errorf("%s is %s and was put in a %s match", n, s.expect[n], m.kind)
			}
		}
	}
	return nil
}

func (s *sim) matched(r *round, name, kind string) bool {
	for _, m := range r.matches {
		for _, n := range m.players {
			if n == name {
				return m.kind == kind
			}
		}
	}
	return false
}

// rendererReport is what a client reports when the game loaded an unsigned OPENGL32.dll
// from its own folder in place of the system's: certain evidence, with the file's hash.
// The simulation sends the report; no such file exists.
func rendererReport(file string) *pb.Finding {
	sum := sha256.Sum256([]byte("carthago-shadow-sim: " + file))
	b := uint64(pb.ModuleSignature_MODULE_SIGNATURE_NONE) | uint64(pb.ModulePathClass_MODULE_PATH_CLASS_GAME_DIR)<<8 |
		uint64(pb.ObservedFlags_OBSERVED_FLAGS_AT_START|pb.ObservedFlags_OBSERVED_FLAGS_SHADOWS_SYSTEM)<<16
	return &pb.Finding{Job: "module_inventory", Code: uint32(pb.FindingCode_FINDING_CODE_MODULE_SIGNATURE), A: 1, B: b, Detail: "OPENGL32.dll", FileSha256: sum[:]}
}

// catch has the clients of the named accounts report the replaced renderer and waits
// until the gateway has put them in the pool.
func (s *sim) catch(file string, names ...string) error {
	for _, n := range names {
		if err := s.player(n).report(s.ctx, rendererReport(file)); err != nil {
			return fmt.Errorf("%s reports: %w", n, err)
		}
		s.expect[n] = bans.StatusShadow
	}
	var last error
	if !s.wait(5*time.Second, func() bool {
		got, err := s.statuses(names)
		if last = err; err != nil {
			return false
		}
		for _, n := range names {
			if got[n] != bans.StatusShadow {
				last = fmt.Errorf("%s is still %s", n, got[n])
				return false
			}
		}
		return true
	}) {
		return last
	}
	return nil
}

// shadowLabels counts the sessions labelled "confirmed cheat" by the pool, per account.
func (s *sim) shadowLabels() (map[string]int, error) {
	labels, err := s.local.st.ListSessionLabels(s.ctx, demoTenant, store.OracleFilter{})
	if err != nil {
		return nil, err
	}
	got := map[string]int{}
	for _, l := range labels {
		if l.Label == store.LabelConfirmedCheat && l.Source == store.LabelSourceShadow && l.BanRef != "" {
			got[l.PlayerHash]++
		}
	}
	return got, nil
}

// quiet says what a pooled client has received next to an honest one: heartbeat
// acknowledgements and nothing else.
func (s *sim) quiet(names []string, honest string, before map[string]seen) error {
	h := s.player(honest).seen()
	for _, n := range names {
		p := s.player(n)
		got := p.seen()
		switch {
		case got.kicked != "" || got.closed:
			return fmt.Errorf("the session of %s was ended (%q)", n, got.kicked)
		case got.notices != 0:
			return fmt.Errorf("the client of %s was sent %d notices", n, got.notices)
		case got.acks <= before[n].acks:
			return fmt.Errorf("the heartbeats of %s are no longer acknowledged", n)
		}
		rec, err := s.local.st.GetSession(s.ctx, fmt.Sprintf("%x", p.sid))
		if err != nil || rec.State != store.SessionActive {
			return fmt.Errorf("the session of %s is not active on the gateway", n)
		}
	}
	if h.notices != 0 || h.kicked != "" {
		return fmt.Errorf("the honest client of %s was sent a notice or a kick", honest)
	}
	return nil
}

func (s *sim) scenes() (passed, total int) {
	s.pcs, s.expect = map[string]deviceKey{}, map[string]string{}
	for i, sc := range []struct {
		title string
		run   func() (string, error)
	}{
		{"Honest players are matched normally", s.honest},
		{"Caught players stay online and are matched only with each other", s.caught},
		{"Another account on a caught player's PC joins the pool", s.secondAccount},
		{"A released player is matched normally again", s.released},
		{"The ban takes effect by itself when the period ends", s.landed},
	} {
		total++
		fmt.Fprintf(s.out, "\n%d. %s\n", i+1, sc.title)
		summary, err := sc.run()
		if err != nil {
			s.say("FAIL  %v", err)
			continue
		}
		s.say("PASS  %s", summary)
		passed++
	}
	return passed, total
}

var (
	honest = []string{"ana", "ben", "cleo", "dov", "eli", "fay", "gus", "hana"}
	cheats = []string{"kex", "lod", "mav", "nyx"}
)

func (s *sim) honest() (string, error) {
	if err := s.signInAll(honest...); err != nil {
		return "", err
	}
	s.say("%d players sign in with clean clients: %s", len(honest), strings.Join(honest, " "))
	r, err := s.matchmake()
	if err != nil {
		return "", err
	}
	s.show(r)
	if err := s.check(r); err != nil {
		return "", err
	}
	if len(r.matches) != 2 {
		return "", fmt.Errorf("%d matches, want 2", len(r.matches))
	}
	return "everybody is normal and plays in a normal match", nil
}

func (s *sim) caught() (string, error) {
	if err := s.signInAll(cheats...); err != nil {
		return "", err
	}
	s.say("%s sign in; their clients report an unsigned OPENGL32.dll in the game folder (certain evidence)", strings.Join(cheats, ", "))
	s.say("without the pool each would get a notice and the ban at once; the period is on, so:")
	if err := s.catch("opengl32-a", cheats...); err != nil {
		return "", err
	}
	before := map[string]seen{}
	for _, n := range cheats {
		before[n] = s.player(n).seen()
	}
	// Three more heartbeats each, to see what comes back.
	if !s.wait(5*time.Second, func() bool {
		for _, n := range cheats {
			if s.player(n).seen().acks < before[n].acks+3 {
				return false
			}
		}
		return true
	}) {
		return "", errors.New("the heartbeats of the caught players are no longer acknowledged")
	}
	if err := s.quiet(cheats, "ana", before); err != nil {
		return "", err
	}
	s.say("their clients since then: heartbeats acknowledged, 0 notices, no kick, session open; the same as ana's client")
	pool, err := s.pool()
	if err != nil {
		return "", err
	}
	for _, n := range cheats {
		if pool[n].IsZero() {
			return "", fmt.Errorf("%s is not in GET /v1/shadow/pool", n)
		}
	}
	if len(pool) != len(cheats) {
		return "", fmt.Errorf("GET /v1/shadow/pool lists %d players, want %d", len(pool), len(cheats))
	}
	s.say("GET /v1/shadow/pool lists %d players; the first ban takes effect in %s", len(pool), time.Until(pool[cheats[0]]).Round(time.Second))
	var labels map[string]int
	if !s.wait(3*time.Second, func() bool {
		labels, err = s.shadowLabels()
		return err == nil && len(labels) == len(cheats)
	}) {
		return "", fmt.Errorf("sessions labelled by the pool: %v %v, want one for each caught player", labels, err)
	}
	props, err := learning.FindProposals(s.ctx, s.local.st, demoTenant)
	if err != nil {
		return "", err
	}
	if len(props.List) != 1 || props.List[0].BannedAccounts != len(cheats) {
		return "", fmt.Errorf("proposed known cheats: %+v, want the one file of the %d caught accounts", props.List, len(cheats))
	}
	s.say("collected: %d sessions labelled confirmed cheat (source shadow); the file only these %d accounts load is proposed as a known cheat", len(labels), props.List[0].BannedAccounts)
	r, err := s.matchmake()
	if err != nil {
		return "", err
	}
	s.show(r)
	if err := s.check(r); err != nil {
		return "", err
	}
	for _, n := range cheats {
		if !s.matched(r, n, bans.StatusShadow) {
			return "", fmt.Errorf("%s is not in a shadow match", n)
		}
	}
	return "the caught players see nothing and play each other; no match mixes them with honest players", nil
}

func (s *sim) secondAccount() (string, error) {
	p, err := s.signIn("kex2", "kex")
	if err != nil {
		return "", fmt.Errorf("kex2 signs in: %w", err)
	}
	s.expect["kex2"] = bans.StatusShadow
	s.say("kex2, a new account with a clean client, signs in on kex's PC (the same device key) and gets a session like anybody")
	// No waiting: the account is in the pool before its client has the session.
	got, err := s.statuses([]string{"kex2"})
	if err != nil {
		return "", err
	}
	if got["kex2"] != bans.StatusShadow {
		return "", fmt.Errorf("kex2 is %s right after signing in", got["kex2"])
	}
	pool, err := s.pool()
	if err != nil {
		return "", err
	}
	if pool["kex2"].IsZero() || !pool["kex2"].Equal(pool["kex"]) {
		return "", fmt.Errorf("kex2's ban takes effect at %v, kex's at %v", pool["kex2"], pool["kex"])
	}
	s.say("status of kex2: shadow, with the same end as kex")
	before := map[string]seen{"kex2": p.seen()}
	if !s.wait(5*time.Second, func() bool { return p.seen().acks >= 2 }) {
		return "", errors.New("the heartbeats of kex2 are not acknowledged")
	}
	if err := s.quiet([]string{"kex2"}, "ana", before); err != nil {
		return "", err
	}
	r, err := s.matchmake()
	if err != nil {
		return "", err
	}
	s.show(r)
	if err := s.check(r); err != nil {
		return "", err
	}
	if w := r.waiting[bans.StatusShadow]; len(w) != 1 || w[0] != "kex2" {
		return "", fmt.Errorf("kex2 is not queued with the pool: %v", w)
	}
	return "the second account is in the pool from its first moment, told nothing", nil
}

func (s *sim) released() (string, error) {
	b, err := s.local.bans.Pooled(s.ctx, demoTenant, "nyx")
	if err != nil || b == nil {
		return "", fmt.Errorf("nyx is not in the pool: %v", err)
	}
	// What Release on the Shadow pool page does, by the same call.
	gone, _, err := s.local.bans.Release(s.ctx, demoTenant, b.ID, "simulation", "simulated release")
	if err != nil {
		return "", err
	}
	if err := s.local.st.AppendAudit(s.ctx, &store.AuditEntry{TenantID: demoTenant, At: time.Now(), Actor: "simulation", Action: "shadow.release", Target: "ban " + gone.Ref, Detail: "simulated release"}); err != nil {
		return "", err
	}
	s.expect["nyx"] = bans.StatusNormal
	s.say("a reviewer releases nyx (Release on the Shadow pool page); three more honest players sign in: ivo jan kim")
	if err := s.signInAll("ivo", "jan", "kim"); err != nil {
		return "", err
	}
	labels, err := s.shadowLabels()
	if err != nil {
		return "", err
	}
	if labels["nyx"] != 0 || labels["kex"] == 0 || labels["kex2"] == 0 {
		return "", fmt.Errorf("labels after the release: %v, want none for nyx and the others kept", labels)
	}
	props, err := learning.FindProposals(s.ctx, s.local.st, demoTenant)
	if err != nil {
		return "", err
	}
	if len(props.List) != 0 {
		return "", fmt.Errorf("the file is still proposed though nyx, who loads it, is not banned: %+v", props.List)
	}
	s.say("nyx's label is removed, and the file is no longer proposed: an account that is not banned loads it too")
	r, err := s.matchmake()
	if err != nil {
		return "", err
	}
	s.show(r)
	if err := s.check(r); err != nil {
		return "", err
	}
	if !s.matched(r, "nyx", bans.StatusNormal) {
		return "", errors.New("nyx is not in a normal match")
	}
	if !s.player("nyx").online() {
		return "", errors.New("the release ended nyx's session")
	}
	return "nyx is normal again and plays with honest players; the others stay in the pool", nil
}

func (s *sim) landed() (string, error) {
	pooled := []string{"kex", "lod", "mav", "kex2"}
	pool, err := s.pool()
	if err != nil {
		return "", err
	}
	var end time.Time
	for _, n := range pooled {
		if pool[n].IsZero() {
			return "", fmt.Errorf("%s left the pool before the period ended", n)
		}
		if pool[n].After(end) {
			end = pool[n]
		}
	}
	s.say("waiting %s for the period to end; nobody acts ...", time.Until(end).Round(time.Second))
	select {
	case <-time.After(time.Until(end)):
	case <-s.ctx.Done():
		return "", errors.New("interrupted")
	}
	if !s.wait(10*time.Second, func() bool {
		for _, n := range pooled {
			if s.player(n).online() {
				return false
			}
		}
		return true
	}) {
		return "", errors.New("a pooled player is still online after the period ended")
	}
	for _, n := range pooled {
		got := s.player(n).seen()
		if got.kicked != "banned" || got.notices != 0 {
			return "", fmt.Errorf("the client of %s got kick %q and %d notices, want the ban and nothing before it", n, got.kicked, got.notices)
		}
		s.expect[n] = bans.StatusNormal
	}
	s.say("%s: session ended by the gateway, reason \"banned\"; no notice came before it", strings.Join(pooled, ", "))
	list, err := s.local.st.ListBans(s.ctx, demoTenant, 100)
	if err != nil {
		return "", err
	}
	active := 0
	for _, b := range list {
		if !b.Lifted() && b.Shadow && b.Active(time.Now()) && !b.LandedAt.IsZero() {
			active++
		}
	}
	audit, err := s.local.st.ListAudit(s.ctx, demoTenant, store.AuditFilter{ActionPrefixes: []string{"shadow.end"}, Limit: 100})
	if err != nil {
		return "", err
	}
	if active != len(pooled) || len(audit) != len(pooled) {
		return "", fmt.Errorf("%d bans in effect and %d audit entries, want %d of each", active, len(audit), len(pooled))
	}
	if pool, err = s.pool(); err != nil || len(pool) != 0 {
		return "", fmt.Errorf("GET /v1/shadow/pool after the end: %v %v, want nobody", pool, err)
	}
	// The account, the second account and a third one on that PC are all refused.
	var refused []string
	for _, n := range []string{"kex", "kex2", "kex3"} {
		_, _, err := signIn(s.ctx, s.ws, demoTenant, n, s.local.identity, s.pcs["kex"])
		if !errors.Is(err, errBanned) {
			return "", fmt.Errorf("%s signs in after the ban: %v, want the ban refusal", n, err)
		}
		refused = append(refused, n+" "+err.Error())
	}
	s.say("signing in again, and kex3, a third account on kex's PC: %s", strings.Join(refused, "; "))
	evs, err := s.local.st.ListEvidence(s.ctx, demoTenant, store.EvidenceFilter{Limit: 1000})
	if err != nil {
		return "", err
	}
	for _, e := range evs {
		if e.PlayerHash != "nyx" && !strings.HasPrefix(e.PlayerHash, "kex") && e.PlayerHash != "lod" && e.PlayerHash != "mav" {
			return "", fmt.Errorf("evidence against an honest player: %s %s", e.PlayerHash, e.Rule)
		}
	}
	for _, p := range s.queue {
		if got := p.seen(); s.expect[p.name] == bans.StatusNormal && p.name != "kex" && p.name != "lod" && p.name != "mav" && p.name != "kex2" && (!p.online() || got.notices != 0) {
			return "", fmt.Errorf("%s, who is not banned, lost the session or got a notice", p.name)
		}
	}
	r, err := s.matchmake()
	if err != nil {
		return "", err
	}
	s.show(r)
	if err := s.check(r); err != nil {
		return "", err
	}
	if !s.matched(r, "nyx", bans.StatusNormal) {
		return "", errors.New("nyx is not in a normal match")
	}
	return fmt.Sprintf("%d bans took effect on account and PC with no action by anybody; the honest players and nyx play on", len(pooled)), nil
}

// leaveSome puts three more players in the pool under a period of two days, so the
// dashboard's Shadow pool page has entries to ban now or release.
func (s *sim) leaveSome() error {
	if err := s.local.setPeriod(s.ctx, dashboardPeriod); err != nil {
		return err
	}
	if err := s.signInAll("ork", "pax"); err != nil {
		return err
	}
	if err := s.catch("opengl32-b", "ork", "pax"); err != nil {
		return err
	}
	if _, err := s.signIn("ork2", "ork"); err != nil {
		return err
	}
	fmt.Fprintf(s.out, "\nFor the dashboard: the period is now 48 hours, and ork, pax and ork2 (on ork's PC) were caught the same way and are in the pool.\n")
	return nil
}
