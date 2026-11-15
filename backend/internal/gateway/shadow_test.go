package gateway

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"
	"time"

	pb "carthago/backend/gen/carthago/v1"
	"carthago/backend/internal/bans"
	"carthago/backend/internal/learning"
	"carthago/backend/internal/pipeline"
	"carthago/backend/internal/protocol"
	"carthago/backend/internal/store"
)

// newPoolEnv is a gateway with notices, automatic bans and the shadow pool wired as the
// gateway binary wires them, for two studios. Every heartbeat ack renews the token, so
// the renewed token is part of what a client is seen to get.
func newPoolEnv(t *testing.T, period time.Duration) *banEnv {
	keys, err := LoadOrCreateKeys(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	st := store.NewMemory()
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	svc := bans.New(st, log)
	svc.AddHook(learning.NewLabeler(st, log))
	var gw *Gateway
	pl := pipeline.New(pipeline.Config{Notices: true}, st, st, kickFunc(func(id, reason string) { gw.Sessions().Kick(id, reason) }), log)
	t.Cleanup(pl.Close)
	pl.SetBanner(svc)
	pl.SetKnownCheats(st)
	pl.SetPool(svc)
	gw = New(Config{
		Tenants: map[string]string{"demo": serverKey, "rival": "rival-server-key"}, HeartbeatInterval: 10 * time.Millisecond, HeartbeatTimeout: 5 * time.Second,
		TokenTTL: time.Minute, RenewBefore: time.Minute, Detections: pl, Bans: svc, Pool: svc, Drivers: st,
	}, keys, st, log)
	pl.SetNotifier(gw)
	svc.SetEnder(gw.Sessions())
	srv := httptest.NewServer(gw.Handler())
	t.Cleanup(srv.Close)
	if err := st.SetShadowPeriod(context.Background(), "demo", period); err != nil {
		t.Fatal(err)
	}
	return &banEnv{env: &env{gw: gw, srv: srv, keys: keys, st: st}, bans: svc}
}

// api calls the game-server API of the test gateway.
func (e *banEnv) api(t *testing.T, method, path, key, body string) (int, map[string]any) {
	t.Helper()
	req, _ := http.NewRequest(method, e.srv.URL+path, strings.NewReader(body))
	if key != "" {
		req.Header.Set("Authorization", "Bearer "+key)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	out := map[string]any{}
	_ = json.NewDecoder(resp.Body).Decode(&out)
	return resp.StatusCode, out
}

func (e *banEnv) status(t *testing.T, player string) string {
	t.Helper()
	code, out := e.api(t, "GET", "/v1/shadow/status?player="+player, serverKey, "")
	if code != http.StatusOK || out["player"] != player {
		t.Fatalf("status of %s: %d %v", player, code, out)
	}
	return out["status"].(string)
}

func eventually(t *testing.T, what string, ok func() bool) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for !ok() {
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting for %s", what)
		}
		time.Sleep(5 * time.Millisecond)
	}
}

// seen writes down everything of one server message that a client can tell apart, with
// what is the player's own taken out: the ids are reduced to their length, times to how
// long the token lasts.
func seen(t *testing.T, e *env, m *pb.ServerMsg) string {
	t.Helper()
	token := func(tok string, expiresMS uint64) string {
		c, err := protocol.VerifyToken(tokenKeys(e), tok, time.Now(), protocol.DefaultLeeway)
		if err != nil {
			t.Fatalf("token: %v", err)
		}
		iat, _ := time.Parse(time.RFC3339, c.Iat)
		exp, _ := time.Parse(time.RFC3339, c.Exp)
		return fmt.Sprintf("token[%d bytes iss=%s tenant=%s player=%d device=%d session=%d lasts=%s trust=%d flags=%#x] expires_in=%s",
			len(tok), c.Iss, c.Tenant, len(c.PlayerHash), len(c.DeviceID), len(c.SessionID), exp.Sub(iat), c.TrustLevel, c.AttestFlags,
			time.UnixMilli(int64(expiresMS)).Sub(time.UnixMilli(int64(m.ServerTsMs))).Round(time.Second))
	}
	head := fmt.Sprintf("seq=%d session_id=%d ", m.Seq, len(m.SessionId))
	switch b := m.Body.(type) {
	case *pb.ServerMsg_Session:
		s := b.Session
		return head + fmt.Sprintf("Session trust=%d flags=%#x notes=%q %s", s.TrustLevel, s.AttestFlags, s.Notes, token(s.SessionToken, s.ExpiresAtMs))
	case *pb.ServerMsg_HeartbeatAck:
		if b.HeartbeatAck.RenewedToken == "" {
			return head + "HeartbeatAck"
		}
		return head + "HeartbeatAck renewed " + token(b.HeartbeatAck.RenewedToken, b.HeartbeatAck.RenewedExpiresAtMs)
	case *pb.ServerMsg_EnforcementNotice:
		return head + "EnforcementNotice"
	case *pb.ServerMsg_Kicked:
		return head + "Kicked " + b.Kicked.Reason
	case *pb.ServerMsg_Banned:
		return head + "Banned"
	}
	return head + fmt.Sprintf("%T", m.Body)
}

// What a client is sent does not say whether its player is in the shadow pool. Two
// players do the same things on a gateway that raises alerts and bans automatically; one
// of them is caught on certain evidence on the first heartbeat and found with a memory
// editor later. Everything the two clients receive is the same: the handshake answer,
// the token and its claims, every heartbeat ack with its renewed token, in the same
// order with nothing in between, on the session that was caught, on the next one, and
// for another account that connects from the same PC. TestCertainEvidenceBansAutomatically
// is the same evidence with the period off: a notice, then the end of the session.
func TestShadowPoolIsInvisibleToTheClient(t *testing.T) {
	e := newPoolEnv(t, 48*time.Hour)
	ctx := context.Background()

	play := func(player, alternate string, cheats bool) (got []string, sessions []string) {
		t.Helper()
		key := softwareKey()
		connect := func(account string) *testClient {
			t.Helper()
			c, err := handshakeAs(t, e.env, key, account, false)
			if err != nil {
				t.Fatalf("%s: handshake: %v", account, err)
			}
			got = append(got, seen(t, e.env, &pb.ServerMsg{SessionId: c.sid, ServerTsMs: uint64(time.Now().UnixMilli()), Body: &pb.ServerMsg_Session{Session: c.session}}))
			sessions = append(sessions, sessionOf(t, e.env, c).SessionID)
			return c
		}
		beat := func(c *testClient, findings ...*pb.Finding) {
			t.Helper()
			time.Sleep(15 * time.Millisecond)
			sendFindings(c, findings...)
			m, err := c.recv()
			if err != nil {
				t.Fatalf("%s: %v", player, err)
			}
			got = append(got, seen(t, e.env, m))
		}
		evidence := func(n int) {
			t.Helper()
			eventually(t, "the evidence of "+player, func() bool {
				evs, _ := e.st.ListEvidence(ctx, "demo", store.EvidenceFilter{SessionID: sessions[0], Limit: 100})
				return len(evs) >= n
			})
		}

		c := connect(player)
		if cheats {
			beat(c, rendererFinding())
			eventually(t, player+" in the pool", func() bool { b, _ := e.bans.Pooled(ctx, "demo", player); return b != nil })
			evidence(1)
		} else {
			beat(c)
		}
		for range 3 {
			beat(c)
		}
		if cheats {
			// On a normal player this raises the alert (TestOnlyCertainEvidenceBans).
			beat(c, memoryToolFinding())
			evidence(2)
		} else {
			beat(c)
		}
		for range 3 {
			beat(c)
		}
		// The same account again, and another account on the same PC.
		c2 := connect(player)
		beat(c2)
		c3 := connect(alternate)
		beat(c3)
		beat(c3)
		// The first connection is still up and has been sent nothing in the meantime.
		beat(c)
		return got, sessions
	}

	caught, caughtSessions := play("player-caught", "second-caught", true)
	normal, normalSessions := play("player-normal", "second-normal", false)
	if !reflect.DeepEqual(caught, normal) {
		for i := 0; i < len(caught) || i < len(normal); i++ {
			a, b := "(nothing)", "(nothing)"
			if i < len(caught) {
				a = caught[i]
			}
			if i < len(normal) {
				b = normal[i]
			}
			mark := "  "
			if a != b {
				mark = "!="
			}
			t.Logf("%s in the pool: %s\n   normal:      %s", mark, a, b)
		}
		t.Fatal("a client can tell that its player is in the shadow pool")
	}
	if len(caught) != 15 || !strings.Contains(caught[0], "Session trust=") || !strings.Contains(caught[1], "HeartbeatAck renewed token[") {
		t.Fatalf("the script did not run as written: %d messages, %q", len(caught), caught[:2])
	}

	// And the gateway did tell them apart, on its side only.
	for player, want := range map[string]string{"player-caught": "shadow", "second-caught": "shadow", "player-normal": "normal", "second-normal": "normal"} {
		if got := e.status(t, player); got != want {
			t.Errorf("%s is %s, want %s", player, got, want)
		}
	}
	for _, id := range append(caughtSessions, normalSessions...) {
		if s, ok := e.gw.Sessions().Get(id); !ok || s.State != store.SessionActive {
			t.Errorf("session %s was ended", id)
		}
	}
	evs, _ := e.st.ListEvidence(ctx, "demo", store.EvidenceFilter{SessionID: caughtSessions[0], Limit: 100})
	rules := map[string]bool{}
	for _, ev := range evs {
		rules[ev.Rule] = true
	}
	if !rules["renderer_replaced"] || !rules["memory_tool"] {
		t.Fatalf("the evidence of the caught session: %v", rules)
	}
	for i, id := range caughtSessions {
		l, err := e.st.GetSessionLabel(ctx, "demo", id)
		if err != nil || l.Label != store.LabelConfirmedCheat || l.Source != store.LabelSourceShadow {
			t.Errorf("session %d of the pool: label %+v %v", i, l, err)
		}
	}
	for _, id := range normalSessions {
		if _, err := e.st.GetSessionLabel(ctx, "demo", id); err == nil {
			t.Errorf("a normal session was labelled")
		}
	}
	list, _ := e.st.ListBans(ctx, "demo", 0)
	if len(list) != 2 || !list[1].Shadow || list[1].PlayerHash != "player-caught" || list[0].ShadowOf != list[1].Ref || !list[0].EffectiveAt.Equal(list[1].EffectiveAt) {
		t.Fatalf("pool entries: %+v", list)
	}
	audit, _ := e.st.ListAudit(ctx, "demo", store.AuditFilter{Limit: 10})
	if len(audit) != 2 || audit[1].Action != "shadow.enter" || audit[0].Action != "shadow.join" || audit[0].Actor != store.BanAutomatic {
		t.Fatalf("audit: %+v", audit)
	}
}

// The pool is told to the studio's own servers and to nobody else: the calls take the
// tenant's server key, answer about that tenant only, and say "normal" or "shadow".
func TestShadowPoolAPI(t *testing.T) {
	e := newPoolEnv(t, 48*time.Hour)
	ctx := context.Background()
	c, err := handshakeAs(t, e.env, softwareKey(), "max", false)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := handshakeAs(t, e.env, softwareKey(), "zed", false); err != nil {
		t.Fatal(err)
	}
	sendFindings(c, rendererFinding())
	eventually(t, "max in the pool", func() bool { b, _ := e.bans.Pooled(ctx, "demo", "max"); return b != nil })
	entry, _ := e.bans.Pooled(ctx, "demo", "max")

	calls := [][3]string{{"GET", "/v1/shadow/status?player=max", ""}, {"POST", "/v1/shadow/status", `{"players":["max"]}`}, {"GET", "/v1/shadow/pool", ""}}
	for _, key := range []string{"", "nope", "demo-dashboard-key", c.session.SessionToken} {
		for _, call := range calls {
			if code, out := e.api(t, call[0], call[1], key, call[2]); code != http.StatusUnauthorized || out["status"] != nil || out["players"] != nil {
				t.Errorf("%s %s with key %q: %d %v, want 401 and nothing", call[0], call[1], key, code, out)
			}
		}
	}
	if e.status(t, "max") != "shadow" || e.status(t, "zed") != "normal" || e.status(t, "never-seen") != "normal" {
		t.Fatal("status of one player")
	}
	code, out := e.api(t, "POST", "/v1/shadow/status", serverKey, `{"players":["zed","max","never-seen","max"]}`)
	if got := fmt.Sprint(out["players"]); code != http.StatusOK ||
		got != "[map[player:zed status:normal] map[player:max status:shadow] map[player:never-seen status:normal] map[player:max status:shadow]]" {
		t.Fatalf("status of many: %d %s", code, got)
	}
	code, out = e.api(t, "GET", "/v1/shadow/pool", serverKey, "")
	pool, _ := out["players"].([]any)
	if code != http.StatusOK || len(pool) != 1 {
		t.Fatalf("pool: %d %v", code, out)
	}
	if p := pool[0].(map[string]any); p["player"] != "max" || int64(p["since_ms"].(float64)) != entry.BannedAt.UnixMilli() || int64(p["until_ms"].(float64)) != entry.EffectiveAt.UnixMilli() || len(p) != 3 {
		t.Fatalf("pool entry: %v", p)
	}
	// Another studio's key sees its own pool, which is empty.
	if code, out := e.api(t, "GET", "/v1/shadow/status?player=max", "rival-server-key", ""); code != http.StatusOK || out["status"] != "normal" {
		t.Fatalf("another studio: %d %v", code, out)
	}
	if code, out := e.api(t, "GET", "/v1/shadow/pool", "rival-server-key", ""); code != http.StatusOK || len(out["players"].([]any)) != 0 {
		t.Fatalf("another studio's pool: %d %v", code, out)
	}
	many := `{"players":["` + strings.Repeat(`p","`, 500) + `p"]}`
	for _, bad := range [][3]string{{"GET", "/v1/shadow/status", ""}, {"GET", "/v1/shadow/status?player=" + strings.Repeat("x", 129), ""}, {"POST", "/v1/shadow/status", `{"players":[]}`},
		{"POST", "/v1/shadow/status", `{"players":["max",""]}`}, {"POST", "/v1/shadow/status", `{"players":["max"],"more":1}`}, {"POST", "/v1/shadow/status", many}, {"POST", "/v1/shadow/status", `nope`}} {
		if code, _ := e.api(t, bad[0], bad[1], serverKey, bad[2]); code != http.StatusBadRequest {
			t.Errorf("%s %s %.40s: %d, want 400", bad[0], bad[1], bad[2], code)
		}
	}
	// A gateway without the pool has no such calls.
	plain := newBanEnv(t, true)
	if code, _ := plain.api(t, "GET", "/v1/shadow/pool", serverKey, ""); code != http.StatusNotFound {
		t.Fatalf("without the pool: %d", code)
	}
}

// Over the wire to the end: the caught player and a second account on the same PC play
// on until the period is over, then both sessions end as for any ban and the next
// handshake of either account, and of anybody on that PC, is refused with the reference.
func TestShadowPoolBanLandsAtTheEndOfThePeriod(t *testing.T) {
	e := newPoolEnv(t, 2*time.Second)
	ctx := context.Background()
	key := softwareKey()
	c, err := handshakeAs(t, e.env, key, "max", false)
	if err != nil {
		t.Fatal(err)
	}
	sendFindings(c, rendererFinding())
	if m, err := c.recv(); err != nil || m.GetHeartbeatAck() == nil {
		t.Fatalf("the heartbeat with the evidence: %v %v", m, err)
	}
	eventually(t, "max in the pool", func() bool { b, _ := e.bans.Pooled(ctx, "demo", "max"); return b != nil })
	entry, _ := e.bans.Pooled(ctx, "demo", "max")
	alt, err := handshakeAs(t, e.env, key, "max-second-account", false)
	if err != nil {
		t.Fatalf("a second account on the PC of the pool was refused: %v", err)
	}
	if e.status(t, "max-second-account") != "shadow" {
		t.Fatal("the second account is not in the pool")
	}
	for _, cl := range []*testClient{c, alt} {
		reason, notices := recvKick(t, cl)
		if reason != bans.KickReason || len(notices) != 0 {
			t.Fatalf("at the end of the period: %q after %d notices", reason, len(notices))
		}
	}
	if left := time.Until(entry.EffectiveAt); left > 0 {
		t.Fatalf("the ban landed %s early", left)
	}
	for _, try := range []struct {
		account string
		key     deviceKey
	}{{"max", softwareKey()}, {"max-second-account", softwareKey()}, {"a-third-account", key}} {
		cl, err := handshakeAs(t, e.env, try.key, try.account, false)
		if body := refusal(t, e.env, cl, err); body.BanRef == "" {
			t.Fatalf("%s: refusal %v", try.account, body)
		}
	}
	if e.status(t, "max") != "normal" {
		t.Fatal("a banned player is still reported as in the pool")
	}
	if _, err := handshakeAs(t, e.env, softwareKey(), "somebody-else", false); err != nil {
		t.Fatalf("a stranger: %v", err)
	}
}

// Ban now and Release reach the live session: the first ends it like any ban, the second
// leaves it running and the player is normal again.
func TestShadowPoolBanNowAndReleaseOverTheWire(t *testing.T) {
	e := newPoolEnv(t, 48*time.Hour)
	ctx := context.Background()
	enter := func(player string) (*testClient, *store.Ban) {
		t.Helper()
		c, err := handshakeAs(t, e.env, softwareKey(), player, false)
		if err != nil {
			t.Fatal(err)
		}
		sendFindings(c, rendererFinding())
		if m, err := c.recv(); err != nil || m.GetHeartbeatAck() == nil {
			t.Fatalf("%v %v", m, err)
		}
		eventually(t, player+" in the pool", func() bool { b, _ := e.bans.Pooled(ctx, "demo", player); return b != nil })
		b, _ := e.bans.Pooled(ctx, "demo", player)
		return c, b
	}
	banned, b1 := enter("max")
	released, b2 := enter("nia")
	if _, _, err := e.bans.BanNow(ctx, "demo", b1.ID); err != nil {
		t.Fatal(err)
	}
	if reason, notices := recvKick(t, banned); reason != bans.KickReason || len(notices) != 0 {
		t.Fatalf("ban now: %q after %d notices", reason, len(notices))
	}
	if _, _, err := e.bans.Release(ctx, "demo", b2.ID, "ada", "false alarm"); err != nil {
		t.Fatal(err)
	}
	for range 3 {
		time.Sleep(15 * time.Millisecond)
		if m := released.heartbeat(); m.GetHeartbeatAck() == nil {
			t.Fatalf("after the release the client got %v", m)
		}
	}
	if e.status(t, "nia") != "normal" || e.status(t, "max") != "normal" {
		t.Fatal("status after ban now and release")
	}
	if _, err := e.st.GetSessionLabel(ctx, "demo", sessionOf(t, e.env, released).SessionID); err == nil {
		t.Fatal("the label outlived the release")
	}
	// Released, the player is a normal player: the same evidence again is a new entry.
	sendFindings(released, &pb.Finding{Code: uint32(pb.FindingCode_FINDING_CODE_MODULE_SIGNATURE), A: 2, B: rendererFinding().B, Detail: "OPENGL32.dll"})
	eventually(t, "nia in the pool again", func() bool { b, _ := e.bans.Pooled(ctx, "demo", "nia"); return b != nil && b.ID != b2.ID })
}
