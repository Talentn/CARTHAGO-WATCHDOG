package main

import (
	"bytes"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"time"

	"carthago/backend/internal/economy"
)

// gameServer is the studio's side of the API: it reports what happens in the game.
type gameServer struct {
	base, key string
	http      *http.Client
	run       string
	seq       int
	// clock is the game's time. The scenarios play inside the last half hour.
	clock time.Time
	err   error
}

func newGameServer(base, key string) *gameServer {
	// A gateway on this PC may serve the development certificate, which no PC trusts;
	// any other gateway must show a certificate that verifies.
	local := false
	if u, err := url.Parse(base); err == nil {
		local = u.Hostname() == "127.0.0.1" || u.Hostname() == "localhost" || u.Hostname() == "::1"
	}
	tr := &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: local}}
	return &gameServer{base: strings.TrimRight(base, "/"), key: key, http: &http.Client{Timeout: 15 * time.Second, Transport: tr}, run: runID(), clock: time.Now().Add(-30 * time.Minute)}
}

func (g *gameServer) call(method, path string, body, into any) {
	if g.err != nil {
		return
	}
	var rd io.Reader
	if body != nil {
		b, _ := json.Marshal(body)
		rd = bytes.NewReader(b)
	}
	req, err := http.NewRequest(method, g.base+path, rd)
	if err != nil {
		g.err = err
		return
	}
	req.Header.Set("Authorization", "Bearer "+g.key)
	req.Header.Set("Content-Type", "application/json")
	resp, err := g.http.Do(req)
	if err != nil {
		g.err = err
		return
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(io.LimitReader(resp.Body, 4<<20))
	if resp.StatusCode != http.StatusOK {
		g.err = fmt.Errorf("%s %s: %s: %s", method, path, resp.Status, strings.TrimSpace(string(raw)))
		return
	}
	g.err = json.Unmarshal(raw, into)
}

// player names one player of this run.
func (g *gameServer) player(name string) string { return name + "-" + g.run }

// event reports one change, a few seconds of game time after the last.
func (g *gameServer) event(player string, amount int64, source, counterparty string) economy.Result {
	g.seq++
	g.clock = g.clock.Add(5 * time.Second)
	ev := economy.Event{EventID: fmt.Sprintf("sim-%s-%d", g.run, g.seq), Player: player, Amount: amount, Source: source, Counterparty: counterparty, AtMS: g.clock.UnixMilli()}
	var out struct {
		Results []economy.Result `json:"results"`
	}
	g.call("POST", "/v1/economy/events", map[string]any{"events": []economy.Event{ev}}, &out)
	if g.err == nil && (len(out.Results) != 1 || out.Results[0].Status != "recorded") {
		g.err = fmt.Errorf("event %s was not recorded: %+v", ev.EventID, out.Results)
	}
	if len(out.Results) == 1 {
		return out.Results[0]
	}
	return economy.Result{}
}

func (g *gameServer) balance(player string, balance int64) economy.BalanceResult {
	g.clock = g.clock.Add(5 * time.Second)
	var out struct {
		Results []economy.BalanceResult `json:"results"`
	}
	g.call("POST", "/v1/economy/balances", map[string]any{"balances": []economy.Balance{{Player: player, Balance: balance, AtMS: g.clock.UnixMilli()}}}, &out)
	if len(out.Results) == 1 {
		return out.Results[0]
	}
	return economy.BalanceResult{}
}

func (g *gameServer) status(player string) economy.Status {
	var st economy.Status
	g.call("GET", "/v1/economy/status?player="+url.QueryEscape(player), nil, &st)
	return st
}

func (g *gameServer) dirty(player string) int64 {
	var out struct {
		Players []economy.DirtyPlayer `json:"players"`
	}
	g.call("GET", "/v1/economy/dirty?player="+url.QueryEscape(player), nil, &out)
	var sum int64
	for _, p := range out.Players {
		sum += p.Dirty
	}
	return sum
}

func rules(st economy.Status) []string {
	out := []string{}
	for _, f := range st.Flags {
		out = append(out, f.Rule)
	}
	return out
}

func describe(st economy.Status) string {
	flags, banned := "none", "no"
	if r := rules(st); len(r) > 0 {
		flags = strings.Join(r, ", ")
	}
	if st.Banned != "" {
		banned = "yes, reference " + st.Banned
	}
	return fmt.Sprintf("flags: %s   banned: %s", flags, banned)
}

// scenarios plays the four scenarios and reports how many came out as they should.
func scenarios(g *gameServer, out io.Writer) (passed, total int) {
	amt := economy.Amount
	say := func(format string, a ...any) { fmt.Fprintf(out, "   "+format+"\n", a...) }
	verdict := func(ok bool, pass, fail string) {
		total++
		switch {
		case g.err != nil:
			say("FAIL: the gateway did not answer as expected: %v", g.err)
			g.err = nil
		case ok:
			passed++
			say("PASS: %s", pass)
		default:
			say("FAIL: %s", fail)
		}
	}
	fmt.Fprintf(out, "run        %s (player names and event ids end in it)\n", g.run)

	fmt.Fprintln(out, "\n1. Honest play")
	hana, ines := g.player("hana"), g.player("ines")
	g.balance(hana, 1_000)
	g.event(hana, 400, "job", "")
	g.event(hana, 1_500, "robbery", "")
	g.event(hana, -700, "purchase", "")
	g.event(hana, -300, "trade", ines)
	g.event(ines, 300, "trade", hana)
	b := g.balance(hana, 1_900)
	st := g.status(hana)
	say("%s starts with 1 000, earns 400 from a job and 1 500 from a robbery, buys for 700, trades 300 to %s", hana, ines)
	say("game server reports a balance of %s; the ledger says %s: %s", amt(b.Reported), amt(b.Ledger), b.Status)
	say("%s", describe(st))
	verdict(b.Status == "ok" && st.Banned == "" && len(st.Flags) == 0, "an honest player is left alone", "an honest player was flagged or banned")

	fmt.Fprintln(out, "\n2. Injected money")
	max, fay, nia := g.player("max"), g.player("fay"), g.player("nia")
	g.balance(max, 500)
	g.event(max, 200, "job", "")
	g.event(max, -300, "trade", fay)
	g.event(fay, 300, "trade", max)
	b = g.balance(max, 1_000_400)
	st = g.status(max)
	say("%s starts with 500, earns 200 from a job, trades 300 to %s, then has %s", max, fay, amt(b.Reported))
	say("game server reports a balance of %s; the ledger says %s: %s", amt(b.Reported), amt(b.Ledger), b.Status)
	say("%s", describe(st))
	r := g.event(nia, 50_000, "console_command", "")
	stNia := g.status(nia)
	say("%s receives 50 000 from the source \"console_command\", which is not a source of the game", nia)
	say("%s", describe(stNia))
	verdict(b.Status == "mismatch" && b.Banned != "" && st.Banned == b.Banned && slices.Contains(rules(st), economy.RuleBalanceMismatch) &&
		r.Banned != "" && slices.Contains(r.Flags, economy.RuleUnknownSource),
		"money that no report explains, and money from an unknown source, ban automatically",
		"injected money did not ban (are automatic bans off on this gateway?)")

	fmt.Fprintln(out, "\n3. Farming over the limit")
	finn := g.player("finn")
	g.balance(finn, 0)
	crossed := 0
	for i := 1; i <= 8; i++ {
		if r := g.event(finn, 1_000, "robbery", ""); slices.Contains(r.Flags, economy.RuleOverLimit) {
			crossed = i
		}
	}
	b = g.balance(finn, 8_000)
	st = g.status(finn)
	say("%s robs 8 times for 1 000 each inside one hour; the studio's limit is %s per hour", finn, amt(robberyPerHour))
	if crossed > 0 {
		say("robbery %d took the hour over the limit and was flagged", crossed)
	}
	say("game server reports a balance of %s; the ledger says %s: %s", amt(b.Reported), amt(b.Ledger), b.Status)
	say("%s", describe(st))
	verdict(crossed == 6 && st.Banned == "" && slices.Equal(rules(st), []string{economy.RuleOverLimit}) && b.Status == "ok",
		"earning over the limit is flagged for review and never bans",
		"farming was not flagged once, or it banned (is the robbery limit set to 5 000 per hour?)")

	fmt.Fprintln(out, "\n4. A banned player passing money on")
	bo := g.player("bo")
	g.event(max, -2_000, "drop", "")
	r = g.event(bo, 2_000, "drop", max)
	dFay, dBo := g.dirty(fay), g.dirty(bo)
	stFay, stBo := g.status(fay), g.status(bo)
	say("%s got 300 from %s in a trade before the ban; %s picks up 2 000 that %s dropped after it", fay, max, bo, max)
	say("dirty money list: %s holds %s, %s holds %s (from %s)", fay, amt(dFay), bo, amt(dBo), r.DirtyFrom)
	say("%s: %s", fay, describe(stFay))
	say("%s: %s", bo, describe(stBo))
	g.event(bo, -2_000, economy.SourceDirtyRemoval, "")
	after := g.dirty(bo)
	say("the game server takes 2 000 back from %s and reports it: %s now holds %s dirty", bo, bo, amt(after))
	verdict(dFay == 300 && dBo == 2_000 && r.DirtyFrom == max && after == 0 && stFay.Banned == "" && stBo.Banned == "" && len(stFay.Flags) == 0 && len(stBo.Flags) == 0,
		"the money is marked on the receivers, who are neither banned nor flagged",
		"the passed-on money was not marked, or a receiver was banned or flagged")
	return passed, total
}
