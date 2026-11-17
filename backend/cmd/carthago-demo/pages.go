package main

import (
	"fmt"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"regexp"
	"strings"

	"carthago/backend/internal/sim/localgw"
	"carthago/backend/internal/store"
)

// browser signs in to the demo's dashboard with the studio key, as a person would.
func (s *story) browser() (*http.Client, error) {
	jar, _ := cookiejar.New(nil)
	c := &http.Client{Jar: jar}
	req, err := http.NewRequestWithContext(s.ctx, "POST", s.gw.Dashboard+"/login", strings.NewReader(url.Values{"tenant": {localgw.Tenant}, "key": {localgw.DashboardKey}}.Encode()))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Sec-Fetch-Site", "same-origin")
	resp, err := c.Do(req)
	if err != nil {
		return nil, err
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK || resp.Request.URL.Path != "/" {
		return nil, fmt.Errorf("the dashboard did not accept the demo login (HTTP %d at %s)", resp.StatusCode, resp.Request.URL.Path)
	}
	return c, nil
}

func (s *story) page(c *http.Client, path string) (string, error) {
	req, err := http.NewRequestWithContext(s.ctx, "GET", s.gw.Dashboard+path, nil)
	if err != nil {
		return "", err
	}
	resp, err := c.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("HTTP %d", resp.StatusCode)
	}
	return string(body), nil
}

var playerLink = regexp.MustCompile(`href="/players/([^"?]+)"`)

// playersListed is the first n players of the dashboard's flagged players list, in order.
func (s *story) playersListed(n int) ([]string, error) {
	c, err := s.browser()
	if err != nil {
		return nil, err
	}
	body, err := s.page(c, "/players")
	if err != nil {
		return nil, fmt.Errorf("the players page: %w", err)
	}
	var names []string
	for _, m := range playerLink.FindAllStringSubmatch(body, -1) {
		if name, err := url.PathUnescape(m[1]); err == nil {
			names = append(names, name)
		}
	}
	if len(names) < n {
		return nil, fmt.Errorf("the players page lists %d players, want at least %d", len(names), n)
	}
	return names[:n], nil
}

// pages opens every page of the dashboard as the demo login sees it and checks that it
// shows what the story left behind.
func (s *story) pages() (ok, total int) {
	fmt.Fprintln(s.out, "\nDashboard check")
	type check struct {
		name, path string
		want       []string
	}
	checks := []check{
		{"Overview", "/", []string{"zied", "renderer_replaced"}},
		{"Sessions", "/sessions", []string{"amira", "tarek"}},
		{"Players", "/players", []string{"Against own players", "nour", "omar"}},
		{"Player nour", "/players/nour", []string{"far outside"}},
		{"Bans", "/bans", []string{s.bannedRef, "wissem", "known_cheat"}},
		{"Shadow pool", "/shadow", []string{"tarek"}},
		{"Known cheats", "/cheats", []string{"aimhelper-loader", "OPENGL32.dll"}},
		{"Economy", "/economy", []string{"economy_balance_mismatch", "robbery"}},
		{"Match replay", "/matches/" + demoMatch, []string{"sami", "information_leak", "Moment", "/static/replay.js"}},
		{"Player " + toxicPlayer, "/players/" + toxicPlayer, []string{"Behaviour", "Killed 2 teammates", "Left at 05:30", "Replay at"}},
		{"Behaviour on the replay", "/matches/" + toxicMatch, []string{toxicPlayer, "team_kill", "left_early", "Behaviour"}},
	}
	// The session of the first ban and a piece of its evidence.
	if a := s.players["zied"]; a != nil {
		checks = append(checks, check{"Session of zied", "/sessions/" + a.SessionID(), []string{"renderer_replaced", "Oracle"}})
		if ev, err := s.gw.Store.ListEvidence(s.ctx, localgw.Tenant, store.EvidenceFilter{SessionID: a.SessionID(), MinSeverity: 3, Limit: 1}); err == nil && len(ev) == 1 {
			checks = append(checks, check{"Evidence", fmt.Sprintf("/evidence/%d", ev[0].ID), []string{"OPENGL32.dll"}})
		}
	}
	total = len(checks)
	c, err := s.browser()
	if err != nil {
		s.say("FAIL: %v", err)
		return 0, total
	}
	var bad []string
	for _, ch := range checks {
		body, err := s.page(c, ch.path)
		missing := ""
		for _, w := range ch.want {
			if err == nil && (w == "" || !strings.Contains(body, w)) {
				missing = w
				break
			}
		}
		switch {
		case err != nil:
			bad = append(bad, fmt.Sprintf("%s (%s): %v", ch.name, ch.path, err))
		case missing != "" || len(ch.want) == 0:
			bad = append(bad, fmt.Sprintf("%s (%s) does not show %q", ch.name, ch.path, missing))
		default:
			ok++
		}
	}
	for _, b := range bad {
		s.say("FAIL: %s", b)
	}
	s.say("%d of %d pages opened with the demo login show the story's data: Overview, Sessions, Players, Bans,", ok, total)
	s.say("Shadow pool, Known cheats, Economy, the replays of both matches, and the pages of two players, one session")
	s.say("and one piece of evidence.")
	return ok, total
}
