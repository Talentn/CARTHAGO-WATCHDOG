package dashboard

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"sort"
	"strconv"

	"carthago/backend/internal/replay"
	"carthago/backend/internal/store"
)

// matchCSP is the policy of the match page, the only page with a script. It adds to the
// policy of every other page the dashboard's own script file and the page's one request
// for the recording, both from this origin; nothing inline and nothing from elsewhere.
const matchCSP = "default-src 'none'; script-src 'self'; connect-src 'self'; style-src 'self'; img-src 'self'; font-src 'self'; form-action 'self'; frame-ancestors 'none'; base-uri 'none'"

// maxMatchMarks bounds the timeline: a match with more findings than this shows the
// first ones in match time.
const maxMatchMarks = 400

// matchMark is one thing a reviewer can jump to on the match timeline.
type matchMark struct {
	Ms   int64
	At   string // mm:ss into the match
	Kind string // finding | moment | oracle | behaviour
	// Level is how the mark is drawn: act, watch or low.
	Level  string
	Slot   int // -1 when the mark is not about one slot
	Player string
	Rule   string
	Text   string
	Href   string
	// Approx is set when the gateway knows the match the mark belongs to but not the
	// moment, so it stands at the end of what was recorded.
	Approx bool
}

type matchPlayer struct {
	store.ReplayPlayer
	Team  uint32
	Marks int
}

type matchData struct {
	R       *store.MatchReplay
	Players []matchPlayer
	Marks   []matchMark
	More    int // marks left out past maxMatchMarks
	// Flagged: at least one mark is a finding or an Oracle flag, not only behaviour.
	Flagged bool
	// StartMs and Focus are where the page opens: a moment (?t=, milliseconds) and a
	// player to ring (?player=).
	StartMs  int64
	Focus    int
	Duration string
	Src      string
}

func matchURL(id string) string { return "/matches/" + url.PathEscape(id) }

func clock(ms int64) string {
	s := ms / 1000
	if s >= 3600 {
		return fmt.Sprintf("%d:%02d:%02d", s/3600, s/60%60, s%60)
	}
	return fmt.Sprintf("%02d:%02d", s/60, s%60)
}

func markLevel(severity int) string {
	switch {
	case severity >= 3:
		return "act"
	case severity == 2:
		return "watch"
	}
	return "low"
}

func (s *Server) match(w http.ResponseWriter, r *http.Request, tenant string) {
	ctx := r.Context()
	id := r.PathValue("id")
	rec, err := s.st.GetMatchReplay(ctx, tenant, id)
	if err != nil {
		s.fail(w, err)
		return
	}
	data, err := replay.Decode(rec.Data)
	if err != nil {
		s.fail(w, err)
		return
	}
	d := matchData{R: rec, Focus: -1, Duration: clock(rec.DurationMs), Src: matchURL(id) + "/replay.json"}
	if t, err := strconv.ParseInt(r.URL.Query().Get("t"), 10, 64); err == nil {
		d.StartMs = min(max(t, 0), rec.DurationMs)
	}
	focus := r.URL.Query().Get("player")
	teams := map[uint32]uint32{}
	for _, p := range data.Players {
		teams[p.Slot] = p.Team
	}
	slotOf := map[string]int{}
	for _, p := range rec.Players {
		d.Players = append(d.Players, matchPlayer{ReplayPlayer: p, Team: teams[p.Slot]})
		slotOf[p.PlayerHash] = int(p.Slot)
		if focus != "" && p.PlayerHash == focus {
			d.Focus = int(p.Slot)
		}
	}
	if d.Marks, err = s.matchMarks(ctx, tenant, rec, data); err != nil {
		s.fail(w, err)
		return
	}
	behaviour, err := s.behaviourMarks(ctx, tenant, id)
	if err != nil {
		s.fail(w, err)
		return
	}
	for i := range behaviour {
		behaviour[i].Ms = min(behaviour[i].Ms, rec.DurationMs)
	}
	d.Marks = append(d.Marks, behaviour...)
	sort.SliceStable(d.Marks, func(i, j int) bool { return d.Marks[i].Ms < d.Marks[j].Ms })
	if len(d.Marks) > maxMatchMarks {
		d.More, d.Marks = len(d.Marks)-maxMatchMarks, d.Marks[:maxMatchMarks]
	}
	for i := range d.Marks {
		m := &d.Marks[i]
		m.At = clock(m.Ms)
		d.Flagged = d.Flagged || m.Kind != "behaviour"
		if m.Slot < 0 {
			if slot, ok := slotOf[m.Player]; ok {
				m.Slot = slot
			}
		}
		for j := range d.Players {
			if int(d.Players[j].Slot) == m.Slot {
				d.Players[j].Marks++
			}
		}
	}
	w.Header().Set("Content-Security-Policy", matchCSP)
	s.render(w, http.StatusOK, "match", page{Title: "Match " + short(id), Nav: "players", Tenant: tenant, Data: d})
}

// matchMarks collects what the gateway found during a match: the gameplay findings that
// name it (with the moments an information-leak finding lists), the client findings of
// its players' sessions made while it was being received, and the Oracle's score of each
// of its players' sessions when that score is not clear.
func (s *Server) matchMarks(ctx context.Context, tenant string, rec *store.MatchReplay, data *replay.Data) ([]matchMark, error) {
	var marks []matchMark
	end := rec.DurationMs
	evs, err := s.st.ListEvidence(ctx, tenant, store.EvidenceFilter{MatchID: rec.MatchID, Limit: 500})
	if err != nil {
		return nil, err
	}
	for _, e := range evs {
		var raw struct {
			Slot     *int   `json:"slot"`
			BatchSeq *int64 `json:"batch_seq"`
			Moments  []struct {
				Tick uint32 `json:"tick"`
				Text string `json:"text"`
			} `json:"moments"`
		}
		_ = json.Unmarshal([]byte(e.Raw), &raw)
		m := matchMark{Ms: end, Kind: "finding", Level: markLevel(e.Severity), Slot: -1, Player: e.PlayerHash, Rule: e.Rule, Text: e.Summary,
			Href: "/evidence/" + strconv.FormatInt(e.ID, 10), Approx: true}
		if raw.Slot != nil {
			m.Slot = *raw.Slot
		}
		if raw.BatchSeq != nil {
			if at, ok := data.BatchMs(*raw.BatchSeq); ok {
				m.Ms, m.Approx = at, false
			}
		}
		marks = append(marks, m)
		for i, mo := range raw.Moments {
			if i == 24 {
				break
			}
			mm := m
			mm.Kind, mm.Ms, mm.Text, mm.Approx = "moment", min(data.TickMs(mo.Tick), end), mo.Text, false
			marks = append(marks, mm)
		}
	}
	for i, p := range rec.Players {
		if p.SessionID == "" || i >= 64 {
			continue
		}
		cl, err := s.st.ListEvidence(ctx, tenant, store.EvidenceFilter{SessionID: p.SessionID, Limit: 200})
		if err != nil {
			return nil, err
		}
		for _, e := range cl {
			at, during := data.WallMs(e.ObservedAt)
			if e.MatchID != "" || !during {
				continue
			}
			marks = append(marks, matchMark{Ms: min(at, end), Kind: "finding", Level: markLevel(e.Severity), Slot: int(p.Slot), Player: e.PlayerHash, Rule: e.Rule, Text: e.Summary,
				Href: "/evidence/" + strconv.FormatInt(e.ID, 10)})
		}
		sc, err := s.st.GetOracleScore(ctx, tenant, p.SessionID)
		if errors.Is(err, store.ErrNotFound) {
			continue
		}
		if err != nil {
			return nil, err
		}
		if sc.MatchID != rec.MatchID || sc.Band == store.OracleBandClear {
			continue
		}
		level := "watch"
		if sc.Band == store.OracleBandReview {
			level = "act"
		}
		marks = append(marks, matchMark{Ms: end, Kind: "oracle", Level: level, Slot: int(p.Slot), Player: p.PlayerHash, Rule: "oracle_" + sc.Band,
			Text:   fmt.Sprintf("The Oracle scored this player's session %.0f%% over the whole match (%s)", sc.Score*100, sc.Band),
			Href:   "/sessions/" + url.PathEscape(p.SessionID),
			Approx: true})
	}
	return marks, nil
}

// matchReplay serves the recording to the match page's script. It is stored compressed
// and sent as it is.
func (s *Server) matchReplay(w http.ResponseWriter, r *http.Request, tenant string) {
	rec, err := s.st.GetMatchReplay(r.Context(), tenant, r.PathValue("id"))
	if err != nil {
		s.fail(w, err)
		return
	}
	h := w.Header()
	h.Set("Content-Type", "application/json")
	h.Set("Content-Encoding", "gzip")
	h.Set("Content-Length", strconv.Itoa(len(rec.Data)))
	_, _ = w.Write(rec.Data)
}

// replayLinks are a player's or a session's recorded matches, for the links to the match
// page.
func (s *Server) replayLinks(ctx context.Context, tenant string, f store.ReplayFilter) ([]store.MatchReplay, error) {
	f.Limit = 20
	return s.st.ListMatchReplays(ctx, tenant, f)
}
