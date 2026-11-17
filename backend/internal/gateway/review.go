package gateway

import (
	"encoding/json"
	"errors"
	"net/http"
	"strconv"
	"strings"

	"carthago/backend/internal/review"
	"carthago/backend/internal/store"
)

// Community review (internal/review). The calls below are for the studio's game server,
// under its server key like /v1/reports. The page a player opens with a review link is
// served under /review/ by the same listener and takes no key: the link is the key.

// maxReviewBody bounds the body of the review calls.
const maxReviewBody = 4 << 10

func reviewBody(w http.ResponseWriter, r *http.Request, into any) bool {
	dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, maxReviewBody))
	dec.DisallowUnknownFields()
	if err := dec.Decode(into); err != nil {
		economyError(w, http.StatusBadRequest, "body is not the JSON this call takes: "+err.Error())
		return false
	}
	return true
}

// reviewURL is the address of a review page: under the configured public address of the
// gateway, or under the one the game server called it by.
func (g *Gateway) reviewURL(r *http.Request, path string) string {
	if base := strings.TrimRight(g.cfg.ReviewURL, "/"); base != "" {
		return base + path
	}
	scheme := "http"
	if r.TLS != nil {
		scheme = "https"
	}
	return scheme + "://" + r.Host + path
}

// POST /v1/review/links {"player"} asks for a review link for a player the studio
// considers eligible. The gateway picks the case. It answers
//
//	201 {"status":"assigned","url","expires_ms"}   a link for that player to open
//	200 {"status":"none"}                          no case this player may review now
//	403 {"status":"off" | "not_eligible","error"}  the studio has the feature off, or the
//	                                               player's verdicts were wrong too often
//	429 with Retry-After                           the player was handed enough cases for now
//
// The answer does not say which match or player the link is about.
func (g *Gateway) handleReviewLink(w http.ResponseWriter, r *http.Request) {
	tenant, ok := g.economyTenant(w, r)
	if !ok {
		return
	}
	var in struct {
		Player string `json:"player"`
	}
	if !reviewBody(w, r, &in) {
		return
	}
	link, err := g.cfg.Review.Assign(r.Context(), tenant, in.Player)
	var bad *review.InvalidError
	var rate *review.RateError
	switch {
	case errors.As(err, &bad):
		economyError(w, http.StatusBadRequest, bad.Msg)
	case errors.Is(err, review.ErrOff):
		economyJSON(w, http.StatusForbidden, map[string]string{"status": "off", "error": "community review is off for this studio"})
	case errors.Is(err, review.ErrNotEligible):
		economyJSON(w, http.StatusForbidden, map[string]string{"status": "not_eligible", "error": "this player's verdicts were wrong too often to be handed more cases"})
	case errors.Is(err, review.ErrNothing):
		economyJSON(w, http.StatusOK, map[string]string{"status": "none"})
	case errors.As(err, &rate):
		w.Header().Set("Retry-After", strconv.Itoa(int(rate.RetryAfter.Seconds())+1))
		economyError(w, http.StatusTooManyRequests, rate.Error())
	case err != nil:
		g.log.Warn("review link", "tenant", tenant, "err", err)
		economyError(w, http.StatusInternalServerError, "no link could be made; ask again")
	default:
		// The link is a credential: it is returned, not logged.
		g.log.Info("review link", "tenant", tenant, "assignment", link.Assignment.ID)
		economyJSON(w, http.StatusCreated, map[string]any{"status": "assigned", "url": g.reviewURL(r, link.Path), "expires_ms": link.ExpiresAt.UnixMilli()})
	}
}

type badgeOut struct {
	Player   string `json:"player,omitempty"`
	Badge    string `json:"badge"`
	EarnedMs int64  `json:"earned_ms"`
	New      bool   `json:"new"`
}

func badgesOut(rows []store.ReviewBadge, withPlayer bool) []badgeOut {
	out := make([]badgeOut, 0, len(rows))
	for _, b := range rows {
		o := badgeOut{Badge: b.Badge, EarnedMs: b.EarnedAt.UnixMilli(), New: b.DeliveredAt.IsZero()}
		if withPlayer {
			o.Player = b.Reviewer
		}
		out = append(out, o)
	}
	return out
}

// GET /v1/review/standing?player=<account> answers how that player has done as a
// reviewer, for the studio to show or reward:
//
//	{"player","verdicts","scored","correct","accuracy","weight","level","level_name",
//	 "eligible","badges":[{"badge","earned_ms","new"}]}
func (g *Gateway) handleReviewStanding(w http.ResponseWriter, r *http.Request) {
	tenant, ok := g.economyTenant(w, r)
	if !ok {
		return
	}
	st, err := g.cfg.Review.Standing(r.Context(), tenant, r.URL.Query().Get("player"))
	var bad *review.InvalidError
	if errors.As(err, &bad) {
		economyError(w, http.StatusBadRequest, bad.Msg)
		return
	}
	if err != nil {
		economyError(w, http.StatusInternalServerError, "the standing could not be read")
		return
	}
	economyJSON(w, http.StatusOK, map[string]any{
		"player": st.Reviewer, "verdicts": st.Verdicts, "scored": st.Scored, "correct": st.Correct, "accuracy": st.Accuracy, "weight": st.Weight,
		"level": st.Level, "level_name": st.LevelName, "eligible": st.Eligible, "badges": badgesOut(st.Badges, false),
	})
}

// GET /v1/review/badges answers {"badges":[{"player","badge","earned_ms","new":true}]}:
// the badges the game server has not acknowledged yet, oldest first, at most 500.
func (g *Gateway) handleReviewBadges(w http.ResponseWriter, r *http.Request) {
	tenant, ok := g.economyTenant(w, r)
	if !ok {
		return
	}
	rows, err := g.cfg.Review.NewBadges(r.Context(), tenant)
	if err != nil {
		economyError(w, http.StatusInternalServerError, "the badges could not be read")
		return
	}
	economyJSON(w, http.StatusOK, map[string]any{"badges": badgesOut(rows, true)})
}

// POST /v1/review/badges/ack {"player","badges":["..."]} says the game server has seen
// those badges of that player (and granted what the studio grants for them). It answers
// {"acknowledged": n}; a badge acknowledged before counts as 0, so the call can be sent
// again.
func (g *Gateway) handleReviewBadgesAck(w http.ResponseWriter, r *http.Request) {
	tenant, ok := g.economyTenant(w, r)
	if !ok {
		return
	}
	var in struct {
		Player string   `json:"player"`
		Badges []string `json:"badges"`
	}
	if !reviewBody(w, r, &in) {
		return
	}
	n, err := g.cfg.Review.AckBadges(r.Context(), tenant, in.Player, in.Badges)
	var bad *review.InvalidError
	if errors.As(err, &bad) {
		economyError(w, http.StatusBadRequest, bad.Msg)
		return
	}
	if err != nil {
		economyError(w, http.StatusInternalServerError, "the badges could not be acknowledged; send it again")
		return
	}
	economyJSON(w, http.StatusOK, map[string]int{"acknowledged": n})
}
