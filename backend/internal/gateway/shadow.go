package gateway

import (
	"context"
	"net/http"
	"strings"

	"carthago/backend/internal/bans"
	"carthago/backend/internal/store"
)

// The shadow pool API is for the studio's matchmaking: plain HTTP with JSON, under the
// tenant's server key like /v1/gs and /v1/economy ("Authorization: Bearer <key>"). It
// says who is in the pool so that those players are matched with each other. No client
// holds the server key, and nothing a client is sent says which pool its player is in.

// ShadowPool is the tenant's shadow pool (bans.Service).
type ShadowPool interface {
	// Connected is told about every session once its handshake has passed.
	Connected(ctx context.Context, sess store.Session)
	// Pooled returns the entry that keeps an account in the pool now, nil for none.
	Pooled(ctx context.Context, tenant, playerHash string) (*store.Ban, error)
	Pool(ctx context.Context, tenant string) ([]store.Ban, error)
}

const (
	maxShadowPlayers = 500
	maxPlayerHash    = 128
)

// shadowStatus is one player's answer: "normal" or "shadow". Attestation is a second,
// unrelated answer that is only there while the studio has the unattested pool on:
// "attested" or "unattested", worked out without looking at the shadow pool.
type shadowStatus struct {
	Player      string `json:"player"`
	Status      string `json:"status"`
	Attestation string `json:"attestation,omitempty"`
}

func (g *Gateway) shadowStatusOf(ctx context.Context, tenant, player string) (shadowStatus, error) {
	st := shadowStatus{Player: player, Status: bans.StatusNormal}
	b, err := g.cfg.Pool.Pooled(ctx, tenant, player)
	if b != nil {
		st.Status = bans.StatusShadow
	}
	if err != nil {
		return st, err
	}
	st.Attestation, err = g.attestationOf(ctx, tenant, player)
	return st, err
}

func validPlayer(p string) bool {
	return p != "" && len(p) <= maxPlayerHash && strings.TrimSpace(p) == p
}

// GET /v1/shadow/status?player= answers {"player","status"}.
// POST /v1/shadow/status {"players":[...]} answers {"players":[{"player","status"}]} in
// the same order. status is "normal" or "shadow"; a player the gateway has never seen is
// normal. While the studio's unattested pool is on, each answer also carries
// "attestation": "attested" or "unattested" (a player never seen is unattested).
func (g *Gateway) handleShadowStatus(w http.ResponseWriter, r *http.Request) {
	tenant, ok := g.economyTenant(w, r)
	if !ok {
		return
	}
	fail := func(err error) {
		g.log.Warn("shadow status", "tenant", tenant, "err", err)
		economyError(w, http.StatusInternalServerError, "the pool could not be read; ask again, and do not match on a guess")
	}
	if r.Method == http.MethodGet {
		player := r.URL.Query().Get("player")
		if !validPlayer(player) {
			economyError(w, http.StatusBadRequest, "player is missing or too long")
			return
		}
		st, err := g.shadowStatusOf(r.Context(), tenant, player)
		if err != nil {
			fail(err)
			return
		}
		economyJSON(w, http.StatusOK, st)
		return
	}
	var body struct {
		Players []string `json:"players"`
	}
	if !economyBody(w, r, &body) {
		return
	}
	if len(body.Players) == 0 || len(body.Players) > maxShadowPlayers {
		economyError(w, http.StatusBadRequest, "a call asks about 1 to 500 players")
		return
	}
	out := make([]shadowStatus, 0, len(body.Players))
	for _, p := range body.Players {
		if !validPlayer(p) {
			economyError(w, http.StatusBadRequest, "a player is empty or too long")
			return
		}
		st, err := g.shadowStatusOf(r.Context(), tenant, p)
		if err != nil {
			fail(err)
			return
		}
		out = append(out, st)
	}
	economyJSON(w, http.StatusOK, map[string]any{"players": out})
}

// shadowEntry is one player of the pool.
type shadowEntry struct {
	Player string `json:"player"`
	// SinceMS is when the player entered the pool, UntilMS when the ban takes effect.
	SinceMS int64 `json:"since_ms"`
	UntilMS int64 `json:"until_ms"`
}

// GET /v1/shadow/pool answers {"players":[{"player","since_ms","until_ms"}]}, the entry
// that ends first first.
func (g *Gateway) handleShadowPool(w http.ResponseWriter, r *http.Request) {
	tenant, ok := g.economyTenant(w, r)
	if !ok {
		return
	}
	pool, err := g.cfg.Pool.Pool(r.Context(), tenant)
	if err != nil {
		g.log.Warn("shadow pool", "tenant", tenant, "err", err)
		economyError(w, http.StatusInternalServerError, "the pool could not be read")
		return
	}
	out := make([]shadowEntry, 0, len(pool))
	for _, b := range pool {
		out = append(out, shadowEntry{Player: b.PlayerHash, SinceMS: b.BannedAt.UnixMilli(), UntilMS: b.EffectiveAt.UnixMilli()})
	}
	economyJSON(w, http.StatusOK, map[string]any{"players": out})
}
