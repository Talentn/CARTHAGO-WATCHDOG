package gateway

import (
	"encoding/json"
	"net/http"

	"carthago/backend/internal/economy"
)

// The economy API is plain HTTP with JSON bodies, for the studio's game servers. A call
// carries the tenant's server key, the same credential as /v1/gs: "Authorization: Bearer
// <key>". Everything a call reads or writes belongs to the tenant of the key.

const (
	maxEconomyBody  = 1 << 20
	maxEconomyBatch = 500
)

func (g *Gateway) economyTenant(w http.ResponseWriter, r *http.Request) (string, bool) {
	tenant, ok := g.tenantForServerKey(r.Header.Get("Authorization"))
	if !ok {
		economyError(w, http.StatusUnauthorized, "unknown server key")
	}
	return tenant, ok
}

func economyJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func economyError(w http.ResponseWriter, status int, msg string) {
	economyJSON(w, status, map[string]string{"error": msg})
}

func economyBody(w http.ResponseWriter, r *http.Request, into any) bool {
	dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, maxEconomyBody))
	dec.DisallowUnknownFields()
	if err := dec.Decode(into); err != nil {
		economyError(w, http.StatusBadRequest, "body is not the JSON this call takes: "+err.Error())
		return false
	}
	return true
}

// POST /v1/economy/events {"events":[{event_id, player, currency, amount, source,
// counterparty, at_ms}]} answers {"results":[...]} in the same order.
func (g *Gateway) handleEconomyEvents(w http.ResponseWriter, r *http.Request) {
	tenant, ok := g.economyTenant(w, r)
	if !ok {
		return
	}
	var body struct {
		Events []economy.Event `json:"events"`
	}
	if !economyBody(w, r, &body) {
		return
	}
	if len(body.Events) == 0 || len(body.Events) > maxEconomyBatch {
		economyError(w, http.StatusBadRequest, "a call carries 1 to 500 events")
		return
	}
	economyJSON(w, http.StatusOK, map[string]any{"results": g.cfg.Economy.Record(r.Context(), tenant, body.Events)})
}

// POST /v1/economy/balances {"balances":[{player, currency, balance, at_ms}]} answers
// {"results":[...]} in the same order.
func (g *Gateway) handleEconomyBalances(w http.ResponseWriter, r *http.Request) {
	tenant, ok := g.economyTenant(w, r)
	if !ok {
		return
	}
	var body struct {
		Balances []economy.Balance `json:"balances"`
	}
	if !economyBody(w, r, &body) {
		return
	}
	if len(body.Balances) == 0 || len(body.Balances) > maxEconomyBatch {
		economyError(w, http.StatusBadRequest, "a call carries 1 to 500 balances")
		return
	}
	economyJSON(w, http.StatusOK, map[string]any{"results": g.cfg.Economy.Snapshot(r.Context(), tenant, body.Balances)})
}

// GET /v1/economy/dirty[?player=] lists the dirty money per player and currency.
func (g *Gateway) handleEconomyDirty(w http.ResponseWriter, r *http.Request) {
	tenant, ok := g.economyTenant(w, r)
	if !ok {
		return
	}
	list, err := g.cfg.Economy.Dirty(r.Context(), tenant, r.URL.Query().Get("player"))
	if err != nil {
		g.log.Warn("economy dirty", "tenant", tenant, "err", err)
		economyError(w, http.StatusInternalServerError, "the ledger could not be read")
		return
	}
	economyJSON(w, http.StatusOK, map[string]any{"players": list})
}

// GET /v1/economy/status?player= reports one player's ban, ledger balances and flags.
func (g *Gateway) handleEconomyStatus(w http.ResponseWriter, r *http.Request) {
	tenant, ok := g.economyTenant(w, r)
	if !ok {
		return
	}
	st, err := g.cfg.Economy.Player(r.Context(), tenant, r.URL.Query().Get("player"))
	if err != nil {
		economyError(w, http.StatusBadRequest, err.Error())
		return
	}
	economyJSON(w, http.StatusOK, st)
}
