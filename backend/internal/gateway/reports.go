package gateway

import (
	"encoding/json"
	"errors"
	"net/http"
	"strconv"

	"carthago/backend/internal/reports"
)

// maxReportBody bounds the body of POST /v1/reports. A report is a few short fields.
const maxReportBody = 4 << 10

// POST /v1/reports takes one report a player made about another player, passed on by the
// studio's game server under the tenant's server key, like /v1/economy and /v1/shadow
// ("Authorization: Bearer <key>"):
//
//	{"reporter", "reported", "match", "tick" with "tick_rate" or "time_ms", "reason", "note"}
//
// It answers 201 {"id", "status":"accepted"}, 200 {"id", "status":"duplicate"} when the
// reporter already reported that player in that match, 400 for a report it does not take
// and 429 with Retry-After when the reporter has made too many. A report is stored for a
// reviewer and changes nothing else.
func (g *Gateway) handleReport(w http.ResponseWriter, r *http.Request) {
	tenant, ok := g.economyTenant(w, r)
	if !ok {
		return
	}
	var in reports.Submission
	dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, maxReportBody))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&in); err != nil {
		economyError(w, http.StatusBadRequest, "body is not the JSON this call takes: "+err.Error())
		return
	}
	if dec.More() {
		economyError(w, http.StatusBadRequest, "a call carries one report")
		return
	}
	out, err := g.cfg.Reports.Submit(r.Context(), tenant, in)
	var bad *reports.InvalidError
	var rate *reports.RateError
	switch {
	case errors.As(err, &bad):
		economyError(w, http.StatusBadRequest, bad.Msg)
	case errors.As(err, &rate):
		w.Header().Set("Retry-After", strconv.Itoa(int(rate.RetryAfter.Seconds())+1))
		economyError(w, http.StatusTooManyRequests, rate.Error())
	case err != nil:
		g.log.Warn("player report", "tenant", tenant, "err", err)
		economyError(w, http.StatusInternalServerError, "the report could not be stored; send it again")
	case out.Status == reports.StatusDuplicate:
		economyJSON(w, http.StatusOK, out)
	default:
		// The note is a player's own words: it is stored, not logged.
		g.log.Info("player report", "tenant", tenant, "id", out.ID, "reason", in.Reason, "match", in.Match)
		economyJSON(w, http.StatusCreated, out)
	}
}
