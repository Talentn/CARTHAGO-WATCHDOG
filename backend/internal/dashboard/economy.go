package dashboard

import (
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"strings"

	"carthago/backend/internal/economy"
	"carthago/backend/internal/store"
)

type economyData struct {
	Flags     []store.EconomyFlag
	Dirty     []economy.DirtyPlayer
	Limits    []store.EconomyLimit
	Tolerance int64
	// Sources a game server may report without a limit of their own.
	Sources string
	// CanEdit: the viewer may change the limits and the tolerance.
	CanEdit bool
	Saved   bool

	// One player's ledger, when the page was asked for one.
	Player   string
	Banned   *store.Ban
	Balances []economy.CurrencyBalance
	Entries  []store.EconomyEntry
}

const economyRows = 200

func (s *Server) economyPage(w http.ResponseWriter, r *http.Request, tenant string) {
	ctx := r.Context()
	q := r.URL.Query()
	d := economyData{Saved: q.Get("saved") == "1", Player: cleanText(q.Get("player"), 128), Sources: strings.Join(economy.Sources, ", ")}
	if v, ok := s.CurrentViewer(r); ok {
		d.CanEdit = v.Admin()
	}
	var err error
	if d.Flags, err = s.st.ListEconomyFlags(ctx, tenant, "", economyRows); err != nil {
		s.fail(w, err)
		return
	}
	if d.Dirty, err = s.eco.Dirty(ctx, tenant, ""); err != nil {
		s.fail(w, err)
		return
	}
	if d.Limits, err = s.st.EconomyLimits(ctx, tenant); err != nil {
		s.fail(w, err)
		return
	}
	if d.Tolerance, err = s.st.EconomyTolerance(ctx, tenant); err != nil {
		s.fail(w, err)
		return
	}
	if d.Player != "" {
		if d.Entries, err = s.st.ListEconomyEntries(ctx, tenant, store.EconomyFilter{PlayerHash: d.Player, Limit: economyRows}); err != nil {
			s.fail(w, err)
			return
		}
		if d.Balances, err = s.eco.Balances(ctx, tenant, d.Player); err != nil {
			s.fail(w, err)
			return
		}
		if b, err := s.st.StandingBan(ctx, tenant, d.Player, ""); err == nil {
			d.Banned = b
		} else if !errors.Is(err, store.ErrNotFound) {
			s.fail(w, err)
			return
		}
	}
	s.render(w, http.StatusOK, "economy", page{Title: "Economy", Nav: "economy", Tenant: tenant, Data: d})
}

// economyKey reads the source and currency a limit is for.
func economyKey(r *http.Request) (source, currency string, ok bool) {
	source = strings.ToLower(cleanText(r.PostFormValue("source"), 64))
	currency = strings.ToLower(cleanText(r.PostFormValue("currency"), 64))
	if currency == "" {
		currency = economy.DefaultCurrency
	}
	ok = source != "" && len(source) <= 32 && len(currency) <= 32 && !strings.ContainsAny(source+currency, " \t")
	return source, currency, ok
}

// setEconomyLimit sets how much of a currency one player may earn from a source per hour
// and per day before the earnings are flagged for review. 0 is no limit.
func (s *Server) setEconomyLimit(w http.ResponseWriter, r *http.Request, v Viewer) {
	source, currency, ok := economyKey(r)
	hour, errH := strconv.ParseInt(strings.TrimSpace(r.PostFormValue("per_hour")), 10, 64)
	day, errD := strconv.ParseInt(strings.TrimSpace(r.PostFormValue("per_day")), 10, 64)
	if !ok || errH != nil || errD != nil || hour < 0 || day < 0 {
		http.Error(w, "a limit names a source and whole amounts of 0 or more per hour and per day", http.StatusBadRequest)
		return
	}
	if err := s.st.SetEconomyLimit(r.Context(), store.EconomyLimit{TenantID: v.Tenant, Source: source, Currency: currency, PerHour: hour, PerDay: day}); err != nil {
		s.fail(w, err)
		return
	}
	s.Audit(r, "economy.limit", "limit for "+source+" in "+currency, fmt.Sprintf("%d per hour, %d per day", hour, day))
	http.Redirect(w, r, "/economy?saved=1#limits", http.StatusSeeOther)
}

func (s *Server) removeEconomyLimit(w http.ResponseWriter, r *http.Request, v Viewer) {
	source, currency, ok := economyKey(r)
	if !ok {
		http.NotFound(w, r)
		return
	}
	if err := s.st.RemoveEconomyLimit(r.Context(), v.Tenant, source, currency); err != nil {
		s.fail(w, err)
		return
	}
	s.Audit(r, "economy.limit.remove", "limit for "+source+" in "+currency, "")
	http.Redirect(w, r, "/economy?saved=1#limits", http.StatusSeeOther)
}

// setEconomyTolerance sets how far a reported balance may be above the ledger before the
// difference counts as money that should not exist.
func (s *Server) setEconomyTolerance(w http.ResponseWriter, r *http.Request, v Viewer) {
	t, err := strconv.ParseInt(strings.TrimSpace(r.PostFormValue("tolerance")), 10, 64)
	if err != nil || t < 0 {
		http.Error(w, "the tolerance is a whole amount of 0 or more", http.StatusBadRequest)
		return
	}
	if err := s.st.SetEconomyTolerance(r.Context(), v.Tenant, t); err != nil {
		s.fail(w, err)
		return
	}
	s.Audit(r, "economy.tolerance", "balance tolerance", fmt.Sprintf("set to %d", t))
	http.Redirect(w, r, "/economy?saved=1#limits", http.StatusSeeOther)
}
