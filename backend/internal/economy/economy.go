// Package economy is the gateway's own ledger of in-game money and items, for games whose
// studio runs the game servers. The game servers report every change with its source and,
// from time to time, the balance a player has. The ledger adds the changes up; money in a
// balance that no report explains, and money reported without a source the studio has, is
// certain and bans through the ban service. Earning faster than the studio's limits is a
// flag for a person. Money a banned player passed on is marked dirty on the receiver's
// entry so the studio can take it back; the receiver is neither flagged nor banned.
package economy

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"sort"
	"strings"
	"sync"
	"time"

	"carthago/backend/internal/analyzer"
	"carthago/backend/internal/bans"
	"carthago/backend/internal/store"
)

// The rules of the ledger. Their tiers are in analyzer/tiers.go with every other rule.
const (
	RuleBalanceMismatch = "economy_balance_mismatch"
	RuleNoSource        = "economy_no_source"
	RuleUnknownSource   = "economy_unknown_source"
	RuleOverLimit       = "economy_over_limit"
	RuleBalanceShort    = "economy_balance_short"
)

// DefaultCurrency is the currency of a report that names none.
const DefaultCurrency = "money"

// Sources a game server may report without the studio listing them. A studio adds its own
// by giving a source a limit on the Economy page.
var Sources = []string{"job", "robbery", "trade", "drop", "purchase", "sale", "admin_grant", SourceDirtyRemoval}

// SourceDirtyRemoval is the source of the debit a studio reports when it takes dirty money
// back from a player; it clears that much of the player's dirty marks, oldest first.
const SourceDirtyRemoval = "dirty_removal"

// Sources the ledger writes itself; a game server cannot report them.
const (
	SourceOpening     = "opening_balance"  // the first balance reported for a player
	SourceUnexplained = "unexplained"      // a balance above the ledger
	SourceUnreported  = "unreported_spend" // a balance below the ledger
)

// passSources move money from one player to another.
var passSources = map[string]bool{"trade": true, "drop": true}

// DirtyLookBack is how far back a ban reaches: what others received from the banned
// player within it is marked dirty.
const DirtyLookBack = 30 * 24 * time.Hour

const (
	maxID     = 128
	maxAmount = int64(1) << 53 // whole numbers a JSON number carries exactly
	// maxAhead is how far a game server's clock may run ahead of the gateway's.
	maxAhead = 10 * time.Minute
)

// Store is what the ledger needs from the gateway's store.
type Store interface {
	store.EconomyStore
	StandingBan(ctx context.Context, tenant, playerHash, deviceID string) (*store.Ban, error)
	ListSessions(ctx context.Context, tenant string, f store.SessionFilter) ([]store.SessionRow, error)
}

// Banner makes bans (bans.Service).
type Banner interface {
	Ban(ctx context.Context, r bans.Request) (b *store.Ban, created bool, err error)
}

type Service struct {
	st  Store
	ban Banner
	log *slog.Logger
	// Now is the clock; tests replace it.
	Now func() time.Time
	// One report at a time: a balance is compared with a ledger that is not moving.
	mu sync.Mutex
}

// New returns the ledger. ban is nil when automatic bans are off: what is certain is then
// flagged and marked, and banning is left to a reviewer.
func New(st Store, ban Banner, log *slog.Logger) *Service {
	return &Service{st: st, ban: ban, log: log, Now: time.Now}
}

// Event is one change of a player's money or items, as a game server reports it.
type Event struct {
	// EventID is the game server's own id of the change. Reporting an id again changes
	// nothing.
	EventID string `json:"event_id"`
	Player  string `json:"player"`
	// Currency is "money" when empty. An item is a currency of its own, counted in pieces.
	Currency string `json:"currency,omitempty"`
	// Amount in the smallest unit: positive received, negative spent or given.
	Amount int64 `json:"amount"`
	// Source says where the money came from or went to.
	Source string `json:"source"`
	// Counterparty is the other player of a trade, or who dropped what was picked up.
	Counterparty string `json:"counterparty,omitempty"`
	// AtMS is the game server's time of the change, Unix milliseconds.
	AtMS int64 `json:"at_ms"`
}

// Result answers one Event.
type Result struct {
	EventID string `json:"event_id"`
	// Status is "recorded", "duplicate" or "rejected".
	Status string `json:"status"`
	Error  string `json:"error,omitempty"`
	// Flags are the rules this event tripped for its player.
	Flags []string `json:"flags,omitempty"`
	// Banned is the reference of the ban a certain flag led to.
	Banned string `json:"banned,omitempty"`
	// Dirty is how much of this credit should not exist, and DirtyFrom the banned player
	// it came from: the receiver is not flagged for it. For money that tripped a flag
	// DirtyFrom is the player themself.
	Dirty     int64  `json:"dirty,omitempty"`
	DirtyFrom string `json:"dirty_from,omitempty"`
}

// Balance is what a player has now, as a game server reports it.
type Balance struct {
	Player   string `json:"player"`
	Currency string `json:"currency,omitempty"`
	Balance  int64  `json:"balance"`
	AtMS     int64  `json:"at_ms"`
}

// BalanceResult answers one Balance.
type BalanceResult struct {
	Player   string `json:"player"`
	Currency string `json:"currency"`
	Reported int64  `json:"reported"`
	// Ledger is what the reported changes add up to, before this report.
	Ledger int64 `json:"ledger"`
	// Status is "ok", "opened" (the first balance of this player: taken as the start),
	// "mismatch" (above the ledger), "short" (below it) or "rejected".
	Status string   `json:"status"`
	Error  string   `json:"error,omitempty"`
	Flags  []string `json:"flags,omitempty"`
	Banned string   `json:"banned,omitempty"`
}

func clean(s string) string { return strings.TrimSpace(s) }

func currencyOf(s string) string {
	if s = strings.ToLower(clean(s)); s != "" {
		return s
	}
	return DefaultCurrency
}

func validName(s string, max int) bool {
	if s == "" || len(s) > max {
		return false
	}
	for _, r := range s {
		if r < 0x21 || r == 0x7f {
			return false
		}
	}
	return true
}

func (s *Service) at(ms int64) time.Time {
	if ms <= 0 {
		return s.Now()
	}
	return time.UnixMilli(ms).UTC()
}

// known reports whether a game server may report this source for the tenant.
func (s *Service) known(ctx context.Context, tenant, source string) (bool, error) {
	for _, k := range Sources {
		if k == source {
			return true, nil
		}
	}
	limits, err := s.st.EconomyLimits(ctx, tenant)
	if err != nil {
		return false, err
	}
	for _, l := range limits {
		if l.Source == source {
			return true, nil
		}
	}
	return false, nil
}

// Record takes reported changes in order and answers each.
func (s *Service) Record(ctx context.Context, tenant string, events []Event) []Result {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]Result, len(events))
	for i, ev := range events {
		out[i] = s.record(ctx, tenant, ev)
	}
	return out
}

func (s *Service) record(ctx context.Context, tenant string, ev Event) Result {
	res := Result{EventID: ev.EventID, Status: "rejected"}
	source := strings.ToLower(clean(ev.Source))
	e := store.EconomyEntry{TenantID: tenant, EventID: clean(ev.EventID), PlayerHash: clean(ev.Player), Currency: currencyOf(ev.Currency), Amount: ev.Amount,
		Source: source, Counterparty: clean(ev.Counterparty), At: s.at(ev.AtMS), ReceivedAt: s.Now()}
	switch {
	case !validName(e.EventID, maxID):
		res.Error = "event_id is missing or too long"
	case !validName(e.PlayerHash, maxID):
		res.Error = "player is missing or too long"
	case e.Counterparty != "" && !validName(e.Counterparty, maxID) || e.Counterparty == e.PlayerHash:
		res.Error = "counterparty is not another player"
	case !validName(e.Currency, 32) || len(source) > 32:
		res.Error = "currency or source is too long"
	case e.Amount == 0 || e.Amount > maxAmount || e.Amount < -maxAmount:
		res.Error = "amount is zero or out of range"
	case source == SourceOpening || source == SourceUnexplained || source == SourceUnreported:
		res.Error = "source " + source + " is written by the ledger itself"
	case e.At.After(e.ReceivedAt.Add(maxAhead)):
		res.Error = "at_ms is in the future"
	}
	if res.Error != "" {
		return res
	}
	fail := func(err error) Result {
		s.log.Warn("economy event", "tenant", tenant, "event", e.EventID, "err", err)
		res.Error = "the ledger could not record this now; report it again"
		return res
	}

	credit := e.Amount > 0
	rule, why := "", ""
	if credit {
		known, err := s.known(ctx, tenant, source)
		switch {
		case err != nil:
			return fail(err)
		case source == "":
			rule, why = RuleNoSource, fmt.Sprintf("%s %s reported with no source", Amount(e.Amount), e.Currency)
		case !known:
			rule, why = RuleUnknownSource, fmt.Sprintf("%s %s reported from %q, which is not a source this studio has", Amount(e.Amount), e.Currency, source)
		case passSources[source] && e.Counterparty != "":
			// Money from a banned player is dirty in the receiver's hands, and says
			// nothing about the receiver.
			if _, err := s.st.StandingBan(ctx, tenant, e.Counterparty, ""); err == nil {
				e.Dirty, e.DirtyFrom = e.Amount, e.Counterparty
			} else if !errors.Is(err, store.ErrNotFound) {
				return fail(err)
			}
		}
		if rule != "" {
			e.Dirty, e.DirtyFrom = e.Amount, e.PlayerHash
		}
	}
	if err := s.st.AddEconomyEntry(ctx, &e); errors.Is(err, store.ErrDuplicate) {
		res.Status = "duplicate"
		return res
	} else if err != nil {
		return fail(err)
	}
	res.Status, res.Dirty, res.DirtyFrom = "recorded", e.Dirty, e.DirtyFrom
	if rule != "" {
		res.Flags, res.Banned = []string{rule}, s.flag(ctx, store.EconomyFlag{TenantID: tenant, PlayerHash: e.PlayerHash, Rule: rule, Currency: e.Currency, Amount: e.Amount,
			Source: source, Summary: why, EventID: e.EventID, At: e.At})
		return res
	}
	if credit {
		if over := s.overLimit(ctx, e); over != "" {
			res.Flags = []string{RuleOverLimit}
			s.flag(ctx, store.EconomyFlag{TenantID: tenant, PlayerHash: e.PlayerHash, Rule: RuleOverLimit, Currency: e.Currency, Amount: e.Amount, Source: source, Summary: over, EventID: e.EventID, At: e.At})
		}
	} else if source == SourceDirtyRemoval {
		s.clearDirty(ctx, tenant, store.EconomyFilter{PlayerHash: e.PlayerHash, Currency: e.Currency, DirtyOnly: true, OldestFirst: true, Limit: 1000}, -e.Amount)
	}
	return res
}

// overLimit says how a credit takes its player over the studio's limit for the source,
// empty when it does not. Only the credit that crosses a limit says so, not each one
// after it.
func (s *Service) overLimit(ctx context.Context, e store.EconomyEntry) string {
	limits, err := s.st.EconomyLimits(ctx, e.TenantID)
	if err != nil {
		s.log.Warn("economy limits", "tenant", e.TenantID, "err", err)
		return ""
	}
	for _, l := range limits {
		if l.Source != e.Source || l.Currency != e.Currency {
			continue
		}
		for _, w := range []struct {
			limit int64
			span  time.Duration
			name  string
		}{{l.PerHour, time.Hour, "hour"}, {l.PerDay, 24 * time.Hour, "day"}} {
			if w.limit <= 0 {
				continue
			}
			sum, _, err := s.st.SumEconomy(ctx, e.TenantID, e.PlayerHash, e.Currency, store.EconomySum{Source: e.Source, CreditsOnly: true, After: e.At.Add(-w.span), Until: e.At})
			if err != nil {
				s.log.Warn("economy limits", "tenant", e.TenantID, "err", err)
				return ""
			}
			if sum > w.limit && sum-e.Amount <= w.limit {
				return fmt.Sprintf("%s %s from %s in one %s; the studio's limit is %s", Amount(sum), e.Currency, e.Source, w.name, Amount(w.limit))
			}
		}
	}
	return ""
}

// flag records what the ledger found and, for a rule of the certain tier, bans the
// player. It returns the reference of the ban.
func (s *Service) flag(ctx context.Context, f store.EconomyFlag) string {
	f.Certain = analyzer.TierOf(f.Rule) == analyzer.TierCertain
	if f.Certain && s.ban != nil {
		// The device key of the player's latest session is banned with the account, as
		// for any other ban.
		sess := store.Session{TenantID: f.TenantID, PlayerHash: f.PlayerHash}
		if rows, err := s.st.ListSessions(ctx, f.TenantID, store.SessionFilter{PlayerHash: f.PlayerHash, Limit: 1}); err == nil && len(rows) > 0 {
			sess.DeviceID, sess.SessionID = rows[0].DeviceID, rows[0].SessionID
		}
		reason := f.Summary
		if len(reason) > 280 {
			reason = reason[:280]
		}
		if b, _, err := s.ban.Ban(ctx, bans.Request{Session: sess, Reason: reason, Rule: f.Rule}); err != nil {
			s.log.Warn("economy ban", "tenant", f.TenantID, "player", f.PlayerHash, "rule", f.Rule, "err", err)
		} else {
			f.BanRef = b.Ref
		}
	}
	if err := s.st.AddEconomyFlag(ctx, &f); err != nil {
		s.log.Warn("economy flag", "tenant", f.TenantID, "player", f.PlayerHash, "rule", f.Rule, "err", err)
	}
	s.log.Info("economy flag", "tenant", f.TenantID, "player", f.PlayerHash, "rule", f.Rule, "certain", f.Certain, "ban", f.BanRef, "summary", f.Summary)
	return f.BanRef
}

// Snapshot compares reported balances with the ledger.
func (s *Service) Snapshot(ctx context.Context, tenant string, balances []Balance) []BalanceResult {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]BalanceResult, len(balances))
	for i, b := range balances {
		out[i] = s.snapshot(ctx, tenant, b)
	}
	return out
}

func (s *Service) snapshot(ctx context.Context, tenant string, b Balance) BalanceResult {
	player, currency, at := clean(b.Player), currencyOf(b.Currency), s.at(b.AtMS)
	res := BalanceResult{Player: player, Currency: currency, Reported: b.Balance, Status: "rejected"}
	switch {
	case !validName(player, maxID):
		res.Error = "player is missing or too long"
	case !validName(currency, 32):
		res.Error = "currency is too long"
	case b.Balance < 0 || b.Balance > maxAmount:
		res.Error = "balance is negative or out of range"
	case at.After(s.Now().Add(maxAhead)):
		res.Error = "at_ms is in the future"
	}
	if res.Error != "" {
		return res
	}
	fail := func(err error) BalanceResult {
		s.log.Warn("economy balance", "tenant", tenant, "player", player, "err", err)
		res.Error = "the ledger could not compare this now; report it again"
		return res
	}
	ledger, _, err := s.st.SumEconomy(ctx, tenant, player, currency, store.EconomySum{Until: at})
	if err != nil {
		return fail(err)
	}
	_, opened, err := s.st.SumEconomy(ctx, tenant, player, currency, store.EconomySum{Source: SourceOpening})
	if err != nil {
		return fail(err)
	}
	tolerance, err := s.st.EconomyTolerance(ctx, tenant)
	if err != nil {
		return fail(err)
	}
	res.Ledger = ledger
	diff := b.Balance - ledger
	entry := store.EconomyEntry{TenantID: tenant, PlayerHash: player, Currency: currency, Amount: diff, At: at, ReceivedAt: s.Now()}
	switch {
	case opened == 0:
		// What a player had before the ledger first heard of them cannot be judged.
		res.Status = "opened"
		entry.EventID, entry.Source = fmt.Sprintf("ledger:open:%s:%s", player, currency), SourceOpening
	case diff > tolerance:
		res.Status = "mismatch"
		entry.EventID, entry.Source = fmt.Sprintf("ledger:above:%s:%s:%d", player, currency, at.UnixMilli()), SourceUnexplained
		entry.Dirty, entry.DirtyFrom = diff, player
	case diff < -tolerance:
		res.Status = "short"
		entry.EventID, entry.Source = fmt.Sprintf("ledger:below:%s:%s:%d", player, currency, at.UnixMilli()), SourceUnreported
	default:
		res.Status = "ok"
		return res
	}
	// The ledger follows the game from here on, so one difference is found once.
	if err := s.st.AddEconomyEntry(ctx, &entry); errors.Is(err, store.ErrDuplicate) {
		res.Status = "ok"
		return res
	} else if err != nil {
		return fail(err)
	}
	f := store.EconomyFlag{TenantID: tenant, PlayerHash: player, Currency: currency, Amount: diff, Source: entry.Source, EventID: entry.EventID, At: at}
	switch res.Status {
	case "mismatch":
		f.Rule = RuleBalanceMismatch
		f.Summary = fmt.Sprintf("balance of %s %s is %s above the ledger (%s): money that no reported change explains", Amount(b.Balance), currency, Amount(diff), Amount(ledger))
		res.Flags, res.Banned = []string{f.Rule}, s.flag(ctx, f)
	case "short":
		f.Rule = RuleBalanceShort
		f.Summary = fmt.Sprintf("balance of %s %s is %s below the ledger (%s): the game server did not report a spend", Amount(b.Balance), currency, Amount(-diff), Amount(ledger))
		res.Flags = []string{f.Rule}
		s.flag(ctx, f)
	}
	return res
}

// clearDirty takes up to amount off the dirty marks of the selected entries, in order.
func (s *Service) clearDirty(ctx context.Context, tenant string, f store.EconomyFilter, amount int64) {
	entries, err := s.st.ListEconomyEntries(ctx, tenant, f)
	if err != nil {
		s.log.Warn("economy dirty", "tenant", tenant, "err", err)
		return
	}
	for _, e := range entries {
		if amount <= 0 {
			return
		}
		take := min(e.Dirty, amount)
		from := e.DirtyFrom
		if take == e.Dirty {
			from = ""
		}
		if err := s.st.SetEconomyDirty(ctx, tenant, e.ID, e.Dirty-take, from); err != nil {
			s.log.Warn("economy dirty", "tenant", tenant, "err", err)
			return
		}
		amount -= take
	}
}

// Banned marks what others received from a newly banned player as dirty (bans.Hook). It
// reaches back DirtyLookBack from the ban; what they receive later is marked as it is
// reported.
func (s *Service) Banned(b *store.Ban) {
	ctx := context.Background()
	entries, err := s.st.ListEconomyEntries(ctx, b.TenantID, store.EconomyFilter{Counterparty: b.PlayerHash, Since: b.BannedAt.Add(-DirtyLookBack), Limit: 1000})
	if err != nil {
		s.log.Warn("economy dirty", "tenant", b.TenantID, "err", err)
		return
	}
	n := 0
	for _, e := range entries {
		if e.Amount <= 0 || !passSources[e.Source] || e.Dirty > 0 {
			continue
		}
		if err := s.st.SetEconomyDirty(ctx, b.TenantID, e.ID, e.Amount, b.PlayerHash); err != nil {
			s.log.Warn("economy dirty", "tenant", b.TenantID, "err", err)
			return
		}
		n++
	}
	if n > 0 {
		s.log.Info("economy: money passed on by a banned player marked dirty", "tenant", b.TenantID, "player", b.PlayerHash, "ban", b.Ref, "entries", n)
	}
}

// Lifted takes the dirty marks of a lifted ban away again (bans.Hook).
func (s *Service) Lifted(b *store.Ban) {
	s.clearDirty(context.Background(), b.TenantID, store.EconomyFilter{DirtyFrom: b.PlayerHash, DirtyOnly: true, Limit: 1000}, maxAmount)
}

// DirtyEntry is one credit that carries dirty money.
type DirtyEntry struct {
	EventID string `json:"event_id"`
	Amount  int64  `json:"amount"`
	Dirty   int64  `json:"dirty"`
	Source  string `json:"source"`
	// From is the banned player the money came from; the player themself for money the
	// ledger could not explain.
	From string `json:"from"`
	AtMS int64  `json:"at_ms"`
}

// DirtyPlayer is the dirty money one player holds in one currency.
type DirtyPlayer struct {
	Player   string       `json:"player"`
	Currency string       `json:"currency"`
	Dirty    int64        `json:"dirty"`
	Entries  []DirtyEntry `json:"entries"`
}

// Dirty lists the dirty money of one player, or of every player when player is empty.
func (s *Service) Dirty(ctx context.Context, tenant, player string) ([]DirtyPlayer, error) {
	entries, err := s.st.ListEconomyEntries(ctx, tenant, store.EconomyFilter{PlayerHash: clean(player), DirtyOnly: true, Limit: 1000})
	if err != nil {
		return nil, err
	}
	at := map[[2]string]int{}
	out := []DirtyPlayer{}
	for _, e := range entries {
		k := [2]string{e.PlayerHash, e.Currency}
		i, ok := at[k]
		if !ok {
			i = len(out)
			at[k] = i
			out = append(out, DirtyPlayer{Player: e.PlayerHash, Currency: e.Currency})
		}
		out[i].Dirty += e.Dirty
		out[i].Entries = append(out[i].Entries, DirtyEntry{EventID: e.EventID, Amount: e.Amount, Dirty: e.Dirty, Source: e.Source, From: e.DirtyFrom, AtMS: e.At.UnixMilli()})
	}
	sort.SliceStable(out, func(i, j int) bool { return out[i].Dirty > out[j].Dirty })
	return out, nil
}

// CurrencyBalance is a player's ledger in one currency.
type CurrencyBalance struct {
	Currency string `json:"currency"`
	Ledger   int64  `json:"ledger"`
	Dirty    int64  `json:"dirty"`
}

// PlayerFlag is one flag of a player, as the game-server API shows it.
type PlayerFlag struct {
	Rule    string `json:"rule"`
	Certain bool   `json:"certain"`
	Summary string `json:"summary"`
	AtMS    int64  `json:"at_ms"`
}

// Status is what the ledger knows about one player.
type Status struct {
	Player string `json:"player"`
	// Banned is the reference of the ban that stands for the player, empty for none.
	Banned   string            `json:"banned"`
	Balances []CurrencyBalance `json:"balances"`
	Flags    []PlayerFlag      `json:"flags"`
}

// Balances adds up a player's ledger per currency, from the player's latest entries.
func (s *Service) Balances(ctx context.Context, tenant, player string) ([]CurrencyBalance, error) {
	entries, err := s.st.ListEconomyEntries(ctx, tenant, store.EconomyFilter{PlayerHash: player, Limit: 1000})
	if err != nil {
		return nil, err
	}
	seen := map[string]bool{}
	out := []CurrencyBalance{}
	for _, e := range entries {
		if seen[e.Currency] {
			continue
		}
		seen[e.Currency] = true
		sum, _, err := s.st.SumEconomy(ctx, tenant, player, e.Currency, store.EconomySum{})
		if err != nil {
			return nil, err
		}
		out = append(out, CurrencyBalance{Currency: e.Currency, Ledger: sum})
	}
	for _, e := range entries {
		for i := range out {
			if out[i].Currency == e.Currency {
				out[i].Dirty += e.Dirty
			}
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Currency < out[j].Currency })
	return out, nil
}

// Player reports one player's ban, balances and flags.
func (s *Service) Player(ctx context.Context, tenant, player string) (*Status, error) {
	player = clean(player)
	if !validName(player, maxID) {
		return nil, errors.New("player is missing or too long")
	}
	st := &Status{Player: player, Flags: []PlayerFlag{}}
	if b, err := s.st.StandingBan(ctx, tenant, player, ""); err == nil {
		st.Banned = b.Ref
	} else if !errors.Is(err, store.ErrNotFound) {
		return nil, err
	}
	var err error
	if st.Balances, err = s.Balances(ctx, tenant, player); err != nil {
		return nil, err
	}
	flags, err := s.st.ListEconomyFlags(ctx, tenant, player, 50)
	if err != nil {
		return nil, err
	}
	for _, f := range flags {
		st.Flags = append(st.Flags, PlayerFlag{Rule: f.Rule, Certain: f.Certain, Summary: f.Summary, AtMS: f.At.UnixMilli()})
	}
	return st, nil
}

// Amount writes a whole number with spaces between thousands.
func Amount(v int64) string {
	neg := v < 0
	if neg {
		v = -v
	}
	s := fmt.Sprint(v)
	var b strings.Builder
	for i, c := range s {
		if i > 0 && (len(s)-i)%3 == 0 {
			b.WriteByte(' ')
		}
		b.WriteRune(c)
	}
	if neg {
		return "-" + b.String()
	}
	return b.String()
}
