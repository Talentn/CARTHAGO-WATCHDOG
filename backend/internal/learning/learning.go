// Package learning turns bans into what the product learns from. A ban on certain
// evidence labels the banned account's recent sessions as cheating for the Oracle's
// training data, and lifting the ban takes those labels away again. Files that only
// banned accounts load are proposed as known cheat files; a reviewer decides. Nothing
// here bans anybody, and nothing is added to the list of known cheats without a person.
package learning

import (
	"context"
	"errors"
	"log/slog"
	"sort"
	"strings"
	"time"

	pb "carthago/backend/gen/carthago/v1"
	"carthago/backend/internal/analyzer"
	"carthago/backend/internal/store"
)

// LabelWindow is how far back from a ban the banned account's sessions are labelled.
const LabelWindow = 30 * 24 * time.Hour

// maxSessions bounds the sessions of one account a ban labels.
const maxSessions = 1000

// Store is what the labeler needs from the gateway's store.
type Store interface {
	SetSessionLabel(ctx context.Context, l *store.SessionLabel, action, remote string) error
	GetSessionLabel(ctx context.Context, tenant, sessionID string) (*store.SessionLabel, error)
	ListSessionLabels(ctx context.Context, tenant string, f store.OracleFilter) ([]store.SessionLabel, error)
	ListSessions(ctx context.Context, tenant string, f store.SessionFilter) ([]store.SessionRow, error)
	ListEvidence(ctx context.Context, tenant string, f store.EvidenceFilter) ([]store.Evidence, error)
}

// Labeler labels sessions from bans. It is a bans.Hook.
type Labeler struct {
	st  Store
	log *slog.Logger
	// Now is the clock; tests replace it.
	Now func() time.Time
}

func NewLabeler(st Store, log *slog.Logger) *Labeler {
	return &Labeler{st: st, log: log, Now: time.Now}
}

// certain reports whether a ban rests on certain evidence. An automatic ban always does:
// its rule is of the certain tier. A person's ban does when the session it was made from
// holds such evidence; a ban on a reviewer's judgement alone labels nothing, and the
// reviewer can label the session by hand.
func (l *Labeler) certain(ctx context.Context, b *store.Ban) bool {
	if analyzer.TierOf(b.Rule) == analyzer.TierCertain {
		return true
	}
	if b.BannedBy == store.BanAutomatic || b.SessionID == "" {
		return false
	}
	evidence, err := l.st.ListEvidence(ctx, b.TenantID, store.EvidenceFilter{SessionID: b.SessionID, MinSeverity: int(analyzer.SeverityHigh), Limit: 500})
	if err != nil {
		l.log.Warn("ban labels", "ban", b.Ref, "err", err)
		return false
	}
	for _, e := range evidence {
		if e.Integrity && analyzer.TierOf(e.Rule) == analyzer.TierCertain {
			return true
		}
	}
	return false
}

// cheatType is the cheat type of a ban's labels: the category a person banned under, and
// client tampering for the integrity findings that ban automatically.
func cheatType(b *store.Ban) string {
	switch {
	case b.BannedBy != store.BanAutomatic:
		return b.Rule
	case strings.HasPrefix(b.Rule, "economy_"), b.ShadowOf != "":
		return ""
	}
	return "client_tampering"
}

// origin is how a ban's labels name where they come from: the source, and the words the
// session page and the label history show.
func origin(b *store.Ban) (source, by string) {
	if b.Shadow {
		return store.LabelSourceShadow, "shadow pool " + b.Ref
	}
	return store.LabelSourceBan, "ban " + b.Ref
}

// Banned labels the session a ban was made from, and the account's other sessions of the
// last LabelWindow, as confirmed cheating with the ban as the source. A session that
// already has a label keeps it. A ban into the shadow pool labels the same way, from the
// moment the player enters. An account that is in the pool because it connected from a
// pooled player's device key is labelled from that session on, not back in time: nothing
// was found on the account itself.
func (l *Labeler) Banned(b *store.Ban) {
	ctx := context.Background()
	if !l.certain(ctx, b) {
		return
	}
	ids := []string{}
	if b.SessionID != "" {
		ids = append(ids, b.SessionID)
	}
	if b.ShadowOf == "" {
		rows, err := l.st.ListSessions(ctx, b.TenantID, store.SessionFilter{PlayerHash: b.PlayerHash, Limit: maxSessions})
		if err != nil {
			l.log.Warn("ban labels", "ban", b.Ref, "err", err)
			return
		}
		since := b.BannedAt.Add(-LabelWindow)
		for _, r := range rows {
			if r.SessionID != b.SessionID && !r.CreatedAt.Before(since) {
				ids = append(ids, r.SessionID)
			}
		}
	}
	if n := l.label(ctx, b, ids); n > 0 {
		l.log.Info("sessions labelled from a ban", "ban", b.Ref, "tenant", b.TenantID, "player", b.PlayerHash, "sessions", n, "shadow_pool", b.Shadow)
	}
}

// PoolSession labels a session that a player in the shadow pool starts (bans.SessionHook):
// what the pool collects is every session until the ban takes effect.
func (l *Labeler) PoolSession(b *store.Ban, sess store.Session) {
	ctx := context.Background()
	if sess.TenantID != b.TenantID || sess.PlayerHash != b.PlayerHash || !l.certain(ctx, b) {
		return
	}
	l.label(ctx, b, []string{sess.SessionID})
}

func (l *Labeler) label(ctx context.Context, b *store.Ban, ids []string) int {
	source, by := origin(b)
	note := by
	switch {
	case b.ShadowOf != "":
		note += ": plays on the device key of " + b.ShadowOf
	case b.Rule != "":
		note += " on " + b.Rule
	}
	n := 0
	for _, id := range ids {
		if _, err := l.st.GetSessionLabel(ctx, b.TenantID, id); err == nil {
			continue
		} else if !errors.Is(err, store.ErrNotFound) {
			l.log.Warn("ban labels", "ban", b.Ref, "err", err)
			return n
		}
		label := &store.SessionLabel{TenantID: b.TenantID, SessionID: id, PlayerHash: b.PlayerHash, Label: store.LabelConfirmedCheat, CheatType: cheatType(b),
			Note: note, Reviewer: by, LabelledAt: l.Now(), Source: source, BanRef: b.Ref}
		if err := l.st.SetSessionLabel(ctx, label, store.LabelSet, ""); err != nil {
			l.log.Warn("ban labels", "ban", b.Ref, "err", err)
			return n
		}
		n++
	}
	return n
}

// Lifted removes the labels a ban put on sessions. Labels a reviewer set stay.
func (l *Labeler) Lifted(b *store.Ban) {
	ctx := context.Background()
	labels, err := l.st.ListSessionLabels(ctx, b.TenantID, store.OracleFilter{PlayerHash: b.PlayerHash, Limit: 4 * maxSessions})
	if err != nil {
		l.log.Warn("ban labels", "ban", b.Ref, "err", err)
		return
	}
	_, by := origin(b)
	n := 0
	for _, have := range labels {
		if !store.LabelFromBan(have.Source) || have.BanRef != b.Ref {
			continue
		}
		gone := &store.SessionLabel{TenantID: b.TenantID, SessionID: have.SessionID, PlayerHash: have.PlayerHash, Note: by + " lifted",
			Reviewer: by, LabelledAt: l.Now()}
		if err := l.st.SetSessionLabel(ctx, gone, store.LabelRemove, ""); err != nil {
			l.log.Warn("ban labels", "ban", b.Ref, "err", err)
			return
		}
		n++
	}
	if n > 0 {
		l.log.Info("labels of a lifted ban removed", "ban", b.Ref, "tenant", b.TenantID, "player", b.PlayerHash, "sessions", n)
	}
}

// ProposalStore is what Proposals reads.
type ProposalStore interface {
	store.CheatStore
	ListBans(ctx context.Context, tenant string, limit int) ([]store.Ban, error)
}

// Proposal is a file that only banned accounts were seen to load.
type Proposal struct {
	SHA256 string
	// Names the file was loaded under, most seen first.
	Names []string
	// Signature says how the file is not validly signed.
	Signature string
	// BannedAccounts loaded the file; no account that is not banned did.
	BannedAccounts int
	Sessions       int
	LastSeen       time.Time
}

// Proposals is the studio's list of proposed known cheats with what it was judged by.
type Proposals struct {
	List []Proposal
	// MinAccounts is the studio's threshold of banned accounts.
	MinAccounts int
	// Compared is how many accounts that are not banned have reported the files they
	// load. With none, the game's own unsigned files cannot be told from a cheat's.
	Compared int
}

const maxBans = 100000

var signatureWords = map[pb.ModuleSignature]string{
	pb.ModuleSignature_MODULE_SIGNATURE_NONE:       "not signed",
	pb.ModuleSignature_MODULE_SIGNATURE_BAD_DIGEST: "changed after signing",
	pb.ModuleSignature_MODULE_SIGNATURE_UNTRUSTED:  "untrusted signer",
	pb.ModuleSignature_MODULE_SIGNATURE_EXPIRED:    "expired certificate",
}

// FindProposals works out the proposals from the files the studio's sessions reported: a
// file that is not validly signed, sits outside the Windows folder, was loaded by at least
// the studio's threshold of distinct accounts with a standing ban and by no account
// without one, is not on the list of known cheats and was not dismissed.
func FindProposals(ctx context.Context, st ProposalStore, tenant string) (*Proposals, error) {
	out := &Proposals{}
	var err error
	if out.MinAccounts, err = st.CheatProposalAccounts(ctx, tenant); err != nil {
		return nil, err
	}
	sightings, err := st.ListModuleSightings(ctx, tenant)
	if err != nil {
		return nil, err
	}
	bans, err := st.ListBans(ctx, tenant, maxBans)
	if err != nil {
		return nil, err
	}
	banned := map[string]bool{}
	for i := range bans {
		if !bans[i].Lifted() {
			banned[bans[i].PlayerHash] = true
		}
	}
	known, err := st.ListKnownCheats(ctx, tenant)
	if err != nil {
		return nil, err
	}
	skip, err := st.DismissedCheatProposals(ctx, tenant)
	if err != nil {
		return nil, err
	}
	for _, k := range known {
		skip[k.SHA256] = true
	}

	type file struct {
		players   map[string]bool
		names     map[string]int
		signature string
		valid     bool
		clean     bool
		sessions  int
		last      time.Time
	}
	files := map[string]*file{}
	compared := map[string]bool{}
	for _, s := range sightings {
		if !banned[s.PlayerHash] {
			compared[s.PlayerHash] = true
		}
		f := files[s.SHA256]
		if f == nil {
			f = &file{players: map[string]bool{}, names: map[string]int{}}
			files[s.SHA256] = f
		}
		f.players[s.PlayerHash] = true
		f.names[s.Module] += s.Sessions
		f.sessions += s.Sessions
		f.clean = f.clean || !banned[s.PlayerHash]
		if s.LastSeen.After(f.last) {
			f.last = s.LastSeen
		}
		if w, ok := signatureWords[pb.ModuleSignature(s.Signature)]; ok {
			f.signature = w
		} else if pb.ModuleSignature(s.Signature) == pb.ModuleSignature_MODULE_SIGNATURE_VALID {
			f.valid = true
		}
	}
	out.Compared = len(compared)
	for sum, f := range files {
		if skip[sum] || f.clean || f.valid || f.signature == "" || len(f.players) < out.MinAccounts {
			continue
		}
		p := Proposal{SHA256: sum, Signature: f.signature, BannedAccounts: len(f.players), Sessions: f.sessions, LastSeen: f.last}
		for n := range f.names {
			p.Names = append(p.Names, n)
		}
		sort.Slice(p.Names, func(i, j int) bool {
			if f.names[p.Names[i]] != f.names[p.Names[j]] {
				return f.names[p.Names[i]] > f.names[p.Names[j]]
			}
			return p.Names[i] < p.Names[j]
		})
		out.List = append(out.List, p)
	}
	sort.Slice(out.List, func(i, j int) bool {
		a, b := out.List[i], out.List[j]
		if a.BannedAccounts != b.BannedAccounts {
			return a.BannedAccounts > b.BannedAccounts
		}
		if !a.LastSeen.Equal(b.LastSeen) {
			return a.LastSeen.After(b.LastSeen)
		}
		return a.SHA256 < b.SHA256
	})
	return out, nil
}

// Proposed returns the proposal for one file, nil when the file is not proposed.
func (p *Proposals) Proposed(sha256 string) *Proposal {
	for i := range p.List {
		if p.List[i].SHA256 == sha256 {
			return &p.List[i]
		}
	}
	return nil
}
