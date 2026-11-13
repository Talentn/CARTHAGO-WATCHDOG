// Package tune turns a studio's reviewed sessions into tuning data for its own Oracle:
// labelled feature rows for the behaviour model and chat-format examples for a private
// fine-tune of the analyst's language model.
//
// Everything it writes is pseudonymised the way case files are: a keyed pseudonym for the
// player and the session, the closed vocabulary of the case file, numbers. Reviewer
// notes and reviewer names are not exported. The files are still the studio's own data
// about its players' behaviour, and belong on the gateway host or a machine the studio
// trusts with it.
package tune

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"hash/fnv"
	"io"
	"sort"
	"strings"
	"time"

	"carthago/backend/internal/oracle"
	"carthago/backend/internal/oracle/analyst"
	"carthago/backend/internal/oracle/train"
	"carthago/backend/internal/store"
)

// Store is what the export reads.
type Store interface {
	ListSessionLabels(ctx context.Context, tenant string, f store.OracleFilter) ([]store.SessionLabel, error)
	GetSession(ctx context.Context, sessionID string) (*store.Session, error)
	GetOracleScore(ctx context.Context, tenant, sessionID string) (*store.OracleScore, error)
	ListEvidence(ctx context.Context, tenant string, f store.EvidenceFilter) ([]store.Evidence, error)
	GetTelemetry(ctx context.Context, tenant, sessionID string) (*store.Telemetry, error)
}

// BehaviourRow is one labelled session for the behaviour model.
type BehaviourRow struct {
	Subject        string        `json:"subject"`
	Session        string        `json:"session"`
	Label          string        `json:"label"`
	CheatType      string        `json:"cheat_type,omitempty"`
	FeatureVersion int           `json:"feature_version"`
	HasMatch       bool          `json:"has_match"`
	Features       oracle.Vector `json:"features"`
	LabelledAt     string        `json:"labelled_at"`
}

// ChatMessage and ChatExample are the chat fine-tuning format most trainers read: one
// JSON object per line with a "messages" list.
type ChatMessage struct {
	Role    string `json:"role"`
	Content string `json:"content"`
}

type ChatExample struct {
	Messages []ChatMessage `json:"messages"`
}

// Stats counts what an export held.
type Stats struct {
	Labels         int
	Confirmed      int
	Cleared        int
	Unsure         int
	ByCheatType    map[string]int
	WithoutMatch   int
	AnalystSamples int
	// Skipped counts labels whose session is gone from the store.
	Skipped int
}

// Minimum labelled sessions before retraining the behaviour model on them is worth it.
// They come from the learning curves on synthetic sessions (carthago-oracle curve) and
// from what a count can prove; real play is noisier, so they are lower bounds:
//
//   - 400 confirmed cheating sessions: below that the model on synthetic data is still
//     visibly short of what it reaches with more (AUC 0.983 at 200, 0.993 at 400, 0.997
//     at 1,140), and it sends far fewer cheating sessions to review;
//   - 100 per cheat type the model should recognise: fewer cannot measure that type's
//     recall to within about 10 points;
//   - 600 cleared sessions: the model itself needs only a few hundred, but 600 is the
//     fewest on which "no honest session in review" bounds the honest review rate at
//     0.5% (95% confidence), and that is counted on held-out sessions only, so a studio
//     that holds out a fifth needs 3,000 in all for that bound;
//   - 50 distinct players, so the model learns behaviour and not a few people's habits.
const (
	MinCleared           = 600
	MinConfirmed         = 400
	MinConfirmedPerType  = 100
	MinDistinctPlayers   = 50
	MinAnalystSamples    = 500
	maxExportedLabels    = 1 << 20
	maxExportedEvidence  = 500
	targetConfidenceHigh = 90
)

// Export reads a tenant's labelled sessions and builds both datasets.
func Export(ctx context.Context, st Store, p *analyst.Pseudonymiser, tenant string, b *oracle.Bundle, prompts analyst.Prompts) ([]BehaviourRow, []ChatExample, Stats, error) {
	stats := Stats{ByCheatType: map[string]int{}}
	labels, err := st.ListSessionLabels(ctx, tenant, store.OracleFilter{Limit: maxExportedLabels})
	if err != nil {
		return nil, nil, stats, err
	}
	// Oldest first, so an export grows at its end as labels are added.
	sort.SliceStable(labels, func(i, j int) bool { return labels[i].LabelledAt.Before(labels[j].LabelledAt) })
	var rows []BehaviourRow
	var chat []ChatExample
	for _, l := range labels {
		sess, err := st.GetSession(ctx, l.SessionID)
		if errors.Is(err, store.ErrNotFound) || err == nil && sess.TenantID != tenant {
			stats.Skipped++
			continue
		}
		if err != nil {
			return nil, nil, stats, err
		}
		evidence, err := st.ListEvidence(ctx, tenant, store.EvidenceFilter{SessionID: l.SessionID, Limit: maxExportedEvidence})
		if err != nil {
			return nil, nil, stats, err
		}
		score, err := st.GetOracleScore(ctx, tenant, l.SessionID)
		if err != nil && !errors.Is(err, store.ErrNotFound) {
			return nil, nil, stats, err
		}
		// The features the engine stored are used as they are. A session the engine
		// never scored (it was off, or the session only sent integrity findings before
		// it was installed) gets its client-side features computed now; its gameplay
		// values stay unknown.
		v, version, hasMatch := oracle.Missing(), oracle.FeatureVersion, false
		if score != nil && json.Unmarshal([]byte(score.Features), &v) == nil {
			version, hasMatch = score.FeatureVersion, score.MatchID != ""
		} else {
			tel, err := st.GetTelemetry(ctx, tenant, l.SessionID)
			if err != nil {
				tel = nil
			}
			oracle.ClientFeatures(&v, sess.TrustLevel, evidence, tel)
			if b != nil {
				score = b.ScoreRow(*sess, v, "", l.LabelledAt)
			}
		}
		stats.Labels++
		switch l.Label {
		case store.LabelConfirmedCheat:
			stats.Confirmed++
			if l.CheatType != "" {
				stats.ByCheatType[l.CheatType]++
			}
		case store.LabelCleared:
			stats.Cleared++
		default:
			stats.Unsure++
		}
		if !hasMatch {
			stats.WithoutMatch++
		}
		rows = append(rows, BehaviourRow{Subject: p.Player(tenant, sess.PlayerHash), Session: p.Session(tenant, sess.SessionID), Label: l.Label, CheatType: l.CheatType,
			FeatureVersion: version, HasMatch: hasMatch, Features: v, LabelledAt: l.LabelledAt.UTC().Format(time.RFC3339)})

		c := analyst.Build(p, oracle.CaseInput(*sess, evidence, score))
		if c.CheckVocabulary() != nil {
			continue
		}
		target := Target(c, l)
		if target == nil {
			continue
		}
		answer, _ := json.Marshal(target)
		if _, err := analyst.ParseVerdict(string(answer), c); err != nil {
			continue // never teach an answer the gateway itself would reject
		}
		chat = append(chat, ChatExample{Messages: []ChatMessage{
			{Role: "system", Content: prompts.System},
			{Role: "user", Content: strings.ReplaceAll(prompts.Case, "{{case}}", string(c.JSON()))},
			{Role: "assistant", Content: string(answer)},
		}})
		stats.AnalystSamples++
	}
	return rows, chat, stats, nil
}

var typeWords = map[string]string{
	analyst.TypeAim: "aim assistance", analyst.TypeInformation: "wallhack information", analyst.TypeInput: "input automation",
	analyst.TypeSpeed: "speed manipulation", analyst.TypeTampering: "client tampering", analyst.TypeMixed: "more than one kind of cheating",
}

// Target is the verdict a reviewer's label stands for on a case: what the analyst should
// have said. A cleared session is "none". A confirmed cheat names the reviewer's cheat
// type and cites the strong evidence that points to it; when the case holds no such
// evidence the honest answer for an analyst that may only cite what is in the case is
// "inconclusive, review by a person". An unsure label teaches nothing and gives nil.
func Target(c *analyst.Case, l store.SessionLabel) *analyst.Verdict {
	switch l.Label {
	case store.LabelCleared:
		return &analyst.Verdict{CitedEvidence: []string{}, CheatType: analyst.TypeNone, Confidence: 85, RecommendedAction: analyst.ActionNone,
			Summary: "Nothing in the case is proof of cheating."}
	case store.LabelConfirmedCheat:
	default:
		return nil
	}
	var cited []string
	critical, high := false, 0
	kinds := map[string]bool{}
	for _, e := range c.Evidence {
		if e.Weight != analyst.WeightStrong {
			continue
		}
		if l.CheatType != "" && l.CheatType != analyst.TypeMixed && e.PointsTo != l.CheatType {
			continue
		}
		cited = append(cited, e.ID)
		kinds[e.PointsTo] = true
		critical = critical || e.Severity == "critical"
		if e.Severity == "high" {
			high++
		}
	}
	if len(cited) == 0 {
		return &analyst.Verdict{CitedEvidence: []string{}, CheatType: analyst.TypeInconclusive, Confidence: 40, RecommendedAction: analyst.ActionReview,
			Summary: "No strong evidence is in the case, so no cheat type can be named from it. A person should review the session."}
	}
	kind := l.CheatType
	if kind == "" || kind == analyst.TypeMixed {
		kind = analyst.TypeMixed
		if len(kinds) == 1 {
			for k := range kinds {
				kind = k
			}
		}
	}
	v := &analyst.Verdict{CitedEvidence: cited, CheatType: kind, Confidence: 70, RecommendedAction: analyst.ActionReview}
	if critical || high >= 2 {
		v.Confidence, v.RecommendedAction = targetConfidenceHigh, analyst.ActionPriority
	} else if high == 1 {
		v.Confidence = 80
	}
	v.Summary = fmt.Sprintf("The strong evidence (%s) is consistent with %s.", strings.Join(cited, ", "), typeWords[kind])
	return v
}

// WriteJSONL writes one JSON object per line.
func WriteJSONL[T any](w io.Writer, rows []T) error {
	bw := bufio.NewWriter(w)
	enc := json.NewEncoder(bw)
	for i := range rows {
		if err := enc.Encode(rows[i]); err != nil {
			return err
		}
	}
	return bw.Flush()
}

// ReadBehaviour reads an exported behaviour dataset as training rows. Sessions labelled
// unsure are left out. One player's sessions share a group, so they stay on one side of
// the train, calibration and test split.
func ReadBehaviour(r io.Reader) ([]train.Row, error) {
	var rows []train.Row
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 64<<10), 1<<20)
	for n := 1; sc.Scan(); n++ {
		line := strings.TrimSpace(sc.Text())
		if line == "" {
			continue
		}
		var b BehaviourRow
		dec := json.NewDecoder(strings.NewReader(line))
		dec.DisallowUnknownFields()
		if err := dec.Decode(&b); err != nil {
			return nil, fmt.Errorf("line %d: %w", n, err)
		}
		if b.FeatureVersion != oracle.FeatureVersion {
			return nil, fmt.Errorf("line %d: feature version %d, this build reads %d", n, b.FeatureVersion, oracle.FeatureVersion)
		}
		row := train.Row{Profile: train.Honest, InMatch: b.HasMatch, Vector: b.Features}
		switch b.Label {
		case store.LabelCleared:
		case store.LabelConfirmedCheat:
			row.Cheating, row.Profile = true, "labelled"
			if b.CheatType != "" {
				row.Profile = "labelled_" + b.CheatType
			}
		case store.LabelUnsure:
			continue
		default:
			return nil, fmt.Errorf("line %d: unknown label", n)
		}
		h := fnv.New32a()
		h.Write([]byte(b.Subject))
		// Groups above the synthetic match numbers, spread over the three splits.
		row.Match = 1<<24 + int(h.Sum32()%(1<<20))
		rows = append(rows, row)
	}
	return rows, sc.Err()
}

// Ready reports what an export still lacks before retraining on it is worth it, in
// sentences for the tool's output. An empty list means every minimum is met.
func (s Stats) Ready(players int) []string {
	var out []string
	need := func(have, want int, what string) {
		if have < want {
			out = append(out, fmt.Sprintf("%d of %d %s", have, want, what))
		}
	}
	need(s.Cleared, MinCleared, "cleared sessions")
	need(s.Confirmed, MinConfirmed, "confirmed cheating sessions")
	for _, t := range []string{analyst.TypeAim, analyst.TypeInformation, analyst.TypeInput, analyst.TypeSpeed, analyst.TypeTampering} {
		if n := s.ByCheatType[t]; n > 0 && n < MinConfirmedPerType {
			out = append(out, fmt.Sprintf("%d of %d confirmed sessions of type %s (below that, its recall cannot be measured to within about 10 points)", n, MinConfirmedPerType, t))
		}
	}
	need(players, MinDistinctPlayers, "distinct players")
	return out
}
