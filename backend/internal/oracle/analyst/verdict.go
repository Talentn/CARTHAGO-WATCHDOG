package analyst

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"
	"unicode"
	"unicode/utf8"
)

// VerdictSchema is the version of the verdict's layout.
const VerdictSchema = 1

// Verdict is the analyst's opinion on one case.
type Verdict struct {
	// CitedEvidence lists the case's evidence ids the opinion rests on.
	CitedEvidence []string `json:"cited_evidence"`
	CheatType     string   `json:"cheat_type"`
	// Confidence is 0..100: how sure the analyst is of CheatType.
	Confidence        int    `json:"confidence"`
	RecommendedAction string `json:"recommended_action"`
	// Summary is one or two plain sentences for the reviewer.
	Summary string `json:"summary"`
}

// Cheat types an opinion can name.
const (
	TypeNone         = "none"
	TypeAim          = "aim_assistance"
	TypeInformation  = "wallhack_information"
	TypeInput        = "input_automation"
	TypeSpeed        = "speed_manipulation"
	TypeTampering    = "client_tampering"
	TypeMixed        = "mixed"
	TypeInconclusive = "inconclusive"
)

// Actions an opinion can recommend. There is deliberately no action that touches the
// player: the strongest thing the analyst can ask for is a human's attention.
const (
	ActionNone     = "no_action"
	ActionMonitor  = "monitor"
	ActionReview   = "manual_review"
	ActionPriority = "priority_review"
)

var (
	CheatTypes = []string{TypeNone, TypeAim, TypeInformation, TypeInput, TypeSpeed, TypeTampering, TypeMixed, TypeInconclusive}
	Actions    = []string{ActionNone, ActionMonitor, ActionReview, ActionPriority}
)

const (
	maxCited        = 8
	maxSummaryRunes = 320
	maxVerdictBytes = 4 << 10
)

// Accuses reports whether the verdict names a kind of cheating.
func (v *Verdict) Accuses() bool { return v.CheatType != TypeNone && v.CheatType != TypeInconclusive }

func oneOf(s string, set []string) bool {
	for _, x := range set {
		if s == x {
			return true
		}
	}
	return false
}

// ParseVerdict accepts a model's answer for a case, or says in one word why not. The
// answer must be a single JSON object with exactly the verdict's fields; the cheat type
// and action must be from the lists above; cited evidence must exist in the case; and an
// opinion that names cheating must cite at least one item.
func ParseVerdict(raw string, c *Case) (*Verdict, error) {
	raw = strings.TrimSpace(raw)
	if len(raw) == 0 || len(raw) > maxVerdictBytes {
		return nil, errors.New("size")
	}
	dec := json.NewDecoder(strings.NewReader(raw))
	dec.DisallowUnknownFields()
	// Required fields are told apart from zero values by decoding into pointers.
	var w struct {
		CitedEvidence     *[]string `json:"cited_evidence"`
		CheatType         *string   `json:"cheat_type"`
		Confidence        *float64  `json:"confidence"`
		RecommendedAction *string   `json:"recommended_action"`
		Summary           *string   `json:"summary"`
	}
	if err := dec.Decode(&w); err != nil {
		return nil, errors.New("not_json")
	}
	if _, err := dec.Token(); err != io.EOF {
		return nil, errors.New("trailing_data")
	}
	if w.CitedEvidence == nil || w.CheatType == nil || w.Confidence == nil || w.RecommendedAction == nil || w.Summary == nil {
		return nil, errors.New("missing_field")
	}
	v := &Verdict{CheatType: *w.CheatType, RecommendedAction: *w.RecommendedAction}
	if !oneOf(v.CheatType, CheatTypes) {
		return nil, errors.New("cheat_type")
	}
	if !oneOf(v.RecommendedAction, Actions) {
		return nil, errors.New("action")
	}
	if conf := *w.Confidence; conf != float64(int(conf)) || conf < 0 || conf > 100 {
		return nil, errors.New("confidence")
	}
	v.Confidence = int(*w.Confidence)
	if len(*w.CitedEvidence) > maxCited {
		return nil, errors.New("citations")
	}
	seen := map[string]bool{}
	v.CitedEvidence = []string{}
	for _, id := range *w.CitedEvidence {
		if !c.HasID(id) {
			return nil, errors.New("unknown_citation")
		}
		if !seen[id] {
			seen[id] = true
			v.CitedEvidence = append(v.CitedEvidence, id)
		}
	}
	if v.Accuses() && len(v.CitedEvidence) == 0 {
		return nil, errors.New("uncited_accusation")
	}
	if v.CheatType == TypeNone && v.RecommendedAction == ActionPriority {
		return nil, errors.New("inconsistent_action")
	}
	if v.Summary = CleanSummary(*w.Summary); v.Summary == "" {
		return nil, errors.New("summary")
	}
	return v, nil
}

// CleanSummary reduces a model's free text to plain prose: letters, digits, spaces and
// ordinary punctuation, capped in length. Markup, control characters and anything that
// could be read as a link or as code are dropped. The dashboard escapes the result again
// when it renders it.
func CleanSummary(s string) string {
	if !utf8.ValidString(s) {
		s = strings.ToValidUTF8(s, "")
	}
	var b strings.Builder
	n, space := 0, true
	for _, r := range s {
		ok := unicode.IsLetter(r) || unicode.IsDigit(r) || strings.ContainsRune(".,;:!?'()%-_", r)
		if !ok {
			r = ' '
		}
		if r == ' ' {
			if space {
				continue
			}
			space = true
		} else {
			space = false
		}
		if n == maxSummaryRunes {
			break
		}
		b.WriteRune(r)
		n++
	}
	return strings.TrimSpace(b.String())
}

// Schema returns the JSON schema of a verdict for one case: cited evidence can only be
// that case's ids. Providers that support constrained output are given it, so the model
// cannot produce anything else; ParseVerdict checks the result regardless.
func Schema(c *Case) json.RawMessage {
	ids := make([]string, len(c.Evidence))
	for i := range c.Evidence {
		ids[i] = c.Evidence[i].ID
	}
	cited := map[string]any{"type": "array", "maxItems": 0, "items": map[string]any{"type": "string"}}
	if len(ids) > 0 {
		cited = map[string]any{"type": "array", "maxItems": min(len(ids), maxCited), "items": map[string]any{"type": "string", "enum": ids}}
	}
	// encoding/json writes map keys sorted, so the property order is given separately:
	// evidence first, then the judgement, then the sentence that explains it.
	var b bytes.Buffer
	b.WriteString(`{"type":"object","additionalProperties":false,"required":["cited_evidence","cheat_type","confidence","recommended_action","summary"],"properties":{`)
	prop := func(name string, v any, last bool) {
		j, _ := json.Marshal(v)
		fmt.Fprintf(&b, "%q:%s", name, j)
		if !last {
			b.WriteByte(',')
		}
	}
	prop("cited_evidence", cited, false)
	prop("cheat_type", map[string]any{"type": "string", "enum": CheatTypes}, false)
	prop("confidence", map[string]any{"type": "integer", "minimum": 0, "maximum": 100}, false)
	prop("recommended_action", map[string]any{"type": "string", "enum": Actions}, false)
	prop("summary", map[string]any{"type": "string", "minLength": 20, "maxLength": maxSummaryRunes}, true)
	b.WriteString("}}")
	return b.Bytes()
}
