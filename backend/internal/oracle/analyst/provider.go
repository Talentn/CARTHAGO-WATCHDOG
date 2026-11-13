package analyst

import (
	"context"
	"encoding/json"
	"fmt"
	"sort"
	"strings"
)

// Provider is a language model that answers one request with one piece of text.
type Provider interface {
	// Name is the kind of provider: local, stub, openai or anthropic.
	Name() string
	// Model names the model, for the verdict's record.
	Model() string
	// External reports whether a request leaves the gateway host. An external provider is
	// only used for tenants that opted in.
	External() bool
	Complete(ctx context.Context, r Request) (Response, error)
}

type Request struct {
	System string
	User   string
	// Schema is the JSON schema the answer must follow, for providers that can constrain
	// their output to it.
	Schema    json.RawMessage
	MaxTokens int
	// Case is the case the request is about. Only the stub reads it.
	Case *Case
}

type Response struct {
	Text      string
	TokensIn  int
	TokensOut int
}

// Stub is a provider without a model: it applies a fixed reading of the case and writes
// the verdict a careful analyst following the reference instructions would. It needs no
// network and always gives the same answer for the same case, so tests and the demo run
// on it, and a language model's verdicts can be measured against it.
type Stub struct{}

func (Stub) Name() string   { return "stub" }
func (Stub) Model() string  { return "carthago-oracle-stub-1" }
func (Stub) External() bool { return false }

func (Stub) Complete(_ context.Context, r Request) (Response, error) {
	if r.Case == nil {
		return Response{}, fmt.Errorf("stub: no case")
	}
	b, err := json.Marshal(StubVerdict(r.Case))
	if err != nil {
		return Response{}, err
	}
	return Response{Text: string(b), TokensIn: (len(r.System) + len(r.User)) / 4, TokensOut: len(b) / 4}, nil
}

var familyType = map[string]string{
	FamilyAim: TypeAim, FamilyInformation: TypeInformation, FamilyInput: TypeInput,
	FamilySpeedTime: TypeSpeed, FamilyTampering: TypeTampering,
}

var severityRank = map[string]int{"low": 1, "medium": 2, "high": 3, "critical": 4}

// StubVerdict is the fixed reading of a case.
func StubVerdict(c *Case) *Verdict {
	type support struct {
		family string
		weight float64
		strong bool // high or critical evidence
		ids    []string
	}
	by := map[string]*support{}
	get := func(f string) *support {
		s := by[f]
		if s == nil {
			s = &support{family: f}
			by[f] = s
		}
		return s
	}
	weights := [5]float64{0, 1, 3, 6, 10}
	critical, weak := false, 0
	for _, e := range c.Evidence {
		rank := severityRank[e.Severity]
		if _, ok := familyType[e.Family]; !ok || rank < 2 {
			weak++
			continue
		}
		s := get(e.Family)
		s.weight += weights[rank] * float64(e.Confidence) / 100
		s.strong = s.strong || rank >= 3
		s.ids = append(s.ids, e.ID)
		critical = critical || rank == 4
	}
	review := c.Model != nil && c.Model.Band == "review"
	if review {
		for _, sig := range c.Model.Signals {
			if _, ok := familyType[sig.Family]; !ok || sig.Effect != "raises" {
				continue
			}
			switch sig.Strength {
			case "strong":
				get(sig.Family).weight += 3
			case "moderate":
				get(sig.Family).weight += 1
			}
		}
	}
	var found []*support
	for _, s := range by {
		if s.weight >= 1.5 {
			found = append(found, s)
		}
	}
	sort.Slice(found, func(i, j int) bool {
		if found[i].weight != found[j].weight {
			return found[i].weight > found[j].weight
		}
		return found[i].family < found[j].family
	})

	v := &Verdict{CitedEvidence: []string{}}
	switch {
	case len(found) == 0 && (review || len(by) > 0):
		v.CheatType, v.Confidence, v.RecommendedAction = TypeInconclusive, 35, ActionMonitor
		if review {
			v.RecommendedAction = ActionReview
		}
		v.Summary = "There are signs worth a look but nothing that supports a specific kind of cheating."
	case len(found) == 0:
		v.CheatType, v.Confidence, v.RecommendedAction = TypeNone, 80, ActionNone
		v.Summary = "Nothing in the case supports cheating."
		if weak > 0 {
			v.Summary = "Only low severity or environment findings are present, which do not indicate cheating on their own."
		}
		return v
	default:
		top := found[0]
		v.CheatType = familyType[top.family]
		total := top.weight
		cite := append([]string{}, top.ids...)
		strong := 0
		for _, s := range found {
			if s.strong {
				strong++
			}
		}
		if strong >= 2 {
			v.CheatType = TypeMixed
			for _, s := range found[1:] {
				if s.strong {
					total += s.weight
					cite = append(cite, s.ids...)
				}
			}
		}
		if len(cite) == 0 {
			// Support came from the behaviour model alone: an accusation needs evidence
			// to cite, so the stub stops at a suspicion.
			v.CheatType, v.Confidence, v.RecommendedAction = TypeInconclusive, 45, ActionReview
			v.Summary = "The behaviour model points at " + strings.ReplaceAll(top.family, "_", " ") + " signals, but no rule evidence backs a specific finding yet."
			return v
		}
		sort.Slice(cite, func(i, j int) bool {
			return len(cite[i]) < len(cite[j]) || len(cite[i]) == len(cite[j]) && cite[i] < cite[j]
		})
		if len(cite) > 6 {
			cite = cite[:6]
		}
		v.CitedEvidence = cite
		v.Confidence = min(95, 45+int(5*total))
		if review {
			v.Confidence = min(95, v.Confidence+10)
		}
		v.RecommendedAction = ActionReview
		if critical || strong >= 2 || total >= 9 {
			v.RecommendedAction = ActionPriority
		}
		kind := strings.ReplaceAll(v.CheatType, "_", " ")
		v.Summary = fmt.Sprintf("The evidence (%s) is consistent with %s.", strings.Join(cite, ", "), kind)
		if review {
			v.Summary += " The behaviour model also places the session in the review band."
		}
	}
	return v
}
