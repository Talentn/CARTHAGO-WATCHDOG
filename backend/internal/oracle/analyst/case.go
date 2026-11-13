// Package analyst is the Carthago Oracle's second opinion: it turns a flagged session
// into a compact case file, asks a language model for a structured verdict, and accepts
// the answer only if it passes a strict check against that case.
//
// Three rules shape everything here.
//
// The verdict is an opinion for a human reviewer. It has no field that could carry a
// punishment, and nothing in this package can reach a session, a kick or a client.
//
// Nothing a player controls reaches the model. A case file is built from numbers and from
// words out of a closed vocabulary that the gateway chose; player and session ids are
// replaced with keyed pseudonyms, match ids with M1, M2..., and every free-text field of
// the evidence (summaries, module and process names, raw details) is left out. A prompt
// injection has no field to arrive in.
//
// The model's answer is untrusted too. It must parse as exactly the verdict schema, cite
// only evidence that is in the case, and its one free-text field is length-capped and
// stripped to plain prose before it is stored.
package analyst

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"math"
	"regexp"
	"sort"
	"strconv"

	"carthago/backend/internal/store"
)

// CaseSchema is the version of the case file's layout.
const CaseSchema = 1

// Case is what the model is shown. Every string in it is either a pseudonym or a word
// from this package's vocabulary; CheckVocabulary enforces that before a case is sent.
type Case struct {
	Schema  int    `json:"case_schema"`
	Subject string `json:"subject"`
	Session string `json:"session"`
	// Trust is how strongly the player's device is attested.
	Trust    string         `json:"device_trust"`
	Model    *CaseModel     `json:"behaviour_model,omitempty"`
	Evidence []CaseEvidence `json:"evidence"`
	// Omitted counts evidence groups left out because the case was full.
	Omitted int `json:"evidence_omitted,omitempty"`
	// Notes counts informational findings (allowlisted overlays and the like), which carry
	// no risk and are not listed.
	Notes int `json:"informational_notes,omitempty"`

	// Refs maps an evidence id of the case to the stored evidence rows behind it. It stays
	// on the gateway.
	Refs map[string][]int64 `json:"-"`
}

type CaseModel struct {
	Score   int          `json:"score"` // 0..100
	Band    string       `json:"band"`
	Signals []CaseSignal `json:"signals,omitempty"`
}

type CaseSignal struct {
	Signal   string `json:"signal"`
	Family   string `json:"family"`
	Effect   string `json:"effect"`   // raises | lowers
	Strength string `json:"strength"` // weak | moderate | strong
}

type CaseEvidence struct {
	ID         string `json:"id"`
	Rule       string `json:"rule"`
	Family     string `json:"family"`
	Severity   string `json:"severity"`
	Confidence int    `json:"confidence"` // 0..100, the rule's own score
	// Tamper marks evidence that the client itself was interfered with.
	Tamper bool   `json:"client_tampering"`
	Source string `json:"source"`
	Match  string `json:"match,omitempty"`
	Count  int    `json:"count"`
}

// Families of evidence and signals.
const (
	FamilyAim         = "aim"
	FamilyInformation = "information"
	FamilyInput       = "input"
	FamilySpeedTime   = "speed_time"
	FamilyTampering   = "tampering"
	FamilyEnvironment = "environment"
	FamilyScanner     = "scanner_health"
	FamilyTrust       = "trust"
	FamilyOther       = "other"
)

// ruleFamily is the closed list of rule names a case may carry. A rule that is not here
// is shown as "other": a name the gateway does not know is not passed on.
var ruleFamily = map[string]string{
	"angle_snap": FamilyAim, "headshot_rate": FamilyAim, "time_to_damage": FamilyAim,
	"information_leak": FamilyInformation, "decoy_reaction": FamilyInformation,
	"macro_interval": FamilyInput, "injected_input": FamilyInput,
	"command_rate": FamilySpeedTime, "time_source_divergence": FamilySpeedTime, "clock_drift": FamilySpeedTime,
	"unbacked_exec": FamilyTampering, "image_not_in_loader": FamilyTampering, "module_not_image": FamilyTampering,
	"thread_start_unbacked": FamilyTampering, "api_hook": FamilyTampering, "code_patch": FamilyTampering, "debugger": FamilyTampering,
	"external_handle": FamilyEnvironment, "overlay_window": FamilyEnvironment, "vulnerable_driver": FamilyEnvironment,
	"module_signature": FamilyEnvironment, "external_exec_regions": FamilyEnvironment,
	"scanner_stalled": FamilyScanner, "scan_quarantined": FamilyScanner, "scan_coverage": FamilyScanner, "evidence_flood": FamilyScanner,
}

var (
	severityWord = [5]string{"info", "low", "medium", "high", "critical"}
	trustWord    = [4]string{"unattested", "basic", "hardware_attested", "hardware_attested_secure_boot"}
	sourceWord   = map[string]string{store.SourceClient: "client_scanner", store.SourceGameplay: "server_gameplay"}
)

var families = map[string]bool{FamilyAim: true, FamilyInformation: true, FamilyInput: true, FamilySpeedTime: true,
	FamilyTampering: true, FamilyEnvironment: true, FamilyScanner: true, FamilyTrust: true, FamilyOther: true}

// Signal is one behaviour-model signal offered to a case.
type Signal struct {
	Key    string
	Family string
	Effect float64
}

// Input is what the engine knows about a session when it builds a case.
type Input struct {
	TenantID   string
	PlayerHash string
	SessionID  string
	TrustLevel uint32
	// Scored is false when the behaviour model has not scored the session.
	Scored  bool
	Score   float64
	Band    string
	Signals []Signal
	// SignalKeys is the set of signal names the engine may send.
	SignalKeys map[string]bool
	Evidence   []store.Evidence
}

const (
	maxCaseEvidence = 16
	maxCaseSignals  = 5
)

// Pseudonymiser replaces identifiers with keyed pseudonyms: stable for one gateway, so a
// reviewer's cases about one player line up, and meaningless to anyone without the key.
type Pseudonymiser struct{ key []byte }

func NewPseudonymiser(key []byte) *Pseudonymiser { return &Pseudonymiser{key: key} }

func (p *Pseudonymiser) name(prefix string, parts ...string) string {
	h := hmac.New(sha256.New, p.key)
	for _, s := range parts {
		h.Write([]byte{byte(len(s) >> 8), byte(len(s))})
		h.Write([]byte(s))
	}
	return prefix + hex.EncodeToString(h.Sum(nil)[:5])
}

// Player and Session return the pseudonyms used in case files.
func (p *Pseudonymiser) Player(tenant, playerHash string) string {
	return p.name("P-", "player", tenant, playerHash)
}

func (p *Pseudonymiser) Session(tenant, sessionID string) string {
	return p.name("S-", "session", tenant, sessionID)
}

func strength(effect float64) string {
	switch a := math.Abs(effect); {
	case a >= 2:
		return "strong"
	case a >= 0.75:
		return "moderate"
	}
	return "weak"
}

// Build assembles the case for a session. It reads only the typed fields of the evidence:
// rule (through the vocabulary), severity, score, integrity flag, source and match.
func Build(p *Pseudonymiser, in Input) *Case {
	c := &Case{
		Schema:  CaseSchema,
		Subject: p.Player(in.TenantID, in.PlayerHash),
		Session: p.Session(in.TenantID, in.SessionID),
		Trust:   trustWord[min(in.TrustLevel, 3)],
		Refs:    map[string][]int64{},
	}
	if in.Scored {
		m := &CaseModel{Score: int(math.Round(100 * math.Max(0, math.Min(1, in.Score)))), Band: "clear"}
		if in.Band == store.OracleBandWatch || in.Band == store.OracleBandReview {
			m.Band = in.Band
		}
		for _, s := range in.Signals {
			if len(m.Signals) == maxCaseSignals {
				break
			}
			if !in.SignalKeys[s.Key] || !families[s.Family] || s.Effect == 0 || math.IsNaN(s.Effect) {
				continue
			}
			eff := "raises"
			if s.Effect < 0 {
				eff = "lowers"
			}
			m.Signals = append(m.Signals, CaseSignal{Signal: s.Key, Family: s.Family, Effect: eff, Strength: strength(s.Effect)})
		}
		c.Model = m
	}

	type key struct {
		rule, source, match string
		sev                 int
		tamper              bool
	}
	type group struct {
		key
		score float64
		count int
		ids   []int64
	}
	groups := map[key]*group{}
	var order []*group
	for i := range in.Evidence {
		e := &in.Evidence[i]
		if e.Bot {
			continue
		}
		if e.Severity <= 0 {
			c.Notes++
			continue
		}
		rule := e.Rule
		if _, ok := ruleFamily[rule]; !ok {
			rule = "other"
		}
		src, ok := sourceWord[e.Source]
		if !ok {
			src = "other"
		}
		k := key{rule, src, e.MatchID, min(e.Severity, 4), e.Integrity}
		g := groups[k]
		if g == nil {
			g = &group{key: k}
			groups[k] = g
			order = append(order, g)
		}
		g.score = math.Max(g.score, e.Score)
		g.count++
		if len(g.ids) < 8 {
			g.ids = append(g.ids, e.ID)
		}
	}
	// Strongest first; the order evidence arrived in breaks ties, so a case is the same
	// every time it is built from the same rows.
	sort.SliceStable(order, func(i, j int) bool {
		if order[i].sev != order[j].sev {
			return order[i].sev > order[j].sev
		}
		return order[i].score > order[j].score
	})
	if len(order) > maxCaseEvidence {
		c.Omitted = len(order) - maxCaseEvidence
		order = order[:maxCaseEvidence]
	}
	matches := map[string]string{}
	c.Evidence = make([]CaseEvidence, 0, len(order))
	for i, g := range order {
		id := "E" + strconv.Itoa(i+1)
		fam := ruleFamily[g.rule]
		if fam == "" {
			fam = FamilyOther
		}
		ev := CaseEvidence{ID: id, Rule: g.rule, Family: fam, Severity: severityWord[g.sev],
			Confidence: int(math.Round(100 * math.Max(0, math.Min(1, g.score)))), Tamper: g.tamper, Source: g.source, Count: g.count}
		if g.match != "" {
			m, ok := matches[g.match]
			if !ok {
				m = "M" + strconv.Itoa(len(matches)+1)
				matches[g.match] = m
			}
			ev.Match = m
		}
		c.Evidence = append(c.Evidence, ev)
		c.Refs[id] = g.ids
	}
	return c
}

var word = regexp.MustCompile(`^(?:[a-z][a-z_]{0,39}|[EM][0-9]{1,3}|[PS]-[0-9a-f]{10})$`)

// CheckVocabulary walks the case as it will be sent and fails on any string that is not
// a pseudonym, an id or a lower-case vocabulary word. It is the last gate before a case
// leaves this package: a field added later that carried free text would stop here.
func (c *Case) CheckVocabulary() error {
	var v any
	if err := json.Unmarshal(c.JSON(), &v); err != nil {
		return err
	}
	var walk func(v any) error
	walk = func(v any) error {
		switch x := v.(type) {
		case string:
			if !word.MatchString(x) {
				return errors.New("case file holds a string outside the vocabulary")
			}
		case []any:
			for _, e := range x {
				if err := walk(e); err != nil {
					return err
				}
			}
		case map[string]any:
			for _, e := range x {
				if err := walk(e); err != nil {
					return err
				}
			}
		}
		return nil
	}
	return walk(v)
}

// JSON is the case as the model sees it.
func (c *Case) JSON() []byte {
	b, _ := json.Marshal(c)
	return b
}

// Hash names a case together with what it would be judged by, so a verdict is reused
// exactly as long as neither the case nor the judge changed.
func (c *Case) Hash(promptVersion, provider, model string) string {
	h := sha256.New()
	for _, s := range []string{promptVersion, provider, model} {
		h.Write([]byte(s))
		h.Write([]byte{0})
	}
	h.Write(c.JSON())
	return hex.EncodeToString(h.Sum(nil)[:16])
}

// HasID reports whether the case lists evidence under id.
func (c *Case) HasID(id string) bool {
	for i := range c.Evidence {
		if c.Evidence[i].ID == id {
			return true
		}
	}
	return false
}
