// Package oracle is the Carthago Oracle: the gateway's own detection engine on top of the
// rules. It has two parts.
//
// The behaviour model scores every session from numbers the gateway already holds: aim,
// reaction and input statistics of the matches the session played, the information-leak
// and decoy scores, client integrity evidence and the trust level. It is a learned additive
// model evaluated in plain Go, so each score comes with the signals that produced it.
//
// The analyst (package analyst) reads the case of a session that the rules or the model
// flagged and writes a structured opinion for a human reviewer.
//
// The engine is advisory by construction. It holds no reference to the session manager,
// writes no evidence and has no code path to a kick, a ban or a client notice: it stores a
// score and an opinion, which the dashboard shows next to the hard evidence.
//
// Everything that makes a deployment's engine its own lives in a bundle directory on the
// gateway host (bundle.go): the model file, the thresholds and the analyst's prompts. The
// gateway reads the bundle at start and serves none of it.
package oracle

import (
	"encoding/json"
	"math"
	"math/bits"

	"carthago/backend/internal/pipeline"
	"carthago/backend/internal/store"
)

// FeatureVersion names the feature definitions in this file. A model file records the
// version it was trained on and is refused by an engine with another one.
const FeatureVersion = 1

// Feature indices. The first NumGameplay come from a match, the rest from the session.
const (
	FAimSnapRate = iota
	FHeadshotZ
	FReactionMs
	FReactionLobbyZ
	FCommandRatio
	FTriggerCV
	FLeakRatio
	FDecoyRatio
	FIntegrityRisk
	FIntegritySeverity
	FClockEvidence
	FInjectedRatio
	FClientFindings
	FScannerGaps
	FTrustLevel
	NumFeatures
)

// NumGameplay is the number of leading features that describe a match.
const NumGameplay = FIntegrityRisk

// Feature describes one input of the behaviour model.
type Feature struct {
	Key string
	// Label is what a reviewer sees for this signal on the dashboard.
	Label string
	// Direction constrains the model: +1 means a larger value can only raise the score,
	// -1 that it can only lower it. A model is trained and checked against this, so a
	// player cannot lower a score by producing more of a suspicious signal.
	Direction int
	// Family groups signals for the analyst's case file.
	Family string
}

var Features = [NumFeatures]Feature{
	FAimSnapRate:       {"aim_snap_rate", "Aim snaps", +1, "aim"},
	FHeadshotZ:         {"headshot_excess", "Headshot rate against rating", +1, "aim"},
	FReactionMs:        {"reaction_time", "Reaction time", -1, "aim"},
	FReactionLobbyZ:    {"reaction_vs_lobby", "Reaction time against the lobby", -1, "aim"},
	FCommandRatio:      {"command_rate", "Command rate", +1, "speed_time"},
	FTriggerCV:         {"trigger_rhythm", "Trigger rhythm", -1, "input"},
	FLeakRatio:         {"information_leak", "Information leak score", +1, "information"},
	FDecoyRatio:        {"decoy_reaction", "Decoy reaction score", +1, "information"},
	FIntegrityRisk:     {"integrity_findings", "Client integrity findings", +1, "tampering"},
	FIntegritySeverity: {"integrity_severity", "Worst integrity finding", +1, "tampering"},
	FClockEvidence:     {"clock_evidence", "Clock divergence", +1, "speed_time"},
	FInjectedRatio:     {"injected_input", "Injected mouse input", +1, "input"},
	FClientFindings:    {"client_findings", "Other client findings", +1, "environment"},
	FScannerGaps:       {"scanner_gaps", "Scanner gaps", +1, "scanner_health"},
	FTrustLevel:        {"trust_level", "Trust level", -1, "trust"},
}

// Vector is one session's feature values. NaN means the value is unknown (the session
// played no match, or too little of one for the statistic to mean anything).
type Vector [NumFeatures]float64

// Missing returns a vector with every value unknown.
func Missing() Vector {
	var v Vector
	for i := range v {
		v[i] = math.NaN()
	}
	return v
}

// MarshalJSON writes the known values by key, so a stored vector stays readable when
// features are added.
func (v Vector) MarshalJSON() ([]byte, error) {
	m := map[string]float64{}
	for i, x := range v {
		if !math.IsNaN(x) && !math.IsInf(x, 0) {
			m[Features[i].Key] = x
		}
	}
	return json.Marshal(m)
}

func (v *Vector) UnmarshalJSON(b []byte) error {
	m := map[string]float64{}
	if err := json.Unmarshal(b, &m); err != nil {
		return err
	}
	*v = Missing()
	for i := range v {
		if x, ok := m[Features[i].Key]; ok {
			v[i] = x
		}
	}
	return nil
}

// Minimum amounts of data before a match statistic is used.
const (
	minAimSeconds   = 30
	minHits         = 10
	minReactions    = 5
	minCommandTicks = 320
	minPresses      = 16
	minMouseEvents  = 400
)

// GameplayFeatures fills the match part of a vector from one player's finished match.
func GameplayFeatures(v *Vector, p *pipeline.MatchPlayer) {
	s := &p.Stats
	if rate := s.TickRate; rate > 0 {
		if secs := float64(s.AimSamples) / rate; secs >= minAimSeconds {
			v[FAimSnapRate] = float64(s.SnapLocks) / (secs / 60)
		}
	}
	if s.Hits >= minHits {
		v[FHeadshotZ] = s.HeadshotZ
	}
	if s.Reactions >= minReactions {
		v[FReactionMs] = s.ReactionMedianMs
		if s.LobbyOK {
			v[FReactionLobbyZ] = s.ReactionZ
		}
	}
	if s.CmdTicks >= minCommandTicks {
		v[FCommandRatio] = float64(s.Cmds) / float64(s.CmdTicks)
	}
	if s.TriggerOK && s.TriggerPresses >= minPresses {
		v[FTriggerCV] = s.TriggerCV
	}
	if k := p.Leak; k.Scored && k.Threshold > 0 {
		v[FLeakRatio] = k.Score / k.Threshold
	}
	if k := p.Decoy; k.Scored && k.Threshold > 0 {
		v[FDecoyRatio] = k.Score / k.Threshold
	}
}

// Rules whose evidence describes the scanner's health rather than the player's machine.
var scannerRules = map[string]bool{"scanner_stalled": true, "scan_quarantined": true, "scan_coverage": true, "evidence_flood": true}

// Rules about a client clock that disagrees with the kernel's or the gateway's.
var clockRules = map[string]bool{"time_source_divergence": true, "clock_drift": true}

// ClientFeatures fills the session part of a vector: the client's evidence (gameplay
// evidence is ignored here, the match statistics already carry it), its latest scanner
// telemetry and its trust level. telemetry may be nil.
func ClientFeatures(v *Vector, trust uint32, evidence []store.Evidence, telemetry *store.Telemetry) {
	var risk, other, gaps float64
	maxSev, clock := 0, 0.0
	for i := range evidence {
		e := &evidence[i]
		if e.Source != store.SourceClient || e.Severity <= 0 {
			continue
		}
		w := store.RiskWeight[min(e.Severity, len(store.RiskWeight)-1)] * e.Score
		switch {
		case clockRules[e.Rule]:
			clock = 1
			if e.Integrity {
				risk += w
				maxSev = max(maxSev, e.Severity)
			}
		case scannerRules[e.Rule]:
			gaps++
		case e.Integrity:
			risk += w
			maxSev = max(maxSev, e.Severity)
		case e.Rule == "injected_input":
			// Carried by the injected-input share itself.
		default:
			other += w
		}
	}
	v[FIntegrityRisk], v[FIntegritySeverity], v[FClockEvidence], v[FClientFindings] = risk, float64(maxSev), clock, other
	if telemetry != nil {
		gaps += float64(bits.OnesCount64(telemetry.MitigationsFailed))
		if telemetry.MouseEvents >= minMouseEvents {
			v[FInjectedRatio] = float64(telemetry.InjectedEvents) / float64(telemetry.MouseEvents)
		}
	}
	v[FScannerGaps] = gaps
	v[FTrustLevel] = float64(min(trust, 3))
}
