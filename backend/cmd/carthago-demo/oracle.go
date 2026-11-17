package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"time"

	pb "carthago/backend/gen/carthago/v1"
	"carthago/backend/internal/oracle"
	"carthago/backend/internal/oracle/analyst"
	"carthago/backend/internal/oracle/train"
	"carthago/backend/internal/protocol"
	"carthago/backend/internal/sim/localgw"
	"carthago/backend/internal/store"
)

// The Oracle needs a history to learn a studio's normal play from, and no demo can play
// two hundred matches while somebody watches. The history is therefore simulated with
// the Oracle's own match simulator, the one `carthago-oracle baseline` measures with:
// every simulated match runs through the real detection pipeline and feature extraction.
// The demo then keeps what a real studio would have (every honest session and a few
// cheating ones), stores them as the demo studio's past sessions with their evidence, and
// has the Oracle score them. Nothing is committed: the model is trained on the same
// simulated matches when the demo starts, into a folder that is deleted when it stops.

const (
	// sessionsPerPlayer groups the simulated sessions into players, as the baseline
	// command does.
	sessionsPerPlayer = 4
	// seed fixes the simulation, so every run of the demo tells the same story.
	seed = 1
)

// The simulated cheaters the studio of the story has among its players, by the
// simulator's profile: a loud aim cheat and a speed cheat.
var outliers = []struct{ name, profile, what string }{
	{"nour", train.AimBlatant, "a loud aim cheat"},
	{"omar", train.Speed, "a speed cheat"},
}

// prepareOracle simulates the matches and writes an Oracle bundle trained on them.
func prepareOracle(dir string, matches int) ([]train.Row, error) {
	if matches < 8 {
		return nil, errors.New("-matches is at least 8")
	}
	rows, err := train.Generate(train.Options{Matches: matches, MinSeconds: 150, MaxSeconds: 240, Seed: seed, KeepEvidence: true})
	if err != nil {
		return nil, err
	}
	tr, calib, _ := train.Split(rows)
	p := train.DefaultParams()
	m, err := train.Fit(tr, p)
	if err != nil {
		return nil, err
	}
	m.Training = oracle.Training{Tool: "carthago-demo", Data: "synthetic (knowledge/synth with behaviour profiles)", Seed: seed,
		Matches: matches, MatchSeconds: 240, Rows: len(tr), Rounds: p.Rounds, LearningRate: p.LearningRate}
	data, err := m.Encode()
	if err != nil {
		return nil, err
	}
	pr := analyst.DefaultPrompts()
	_, err = oracle.WriteBundle(dir, oracle.Contents{Model: data, Thresholds: train.Thresholds(m, calib, 0.05, 0.005), PromptVersion: pr.Version,
		SchemaVersion: analyst.VerdictSchema, SystemPrompt: pr.System, CasePrompt: pr.Case})
	return rows, err
}

var syllables = []string{"ka", "ri", "mo", "ta", "le", "su", "ne", "do", "fa", "zi", "bo", "hu", "ya", "me", "sa", "ti"}

// handle is a made-up account name for honest player i.
func handle(i int) string {
	i = i*37 + 11
	return syllables[i%16] + syllables[i/16%16] + syllables[(i/256+i)%16]
}

func attestFlags(trust uint32) uint64 {
	var f uint64
	if trust >= protocol.TrustTPMKey {
		f |= protocol.FlagTPMDeviceKey
	}
	if trust >= protocol.TrustAttested {
		f |= protocol.FlagDeviceKeyCertified | protocol.FlagAKBoundToEK | protocol.FlagQuoteVerified | protocol.FlagEKCertMatches | protocol.FlagEKChainVerified
	}
	if trust >= protocol.TrustRankedBoot {
		f |= protocol.FlagSecureBoot | protocol.FlagHVCI | protocol.FlagTestSigningOff | protocol.FlagKernelDebugOff | protocol.FlagBootDebugOff | protocol.FlagCodeIntegrity
	}
	return f
}

// importHistory stores the simulated sessions as the demo studio's past sessions and has
// the Oracle score them. It returns how many sessions and players it stored.
func (s *story) importHistory() (sessions, players int, err error) {
	st, now := s.gw.Store, time.Now()
	simStart := time.Unix(1_800_000_000, 0).UTC()
	want := map[string]string{}
	for _, o := range outliers {
		want[o.profile] = o.name
	}
	// Players: the next few sessions of one profile, as in the baseline command.
	count, honest := map[string]int{}, 0
	named := map[string]bool{}
	for i := range s.history {
		r := &s.history[i]
		var name string
		switch {
		case !r.Cheating:
			name = handle(honest / sessionsPerPlayer)
			honest++
		case r.InMatch && want[r.Profile] != "" && count[r.Profile] < sessionsPerPlayer:
			name = want[r.Profile]
			count[r.Profile]++
		default:
			// The studio of the story has few cheaters. The simulator makes many, to train on.
			continue
		}
		named[name] = true
		// Matches are spread over the last days, the newest two hours ago.
		at := now.Add(-2*time.Hour - time.Duration(r.Match)*170*time.Minute)
		sess := r.Session
		sess.TenantID, sess.PlayerHash, sess.DeviceID = localgw.Tenant, name, "demo-history-"+name
		sess.AttestFlags, sess.State = attestFlags(sess.TrustLevel), store.SessionClosed
		sess.CreatedAt, sess.ExpiresAt, sess.LastHeartbeat, sess.Heartbeats = at, at.Add(15*time.Minute), at.Add(4*time.Minute), 16
		alg := pb.DeviceKeyAlg_DEVICE_KEY_ALG_ED25519_SOFTWARE
		if sess.TrustLevel >= protocol.TrustTPMKey {
			alg = pb.DeviceKeyAlg_DEVICE_KEY_ALG_ECDSA_P256_TPM
		}
		if err := st.UpsertDevice(s.ctx, &store.Device{DeviceID: sess.DeviceID, TenantID: localgw.Tenant, KeyAlg: int32(alg), PublicKey: []byte{0}, FirstSeen: at, LastSeen: at}); err != nil {
			return 0, 0, err
		}
		if err := st.PutSession(s.ctx, &sess); err != nil {
			return 0, 0, err
		}
		evidence := make([]store.Evidence, len(r.Evidence))
		for j, e := range r.Evidence {
			e.ID, e.TenantID, e.PlayerHash = 0, localgw.Tenant, name
			e.ObservedAt = at.Add(e.ObservedAt.Sub(simStart))
			evidence[j] = e
		}
		if len(evidence) > 0 {
			if err := st.AddEvidence(s.ctx, evidence); err != nil {
				return 0, 0, err
			}
		}
		matchID := ""
		if r.InMatch {
			matchID = fmt.Sprintf("syn-%d", r.Match)
		}
		if err := st.PutOracleScore(s.ctx, s.gw.Bundle.ScoreRow(sess, r.Vector, matchID, at.Add(4*time.Minute))); err != nil {
			return 0, 0, err
		}
		if r.Cheating {
			// The engine takes the session up from what is stored, as after a restart,
			// and its analyst writes an opinion on the case.
			s.gw.Oracle.SessionActivity(sess, true, at.Add(4*time.Minute))
		}
		sessions++
	}
	s.gw.Oracle.Flush(s.ctx)
	return sessions, len(named), nil
}

func (s *story) oracle() error {
	sessions, players, err := s.importHistory()
	if err != nil {
		return err
	}
	// The baseline, computed as the dashboard computes it: from the score rows the
	// Oracle stored for this studio, with no labels.
	rows, err := s.gw.Store.ListOracleScores(s.ctx, localgw.Tenant, store.OracleFilter{Limit: store.OracleScoreLimit})
	if err != nil {
		return err
	}
	var samples []oracle.BaselineSample
	for i := range rows {
		var v oracle.Vector
		if rows[i].FeatureVersion == oracle.FeatureVersion && json.Unmarshal([]byte(rows[i].Features), &v) == nil {
			samples = append(samples, oracle.BaselineSample{PlayerHash: rows[i].PlayerHash, Vector: v, At: rows[i].UpdatedAt})
		}
	}
	base := oracle.LearnBaseline(samples)
	s.say("The studio's history: %d past sessions of %d players, from the Oracle's own match simulator, scored by", sessions, players)
	s.say("the Oracle. Two of the players cheat: nour with %s, omar with %s. Nobody told the Oracle.", outliers[0].what, outliers[1].what)
	if !base.Ready {
		return fmt.Errorf("the baseline is still learning: %d of %d sessions with gameplay (run with more -matches)", base.Sessions, oracle.BaselineMinSessions)
	}
	type scored struct {
		name string
		p    oracle.PlayerBaseline
	}
	var out []scored
	for name, p := range base.Players(samples, time.Now()) {
		if p.Band != oracle.BaselineNormal {
			out = append(out, scored{name, p})
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].p.Distance > out[j].p.Distance })
	cheats := map[string]bool{}
	for _, o := range outliers {
		cheats[o.name] = true
	}
	found, wrong := 0, 0
	for _, o := range out {
		s.outside = append(s.outside, o.name)
		if cheats[o.name] {
			found++
		} else {
			wrong++
		}
	}
	s.say("From %d sessions with gameplay it learned what is normal for this studio, with no labels.", base.Sessions)
	for _, o := range out {
		band := "outside normal"
		if o.p.Band == oracle.BaselineFar {
			band = "far outside"
		}
		signal := ""
		if len(o.p.Signals) > 0 {
			signal = ", most in: " + o.p.Signals[0].Label
		}
		s.say("- %s: %s, score %d%% over %d sessions%s", o.name, band, int(100*o.p.Score+0.5), o.p.Sessions, signal)
	}
	if found != len(outliers) || wrong != 0 {
		return fmt.Errorf("outside normal: %d of the %d cheating players and %d honest ones", found, len(outliers), wrong)
	}
	// The dashboard's players list must open with them.
	first, err := s.playersListed(len(out))
	if err != nil {
		return err
	}
	for i, o := range out {
		if first[i] != o.name {
			return fmt.Errorf("the dashboard's players list starts with %v, want %s at place %d", first, o.name, i+1)
		}
	}
	verdicts, err := s.gw.Store.ListOracleVerdicts(s.ctx, localgw.Tenant, store.OracleFilter{Limit: 200})
	if err != nil {
		return err
	}
	s.say("The players list of the dashboard opens with them, the furthest first; the %d honest players follow by", players-len(outliers))
	s.say("rule risk as before. The Oracle's analyst wrote %d opinions for the reviewer. It is advice only: the Oracle", len(verdicts))
	s.say("cannot kick or ban.")
	return nil
}
