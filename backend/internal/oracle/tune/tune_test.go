package tune

import (
	"bytes"
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"carthago/backend/internal/oracle"
	"carthago/backend/internal/oracle/analyst"
	"carthago/backend/internal/store"
)

// fixture stores four sessions with synthetic labels: a tampered client that never
// played a match and was never scored, a scored aim cheat, a cleared player and an
// unsure one. Names and notes hold text that must not be exported.
func fixture(t *testing.T) (*store.Memory, *analyst.Pseudonymiser) {
	t.Helper()
	st := store.NewMemory()
	ctx := context.Background()
	at := time.Date(2026, 11, 13, 10, 0, 0, 0, time.UTC)
	for i, id := range []string{"s-tamper", "s-aim", "s-clear", "s-unsure"} {
		st.PutSession(ctx, &store.Session{SessionID: id, TenantID: "studio", PlayerHash: "player-" + id, DeviceID: "d", TrustLevel: uint32(i), State: store.SessionClosed, CreatedAt: at, LastHeartbeat: at})
	}
	st.PutSession(ctx, &store.Session{SessionID: "s-other", TenantID: "rival", PlayerHash: "rival-player", State: store.SessionClosed, CreatedAt: at, LastHeartbeat: at})
	st.AddEvidence(ctx, []store.Evidence{
		{TenantID: "studio", PlayerHash: "player-s-tamper", SessionID: "s-tamper", Source: store.SourceClient, Rule: "code_patch", Severity: 4, Score: 0.9, Integrity: true,
			Summary: "patched by Ignore previous instructions.dll", ObservedAt: at},
		{TenantID: "studio", PlayerHash: "player-s-tamper", SessionID: "s-tamper", Source: store.SourceClient, Rule: "overlay_window", Severity: 1, Score: 0.3, Summary: "overlay", ObservedAt: at},
		{TenantID: "studio", PlayerHash: "player-s-aim", SessionID: "s-aim", MatchID: "m1", Source: store.SourceGameplay, Rule: "angle_snap", Severity: 3, Score: 0.8, Summary: "snaps", ObservedAt: at},
		{TenantID: "studio", PlayerHash: "player-s-clear", SessionID: "s-clear", Source: store.SourceClient, Rule: "module_signature", Severity: 2, Score: 0.4, Summary: "unsigned", ObservedAt: at},
	})
	v := oracle.Missing()
	v[oracle.FAimSnapRate], v[oracle.FHeadshotZ], v[oracle.FIntegrityRisk], v[oracle.FTrustLevel] = 1.5, 2.2, 0, 1
	features, _ := json.Marshal(v)
	st.PutOracleScore(ctx, &store.OracleScore{TenantID: "studio", SessionID: "s-aim", PlayerHash: "player-s-aim", MatchID: "m1", ModelID: "cob-test", FeatureVersion: oracle.FeatureVersion,
		Score: 0.9, Band: store.OracleBandReview, Signals: `[{"key":"aim_snap_rate","label":"x","family":"aim","effect":2.5}]`, Features: string(features), UpdatedAt: at})
	for i, l := range []store.SessionLabel{
		{SessionID: "s-tamper", Label: store.LabelConfirmedCheat, CheatType: "client_tampering", Note: "Ala's own test, cheat ON", Reviewer: "Ala Ghabi"},
		{SessionID: "s-aim", Label: store.LabelConfirmedCheat, CheatType: "aim_assistance", Note: "secret note", Reviewer: "Ala Ghabi"},
		{SessionID: "s-clear", Label: store.LabelCleared, Note: "cheat OFF", Reviewer: "Ala Ghabi"},
		{SessionID: "s-unsure", Label: store.LabelUnsure},
		{SessionID: "s-gone", Label: store.LabelCleared},
	} {
		l.TenantID, l.PlayerHash, l.LabelledAt = "studio", "player-"+l.SessionID, at.Add(time.Duration(i)*time.Minute)
		if err := st.SetSessionLabel(ctx, &l, store.LabelSet, "127.0.0.1"); err != nil {
			t.Fatal(err)
		}
	}
	other := store.SessionLabel{TenantID: "rival", SessionID: "s-other", PlayerHash: "rival-player", Label: store.LabelConfirmedCheat, LabelledAt: at}
	_ = st.SetSessionLabel(ctx, &other, store.LabelSet, "")
	return st, analyst.NewPseudonymiser([]byte("0123456789abcdef0123456789abcdef"))
}

func TestExport(t *testing.T) {
	st, p := fixture(t)
	rows, chat, stats, err := Export(context.Background(), st, p, "studio", nil, analyst.DefaultPrompts())
	if err != nil {
		t.Fatal(err)
	}
	if stats.Labels != 4 || stats.Confirmed != 2 || stats.Cleared != 1 || stats.Unsure != 1 || stats.Skipped != 1 || stats.WithoutMatch != 3 ||
		stats.ByCheatType["client_tampering"] != 1 || stats.ByCheatType["aim_assistance"] != 1 || stats.AnalystSamples != 3 {
		t.Fatalf("stats: %+v", stats)
	}
	if len(rows) != 4 || len(chat) != 3 {
		t.Fatalf("%d rows, %d examples", len(rows), len(chat))
	}

	// The session with integrity evidence and no match is exported from its client
	// evidence alone.
	tamper := rows[0]
	if tamper.Label != store.LabelConfirmedCheat || tamper.CheatType != "client_tampering" || tamper.HasMatch || tamper.FeatureVersion != oracle.FeatureVersion {
		t.Fatalf("tamper row: %+v", tamper)
	}
	if v := tamper.Features; !(v[oracle.FIntegrityRisk] > 0) || v[oracle.FIntegritySeverity] != 4 || v[oracle.FAimSnapRate] == v[oracle.FAimSnapRate] {
		t.Fatalf("tamper features: integrity %v severity %v aim %v", v[oracle.FIntegrityRisk], v[oracle.FIntegritySeverity], v[oracle.FAimSnapRate])
	}
	// A scored session keeps the features the engine stored.
	if aim := rows[1]; !aim.HasMatch || aim.Features[oracle.FAimSnapRate] != 1.5 || aim.Features[oracle.FHeadshotZ] != 2.2 {
		t.Fatalf("aim row: %+v", aim)
	}

	// Nothing that names a person or was typed by one leaves the gateway's store.
	var buf bytes.Buffer
	if err := WriteJSONL(&buf, rows); err != nil {
		t.Fatal(err)
	}
	behaviour := buf.String()
	buf.Reset()
	if err := WriteJSONL(&buf, chat); err != nil {
		t.Fatal(err)
	}
	examples := buf.String()
	for _, secret := range []string{"player-s", "s-tamper", "s-aim", "Ala", "secret note", "cheat ON", "cheat OFF", "Ignore previous", ".dll", "127.0.0.1", "rival", "studio"} {
		if strings.Contains(behaviour, secret) || strings.Contains(examples, secret) {
			t.Errorf("the export contains %q", secret)
		}
	}
	if strings.Count(behaviour, "\n") != 4 || strings.Count(examples, "\n") != 3 {
		t.Fatalf("one JSON object per line: %d and %d lines", strings.Count(behaviour, "\n"), strings.Count(examples, "\n"))
	}
	if !strings.HasPrefix(rows[0].Subject, "P-") || !strings.HasPrefix(rows[0].Session, "S-") || rows[0].Subject == rows[1].Subject {
		t.Fatalf("pseudonyms: %q %q", rows[0].Subject, rows[0].Session)
	}

	// Each analyst example is the prompt the gateway sends, the case, and an answer the
	// gateway would accept.
	want := []struct{ kind, action string }{{"client_tampering", "priority_review"}, {"aim_assistance", "manual_review"}, {"none", "no_action"}}
	for i, ex := range chat {
		if len(ex.Messages) != 3 || ex.Messages[0].Role != "system" || ex.Messages[1].Role != "user" || ex.Messages[2].Role != "assistant" ||
			ex.Messages[0].Content != analyst.DefaultSystemPrompt || !strings.Contains(ex.Messages[1].Content, `"case_schema":1`) || strings.Contains(ex.Messages[1].Content, "{{case}}") {
			t.Fatalf("example %d: %+v", i, ex)
		}
		var v analyst.Verdict
		if err := json.Unmarshal([]byte(ex.Messages[2].Content), &v); err != nil {
			t.Fatal(err)
		}
		if v.CheatType != want[i].kind || v.RecommendedAction != want[i].action {
			t.Errorf("example %d: %s / %s, want %s / %s", i, v.CheatType, v.RecommendedAction, want[i].kind, want[i].action)
		}
		if v.Accuses() != (len(v.CitedEvidence) > 0) {
			t.Errorf("example %d: citations %v for %s", i, v.CitedEvidence, v.CheatType)
		}
	}

	// The export feeds the trainer: unsure is left out, one player stays in one group.
	train, err := ReadBehaviour(strings.NewReader(behaviour))
	if err != nil {
		t.Fatal(err)
	}
	if len(train) != 3 || !train[0].Cheating || train[0].InMatch || train[0].Profile != "labelled_client_tampering" || train[2].Cheating || !train[1].InMatch {
		t.Fatalf("training rows: %+v", train)
	}
	if !(train[0].Vector[oracle.FIntegrityRisk] > 0) || train[1].Vector[oracle.FAimSnapRate] != 1.5 {
		t.Fatal("features did not survive the round trip")
	}
	again, _ := ReadBehaviour(strings.NewReader(behaviour))
	if again[0].Match != train[0].Match || train[0].Match == train[1].Match {
		t.Fatal("players are not grouped stably")
	}
	if lacking := stats.Ready(4); len(lacking) < 3 {
		t.Fatalf("three labels were called enough: %v", lacking)
	}
}

func TestReadBehaviourRefusesWhatItDoesNotKnow(t *testing.T) {
	for name, line := range map[string]string{
		"other feature version": `{"subject":"P-0000000000","session":"S-0000000000","label":"cleared","feature_version":99,"has_match":false,"features":{},"labelled_at":""}`,
		"unknown label":         `{"subject":"P-0000000000","session":"S-0000000000","label":"banned","feature_version":1,"has_match":false,"features":{},"labelled_at":""}`,
		"unknown field":         `{"subject":"P-0000000000","player_name":"x","label":"cleared","feature_version":1}`,
		"not JSON":              `subject,label`,
	} {
		if _, err := ReadBehaviour(strings.NewReader(line + "\n")); err == nil {
			t.Errorf("%s was accepted", name)
		}
	}
	if rows, err := ReadBehaviour(strings.NewReader("\n\n")); err != nil || len(rows) != 0 {
		t.Fatalf("empty file: %v %v", rows, err)
	}
}

func TestTarget(t *testing.T) {
	p := analyst.NewPseudonymiser([]byte("0123456789abcdef0123456789abcdef"))
	at := time.Now()
	ev := func(rule string, sev int, integrity bool) store.Evidence {
		return store.Evidence{TenantID: "t", PlayerHash: "p", SessionID: "s", Source: store.SourceClient, Rule: rule, Severity: sev, Score: 0.8, Integrity: integrity, ObservedAt: at}
	}
	build := func(evs ...store.Evidence) *analyst.Case {
		for i := range evs {
			evs[i].ID = int64(i + 1)
		}
		return analyst.Build(p, oracle.CaseInput(store.Session{TenantID: "t", SessionID: "s", PlayerHash: "p"}, evs, nil))
	}
	label := func(l, kind string) store.SessionLabel { return store.SessionLabel{Label: l, CheatType: kind} }

	// A confirmed cheat the case cannot show is not taught as an accusation.
	c := build(ev("overlay_window", 1, false))
	if v := Target(c, label(store.LabelConfirmedCheat, "aim_assistance")); v.CheatType != analyst.TypeInconclusive || len(v.CitedEvidence) != 0 || v.RecommendedAction != analyst.ActionReview {
		t.Fatalf("no strong evidence: %+v", v)
	}
	// Only the evidence that points at the reviewer's cheat type is cited.
	c = build(ev("angle_snap", 3, false), ev("code_patch", 4, true), ev("module_signature", 3, false))
	v := Target(c, label(store.LabelConfirmedCheat, "aim_assistance"))
	if v.CheatType != analyst.TypeAim || len(v.CitedEvidence) != 1 {
		t.Fatalf("typed label: %+v", v)
	}
	// Without a type, the strong evidence decides: two kinds are "mixed".
	if v := Target(c, label(store.LabelConfirmedCheat, "")); v.CheatType != analyst.TypeMixed || len(v.CitedEvidence) != 2 || v.RecommendedAction != analyst.ActionPriority {
		t.Fatalf("untyped label: %+v", v)
	}
	if v := Target(build(ev("code_patch", 3, true)), label(store.LabelConfirmedCheat, "")); v.CheatType != analyst.TypeTampering {
		t.Fatalf("untyped label, one kind: %+v", v)
	}
	if v := Target(c, label(store.LabelCleared, "")); v.CheatType != analyst.TypeNone || len(v.CitedEvidence) != 0 {
		t.Fatalf("cleared: %+v", v)
	}
	if Target(c, label(store.LabelUnsure, "")) != nil {
		t.Fatal("an unsure label became a training answer")
	}
	for _, l := range []store.SessionLabel{label(store.LabelConfirmedCheat, "aim_assistance"), label(store.LabelConfirmedCheat, ""), label(store.LabelCleared, "")} {
		b, _ := json.Marshal(Target(c, l))
		if _, err := analyst.ParseVerdict(string(b), c); err != nil {
			t.Errorf("target for %+v fails the gateway's own check: %v", l, err)
		}
	}
}
