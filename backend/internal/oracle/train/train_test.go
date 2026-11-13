package train

import (
	"bytes"
	"encoding/json"
	"math"
	"testing"

	"carthago/backend/internal/oracle"
)

// handRows builds sessions without the simulator: cheating ones have a higher headshot
// excess and, for half of them, an integrity finding; a share of all sessions played no
// match and so has no gameplay values.
func handRows(n int, seed uint64) []Row {
	r := &rng{s: seed}
	rows := make([]Row, 0, n)
	for i := range n {
		row := Row{Match: i / 12, Profile: Honest, InMatch: i%6 != 0, Vector: oracle.Missing()}
		row.Cheating = r.chance(0.3)
		if row.Cheating {
			row.Profile = AimBlatant
		}
		v := &row.Vector
		v[oracle.FTrustLevel] = float64(r.intn(4))
		v[oracle.FIntegrityRisk], v[oracle.FIntegritySeverity], v[oracle.FClockEvidence], v[oracle.FClientFindings] = 0, 0, 0, 0
		if row.InMatch {
			v[oracle.FHeadshotZ] = r.normal()
			v[oracle.FReactionMs] = 260 + 40*r.normal()
			if row.Cheating {
				v[oracle.FHeadshotZ] += 2.5
				v[oracle.FReactionMs] -= 90
			}
		}
		if row.Cheating && (r.chance(0.5) || !row.InMatch) {
			v[oracle.FIntegrityRisk], v[oracle.FIntegritySeverity] = 6+4*r.unit(), 3
			row.RuleFlag = true
		}
		rows = append(rows, row)
	}
	return rows
}

func TestFitLearnsAMonotoneModel(t *testing.T) {
	rows := handRows(2400, 1)
	fit, calib, test := Split(rows)
	m, err := Fit(fit, DefaultParams())
	if err != nil {
		t.Fatal(err)
	}
	if err := m.Validate(); err != nil {
		t.Fatalf("the trained model fails its own checks: %v", err)
	}
	th := Thresholds(m, calib, 0.05, 0.005)
	rep := Evaluate(m, th, test)
	if rep.AUC < 0.95 {
		t.Errorf("AUC %.3f on separable data", rep.AUC)
	}
	if rep.Honest == 0 || rep.Cheating == 0 || rep.Sessions != len(test) {
		t.Fatalf("report counts: %+v", rep)
	}
	if rate := float64(rep.HonestReview) / float64(rep.Honest); rate > 0.03 {
		t.Errorf("honest sessions in review: %.3f", rate)
	}
	if rep.HonestReviewBound < float64(rep.HonestReview)/float64(rep.Honest) {
		t.Errorf("the upper bound %.4f is below the observed rate", rep.HonestReviewBound)
	}

	// More of a suspicious signal never lowers a score, and less of a protective one
	// never does either.
	base := oracle.Missing()
	for f := range base {
		base[f] = 0
	}
	base[oracle.FReactionMs], base[oracle.FTrustLevel] = 260, 2
	for f, feat := range oracle.Features {
		prev := math.Inf(-1)
		for step := 0; step <= 40; step++ {
			v := base
			x := -5 + 0.5*float64(step)
			if f == oracle.FReactionMs {
				x = 50 + 15*float64(step)
			}
			v[f] = x
			s, _ := m.Score(v)
			if feat.Direction < 0 {
				s = -s
			}
			if s < prev-1e-12 {
				t.Fatalf("%s is not monotone at %v", feat.Key, x)
			}
			prev = s
		}
	}

	// A session without a match is still scored, from its client evidence.
	clean, tampered := oracle.Missing(), oracle.Missing()
	clean[oracle.FIntegrityRisk], tampered[oracle.FIntegrityRisk] = 0, 9
	clean[oracle.FIntegritySeverity], tampered[oracle.FIntegritySeverity] = 0, 3
	a, _ := m.Score(clean)
	b, _ := m.Score(tampered)
	if !(b > a) || b < th.Review {
		t.Errorf("client-only sessions: clean %.3f, tampered %.3f, review at %.3f", a, b, th.Review)
	}
}

func TestFitIsReproducible(t *testing.T) {
	rows := handRows(1200, 2)
	a, err := Fit(rows, DefaultParams())
	if err != nil {
		t.Fatal(err)
	}
	b, _ := Fit(rows, DefaultParams())
	ea, _ := a.Encode()
	eb, _ := b.Encode()
	if !bytes.Equal(ea, eb) || oracle.ModelID(ea) != oracle.ModelID(eb) {
		t.Fatal("two fits of the same data differ")
	}
	c, _ := Fit(handRows(1200, 3), DefaultParams())
	ec, _ := c.Encode()
	if oracle.ModelID(ea) == oracle.ModelID(ec) {
		t.Fatal("different data gave the same model id")
	}
	if _, _, err := oracle.ParseModel(ea); err != nil {
		t.Fatalf("the encoded model does not load: %v", err)
	}
}

func TestFitNeedsBothClasses(t *testing.T) {
	rows := handRows(200, 4)
	for i := range rows {
		rows[i].Cheating = false
	}
	if _, err := Fit(rows, DefaultParams()); err == nil {
		t.Fatal("a model was fitted without a single cheating session")
	}
}

func TestSplitKeepsMatchesTogether(t *testing.T) {
	fit, calib, test := Split(handRows(1200, 5))
	if len(fit)+len(calib)+len(test) != 1200 || len(calib) == 0 || len(test) == 0 {
		t.Fatalf("split sizes %d %d %d", len(fit), len(calib), len(test))
	}
	where := map[int]int{}
	for part, rows := range [][]Row{fit, calib, test} {
		for _, r := range rows {
			if prev, ok := where[r.Match]; ok && prev != part {
				t.Fatalf("match %d is on both sides of the split", r.Match)
			}
			where[r.Match] = part
		}
	}
}

func TestThresholds(t *testing.T) {
	rows := handRows(2400, 6)
	fit, calib, _ := Split(rows)
	m, _ := Fit(fit, DefaultParams())
	th := Thresholds(m, calib, 0.05, 0.005)
	if th.Review < 0.5 || th.Watch > th.Review || th.Watch <= 0 || th.Review >= 1 {
		t.Fatalf("thresholds %+v", th)
	}
	honest, watch, review := 0, 0, 0
	for _, r := range calib {
		if r.Cheating {
			continue
		}
		honest++
		s, _ := m.Score(r.Vector)
		if s >= th.Watch {
			watch++
		}
		if s >= th.Review {
			review++
		}
	}
	if float64(review) > 0.005*float64(honest) || float64(watch) > 0.05*float64(honest) {
		t.Fatalf("on the sessions they were chosen on, %d and %d of %d honest sessions are at or above review and watch", review, watch, honest)
	}
	// Without honest sessions to choose on, review still means "leans towards cheating".
	if th := Thresholds(m, nil, 0.05, 0.005); th.Review < 0.5 || th.Watch > th.Review {
		t.Fatalf("thresholds without data: %+v", th)
	}
	if th.Band(th.Review) != "review" || th.Band(th.Watch) != "watch" && th.Watch < th.Review || th.Band(0) != "clear" {
		t.Fatalf("bands at the thresholds: %+v", th)
	}
}

// The simulator gives the same sessions whatever the number of workers, so a bundle can
// be rebuilt from its seed.
func TestGenerateIsDeterministic(t *testing.T) {
	if testing.Short() {
		t.Skip("simulates matches")
	}
	opt := Options{Matches: 3, MinSeconds: 60, MaxSeconds: 80, Seed: 11, KeepEvidence: true}
	sig := func(workers int, seed uint64) []byte {
		o := opt
		o.Workers, o.Seed = workers, seed
		rows, err := Generate(o)
		if err != nil {
			t.Fatal(err)
		}
		if len(rows) != 36 {
			t.Fatalf("%d sessions from 3 matches", len(rows))
		}
		type line struct {
			Match    int
			Profile  string
			Cheating bool
			InMatch  bool
			Rule     bool
			Vector   oracle.Vector
			Evidence []string
		}
		var out []line
		for _, r := range rows {
			l := line{r.Match, r.Profile, r.Cheating, r.InMatch, r.RuleFlag, r.Vector, nil}
			if r.Cheating != (r.Profile != Honest) || Truth[r.Profile] == "" {
				t.Fatalf("row labels: %+v", l)
			}
			if r.Session.TenantID != Tenant || r.Session.SessionID == "" {
				t.Fatalf("session: %+v", r.Session)
			}
			for _, e := range r.Evidence {
				l.Evidence = append(l.Evidence, e.Rule)
			}
			out = append(out, l)
		}
		b, _ := json.Marshal(out)
		return b
	}
	one := sig(1, 11)
	if !bytes.Equal(one, sig(3, 11)) {
		t.Fatal("the number of workers changed the sessions")
	}
	if bytes.Equal(one, sig(1, 12)) {
		t.Fatal("the seed does not change the sessions")
	}
}
