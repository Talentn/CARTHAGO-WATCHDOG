package store

import (
	"context"
	"database/sql"
	"errors"
	"sort"
	"strings"
	"time"
)

// Community review (internal/review): players watch the anonymised replay of a
// suspicious match and give a verdict. What is kept here is advice for the studio's
// reviewers; nothing reads it to ban, to pool or to teach the Oracle.

// ReviewSettings is a studio's switch and thresholds. A studio without a row has the
// defaults, with the feature off.
type ReviewSettings struct {
	Enabled bool
	// Quorum is how many verdicts close a case.
	Quorum int
	// Agreement is the weighted share of the verdicts the leading answer needs for the
	// case to close as decided; below it the case closes as undecided.
	Agreement float64
	// ReportWeight is the summed weight of the reporters of one player in one match from
	// which the reports make a case.
	ReportWeight float64
}

// DefaultReviewSettings is what a studio has until it sets its own.
func DefaultReviewSettings() ReviewSettings {
	return ReviewSettings{Quorum: 5, Agreement: 0.7, ReportWeight: 1.0}
}

const (
	ReviewOpen      = "open"
	ReviewDecided   = "decided"
	ReviewUndecided = "undecided"

	ReviewSourceOracle      = "oracle"
	ReviewSourceReports     = "reports"
	ReviewSourceFinding     = "finding"
	ReviewSourceCalibration = "calibration"

	ReviewConfirmed = "confirmed"
	ReviewDismissed = "dismissed"

	ReviewCorrect = "correct"
	ReviewWrong   = "wrong"
)

// ReviewCase is one suspect in one recorded match, put before reviewers.
type ReviewCase struct {
	ID       int64
	TenantID string
	MatchID  string
	Suspect  string
	Source   string
	// Calibration: the answer is known (Expected) and the case never closes; it is mixed
	// in to score reviewers.
	Calibration bool
	Expected    string
	State       string
	// Verdict is what the reviewers agreed on (cheating, toxic, insufficient), Kind the
	// kind of cheating most of them named, Agreement the weighted share behind Verdict.
	Verdict   string
	Kind      string
	Agreement float64
	CreatedAt time.Time
	ClosedAt  time.Time
	// Decision is what the studio made of a decided case.
	Decision  string
	DecidedBy string
	DecidedAt time.Time
}

// ReviewAssignment is a case handed to one reviewer, with the verdict once given.
type ReviewAssignment struct {
	ID          int64
	TenantID    string
	CaseID      int64
	Reviewer    string
	Suspect     string
	Calibration bool
	AssignedAt  time.Time
	ExpiresAt   time.Time
	Verdict     string
	Weight      float64
	VotedAt     time.Time
	// Outcome is correct or wrong once the answer is known; empty until then.
	Outcome string
}

// ReviewBadge is a badge a reviewer earned. DeliveredAt is set once the studio's game
// server acknowledged it.
type ReviewBadge struct {
	Reviewer    string
	Badge       string
	EarnedAt    time.Time
	DeliveredAt time.Time
}

type ReviewCaseFilter struct {
	State string
	// Calibration: 0 for all cases, 1 for calibration cases only, -1 for the others.
	Calibration int
	Limit       int
}

type ReviewAssignmentFilter struct {
	CaseID   int64
	Reviewer string
	Limit    int
}

// ReviewStore keeps community review. Reads are tenant-scoped.
type ReviewStore interface {
	ReviewSettings(ctx context.Context, tenant string) (ReviewSettings, error)
	PutReviewSettings(ctx context.Context, tenant string, s ReviewSettings, at time.Time) error
	// AddReviewCase stores a case unless the studio already has one for that match and
	// suspect; it reports whether it was added and sets c.ID either way.
	AddReviewCase(ctx context.Context, c *ReviewCase) (bool, error)
	GetReviewCase(ctx context.Context, tenant string, id int64) (*ReviewCase, error)
	// ListReviewCases returns cases, oldest first.
	ListReviewCases(ctx context.Context, tenant string, f ReviewCaseFilter) ([]ReviewCase, error)
	// UpdateReviewCase writes a case's state, verdict and decision.
	UpdateReviewCase(ctx context.Context, c *ReviewCase) error
	// AddReviewAssignment hands a case to a reviewer; ErrConflict when that reviewer
	// already has it.
	AddReviewAssignment(ctx context.Context, a *ReviewAssignment) error
	GetReviewAssignment(ctx context.Context, tenant string, id int64) (*ReviewAssignment, error)
	// ListReviewAssignments returns assignments, oldest first.
	ListReviewAssignments(ctx context.Context, tenant string, f ReviewAssignmentFilter) ([]ReviewAssignment, error)
	// ExtendReviewAssignment moves the expiry of an assignment without a verdict.
	ExtendReviewAssignment(ctx context.Context, tenant string, id int64, expires time.Time) error
	// CastReviewVerdict records the verdict of an assignment that has none yet; false
	// when it already had one.
	CastReviewVerdict(ctx context.Context, tenant string, id int64, verdict string, weight float64, outcome string, at time.Time) (bool, error)
	// SetReviewOutcome marks a given verdict correct, wrong or (empty) not scored.
	SetReviewOutcome(ctx context.Context, tenant string, id int64, outcome string) error
	// AddReviewBadge records a badge once; false when the reviewer already had it.
	AddReviewBadge(ctx context.Context, tenant, reviewer, badge string, at time.Time) (bool, error)
	// ListReviewBadges returns badges, oldest first: of one reviewer, or of all with
	// reviewer empty; undelivered only with onlyNew.
	ListReviewBadges(ctx context.Context, tenant, reviewer string, onlyNew bool, limit int) ([]ReviewBadge, error)
	// AckReviewBadges marks a reviewer's badges delivered and returns how many were new.
	AckReviewBadges(ctx context.Context, tenant, reviewer string, badges []string, at time.Time) (int, error)
}

var (
	_ ReviewStore = (*SQLite)(nil)
	_ ReviewStore = (*Memory)(nil)
)

func timeOrZero(v int64) time.Time {
	if v == 0 {
		return time.Time{}
	}
	return fromMS(v)
}

func (s *SQLite) ReviewSettings(ctx context.Context, tenant string) (ReviewSettings, error) {
	out := DefaultReviewSettings()
	err := s.db.QueryRowContext(ctx, `SELECT enabled, quorum, agreement, report_weight FROM review_settings WHERE tenant_id = ?`, tenant).
		Scan(&out.Enabled, &out.Quorum, &out.Agreement, &out.ReportWeight)
	if errors.Is(err, sql.ErrNoRows) {
		return out, nil
	}
	return out, err
}

func (s *SQLite) PutReviewSettings(ctx context.Context, tenant string, v ReviewSettings, at time.Time) error {
	_, err := s.db.ExecContext(ctx, `INSERT INTO review_settings (tenant_id, enabled, quorum, agreement, report_weight, updated_ms) VALUES (?, ?, ?, ?, ?, ?)
		ON CONFLICT (tenant_id) DO UPDATE SET enabled = excluded.enabled, quorum = excluded.quorum, agreement = excluded.agreement,
			report_weight = excluded.report_weight, updated_ms = excluded.updated_ms`, tenant, v.Enabled, v.Quorum, v.Agreement, v.ReportWeight, ms(at))
	return err
}

func (s *SQLite) AddReviewCase(ctx context.Context, c *ReviewCase) (bool, error) {
	if c.State == "" {
		c.State = ReviewOpen
	}
	res, err := s.db.ExecContext(ctx, `INSERT INTO review_cases (tenant_id, match_id, suspect, source, calibration, expected, state, created_ms)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?) ON CONFLICT (tenant_id, match_id, suspect) DO NOTHING`,
		c.TenantID, c.MatchID, c.Suspect, c.Source, c.Calibration, c.Expected, c.State, ms(c.CreatedAt))
	if err != nil {
		return false, err
	}
	if n, _ := res.RowsAffected(); n == 1 {
		c.ID, _ = res.LastInsertId()
		return true, nil
	}
	err = s.db.QueryRowContext(ctx, `SELECT id FROM review_cases WHERE tenant_id = ? AND match_id = ? AND suspect = ?`, c.TenantID, c.MatchID, c.Suspect).Scan(&c.ID)
	return false, err
}

const reviewCaseColumns = `id, match_id, suspect, source, calibration, expected, state, verdict, kind, agreement, created_ms, closed_ms, decision, decided_by, decided_ms`

func scanReviewCase(row interface{ Scan(...any) error }, tenant string) (ReviewCase, error) {
	c := ReviewCase{TenantID: tenant}
	var created, closed, decided int64
	err := row.Scan(&c.ID, &c.MatchID, &c.Suspect, &c.Source, &c.Calibration, &c.Expected, &c.State, &c.Verdict, &c.Kind, &c.Agreement, &created, &closed, &c.Decision, &c.DecidedBy, &decided)
	c.CreatedAt, c.ClosedAt, c.DecidedAt = fromMS(created), timeOrZero(closed), timeOrZero(decided)
	return c, err
}

func (s *SQLite) GetReviewCase(ctx context.Context, tenant string, id int64) (*ReviewCase, error) {
	c, err := scanReviewCase(s.db.QueryRowContext(ctx, `SELECT `+reviewCaseColumns+` FROM review_cases WHERE tenant_id = ? AND id = ?`, tenant, id), tenant)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	return &c, nil
}

func (s *SQLite) ListReviewCases(ctx context.Context, tenant string, f ReviewCaseFilter) ([]ReviewCase, error) {
	q, args := `SELECT `+reviewCaseColumns+` FROM review_cases WHERE tenant_id = ?`, []any{tenant}
	if f.State != "" {
		q, args = q+` AND state = ?`, append(args, f.State)
	}
	if f.Calibration != 0 {
		q, args = q+` AND calibration = ?`, append(args, f.Calibration > 0)
	}
	rows, err := s.db.QueryContext(ctx, q+` ORDER BY created_ms, id LIMIT ?`, append(args, limitOr(f.Limit, 500))...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []ReviewCase
	for rows.Next() {
		c, err := scanReviewCase(rows, tenant)
		if err != nil {
			return nil, err
		}
		out = append(out, c)
	}
	return out, rows.Err()
}

func (s *SQLite) UpdateReviewCase(ctx context.Context, c *ReviewCase) error {
	res, err := s.db.ExecContext(ctx, `UPDATE review_cases SET state = ?, verdict = ?, kind = ?, agreement = ?, closed_ms = ?, decision = ?, decided_by = ?, decided_ms = ?
		WHERE tenant_id = ? AND id = ?`, c.State, c.Verdict, c.Kind, c.Agreement, msOrZero(c.ClosedAt), c.Decision, c.DecidedBy, msOrZero(c.DecidedAt), c.TenantID, c.ID)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return ErrNotFound
	}
	return nil
}

func (s *SQLite) AddReviewAssignment(ctx context.Context, a *ReviewAssignment) error {
	res, err := s.db.ExecContext(ctx, `INSERT INTO review_assignments (tenant_id, case_id, reviewer, suspect, calibration, assigned_ms, expires_ms)
		VALUES (?, ?, ?, ?, ?, ?, ?) ON CONFLICT (tenant_id, case_id, reviewer) DO NOTHING`,
		a.TenantID, a.CaseID, a.Reviewer, a.Suspect, a.Calibration, ms(a.AssignedAt), ms(a.ExpiresAt))
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return ErrConflict
	}
	a.ID, _ = res.LastInsertId()
	return nil
}

const reviewAssignmentColumns = `id, case_id, reviewer, suspect, calibration, assigned_ms, expires_ms, verdict, weight, voted_ms, outcome`

func scanReviewAssignment(row interface{ Scan(...any) error }, tenant string) (ReviewAssignment, error) {
	a := ReviewAssignment{TenantID: tenant}
	var assigned, expires, voted int64
	err := row.Scan(&a.ID, &a.CaseID, &a.Reviewer, &a.Suspect, &a.Calibration, &assigned, &expires, &a.Verdict, &a.Weight, &voted, &a.Outcome)
	a.AssignedAt, a.ExpiresAt, a.VotedAt = fromMS(assigned), fromMS(expires), timeOrZero(voted)
	return a, err
}

func (s *SQLite) GetReviewAssignment(ctx context.Context, tenant string, id int64) (*ReviewAssignment, error) {
	a, err := scanReviewAssignment(s.db.QueryRowContext(ctx, `SELECT `+reviewAssignmentColumns+` FROM review_assignments WHERE tenant_id = ? AND id = ?`, tenant, id), tenant)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	return &a, nil
}

func (s *SQLite) ListReviewAssignments(ctx context.Context, tenant string, f ReviewAssignmentFilter) ([]ReviewAssignment, error) {
	q, args := `SELECT `+reviewAssignmentColumns+` FROM review_assignments WHERE tenant_id = ?`, []any{tenant}
	if f.CaseID != 0 {
		q, args = q+` AND case_id = ?`, append(args, f.CaseID)
	}
	if f.Reviewer != "" {
		q, args = q+` AND reviewer = ?`, append(args, f.Reviewer)
	}
	rows, err := s.db.QueryContext(ctx, q+` ORDER BY assigned_ms, id LIMIT ?`, append(args, limitOr(f.Limit, 5000))...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []ReviewAssignment
	for rows.Next() {
		a, err := scanReviewAssignment(rows, tenant)
		if err != nil {
			return nil, err
		}
		out = append(out, a)
	}
	return out, rows.Err()
}

func (s *SQLite) ExtendReviewAssignment(ctx context.Context, tenant string, id int64, expires time.Time) error {
	_, err := s.db.ExecContext(ctx, `UPDATE review_assignments SET expires_ms = ? WHERE tenant_id = ? AND id = ? AND verdict = ''`, ms(expires), tenant, id)
	return err
}

func (s *SQLite) CastReviewVerdict(ctx context.Context, tenant string, id int64, verdict string, weight float64, outcome string, at time.Time) (bool, error) {
	res, err := s.db.ExecContext(ctx, `UPDATE review_assignments SET verdict = ?, weight = ?, outcome = ?, voted_ms = ? WHERE tenant_id = ? AND id = ? AND verdict = ''`,
		verdict, weight, outcome, ms(at), tenant, id)
	if err != nil {
		return false, err
	}
	n, _ := res.RowsAffected()
	return n == 1, nil
}

func (s *SQLite) SetReviewOutcome(ctx context.Context, tenant string, id int64, outcome string) error {
	_, err := s.db.ExecContext(ctx, `UPDATE review_assignments SET outcome = ? WHERE tenant_id = ? AND id = ? AND verdict <> ''`, outcome, tenant, id)
	return err
}

func (s *SQLite) AddReviewBadge(ctx context.Context, tenant, reviewer, badge string, at time.Time) (bool, error) {
	res, err := s.db.ExecContext(ctx, `INSERT INTO review_badges (tenant_id, reviewer, badge, earned_ms) VALUES (?, ?, ?, ?)
		ON CONFLICT (tenant_id, reviewer, badge) DO NOTHING`, tenant, reviewer, badge, ms(at))
	if err != nil {
		return false, err
	}
	n, _ := res.RowsAffected()
	return n == 1, nil
}

func (s *SQLite) ListReviewBadges(ctx context.Context, tenant, reviewer string, onlyNew bool, limit int) ([]ReviewBadge, error) {
	q, args := `SELECT reviewer, badge, earned_ms, delivered_ms FROM review_badges WHERE tenant_id = ?`, []any{tenant}
	if reviewer != "" {
		q, args = q+` AND reviewer = ?`, append(args, reviewer)
	}
	if onlyNew {
		q += ` AND delivered_ms = 0`
	}
	rows, err := s.db.QueryContext(ctx, q+` ORDER BY earned_ms, reviewer, badge LIMIT ?`, append(args, limitOr(limit, 500))...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []ReviewBadge
	for rows.Next() {
		var b ReviewBadge
		var earned, delivered int64
		if err := rows.Scan(&b.Reviewer, &b.Badge, &earned, &delivered); err != nil {
			return nil, err
		}
		b.EarnedAt, b.DeliveredAt = fromMS(earned), timeOrZero(delivered)
		out = append(out, b)
	}
	return out, rows.Err()
}

func (s *SQLite) AckReviewBadges(ctx context.Context, tenant, reviewer string, badges []string, at time.Time) (int, error) {
	if len(badges) == 0 {
		return 0, nil
	}
	args := []any{ms(at), tenant, reviewer}
	for _, b := range badges {
		args = append(args, b)
	}
	res, err := s.db.ExecContext(ctx, `UPDATE review_badges SET delivered_ms = ? WHERE tenant_id = ? AND reviewer = ? AND delivered_ms = 0
		AND badge IN (?`+strings.Repeat(`, ?`, len(badges)-1)+`)`, args...)
	if err != nil {
		return 0, err
	}
	n, _ := res.RowsAffected()
	return int(n), nil
}

type memReview struct {
	settings    map[string]ReviewSettings
	cases       []ReviewCase
	assignments []ReviewAssignment
	badges      []memBadge
	caseSeq     int64
	assignSeq   int64
}

type memBadge struct {
	tenant string
	ReviewBadge
}

func (m *Memory) rev() *memReview {
	if m.review == nil {
		m.review = &memReview{settings: map[string]ReviewSettings{}}
	}
	return m.review
}

func (m *Memory) ReviewSettings(_ context.Context, tenant string) (ReviewSettings, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if s, ok := m.rev().settings[tenant]; ok {
		return s, nil
	}
	return DefaultReviewSettings(), nil
}

func (m *Memory) PutReviewSettings(_ context.Context, tenant string, s ReviewSettings, _ time.Time) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.rev().settings[tenant] = s
	return nil
}

func (m *Memory) AddReviewCase(_ context.Context, c *ReviewCase) (bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	t := m.rev()
	for _, old := range t.cases {
		if old.TenantID == c.TenantID && old.MatchID == c.MatchID && old.Suspect == c.Suspect {
			c.ID = old.ID
			return false, nil
		}
	}
	if c.State == "" {
		c.State = ReviewOpen
	}
	t.caseSeq++
	c.ID = t.caseSeq
	t.cases = append(t.cases, *c)
	return true, nil
}

func (m *Memory) GetReviewCase(_ context.Context, tenant string, id int64) (*ReviewCase, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, c := range m.rev().cases {
		if c.TenantID == tenant && c.ID == id {
			return &c, nil
		}
	}
	return nil, ErrNotFound
}

func (m *Memory) ListReviewCases(_ context.Context, tenant string, f ReviewCaseFilter) ([]ReviewCase, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	var out []ReviewCase
	for _, c := range m.rev().cases {
		if c.TenantID != tenant || (f.State != "" && c.State != f.State) || (f.Calibration > 0 && !c.Calibration) || (f.Calibration < 0 && c.Calibration) {
			continue
		}
		out = append(out, c)
	}
	sort.SliceStable(out, func(i, j int) bool { return out[i].CreatedAt.Before(out[j].CreatedAt) })
	if n := limitOr(f.Limit, 500); len(out) > n {
		out = out[:n]
	}
	return out, nil
}

func (m *Memory) UpdateReviewCase(_ context.Context, c *ReviewCase) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	t := m.rev()
	for i := range t.cases {
		if old := &t.cases[i]; old.TenantID == c.TenantID && old.ID == c.ID {
			old.State, old.Verdict, old.Kind, old.Agreement, old.ClosedAt = c.State, c.Verdict, c.Kind, c.Agreement, c.ClosedAt
			old.Decision, old.DecidedBy, old.DecidedAt = c.Decision, c.DecidedBy, c.DecidedAt
			return nil
		}
	}
	return ErrNotFound
}

func (m *Memory) AddReviewAssignment(_ context.Context, a *ReviewAssignment) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	t := m.rev()
	for _, old := range t.assignments {
		if old.TenantID == a.TenantID && old.CaseID == a.CaseID && old.Reviewer == a.Reviewer {
			return ErrConflict
		}
	}
	t.assignSeq++
	a.ID = t.assignSeq
	t.assignments = append(t.assignments, *a)
	return nil
}

func (m *Memory) assignment(tenant string, id int64) *ReviewAssignment {
	t := m.rev()
	for i := range t.assignments {
		if t.assignments[i].TenantID == tenant && t.assignments[i].ID == id {
			return &t.assignments[i]
		}
	}
	return nil
}

func (m *Memory) GetReviewAssignment(_ context.Context, tenant string, id int64) (*ReviewAssignment, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if a := m.assignment(tenant, id); a != nil {
		c := *a
		return &c, nil
	}
	return nil, ErrNotFound
}

func (m *Memory) ListReviewAssignments(_ context.Context, tenant string, f ReviewAssignmentFilter) ([]ReviewAssignment, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	var out []ReviewAssignment
	for _, a := range m.rev().assignments {
		if a.TenantID != tenant || (f.CaseID != 0 && a.CaseID != f.CaseID) || (f.Reviewer != "" && a.Reviewer != f.Reviewer) {
			continue
		}
		out = append(out, a)
	}
	sort.SliceStable(out, func(i, j int) bool { return out[i].AssignedAt.Before(out[j].AssignedAt) })
	if n := limitOr(f.Limit, 5000); len(out) > n {
		out = out[:n]
	}
	return out, nil
}

func (m *Memory) ExtendReviewAssignment(_ context.Context, tenant string, id int64, expires time.Time) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if a := m.assignment(tenant, id); a != nil && a.Verdict == "" {
		a.ExpiresAt = expires
	}
	return nil
}

func (m *Memory) CastReviewVerdict(_ context.Context, tenant string, id int64, verdict string, weight float64, outcome string, at time.Time) (bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	a := m.assignment(tenant, id)
	if a == nil || a.Verdict != "" {
		return false, nil
	}
	a.Verdict, a.Weight, a.Outcome, a.VotedAt = verdict, weight, outcome, at
	return true, nil
}

func (m *Memory) SetReviewOutcome(_ context.Context, tenant string, id int64, outcome string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if a := m.assignment(tenant, id); a != nil && a.Verdict != "" {
		a.Outcome = outcome
	}
	return nil
}

func (m *Memory) AddReviewBadge(_ context.Context, tenant, reviewer, badge string, at time.Time) (bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	t := m.rev()
	for _, b := range t.badges {
		if b.tenant == tenant && b.Reviewer == reviewer && b.Badge == badge {
			return false, nil
		}
	}
	t.badges = append(t.badges, memBadge{tenant, ReviewBadge{Reviewer: reviewer, Badge: badge, EarnedAt: at}})
	return true, nil
}

func (m *Memory) ListReviewBadges(_ context.Context, tenant, reviewer string, onlyNew bool, limit int) ([]ReviewBadge, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	var out []ReviewBadge
	for _, b := range m.rev().badges {
		if b.tenant != tenant || (reviewer != "" && b.Reviewer != reviewer) || (onlyNew && !b.DeliveredAt.IsZero()) {
			continue
		}
		out = append(out, b.ReviewBadge)
	}
	sort.SliceStable(out, func(i, j int) bool { return out[i].EarnedAt.Before(out[j].EarnedAt) })
	if n := limitOr(limit, 500); len(out) > n {
		out = out[:n]
	}
	return out, nil
}

func (m *Memory) AckReviewBadges(_ context.Context, tenant, reviewer string, badges []string, at time.Time) (int, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	t, n := m.rev(), 0
	for i := range t.badges {
		b := &t.badges[i]
		if b.tenant != tenant || b.Reviewer != reviewer || !b.DeliveredAt.IsZero() {
			continue
		}
		for _, want := range badges {
			if b.Badge == want {
				b.DeliveredAt = at
				n++
			}
		}
	}
	return n, nil
}
