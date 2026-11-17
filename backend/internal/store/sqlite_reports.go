package store

import (
	"context"
	"database/sql"
	"errors"
	"time"
)

func (s *SQLite) AddPlayerReport(ctx context.Context, r *PlayerReport) (bool, error) {
	if r.State == "" {
		r.State = ReportOpen
	}
	res, err := s.db.ExecContext(ctx, `INSERT INTO player_reports (tenant_id, reporter, reported, match_id, match_ms, reason, note, state, created_ms)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?) ON CONFLICT (tenant_id, reporter, reported, match_id) DO NOTHING`,
		r.TenantID, r.Reporter, r.Reported, r.MatchID, r.MatchMs, r.Reason, r.Note, r.State, ms(r.CreatedAt))
	if err != nil {
		return false, err
	}
	if n, _ := res.RowsAffected(); n == 1 {
		r.ID, _ = res.LastInsertId()
		return true, nil
	}
	err = s.db.QueryRowContext(ctx, `SELECT id FROM player_reports WHERE tenant_id = ? AND reporter = ? AND reported = ? AND match_id = ?`,
		r.TenantID, r.Reporter, r.Reported, r.MatchID).Scan(&r.ID)
	return false, err
}

const reportColumns = `id, reporter, reported, match_id, match_ms, reason, note, state, created_ms, decided_by, decided_ms`

func scanReport(row interface{ Scan(...any) error }, tenant string) (PlayerReport, error) {
	r := PlayerReport{TenantID: tenant}
	var created, decided int64
	err := row.Scan(&r.ID, &r.Reporter, &r.Reported, &r.MatchID, &r.MatchMs, &r.Reason, &r.Note, &r.State, &created, &r.DecidedBy, &decided)
	r.CreatedAt = fromMS(created)
	if decided != 0 {
		r.DecidedAt = fromMS(decided)
	}
	return r, err
}

func (s *SQLite) GetPlayerReport(ctx context.Context, tenant string, id int64) (*PlayerReport, error) {
	r, err := scanReport(s.db.QueryRowContext(ctx, `SELECT `+reportColumns+` FROM player_reports WHERE tenant_id = ? AND id = ?`, tenant, id), tenant)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	return &r, nil
}

func reportWhere(tenant string, f ReportFilter) (string, []any) {
	q, args := ` WHERE tenant_id = ?`, []any{tenant}
	for _, c := range []struct{ col, v string }{{"state", f.State}, {"reporter", f.Reporter}, {"reported", f.Reported}, {"match_id", f.MatchID}} {
		if c.v != "" {
			q += ` AND ` + c.col + ` = ?`
			args = append(args, c.v)
		}
	}
	if !f.Since.IsZero() {
		q += ` AND created_ms >= ?`
		args = append(args, ms(f.Since))
	}
	return q, args
}

func (s *SQLite) ListPlayerReports(ctx context.Context, tenant string, f ReportFilter) ([]PlayerReport, error) {
	where, args := reportWhere(tenant, f)
	rows, err := s.db.QueryContext(ctx, `SELECT `+reportColumns+` FROM player_reports`+where+` ORDER BY created_ms DESC, id DESC LIMIT ?`, append(args, limitOr(f.Limit, 100))...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []PlayerReport
	for rows.Next() {
		r, err := scanReport(rows, tenant)
		if err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

func (s *SQLite) CountPlayerReports(ctx context.Context, tenant string, f ReportFilter) (int, error) {
	where, args := reportWhere(tenant, f)
	var n int
	err := s.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM player_reports`+where, args...).Scan(&n)
	return n, err
}

func (s *SQLite) SetPlayerReportState(ctx context.Context, tenant string, id int64, state, by string, at time.Time) error {
	res, err := s.db.ExecContext(ctx, `UPDATE player_reports SET state = ?, decided_by = ?, decided_ms = ? WHERE tenant_id = ? AND id = ?`, state, by, ms(at), tenant, id)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return ErrNotFound
	}
	return nil
}

func (s *SQLite) TallyPlayerReports(ctx context.Context, tenant string, since time.Time) (map[string]ReportTally, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT reported, COUNT(*), COUNT(DISTINCT reporter) FROM player_reports
		WHERE tenant_id = ? AND created_ms >= ? AND state <> ? GROUP BY reported`, tenant, ms(since), ReportDismissed)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := map[string]ReportTally{}
	for rows.Next() {
		var p string
		var t ReportTally
		if err := rows.Scan(&p, &t.Reports, &t.Reporters); err != nil {
			return nil, err
		}
		out[p] = t
	}
	return out, rows.Err()
}

func (s *SQLite) PrunePlayerReports(ctx context.Context, before time.Time) (int64, error) {
	res, err := s.db.ExecContext(ctx, `DELETE FROM player_reports WHERE created_ms < ?`, ms(before))
	if err != nil {
		return 0, err
	}
	return res.RowsAffected()
}
