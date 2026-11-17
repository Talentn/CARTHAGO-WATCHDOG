package store

import (
	"context"
	"database/sql"
	"errors"
	"time"
)

func (s *SQLite) AddToxicityFindings(ctx context.Context, rows []ToxicityFinding) error {
	if len(rows) == 0 {
		return nil
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	for i := range rows {
		r := &rows[i]
		res, err := tx.ExecContext(ctx, `INSERT INTO toxicity_findings (tenant_id, player_hash, session_id, match_id, slot, kind, count, match_ms, summary, bot, observed_ms)
			VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`, r.TenantID, r.PlayerHash, r.SessionID, r.MatchID, r.Slot, r.Kind, r.Count, r.MatchMs, r.Summary, r.Bot, ms(r.ObservedAt))
		if err != nil {
			return err
		}
		r.ID, _ = res.LastInsertId()
	}
	return tx.Commit()
}

func (s *SQLite) ListToxicityFindings(ctx context.Context, tenant string, f ToxicityFilter) ([]ToxicityFinding, error) {
	q := `SELECT id, player_hash, session_id, match_id, slot, kind, count, match_ms, summary, bot, observed_ms FROM toxicity_findings WHERE tenant_id = ?`
	args := []any{tenant}
	if f.PlayerHash != "" {
		q += ` AND player_hash = ?`
		args = append(args, f.PlayerHash)
	}
	if f.MatchID != "" {
		q += ` AND match_id = ?`
		args = append(args, f.MatchID)
	}
	if !f.Since.IsZero() {
		q += ` AND observed_ms >= ?`
		args = append(args, ms(f.Since))
	}
	q += ` ORDER BY observed_ms DESC, id DESC LIMIT ?`
	args = append(args, limitOr(f.Limit, 100))
	rows, err := s.db.QueryContext(ctx, q, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []ToxicityFinding
	for rows.Next() {
		r := ToxicityFinding{TenantID: tenant}
		var at int64
		if err := rows.Scan(&r.ID, &r.PlayerHash, &r.SessionID, &r.MatchID, &r.Slot, &r.Kind, &r.Count, &r.MatchMs, &r.Summary, &r.Bot, &at); err != nil {
			return nil, err
		}
		r.ObservedAt = fromMS(at)
		out = append(out, r)
	}
	return out, rows.Err()
}

func (s *SQLite) PruneToxicityFindings(ctx context.Context, before time.Time) (int64, error) {
	res, err := s.db.ExecContext(ctx, `DELETE FROM toxicity_findings WHERE observed_ms < ?`, ms(before))
	if err != nil {
		return 0, err
	}
	return res.RowsAffected()
}

func (s *SQLite) GetToxicityLimits(ctx context.Context, tenant string) (string, error) {
	var limits string
	err := s.db.QueryRowContext(ctx, `SELECT limits FROM toxicity_settings WHERE tenant_id = ?`, tenant).Scan(&limits)
	if errors.Is(err, sql.ErrNoRows) {
		return "", nil
	}
	return limits, err
}

func (s *SQLite) SetToxicityLimits(ctx context.Context, tenant, limits string, at time.Time) error {
	if limits == "" {
		_, err := s.db.ExecContext(ctx, `DELETE FROM toxicity_settings WHERE tenant_id = ?`, tenant)
		return err
	}
	_, err := s.db.ExecContext(ctx, `INSERT INTO toxicity_settings (tenant_id, limits, updated_ms) VALUES (?, ?, ?)
		ON CONFLICT (tenant_id) DO UPDATE SET limits = excluded.limits, updated_ms = excluded.updated_ms`, tenant, limits, ms(at))
	return err
}
