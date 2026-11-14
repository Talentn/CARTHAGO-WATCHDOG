package store

import (
	"context"
	"database/sql"
	"errors"
	"strings"
)

func (s *SQLite) AddEconomyEntry(ctx context.Context, e *EconomyEntry) error {
	res, err := s.db.ExecContext(ctx, `INSERT INTO economy_entries (tenant_id, event_id, player_hash, currency, amount, source, counterparty, at_ms, received_ms, dirty, dirty_from)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		e.TenantID, e.EventID, e.PlayerHash, e.Currency, e.Amount, e.Source, e.Counterparty, ms(e.At), ms(e.ReceivedAt), e.Dirty, e.DirtyFrom)
	if err != nil {
		if strings.Contains(err.Error(), "UNIQUE") {
			return ErrDuplicate
		}
		return err
	}
	e.ID, err = res.LastInsertId()
	return err
}

func (s *SQLite) ListEconomyEntries(ctx context.Context, tenant string, f EconomyFilter) ([]EconomyEntry, error) {
	q := `SELECT id, event_id, player_hash, currency, amount, source, counterparty, at_ms, received_ms, dirty, dirty_from FROM economy_entries WHERE tenant_id = ?`
	args := []any{tenant}
	add := func(cond string, v any) {
		q += " AND " + cond
		args = append(args, v)
	}
	if f.PlayerHash != "" {
		add("player_hash = ?", f.PlayerHash)
	}
	if f.Currency != "" {
		add("currency = ?", f.Currency)
	}
	if f.Counterparty != "" {
		add("counterparty = ?", f.Counterparty)
	}
	if f.DirtyFrom != "" {
		add("dirty_from = ?", f.DirtyFrom)
	}
	if f.DirtyOnly {
		q += " AND dirty > 0"
	}
	if !f.Since.IsZero() {
		add("at_ms >= ?", ms(f.Since))
	}
	if f.OldestFirst {
		q += " ORDER BY at_ms, id LIMIT ?"
	} else {
		q += " ORDER BY at_ms DESC, id DESC LIMIT ?"
	}
	rows, err := s.db.QueryContext(ctx, q, append(args, limitOr(f.Limit, 200))...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []EconomyEntry
	for rows.Next() {
		e := EconomyEntry{TenantID: tenant}
		var at, received int64
		if err := rows.Scan(&e.ID, &e.EventID, &e.PlayerHash, &e.Currency, &e.Amount, &e.Source, &e.Counterparty, &at, &received, &e.Dirty, &e.DirtyFrom); err != nil {
			return nil, err
		}
		e.At, e.ReceivedAt = fromMS(at), fromMS(received)
		out = append(out, e)
	}
	return out, rows.Err()
}

func (s *SQLite) SumEconomy(ctx context.Context, tenant, player, currency string, f EconomySum) (int64, int, error) {
	q := `SELECT COALESCE(SUM(amount), 0), COUNT(*) FROM economy_entries WHERE tenant_id = ? AND player_hash = ? AND currency = ?`
	args := []any{tenant, player, currency}
	if f.Source != "" {
		q += " AND source = ?"
		args = append(args, f.Source)
	}
	if f.CreditsOnly {
		q += " AND amount > 0"
	}
	if !f.After.IsZero() {
		q += " AND at_ms > ?"
		args = append(args, ms(f.After))
	}
	if !f.Until.IsZero() {
		q += " AND at_ms <= ?"
		args = append(args, ms(f.Until))
	}
	var sum int64
	var n int
	err := s.db.QueryRowContext(ctx, q, args...).Scan(&sum, &n)
	return sum, n, err
}

func (s *SQLite) SetEconomyDirty(ctx context.Context, tenant string, id, dirty int64, from string) error {
	_, err := s.db.ExecContext(ctx, `UPDATE economy_entries SET dirty = ?, dirty_from = ? WHERE tenant_id = ? AND id = ?`, dirty, from, tenant, id)
	return err
}

func (s *SQLite) AddEconomyFlag(ctx context.Context, f *EconomyFlag) error {
	res, err := s.db.ExecContext(ctx, `INSERT INTO economy_flags (tenant_id, player_hash, rule, certain, currency, amount, source, summary, event_id, ban_ref, at_ms)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`, f.TenantID, f.PlayerHash, f.Rule, f.Certain, f.Currency, f.Amount, f.Source, f.Summary, f.EventID, f.BanRef, ms(f.At))
	if err != nil {
		return err
	}
	f.ID, err = res.LastInsertId()
	return err
}

func (s *SQLite) ListEconomyFlags(ctx context.Context, tenant, player string, limit int) ([]EconomyFlag, error) {
	q := `SELECT id, player_hash, rule, certain, currency, amount, source, summary, event_id, ban_ref, at_ms FROM economy_flags WHERE tenant_id = ?`
	args := []any{tenant}
	if player != "" {
		q += " AND player_hash = ?"
		args = append(args, player)
	}
	rows, err := s.db.QueryContext(ctx, q+" ORDER BY id DESC LIMIT ?", append(args, limitOr(limit, 200))...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []EconomyFlag
	for rows.Next() {
		f := EconomyFlag{TenantID: tenant}
		var at int64
		if err := rows.Scan(&f.ID, &f.PlayerHash, &f.Rule, &f.Certain, &f.Currency, &f.Amount, &f.Source, &f.Summary, &f.EventID, &f.BanRef, &at); err != nil {
			return nil, err
		}
		f.At = fromMS(at)
		out = append(out, f)
	}
	return out, rows.Err()
}

func (s *SQLite) EconomyLimits(ctx context.Context, tenant string) ([]EconomyLimit, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT source, currency, per_hour, per_day FROM economy_limits WHERE tenant_id = ? ORDER BY source, currency`, tenant)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []EconomyLimit
	for rows.Next() {
		l := EconomyLimit{TenantID: tenant}
		if err := rows.Scan(&l.Source, &l.Currency, &l.PerHour, &l.PerDay); err != nil {
			return nil, err
		}
		out = append(out, l)
	}
	return out, rows.Err()
}

func (s *SQLite) SetEconomyLimit(ctx context.Context, l EconomyLimit) error {
	_, err := s.db.ExecContext(ctx, `INSERT INTO economy_limits (tenant_id, source, currency, per_hour, per_day) VALUES (?, ?, ?, ?, ?)
		ON CONFLICT (tenant_id, source, currency) DO UPDATE SET per_hour = excluded.per_hour, per_day = excluded.per_day`, l.TenantID, l.Source, l.Currency, l.PerHour, l.PerDay)
	return err
}

func (s *SQLite) RemoveEconomyLimit(ctx context.Context, tenant, source, currency string) error {
	res, err := s.db.ExecContext(ctx, `DELETE FROM economy_limits WHERE tenant_id = ? AND source = ? AND currency = ?`, tenant, source, currency)
	if err != nil {
		return err
	}
	if n, err := res.RowsAffected(); err != nil {
		return err
	} else if n == 0 {
		return ErrNotFound
	}
	return nil
}

func (s *SQLite) EconomyTolerance(ctx context.Context, tenant string) (int64, error) {
	var v int64
	err := s.db.QueryRowContext(ctx, `SELECT tolerance FROM economy_settings WHERE tenant_id = ?`, tenant).Scan(&v)
	if errors.Is(err, sql.ErrNoRows) {
		return 0, nil
	}
	return v, err
}

func (s *SQLite) SetEconomyTolerance(ctx context.Context, tenant string, tolerance int64) error {
	_, err := s.db.ExecContext(ctx, `INSERT INTO economy_settings (tenant_id, tolerance) VALUES (?, ?)
		ON CONFLICT (tenant_id) DO UPDATE SET tolerance = excluded.tolerance`, tenant, tolerance)
	return err
}
