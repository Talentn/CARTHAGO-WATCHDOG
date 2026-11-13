package store

import (
	"context"
	"database/sql"
	"errors"
	"time"
)

const banCols = `id, ref, player_hash, device_id, device_tpm, reason, rule, session_id, banned_by, banned_ms, effective_ms, lifted_by, lifted_ms, lift_note`

func scanBan(tenant string, sc interface{ Scan(...any) error }) (*Ban, error) {
	b := Ban{TenantID: tenant}
	var banned, effective, lifted int64
	if err := sc.Scan(&b.ID, &b.Ref, &b.PlayerHash, &b.DeviceID, &b.DeviceTPM, &b.Reason, &b.Rule, &b.SessionID, &b.BannedBy, &banned, &effective, &b.LiftedBy, &lifted, &b.LiftNote); err != nil {
		return nil, err
	}
	b.BannedAt, b.EffectiveAt = fromMS(banned), fromMS(effective)
	if lifted != 0 {
		b.LiftedAt = fromMS(lifted)
	}
	return &b, nil
}

func (s *SQLite) AddBan(ctx context.Context, b *Ban) error {
	res, err := s.db.ExecContext(ctx, `INSERT INTO bans (tenant_id, ref, player_hash, device_id, device_tpm, reason, rule, session_id, banned_by, banned_ms, effective_ms)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		b.TenantID, b.Ref, b.PlayerHash, b.DeviceID, b.DeviceTPM, b.Reason, b.Rule, b.SessionID, b.BannedBy, ms(b.BannedAt), ms(b.EffectiveAt))
	if err != nil {
		return err
	}
	b.ID, err = res.LastInsertId()
	return err
}

func (s *SQLite) LiftBan(ctx context.Context, tenant string, id int64, by, note string, at time.Time) (*Ban, error) {
	res, err := s.db.ExecContext(ctx, `UPDATE bans SET lifted_by = ?, lifted_ms = ?, lift_note = ? WHERE tenant_id = ? AND id = ? AND lifted_ms = 0`, by, ms(at), note, tenant, id)
	if err != nil {
		return nil, err
	}
	if n, err := res.RowsAffected(); err != nil {
		return nil, err
	} else if n == 0 {
		return nil, ErrNotFound
	}
	return scanBan(tenant, s.db.QueryRowContext(ctx, `SELECT `+banCols+` FROM bans WHERE tenant_id = ? AND id = ?`, tenant, id))
}

func (s *SQLite) ListBans(ctx context.Context, tenant string, limit int) ([]Ban, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT `+banCols+` FROM bans WHERE tenant_id = ? ORDER BY id DESC LIMIT ?`, tenant, limitOr(limit, 200))
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Ban
	for rows.Next() {
		b, err := scanBan(tenant, rows)
		if err != nil {
			return nil, err
		}
		out = append(out, *b)
	}
	return out, rows.Err()
}

func (s *SQLite) StandingBan(ctx context.Context, tenant, playerHash, deviceID string) (*Ban, error) {
	b, err := scanBan(tenant, s.db.QueryRowContext(ctx, `SELECT `+banCols+` FROM bans
		WHERE tenant_id = ? AND lifted_ms = 0 AND (player_hash = ? OR (? <> '' AND device_id = ?))
		ORDER BY effective_ms, id LIMIT 1`, tenant, playerHash, deviceID, deviceID))
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	return b, err
}

func (s *SQLite) BanDelay(ctx context.Context, tenant string) (time.Duration, error) {
	var min int64
	err := s.db.QueryRowContext(ctx, `SELECT auto_delay_min FROM ban_settings WHERE tenant_id = ?`, tenant).Scan(&min)
	if errors.Is(err, sql.ErrNoRows) {
		return 0, nil
	}
	return time.Duration(min) * time.Minute, err
}

func (s *SQLite) SetBanDelay(ctx context.Context, tenant string, d time.Duration) error {
	_, err := s.db.ExecContext(ctx, `INSERT INTO ban_settings (tenant_id, auto_delay_min) VALUES (?, ?)
		ON CONFLICT (tenant_id) DO UPDATE SET auto_delay_min = excluded.auto_delay_min`, tenant, int64(clampBanDelay(d)/time.Minute))
	return err
}

func clampBanDelay(d time.Duration) time.Duration {
	return min(max(d, 0), MaxBanDelay).Truncate(time.Minute)
}
