package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
)

const driverListCols = `session_id, player_hash, trust_level, status, reason, overflowed, test_signing, flagged, drivers, received_ms`

func scanDriverList(tenant string, row *sql.Row) (*DriverList, error) {
	d := DriverList{TenantID: tenant}
	var drivers string
	var received int64
	if err := row.Scan(&d.SessionID, &d.PlayerHash, &d.TrustLevel, &d.Status, &d.Reason, &d.Overflowed, &d.TestSigning, &d.Flagged, &drivers, &received); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, ErrNotFound
		}
		return nil, err
	}
	if err := json.Unmarshal([]byte(drivers), &d.Drivers); err != nil {
		return nil, err
	}
	d.ReceivedAt = fromMS(received)
	return &d, nil
}

func (s *SQLite) PutDriverList(ctx context.Context, d *DriverList) error {
	drivers, err := json.Marshal(append([]ListedDriver{}, d.Drivers...))
	if err != nil {
		return err
	}
	_, err = s.db.ExecContext(ctx, `INSERT OR REPLACE INTO session_drivers (tenant_id, `+driverListCols+`) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		d.TenantID, d.SessionID, d.PlayerHash, d.TrustLevel, d.Status, d.Reason, d.Overflowed, d.TestSigning, d.Flagged, string(drivers), ms(d.ReceivedAt))
	return err
}

func (s *SQLite) SessionDriverList(ctx context.Context, tenant, sessionID string) (*DriverList, error) {
	return scanDriverList(tenant, s.db.QueryRowContext(ctx, `SELECT `+driverListCols+` FROM session_drivers WHERE tenant_id = ? AND session_id = ?`, tenant, sessionID))
}

func (s *SQLite) LatestDriverList(ctx context.Context, tenant, playerHash string) (*DriverList, error) {
	return scanDriverList(tenant, s.db.QueryRowContext(ctx,
		`SELECT `+driverListCols+` FROM session_drivers WHERE tenant_id = ? AND player_hash = ? ORDER BY received_ms DESC, rowid DESC LIMIT 1`, tenant, playerHash))
}

func (s *SQLite) UnattestedPool(ctx context.Context, tenant string) (bool, error) {
	var on bool
	err := s.db.QueryRowContext(ctx, `SELECT unattested_pool FROM attestation_settings WHERE tenant_id = ?`, tenant).Scan(&on)
	if errors.Is(err, sql.ErrNoRows) {
		return false, nil
	}
	return on, err
}

func (s *SQLite) SetUnattestedPool(ctx context.Context, tenant string, on bool) error {
	_, err := s.db.ExecContext(ctx, `INSERT INTO attestation_settings (tenant_id, unattested_pool) VALUES (?, ?)
		ON CONFLICT (tenant_id) DO UPDATE SET unattested_pool = excluded.unattested_pool`, tenant, on)
	return err
}
