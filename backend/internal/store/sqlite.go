package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"

	_ "modernc.org/sqlite" // pure Go, no cgo

	"sentinel/backend/migrations"
)

type SQLite struct {
	db *sql.DB
}

// OpenSQLite opens (creating if needed) a database file and applies the schema.
func OpenSQLite(path string) (*SQLite, error) {
	db, err := sql.Open("sqlite", "file:"+path+"?_pragma=busy_timeout(5000)&_pragma=journal_mode(WAL)&_pragma=foreign_keys(1)")
	if err != nil {
		return nil, err
	}
	db.SetMaxOpenConns(1)
	if err := migrate(db); err != nil {
		db.Close()
		return nil, fmt.Errorf("apply schema: %w", err)
	}
	return &SQLite{db: db}, nil
}

// migrate applies the migrations newer than PRAGMA user_version. Databases created before
// versioning have user_version 0 and the idempotent 0001 schema.
func migrate(db *sql.DB) error {
	var v int
	if err := db.QueryRow(`PRAGMA user_version`).Scan(&v); err != nil {
		return err
	}
	for i, m := range migrations.SQLite {
		if i < v {
			continue
		}
		tx, err := db.Begin()
		if err != nil {
			return err
		}
		if _, err := tx.Exec(m); err != nil {
			tx.Rollback()
			return fmt.Errorf("migration %d: %w", i+1, err)
		}
		if _, err := tx.Exec(fmt.Sprintf(`PRAGMA user_version = %d`, i+1)); err != nil {
			tx.Rollback()
			return err
		}
		if err := tx.Commit(); err != nil {
			return err
		}
	}
	return nil
}

func ms(t time.Time) int64 { return t.UnixMilli() }

func fromMS(v int64) time.Time { return time.UnixMilli(v).UTC() }

func (s *SQLite) GetDevice(ctx context.Context, id string) (*Device, error) {
	d := Device{DeviceID: id}
	var first, last int64
	err := s.db.QueryRowContext(ctx, `SELECT tenant_id, key_alg, public_key, ak_public, ek_public_sha256, ek_cert_matches, ek_chain, ek_chain_root, bound_via, first_seen_ms, last_seen_ms
		FROM devices WHERE device_id = ?`, id).
		Scan(&d.TenantID, &d.KeyAlg, &d.PublicKey, &d.AKPublic, &d.EKPublicSHA256, &d.EKCertMatches, &d.EKChain, &d.EKChainRoot, &d.BoundVia, &first, &last)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	d.FirstSeen, d.LastSeen = fromMS(first), fromMS(last)
	return &d, nil
}

func (s *SQLite) UpsertDevice(ctx context.Context, d *Device) error {
	_, err := s.db.ExecContext(ctx, `INSERT INTO devices (device_id, tenant_id, key_alg, public_key, ak_public, ek_public_sha256, ek_cert_matches, ek_chain, ek_chain_root, bound_via, first_seen_ms, last_seen_ms)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
		ON CONFLICT (device_id) DO UPDATE SET ak_public = excluded.ak_public, ek_public_sha256 = excluded.ek_public_sha256,
			ek_cert_matches = excluded.ek_cert_matches, ek_chain = excluded.ek_chain, ek_chain_root = excluded.ek_chain_root,
			bound_via = excluded.bound_via, last_seen_ms = excluded.last_seen_ms`,
		d.DeviceID, d.TenantID, d.KeyAlg, d.PublicKey, d.AKPublic, d.EKPublicSHA256, d.EKCertMatches, d.EKChain, d.EKChainRoot, d.BoundVia, ms(d.FirstSeen), ms(d.LastSeen))
	return err
}

func (s *SQLite) PutSession(ctx context.Context, x *Session) error {
	_, err := s.db.ExecContext(ctx, `INSERT INTO sessions (session_id, tenant_id, player_hash, device_id, trust_level, attest_flags, state, kick_reason, created_ms, expires_ms, last_heartbeat_ms, heartbeats)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
		ON CONFLICT (session_id) DO UPDATE SET state = excluded.state, kick_reason = excluded.kick_reason, expires_ms = excluded.expires_ms,
			last_heartbeat_ms = excluded.last_heartbeat_ms, heartbeats = excluded.heartbeats, trust_level = excluded.trust_level, attest_flags = excluded.attest_flags`,
		x.SessionID, x.TenantID, x.PlayerHash, x.DeviceID, x.TrustLevel, int64(x.AttestFlags), string(x.State), x.KickReason,
		ms(x.CreatedAt), ms(x.ExpiresAt), ms(x.LastHeartbeat), int64(x.Heartbeats))
	return err
}

func (s *SQLite) GetSession(ctx context.Context, id string) (*Session, error) {
	x := Session{SessionID: id}
	var flags, hb, created, expires, last int64
	var state string
	err := s.db.QueryRowContext(ctx, `SELECT tenant_id, player_hash, device_id, trust_level, attest_flags, state, kick_reason, created_ms, expires_ms, last_heartbeat_ms, heartbeats
		FROM sessions WHERE session_id = ?`, id).
		Scan(&x.TenantID, &x.PlayerHash, &x.DeviceID, &x.TrustLevel, &flags, &state, &x.KickReason, &created, &expires, &last, &hb)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	x.AttestFlags, x.Heartbeats, x.State = uint64(flags), uint64(hb), SessionState(state)
	x.CreatedAt, x.ExpiresAt, x.LastHeartbeat = fromMS(created), fromMS(expires), fromMS(last)
	return &x, nil
}

func (s *SQLite) AddAttestation(ctx context.Context, a *Attestation) error {
	_, err := s.db.ExecContext(ctx, `INSERT INTO attestations (session_id, device_id, verified_ms, quote_ok, secure_boot, hvci, test_signing, kernel_debug, boot_debug, code_integrity, ranked_policy, failures)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		a.SessionID, a.DeviceID, ms(a.VerifiedAt), a.QuoteOK, a.SecureBoot, a.HVCI, a.TestSigning, a.KernelDebug, a.BootDebug, a.CodeIntegrity, a.RankedPolicy, a.Failures)
	return err
}

func (s *SQLite) Close() error { return s.db.Close() }
