package store

import (
	"context"
	"database/sql"
	"errors"
	"strings"
	"time"
)

const cheatCols = `id, sha256, name, note, added_by, added_ms`

func scanCheat(tenant string, sc interface{ Scan(...any) error }) (*KnownCheat, error) {
	c := KnownCheat{TenantID: tenant}
	var added int64
	if err := sc.Scan(&c.ID, &c.SHA256, &c.Name, &c.Note, &c.AddedBy, &added); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, ErrNotFound
		}
		return nil, err
	}
	c.AddedAt = fromMS(added)
	return &c, nil
}

func (s *SQLite) AddKnownCheat(ctx context.Context, c *KnownCheat) error {
	res, err := s.db.ExecContext(ctx, `INSERT INTO known_cheats (tenant_id, sha256, name, note, added_by, added_ms) VALUES (?, ?, ?, ?, ?, ?)`,
		c.TenantID, c.SHA256, c.Name, c.Note, c.AddedBy, ms(c.AddedAt))
	if err != nil {
		if strings.Contains(err.Error(), "UNIQUE") {
			return ErrDuplicate
		}
		return err
	}
	c.ID, err = res.LastInsertId()
	return err
}

func (s *SQLite) RemoveKnownCheat(ctx context.Context, tenant string, id int64) (*KnownCheat, error) {
	c, err := scanCheat(tenant, s.db.QueryRowContext(ctx, `SELECT `+cheatCols+` FROM known_cheats WHERE tenant_id = ? AND id = ?`, tenant, id))
	if err != nil {
		return nil, err
	}
	_, err = s.db.ExecContext(ctx, `DELETE FROM known_cheats WHERE tenant_id = ? AND id = ?`, tenant, id)
	return c, err
}

func (s *SQLite) ListKnownCheats(ctx context.Context, tenant string) ([]KnownCheat, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT `+cheatCols+` FROM known_cheats WHERE tenant_id = ? ORDER BY id DESC`, tenant)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []KnownCheat
	for rows.Next() {
		c, err := scanCheat(tenant, rows)
		if err != nil {
			return nil, err
		}
		out = append(out, *c)
	}
	return out, rows.Err()
}

func (s *SQLite) KnownCheat(ctx context.Context, tenant, sha256 string) (*KnownCheat, error) {
	return scanCheat(tenant, s.db.QueryRowContext(ctx, `SELECT `+cheatCols+` FROM known_cheats WHERE tenant_id = ? AND sha256 = ?`, tenant, sha256))
}

func (s *SQLite) ListModuleSightings(ctx context.Context, tenant string) ([]ModuleSighting, error) {
	// The end of b is enough for the signature state and the path class, and leaves out
	// what differs from one session to the next.
	rows, err := s.db.QueryContext(ctx, `SELECT json_extract(raw, '$.sha256'), COALESCE(json_extract(raw, '$.detail'), ''), substr(COALESCE(json_extract(raw, '$.b'), ''), -4),
			player_hash, COUNT(DISTINCT session_id), MAX(observed_ms)
		FROM evidence
		WHERE tenant_id = ? AND source = ? AND raw LIKE '%"sha256"%' AND json_valid(raw) AND json_extract(raw, '$.code') = ?
		GROUP BY 1, 2, 3, 4`, tenant, SourceClient, moduleSignatureCode)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []ModuleSighting
	for rows.Next() {
		var m ModuleSighting
		var sum, bits string
		var seen int64
		if err := rows.Scan(&sum, &m.Module, &bits, &m.PlayerHash, &m.Sessions, &seen); err != nil {
			return nil, err
		}
		var ok bool
		if m.SHA256, ok = CleanSHA256(sum); !ok {
			continue
		}
		m.Signature, m.PathClass = moduleBits(bits)
		m.LastSeen = fromMS(seen)
		out = append(out, m)
	}
	return out, rows.Err()
}

func (s *SQLite) CheatProposalAccounts(ctx context.Context, tenant string) (int, error) {
	n := DefaultProposalAccounts
	err := s.db.QueryRowContext(ctx, `SELECT min_accounts FROM cheat_proposal_settings WHERE tenant_id = ?`, tenant).Scan(&n)
	if errors.Is(err, sql.ErrNoRows) {
		return DefaultProposalAccounts, nil
	}
	return n, err
}

func (s *SQLite) SetCheatProposalAccounts(ctx context.Context, tenant string, n int) error {
	_, err := s.db.ExecContext(ctx, `INSERT INTO cheat_proposal_settings (tenant_id, min_accounts) VALUES (?, ?)
		ON CONFLICT (tenant_id) DO UPDATE SET min_accounts = excluded.min_accounts`, tenant, n)
	return err
}

func (s *SQLite) DismissCheatProposal(ctx context.Context, tenant, sha256, by string, at time.Time) error {
	_, err := s.db.ExecContext(ctx, `INSERT INTO cheat_proposal_dismissals (tenant_id, sha256, dismissed_by, dismissed_ms) VALUES (?, ?, ?, ?)
		ON CONFLICT (tenant_id, sha256) DO NOTHING`, tenant, sha256, by, ms(at))
	return err
}

func (s *SQLite) DismissedCheatProposals(ctx context.Context, tenant string) (map[string]bool, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT sha256 FROM cheat_proposal_dismissals WHERE tenant_id = ?`, tenant)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := map[string]bool{}
	for rows.Next() {
		var sum string
		if err := rows.Scan(&sum); err != nil {
			return nil, err
		}
		out[sum] = true
	}
	return out, rows.Err()
}
