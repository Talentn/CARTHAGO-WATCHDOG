package store

import (
	"context"
	"database/sql"
	"errors"
	"strings"
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
