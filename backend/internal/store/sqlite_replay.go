package store

import (
	"context"
	"database/sql"
	"errors"
	"time"
)

func (s *SQLite) PutMatchReplay(ctx context.Context, r *MatchReplay) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if _, err := tx.ExecContext(ctx, `INSERT INTO match_replays (tenant_id, match_id, started_ms, updated_ms, duration_ms, samples, truncated, data) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
		ON CONFLICT (tenant_id, match_id) DO UPDATE SET updated_ms = excluded.updated_ms, duration_ms = excluded.duration_ms, samples = excluded.samples,
			truncated = excluded.truncated, data = excluded.data`,
		r.TenantID, r.MatchID, ms(r.StartedAt), ms(r.UpdatedAt), r.DurationMs, r.Samples, r.Truncated, r.Data); err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, `DELETE FROM match_replay_players WHERE tenant_id = ? AND match_id = ?`, r.TenantID, r.MatchID); err != nil {
		return err
	}
	for _, p := range r.Players {
		if _, err := tx.ExecContext(ctx, `INSERT INTO match_replay_players (tenant_id, match_id, slot, player_hash, session_id, bot) VALUES (?, ?, ?, ?, ?, ?)`,
			r.TenantID, r.MatchID, p.Slot, p.PlayerHash, p.SessionID, p.Bot); err != nil {
			return err
		}
	}
	return tx.Commit()
}

func (s *SQLite) GetMatchReplay(ctx context.Context, tenant, matchID string) (*MatchReplay, error) {
	r := MatchReplay{TenantID: tenant, MatchID: matchID}
	var started, updated int64
	err := s.db.QueryRowContext(ctx, `SELECT started_ms, updated_ms, duration_ms, samples, truncated, data FROM match_replays WHERE tenant_id = ? AND match_id = ?`, tenant, matchID).
		Scan(&started, &updated, &r.DurationMs, &r.Samples, &r.Truncated, &r.Data)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	r.StartedAt, r.UpdatedAt = fromMS(started), fromMS(updated)
	rows, err := s.db.QueryContext(ctx, `SELECT slot, player_hash, session_id, bot FROM match_replay_players WHERE tenant_id = ? AND match_id = ? ORDER BY slot`, tenant, matchID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	for rows.Next() {
		var p ReplayPlayer
		if err := rows.Scan(&p.Slot, &p.PlayerHash, &p.SessionID, &p.Bot); err != nil {
			return nil, err
		}
		r.Players = append(r.Players, p)
	}
	return &r, rows.Err()
}

func (s *SQLite) ListMatchReplays(ctx context.Context, tenant string, f ReplayFilter) ([]MatchReplay, error) {
	q := `SELECT match_id, started_ms, updated_ms, duration_ms, samples, truncated FROM match_replays r WHERE tenant_id = ?`
	args := []any{tenant}
	if f.PlayerHash != "" {
		q += ` AND EXISTS (SELECT 1 FROM match_replay_players p WHERE p.tenant_id = r.tenant_id AND p.match_id = r.match_id AND p.player_hash = ?)`
		args = append(args, f.PlayerHash)
	}
	if f.SessionID != "" {
		q += ` AND EXISTS (SELECT 1 FROM match_replay_players p WHERE p.tenant_id = r.tenant_id AND p.match_id = r.match_id AND p.session_id = ?)`
		args = append(args, f.SessionID)
	}
	q += ` ORDER BY started_ms DESC, match_id LIMIT ?`
	args = append(args, limitOr(f.Limit, 100))
	rows, err := s.db.QueryContext(ctx, q, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []MatchReplay
	for rows.Next() {
		r := MatchReplay{TenantID: tenant}
		var started, updated int64
		if err := rows.Scan(&r.MatchID, &started, &updated, &r.DurationMs, &r.Samples, &r.Truncated); err != nil {
			return nil, err
		}
		r.StartedAt, r.UpdatedAt = fromMS(started), fromMS(updated)
		out = append(out, r)
	}
	return out, rows.Err()
}

func (s *SQLite) PruneMatchReplays(ctx context.Context, before time.Time) (int64, error) {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return 0, err
	}
	defer tx.Rollback()
	if _, err := tx.ExecContext(ctx, `DELETE FROM match_replay_players WHERE (tenant_id, match_id) IN (SELECT tenant_id, match_id FROM match_replays WHERE updated_ms < ?)`, ms(before)); err != nil {
		return 0, err
	}
	res, err := tx.ExecContext(ctx, `DELETE FROM match_replays WHERE updated_ms < ?`, ms(before))
	if err != nil {
		return 0, err
	}
	n, _ := res.RowsAffected()
	return n, tx.Commit()
}
