package store

import (
	"context"
	"database/sql"
	"errors"
	"time"
)

func (s *SQLite) PutMap(ctx context.Context, r *MapRecord) error {
	res, err := s.db.ExecContext(ctx, `INSERT INTO maps (tenant_id, map_id, version, hash, geometry, created_ms) VALUES (?, ?, ?, ?, ?, ?)
		ON CONFLICT (tenant_id, map_id, version) DO NOTHING`, r.TenantID, r.MapID, r.Version, r.Hash, r.Geometry, ms(r.CreatedAt))
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 1 {
		return nil
	}
	var hash string
	if err := s.db.QueryRowContext(ctx, `SELECT hash FROM maps WHERE tenant_id = ? AND map_id = ? AND version = ?`, r.TenantID, r.MapID, r.Version).Scan(&hash); err != nil {
		return err
	}
	if hash != r.Hash {
		return ErrMapConflict
	}
	return nil
}

func (s *SQLite) GetMap(ctx context.Context, tenant, mapID string, version uint32) (*MapRecord, error) {
	r := MapRecord{TenantID: tenant, MapID: mapID, Version: version}
	var created int64
	err := s.db.QueryRowContext(ctx, `SELECT hash, geometry, created_ms FROM maps WHERE tenant_id = ? AND map_id = ? AND version = ?`, tenant, mapID, version).
		Scan(&r.Hash, &r.Geometry, &created)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	r.CreatedAt = fromMS(created)
	return &r, nil
}

func (s *SQLite) PutGameplayBatch(ctx context.Context, b *GameplayBatchRow) error {
	_, err := s.db.ExecContext(ctx, `INSERT INTO gameplay_batches (tenant_id, match_id, batch_seq, received_ms, data) VALUES (?, ?, ?, ?, ?)
		ON CONFLICT (tenant_id, match_id, batch_seq) DO NOTHING`, b.TenantID, b.MatchID, i64(b.BatchSeq), ms(b.ReceivedAt), b.Data)
	return err
}

func (s *SQLite) ListGameplayBatches(ctx context.Context, tenant, matchID string, limit int) ([]GameplayBatchRow, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT batch_seq, received_ms, data FROM gameplay_batches WHERE tenant_id = ? AND match_id = ? ORDER BY batch_seq LIMIT ?`,
		tenant, matchID, limitOr(limit, 100000))
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []GameplayBatchRow
	for rows.Next() {
		b := GameplayBatchRow{TenantID: tenant, MatchID: matchID}
		var seq, at int64
		if err := rows.Scan(&seq, &at, &b.Data); err != nil {
			return nil, err
		}
		b.BatchSeq, b.ReceivedAt = uint64(seq), fromMS(at)
		out = append(out, b)
	}
	return out, rows.Err()
}

func (s *SQLite) PruneGameplayBatches(ctx context.Context, before time.Time) (int64, error) {
	res, err := s.db.ExecContext(ctx, `DELETE FROM gameplay_batches WHERE received_ms < ?`, ms(before))
	if err != nil {
		return 0, err
	}
	return res.RowsAffected()
}

func (s *SQLite) UpsertGameplaySummaries(ctx context.Context, rows []GameplaySummary) error {
	if len(rows) == 0 {
		return nil
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	st, err := tx.PrepareContext(ctx, `INSERT INTO gameplay_sessions (tenant_id, match_id, slot, session_id, player_hash, team, device, aim_assist, mode,
			map_id, map_version, schema_version, batches, motion_samples, sounds, team_info, shots, dropped_events, leak_scored, leak_score, leak_flagged, updated_ms)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
		ON CONFLICT (tenant_id, match_id, slot) DO UPDATE SET session_id = excluded.session_id, player_hash = excluded.player_hash, team = excluded.team,
			device = excluded.device, aim_assist = excluded.aim_assist, mode = excluded.mode, map_id = excluded.map_id, map_version = excluded.map_version,
			schema_version = excluded.schema_version, batches = excluded.batches, motion_samples = excluded.motion_samples, sounds = excluded.sounds,
			team_info = excluded.team_info, shots = excluded.shots, dropped_events = excluded.dropped_events, leak_scored = excluded.leak_scored,
			leak_score = excluded.leak_score, leak_flagged = excluded.leak_flagged, updated_ms = excluded.updated_ms`)
	if err != nil {
		return err
	}
	defer st.Close()
	for _, r := range rows {
		if _, err := st.ExecContext(ctx, r.TenantID, r.MatchID, r.Slot, r.SessionID, r.PlayerHash, r.Team, r.Device, r.AimAssist, r.Mode,
			r.MapID, r.MapVersion, r.SchemaVersion, i64(r.Batches), i64(r.MotionSamples), i64(r.Sounds), i64(r.TeamInfo), i64(r.Shots),
			i64(r.DroppedEvents), r.LeakScored, r.LeakScore, r.LeakFlagged, ms(r.UpdatedAt)); err != nil {
			return err
		}
	}
	return tx.Commit()
}

func (s *SQLite) ListGameplaySummaries(ctx context.Context, tenant string, f GameplayFilter) ([]GameplaySummary, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT match_id, slot, session_id, player_hash, team, device, aim_assist, mode, map_id, map_version, schema_version,
			batches, motion_samples, sounds, team_info, shots, dropped_events, leak_scored, leak_score, leak_flagged, updated_ms
		FROM gameplay_sessions WHERE tenant_id = ?1 AND (?2 = '' OR session_id = ?2) AND (?3 = '' OR match_id = ?3)
		ORDER BY updated_ms DESC, match_id, slot LIMIT ?4`, tenant, f.SessionID, f.MatchID, limitOr(f.Limit, 100))
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []GameplaySummary
	for rows.Next() {
		r := GameplaySummary{TenantID: tenant}
		var batches, motion, sounds, team, shots, dropped, updated int64
		if err := rows.Scan(&r.MatchID, &r.Slot, &r.SessionID, &r.PlayerHash, &r.Team, &r.Device, &r.AimAssist, &r.Mode, &r.MapID, &r.MapVersion,
			&r.SchemaVersion, &batches, &motion, &sounds, &team, &shots, &dropped, &r.LeakScored, &r.LeakScore, &r.LeakFlagged, &updated); err != nil {
			return nil, err
		}
		r.Batches, r.MotionSamples, r.Sounds, r.TeamInfo, r.Shots, r.DroppedEvents = uint64(batches), uint64(motion), uint64(sounds), uint64(team), uint64(shots), uint64(dropped)
		r.UpdatedAt = fromMS(updated)
		out = append(out, r)
	}
	return out, rows.Err()
}
