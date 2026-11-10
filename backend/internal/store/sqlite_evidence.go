package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"
	"time"
)

func (s *SQLite) AddEvidence(ctx context.Context, evs []Evidence) error {
	if len(evs) == 0 {
		return nil
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	st, err := tx.PrepareContext(ctx, `INSERT INTO evidence (tenant_id, player_hash, session_id, match_id, source, rule, severity, score, integrity, summary, raw, observed_ms)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`)
	if err != nil {
		return err
	}
	defer st.Close()
	for i := range evs {
		e := &evs[i]
		res, err := st.ExecContext(ctx, e.TenantID, e.PlayerHash, e.SessionID, e.MatchID, e.Source, e.Rule, e.Severity, e.Score, e.Integrity, e.Summary, e.Raw, ms(e.ObservedAt))
		if err != nil {
			return err
		}
		e.ID, _ = res.LastInsertId()
	}
	return tx.Commit()
}

func (s *SQLite) PutTelemetry(ctx context.Context, t *Telemetry) error {
	_, err := s.db.ExecContext(ctx, `INSERT INTO session_telemetry (session_id, updated_ms, activity, worker_cpu_ns, slices, slice_cpu_max_ns, slice_overruns, frames,
			jobs_quarantined, findings_dropped, findings_total, input_thread_cpu_ns, mouse_events, injected_events, mitigations_applied, mitigations_failed, coverage)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
		ON CONFLICT (session_id) DO UPDATE SET updated_ms = excluded.updated_ms, activity = excluded.activity, worker_cpu_ns = excluded.worker_cpu_ns,
			slices = excluded.slices, slice_cpu_max_ns = excluded.slice_cpu_max_ns, slice_overruns = excluded.slice_overruns, frames = excluded.frames,
			jobs_quarantined = excluded.jobs_quarantined, findings_dropped = excluded.findings_dropped, findings_total = excluded.findings_total,
			input_thread_cpu_ns = excluded.input_thread_cpu_ns, mouse_events = excluded.mouse_events, injected_events = excluded.injected_events,
			mitigations_applied = excluded.mitigations_applied, mitigations_failed = excluded.mitigations_failed, coverage = excluded.coverage`,
		t.SessionID, ms(t.UpdatedAt), t.Activity, i64(t.WorkerCPUNs), i64(t.Slices), i64(t.SliceCPUMaxNs), i64(t.SliceOverruns), i64(t.Frames),
		t.JobsQuarantined, i64(t.FindingsDropped), i64(t.FindingsTotal), i64(t.InputThreadCPUNs), i64(t.MouseEvents), i64(t.InjectedEvents),
		i64(t.MitigationsApplied), i64(t.MitigationsFailed), t.Coverage)
	return err
}

// i64 stores a counter in a BIGINT column; counters never approach 2^63.
func i64(v uint64) int64 { return int64(v) }

func (s *SQLite) AdvanceMatch(ctx context.Context, tenant, matchID string, seq uint64, at time.Time, over bool) (bool, error) {
	// The upsert only moves last_batch_seq forward; RowsAffected is 0 when seq is stale.
	res, err := s.db.ExecContext(ctx, `INSERT INTO matches (tenant_id, match_id, last_batch_seq, started_ms, updated_ms, over) VALUES (?, ?, ?, ?, ?, ?)
		ON CONFLICT (tenant_id, match_id) DO UPDATE SET last_batch_seq = excluded.last_batch_seq, updated_ms = excluded.updated_ms, over = excluded.over
		WHERE excluded.last_batch_seq > matches.last_batch_seq`,
		tenant, matchID, i64(seq), ms(at), ms(at), over)
	if err != nil {
		return false, err
	}
	n, err := res.RowsAffected()
	return n == 1, err
}

func (s *SQLite) Overview(ctx context.Context, tenant string, since, online time.Time) (Overview, error) {
	var o Overview
	row := s.db.QueryRowContext(ctx, `SELECT
			(SELECT COUNT(*) FROM sessions WHERE tenant_id = ?1 AND state = 'active' AND last_heartbeat_ms >= ?3),
			(SELECT COUNT(*) FROM sessions WHERE tenant_id = ?1 AND created_ms >= ?2),
			(SELECT COUNT(DISTINCT player_hash) FROM sessions WHERE tenant_id = ?1 AND created_ms >= ?2),
			(SELECT COUNT(*) FROM evidence WHERE tenant_id = ?1 AND observed_ms >= ?2 AND severity > 0),
			(SELECT COUNT(*) FROM matches WHERE tenant_id = ?1 AND updated_ms >= ?2)`,
		tenant, ms(since), ms(online))
	if err := row.Scan(&o.OnlineSessions, &o.Sessions, &o.Players, &o.Evidence, &o.Matches); err != nil {
		return o, err
	}
	rows, err := s.db.QueryContext(ctx, `SELECT trust_level, COUNT(*) FROM sessions WHERE tenant_id = ? AND created_ms >= ? GROUP BY trust_level`, tenant, ms(since))
	if err != nil {
		return o, err
	}
	defer rows.Close()
	for rows.Next() {
		var lvl, n int
		if err := rows.Scan(&lvl, &n); err != nil {
			return o, err
		}
		if lvl >= 0 && lvl < len(o.TrustLevels) {
			o.TrustLevels[lvl] = n
		}
	}
	if err := rows.Err(); err != nil {
		return o, err
	}
	err = s.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM (SELECT player_hash FROM evidence WHERE tenant_id = ? AND severity > 0
		GROUP BY player_hash HAVING SUM(score * `+riskCase+`) >= ?)`, tenant, FlaggedRisk).Scan(&o.FlaggedPlayers)
	return o, err
}

// riskCase is RiskWeight as SQL, so risk is computed in the query that aggregates evidence.
var riskCase = func() string {
	var b strings.Builder
	b.WriteString("CASE severity")
	for sev, w := range RiskWeight {
		fmt.Fprintf(&b, " WHEN %d THEN %g", sev, w)
	}
	b.WriteString(" ELSE 0 END")
	return b.String()
}()

const sessionCols = `s.session_id, s.tenant_id, s.player_hash, s.device_id, s.trust_level, s.attest_flags, s.state, s.kick_reason, s.created_ms, s.expires_ms, s.last_heartbeat_ms, s.heartbeats`

func (s *SQLite) ListSessions(ctx context.Context, tenant string, f SessionFilter) ([]SessionRow, error) {
	q := `SELECT ` + sessionCols + `, COUNT(e.id), COALESCE(MAX(e.severity), -1)
		FROM sessions s LEFT JOIN evidence e ON e.session_id = s.session_id AND e.severity > 0
		WHERE s.tenant_id = ?`
	args := []any{tenant}
	if f.PlayerHash != "" {
		q += ` AND s.player_hash = ?`
		args = append(args, f.PlayerHash)
	}
	q += ` GROUP BY s.session_id ORDER BY s.created_ms DESC LIMIT ?`
	args = append(args, limitOr(f.Limit, 100))
	rows, err := s.db.QueryContext(ctx, q, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []SessionRow
	for rows.Next() {
		var r SessionRow
		var flags, hb, created, expires, last int64
		var state string
		if err := rows.Scan(&r.SessionID, &r.TenantID, &r.PlayerHash, &r.DeviceID, &r.TrustLevel, &flags, &state, &r.KickReason, &created, &expires, &last, &hb,
			&r.EvidenceCount, &r.MaxSeverity); err != nil {
			return nil, err
		}
		r.AttestFlags, r.Heartbeats, r.State = uint64(flags), uint64(hb), SessionState(state)
		r.CreatedAt, r.ExpiresAt, r.LastHeartbeat = fromMS(created), fromMS(expires), fromMS(last)
		out = append(out, r)
	}
	return out, rows.Err()
}

func (s *SQLite) GetTelemetry(ctx context.Context, tenant, sessionID string) (*Telemetry, error) {
	t := Telemetry{SessionID: sessionID}
	var upd, cpu, slices, smax, over, frames, dropped, total, icpu, mouse, inj, mapp, mfail int64
	err := s.db.QueryRowContext(ctx, `SELECT t.updated_ms, t.activity, t.worker_cpu_ns, t.slices, t.slice_cpu_max_ns, t.slice_overruns, t.frames, t.jobs_quarantined,
			t.findings_dropped, t.findings_total, t.input_thread_cpu_ns, t.mouse_events, t.injected_events, t.mitigations_applied, t.mitigations_failed, t.coverage
		FROM session_telemetry t JOIN sessions s ON s.session_id = t.session_id WHERE t.session_id = ? AND s.tenant_id = ?`, sessionID, tenant).
		Scan(&upd, &t.Activity, &cpu, &slices, &smax, &over, &frames, &t.JobsQuarantined, &dropped, &total, &icpu, &mouse, &inj, &mapp, &mfail, &t.Coverage)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	t.UpdatedAt = fromMS(upd)
	t.WorkerCPUNs, t.Slices, t.SliceCPUMaxNs, t.SliceOverruns, t.Frames = uint64(cpu), uint64(slices), uint64(smax), uint64(over), uint64(frames)
	t.FindingsDropped, t.FindingsTotal, t.InputThreadCPUNs = uint64(dropped), uint64(total), uint64(icpu)
	t.MouseEvents, t.InjectedEvents, t.MitigationsApplied, t.MitigationsFailed = uint64(mouse), uint64(inj), uint64(mapp), uint64(mfail)
	return &t, nil
}

const evidenceCols = `id, tenant_id, player_hash, session_id, match_id, source, rule, severity, score, integrity, summary, raw, observed_ms`

func scanEvidence(sc interface{ Scan(...any) error }) (Evidence, error) {
	var e Evidence
	var at int64
	err := sc.Scan(&e.ID, &e.TenantID, &e.PlayerHash, &e.SessionID, &e.MatchID, &e.Source, &e.Rule, &e.Severity, &e.Score, &e.Integrity, &e.Summary, &e.Raw, &at)
	e.ObservedAt = fromMS(at)
	return e, err
}

func (s *SQLite) ListEvidence(ctx context.Context, tenant string, f EvidenceFilter) ([]Evidence, error) {
	q := `SELECT ` + evidenceCols + ` FROM evidence WHERE tenant_id = ? AND severity >= ?`
	args := []any{tenant, f.MinSeverity}
	if f.PlayerHash != "" {
		q += ` AND player_hash = ?`
		args = append(args, f.PlayerHash)
	}
	if f.SessionID != "" {
		q += ` AND session_id = ?`
		args = append(args, f.SessionID)
	}
	q += ` ORDER BY observed_ms DESC, id DESC LIMIT ?`
	args = append(args, limitOr(f.Limit, 100))
	rows, err := s.db.QueryContext(ctx, q, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Evidence
	for rows.Next() {
		e, err := scanEvidence(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, e)
	}
	return out, rows.Err()
}

func (s *SQLite) GetEvidence(ctx context.Context, tenant string, id int64) (*Evidence, error) {
	e, err := scanEvidence(s.db.QueryRowContext(ctx, `SELECT `+evidenceCols+` FROM evidence WHERE id = ? AND tenant_id = ?`, id, tenant))
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	return &e, nil
}

func (s *SQLite) ListPlayers(ctx context.Context, tenant string, f PlayerFilter) ([]PlayerRow, error) {
	minRisk := 0.0
	if f.FlaggedOnly {
		minRisk = FlaggedRisk
	}
	rows, err := s.db.QueryContext(ctx, `
		WITH s AS (SELECT player_hash, COUNT(*) AS n, MAX(created_ms) AS last FROM sessions WHERE tenant_id = ?1 GROUP BY player_hash),
		     e AS (SELECT player_hash, COUNT(*) AS n, MAX(severity) AS maxsev, SUM(integrity) AS integ, SUM(score * `+riskCase+`) AS risk, MAX(observed_ms) AS last
		           FROM evidence WHERE tenant_id = ?1 AND severity > 0 GROUP BY player_hash),
		     p AS (SELECT player_hash FROM s UNION SELECT player_hash FROM e)
		SELECT p.player_hash, COALESCE(s.n, 0), MAX(COALESCE(s.last, 0), COALESCE(e.last, 0)), COALESCE(e.n, 0), COALESCE(e.maxsev, -1),
		       COALESCE(e.integ, 0), COALESCE(e.risk, 0),
		       (SELECT trust_level FROM sessions x WHERE x.tenant_id = ?1 AND x.player_hash = p.player_hash ORDER BY x.created_ms DESC LIMIT 1),
		       (SELECT rule FROM evidence y WHERE y.tenant_id = ?1 AND y.player_hash = p.player_hash AND y.severity > 0 ORDER BY y.severity DESC, y.score DESC LIMIT 1)
		FROM p LEFT JOIN s ON s.player_hash = p.player_hash LEFT JOIN e ON e.player_hash = p.player_hash
		WHERE COALESCE(e.risk, 0) >= ?2
		ORDER BY 7 DESC, 3 DESC LIMIT ?3`, tenant, minRisk, limitOr(f.Limit, 100))
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []PlayerRow
	for rows.Next() {
		var r PlayerRow
		var last int64
		var trust sql.NullInt64
		var rule sql.NullString
		if err := rows.Scan(&r.PlayerHash, &r.Sessions, &last, &r.EvidenceCount, &r.MaxSeverity, &r.Integrity, &r.Risk, &trust, &rule); err != nil {
			return nil, err
		}
		r.LastSeen, r.TrustLevel, r.TopRule = fromMS(last), uint32(trust.Int64), rule.String
		out = append(out, r)
	}
	return out, rows.Err()
}
