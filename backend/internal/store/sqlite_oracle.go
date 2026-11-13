package store

import (
	"context"
	"database/sql"
	"errors"
)

func (s *SQLite) PutOracleScore(ctx context.Context, x *OracleScore) error {
	_, err := s.db.ExecContext(ctx, `INSERT INTO oracle_scores (tenant_id, session_id, player_hash, match_id, model_id, feature_version, score, band, signals, features, updated_ms)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
		ON CONFLICT (tenant_id, session_id) DO UPDATE SET player_hash = excluded.player_hash, match_id = excluded.match_id, model_id = excluded.model_id,
			feature_version = excluded.feature_version, score = excluded.score, band = excluded.band, signals = excluded.signals,
			features = excluded.features, updated_ms = excluded.updated_ms`,
		x.TenantID, x.SessionID, x.PlayerHash, x.MatchID, x.ModelID, x.FeatureVersion, x.Score, x.Band, x.Signals, x.Features, ms(x.UpdatedAt))
	return err
}

const oracleScoreCols = `session_id, player_hash, match_id, model_id, feature_version, score, band, signals, features, updated_ms`

func scanOracleScore(tenant string, sc interface{ Scan(...any) error }) (*OracleScore, error) {
	x := OracleScore{TenantID: tenant}
	var at int64
	if err := sc.Scan(&x.SessionID, &x.PlayerHash, &x.MatchID, &x.ModelID, &x.FeatureVersion, &x.Score, &x.Band, &x.Signals, &x.Features, &at); err != nil {
		return nil, err
	}
	x.UpdatedAt = fromMS(at)
	return &x, nil
}

func (s *SQLite) GetOracleScore(ctx context.Context, tenant, sessionID string) (*OracleScore, error) {
	x, err := scanOracleScore(tenant, s.db.QueryRowContext(ctx, `SELECT `+oracleScoreCols+` FROM oracle_scores WHERE tenant_id = ? AND session_id = ?`, tenant, sessionID))
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	return x, err
}

func (s *SQLite) ListOracleScores(ctx context.Context, tenant string, f OracleFilter) ([]OracleScore, error) {
	q, args := `SELECT `+oracleScoreCols+` FROM oracle_scores WHERE tenant_id = ?`, []any{tenant}
	if f.PlayerHash != "" {
		q, args = q+` AND player_hash = ?`, append(args, f.PlayerHash)
	}
	rows, err := s.db.QueryContext(ctx, q+` ORDER BY updated_ms DESC LIMIT ?`, append(args, limitOr(f.Limit, 100))...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []OracleScore
	for rows.Next() {
		x, err := scanOracleScore(tenant, rows)
		if err != nil {
			return nil, err
		}
		out = append(out, *x)
	}
	return out, rows.Err()
}

func (s *SQLite) PutOracleVerdict(ctx context.Context, v *OracleVerdict) error {
	_, err := s.db.ExecContext(ctx, `INSERT INTO oracle_verdicts (tenant_id, session_id, player_hash, case_hash, status, reason, provider, analyst_model, prompt_version,
			cheat_type, confidence, action, summary, cited, case_file, latency_ms, tokens_in, tokens_out, created_ms)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
		ON CONFLICT (tenant_id, session_id) DO UPDATE SET player_hash = excluded.player_hash, case_hash = excluded.case_hash, status = excluded.status,
			reason = excluded.reason, provider = excluded.provider, analyst_model = excluded.analyst_model, prompt_version = excluded.prompt_version,
			cheat_type = excluded.cheat_type, confidence = excluded.confidence, action = excluded.action, summary = excluded.summary,
			cited = excluded.cited, case_file = excluded.case_file, latency_ms = excluded.latency_ms, tokens_in = excluded.tokens_in,
			tokens_out = excluded.tokens_out, created_ms = excluded.created_ms`,
		v.TenantID, v.SessionID, v.PlayerHash, v.CaseHash, v.Status, v.Reason, v.Provider, v.AnalystModel, v.PromptVersion,
		v.CheatType, v.Confidence, v.Action, v.Summary, v.Cited, v.CaseFile, v.LatencyMs, v.TokensIn, v.TokensOut, ms(v.CreatedAt))
	return err
}

const oracleVerdictCols = `v.session_id, v.player_hash, v.case_hash, v.status, v.reason, v.provider, v.analyst_model, v.prompt_version,
	v.cheat_type, v.confidence, v.action, v.summary, v.cited, v.case_file, v.latency_ms, v.tokens_in, v.tokens_out, v.created_ms`

func oracleVerdictDest(v *OracleVerdict, at *int64) []any {
	return []any{&v.SessionID, &v.PlayerHash, &v.CaseHash, &v.Status, &v.Reason, &v.Provider, &v.AnalystModel, &v.PromptVersion,
		&v.CheatType, &v.Confidence, &v.Action, &v.Summary, &v.Cited, &v.CaseFile, &v.LatencyMs, &v.TokensIn, &v.TokensOut, at}
}

func (s *SQLite) GetOracleVerdict(ctx context.Context, tenant, sessionID string) (*OracleVerdict, error) {
	v := OracleVerdict{TenantID: tenant}
	var at int64
	err := s.db.QueryRowContext(ctx, `SELECT `+oracleVerdictCols+` FROM oracle_verdicts v WHERE v.tenant_id = ? AND v.session_id = ?`, tenant, sessionID).
		Scan(oracleVerdictDest(&v, &at)...)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	v.CreatedAt = fromMS(at)
	return &v, nil
}

func (s *SQLite) ListOracleVerdicts(ctx context.Context, tenant string, f OracleFilter) ([]OracleVerdict, error) {
	q, args := `SELECT `+oracleVerdictCols+` FROM oracle_verdicts v WHERE v.tenant_id = ?`, []any{tenant}
	if f.PlayerHash != "" {
		q, args = q+` AND v.player_hash = ?`, append(args, f.PlayerHash)
	}
	rows, err := s.db.QueryContext(ctx, q+` ORDER BY v.created_ms DESC LIMIT ?`, append(args, limitOr(f.Limit, 100))...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []OracleVerdict
	for rows.Next() {
		v := OracleVerdict{TenantID: tenant}
		var at int64
		if err := rows.Scan(oracleVerdictDest(&v, &at)...); err != nil {
			return nil, err
		}
		v.CreatedAt = fromMS(at)
		out = append(out, v)
	}
	return out, rows.Err()
}

func (s *SQLite) AddOracleUsage(ctx context.Context, tenant, day string, cases, tokens int64) (OracleUsage, error) {
	var u OracleUsage
	err := s.db.QueryRowContext(ctx, `INSERT INTO oracle_usage (tenant_id, day, cases, tokens) VALUES (?, ?, ?, ?)
		ON CONFLICT (tenant_id, day) DO UPDATE SET cases = cases + excluded.cases, tokens = tokens + excluded.tokens
		RETURNING cases, tokens`, tenant, day, cases, tokens).Scan(&u.Cases, &u.Tokens)
	return u, err
}

func (s *SQLite) SetSessionLabel(ctx context.Context, l *SessionLabel, action, remote string) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if l.Label == "" {
		_, err = tx.ExecContext(ctx, `DELETE FROM session_labels WHERE tenant_id = ? AND session_id = ?`, l.TenantID, l.SessionID)
	} else {
		_, err = tx.ExecContext(ctx, `INSERT INTO session_labels (tenant_id, session_id, player_hash, label, cheat_type, note, reviewer, labelled_ms) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
			ON CONFLICT (tenant_id, session_id) DO UPDATE SET player_hash = excluded.player_hash, label = excluded.label, cheat_type = excluded.cheat_type,
				note = excluded.note, reviewer = excluded.reviewer, labelled_ms = excluded.labelled_ms`,
			l.TenantID, l.SessionID, l.PlayerHash, l.Label, l.CheatType, l.Note, l.Reviewer, ms(l.LabelledAt))
	}
	if err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, `INSERT INTO session_label_audit (tenant_id, session_id, action, label, cheat_type, note, reviewer, remote, at_ms) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		l.TenantID, l.SessionID, action, l.Label, l.CheatType, l.Note, l.Reviewer, remote, ms(l.LabelledAt)); err != nil {
		return err
	}
	return tx.Commit()
}

func (s *SQLite) GetSessionLabel(ctx context.Context, tenant, sessionID string) (*SessionLabel, error) {
	l := SessionLabel{TenantID: tenant, SessionID: sessionID}
	var at int64
	err := s.db.QueryRowContext(ctx, `SELECT player_hash, label, cheat_type, note, reviewer, labelled_ms FROM session_labels WHERE tenant_id = ? AND session_id = ?`,
		tenant, sessionID).Scan(&l.PlayerHash, &l.Label, &l.CheatType, &l.Note, &l.Reviewer, &at)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	l.LabelledAt = fromMS(at)
	return &l, nil
}

func (s *SQLite) ListSessionLabels(ctx context.Context, tenant string, f OracleFilter) ([]SessionLabel, error) {
	q, args := `SELECT session_id, player_hash, label, cheat_type, note, reviewer, labelled_ms FROM session_labels WHERE tenant_id = ?`, []any{tenant}
	if f.PlayerHash != "" {
		q, args = q+` AND player_hash = ?`, append(args, f.PlayerHash)
	}
	rows, err := s.db.QueryContext(ctx, q+` ORDER BY labelled_ms DESC, session_id LIMIT ?`, append(args, limitOr(f.Limit, 100))...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []SessionLabel
	for rows.Next() {
		l := SessionLabel{TenantID: tenant}
		var at int64
		if err := rows.Scan(&l.SessionID, &l.PlayerHash, &l.Label, &l.CheatType, &l.Note, &l.Reviewer, &at); err != nil {
			return nil, err
		}
		l.LabelledAt = fromMS(at)
		out = append(out, l)
	}
	return out, rows.Err()
}

func (s *SQLite) ListLabelAudit(ctx context.Context, tenant, sessionID string, limit int) ([]LabelAudit, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT id, action, label, cheat_type, note, reviewer, remote, at_ms FROM session_label_audit
		WHERE tenant_id = ? AND session_id = ? ORDER BY id DESC LIMIT ?`, tenant, sessionID, limitOr(limit, 50))
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []LabelAudit
	for rows.Next() {
		a := LabelAudit{TenantID: tenant, SessionID: sessionID}
		var at int64
		if err := rows.Scan(&a.ID, &a.Action, &a.Label, &a.CheatType, &a.Note, &a.Reviewer, &a.Remote, &at); err != nil {
			return nil, err
		}
		a.At = fromMS(at)
		out = append(out, a)
	}
	return out, rows.Err()
}
