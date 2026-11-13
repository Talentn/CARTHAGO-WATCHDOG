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

func (s *SQLite) PutOracleReview(ctx context.Context, r *OracleReview) error {
	_, err := s.db.ExecContext(ctx, `INSERT INTO oracle_reviews (tenant_id, session_id, case_hash, cheat_type, action, note, reviewed_ms) VALUES (?, ?, ?, ?, ?, ?, ?)
		ON CONFLICT (tenant_id, session_id) DO UPDATE SET case_hash = excluded.case_hash, cheat_type = excluded.cheat_type, action = excluded.action,
			note = excluded.note, reviewed_ms = excluded.reviewed_ms`,
		r.TenantID, r.SessionID, r.CaseHash, r.CheatType, r.Action, r.Note, ms(r.ReviewedAt))
	return err
}

func (s *SQLite) ListOracleCases(ctx context.Context, tenant string, reviewedOnly bool, limit int) ([]OracleCase, error) {
	join := `LEFT JOIN`
	if reviewedOnly {
		join = `JOIN`
	}
	rows, err := s.db.QueryContext(ctx, `SELECT `+oracleVerdictCols+`, r.case_hash, r.cheat_type, r.action, r.note, r.reviewed_ms
		FROM oracle_verdicts v `+join+` oracle_reviews r ON r.tenant_id = v.tenant_id AND r.session_id = v.session_id
		WHERE v.tenant_id = ? AND v.case_file <> '' ORDER BY v.created_ms DESC LIMIT ?`, tenant, limitOr(limit, 1000))
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []OracleCase
	for rows.Next() {
		c := OracleCase{Verdict: OracleVerdict{TenantID: tenant}}
		var at int64
		var hash, cheat, action, note sql.NullString
		var reviewed sql.NullInt64
		if err := rows.Scan(append(oracleVerdictDest(&c.Verdict, &at), &hash, &cheat, &action, &note, &reviewed)...); err != nil {
			return nil, err
		}
		c.Verdict.CreatedAt = fromMS(at)
		if hash.Valid {
			c.Review = &OracleReview{TenantID: tenant, SessionID: c.Verdict.SessionID, CaseHash: hash.String, CheatType: cheat.String,
				Action: action.String, Note: note.String, ReviewedAt: fromMS(reviewed.Int64)}
		}
		out = append(out, c)
	}
	return out, rows.Err()
}
