package store

import (
	"context"
	"database/sql"
	"errors"
	"strings"
	"time"
)

const dashUserCols = `id, tenant_id, name, role, password_hash, totp_secret, totp_last_step, disabled, created_ms, created_by, password_changed_ms, last_login_ms`

type rowScanner interface{ Scan(dest ...any) error }

func scanDashUser(r rowScanner) (*DashUser, error) {
	var u DashUser
	var created, changed, login int64
	err := r.Scan(&u.ID, &u.TenantID, &u.Name, &u.Role, &u.PasswordHash, &u.TOTPSecret, &u.TOTPLastStep, &u.Disabled, &created, &u.CreatedBy, &changed, &login)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	u.CreatedAt, u.PasswordChangedAt = fromMS(created), fromMS(changed)
	if login > 0 {
		u.LastLoginAt = fromMS(login)
	}
	return &u, nil
}

func msOrZero(t time.Time) int64 {
	if t.IsZero() {
		return 0
	}
	return ms(t)
}

func (s *SQLite) CountDashUsers(ctx context.Context, tenant string) (int, error) {
	var n int
	err := s.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM dashboard_users WHERE tenant_id = ?`, tenant).Scan(&n)
	return n, err
}

func (s *SQLite) CreateDashUser(ctx context.Context, u *DashUser) error {
	res, err := s.db.ExecContext(ctx, `INSERT INTO dashboard_users (tenant_id, name, role, password_hash, totp_secret, disabled, created_ms, created_by, password_changed_ms, last_login_ms)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?) ON CONFLICT (tenant_id, name) DO NOTHING`,
		u.TenantID, u.Name, u.Role, u.PasswordHash, u.TOTPSecret, u.Disabled, ms(u.CreatedAt), u.CreatedBy, ms(u.PasswordChangedAt), msOrZero(u.LastLoginAt))
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return ErrConflict
	}
	u.ID, err = res.LastInsertId()
	return err
}

func (s *SQLite) GetDashUser(ctx context.Context, tenant string, id int64) (*DashUser, error) {
	return scanDashUser(s.db.QueryRowContext(ctx, `SELECT `+dashUserCols+` FROM dashboard_users WHERE tenant_id = ? AND id = ?`, tenant, id))
}

func (s *SQLite) GetDashUserByName(ctx context.Context, tenant, name string) (*DashUser, error) {
	return scanDashUser(s.db.QueryRowContext(ctx, `SELECT `+dashUserCols+` FROM dashboard_users WHERE tenant_id = ? AND name = ?`, tenant, name))
}

func (s *SQLite) ListDashUsers(ctx context.Context, tenant string) ([]DashUser, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT `+dashUserCols+` FROM dashboard_users WHERE tenant_id = ? ORDER BY name`, tenant)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []DashUser
	for rows.Next() {
		u, err := scanDashUser(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, *u)
	}
	return out, rows.Err()
}

func (s *SQLite) UpdateDashUser(ctx context.Context, u *DashUser) error {
	res, err := s.db.ExecContext(ctx, `UPDATE dashboard_users SET role = ?, password_hash = ?, totp_secret = ?, disabled = ?, password_changed_ms = ?, last_login_ms = ?
		WHERE tenant_id = ? AND id = ?`,
		u.Role, u.PasswordHash, u.TOTPSecret, u.Disabled, ms(u.PasswordChangedAt), msOrZero(u.LastLoginAt), u.TenantID, u.ID)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return ErrNotFound
	}
	return nil
}

func (s *SQLite) AdvanceTOTPStep(ctx context.Context, userID, step int64) (bool, error) {
	res, err := s.db.ExecContext(ctx, `UPDATE dashboard_users SET totp_last_step = ? WHERE id = ? AND totp_last_step < ?`, step, userID, step)
	if err != nil {
		return false, err
	}
	n, _ := res.RowsAffected()
	return n == 1, nil
}

func (s *SQLite) SetRecoveryCodes(ctx context.Context, userID int64, hashes []string) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if _, err := tx.ExecContext(ctx, `DELETE FROM dashboard_recovery_codes WHERE user_id = ?`, userID); err != nil {
		return err
	}
	for _, h := range hashes {
		if _, err := tx.ExecContext(ctx, `INSERT INTO dashboard_recovery_codes (user_id, code_hash) VALUES (?, ?)`, userID, h); err != nil {
			return err
		}
	}
	return tx.Commit()
}

func (s *SQLite) UseRecoveryCode(ctx context.Context, userID int64, hash string) (bool, error) {
	res, err := s.db.ExecContext(ctx, `DELETE FROM dashboard_recovery_codes WHERE user_id = ? AND code_hash = ?`, userID, hash)
	if err != nil {
		return false, err
	}
	n, _ := res.RowsAffected()
	return n == 1, nil
}

func (s *SQLite) CountRecoveryCodes(ctx context.Context, userID int64) (int, error) {
	var n int
	err := s.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM dashboard_recovery_codes WHERE user_id = ?`, userID).Scan(&n)
	return n, err
}

const dashInviteCols = `token_hash, tenant_id, kind, name, role, user_id, created_by, created_ms, expires_ms, used_ms`

func scanDashInvite(r rowScanner) (*DashInvite, error) {
	var v DashInvite
	var created, expires, used int64
	err := r.Scan(&v.TokenHash, &v.TenantID, &v.Kind, &v.Name, &v.Role, &v.UserID, &v.CreatedBy, &created, &expires, &used)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	v.CreatedAt, v.ExpiresAt = fromMS(created), fromMS(expires)
	if used > 0 {
		v.UsedAt = fromMS(used)
	}
	return &v, nil
}

func (s *SQLite) CreateDashInvite(ctx context.Context, v *DashInvite) error {
	_, err := s.db.ExecContext(ctx, `INSERT INTO dashboard_invites (`+dashInviteCols+`) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 0)`,
		v.TokenHash, v.TenantID, v.Kind, v.Name, v.Role, v.UserID, v.CreatedBy, ms(v.CreatedAt), ms(v.ExpiresAt))
	return err
}

func (s *SQLite) GetDashInvite(ctx context.Context, tokenHash string, now time.Time) (*DashInvite, error) {
	return scanDashInvite(s.db.QueryRowContext(ctx, `SELECT `+dashInviteCols+` FROM dashboard_invites WHERE token_hash = ? AND used_ms = 0 AND expires_ms > ?`, tokenHash, ms(now)))
}

func (s *SQLite) RedeemDashInvite(ctx context.Context, tokenHash string, now time.Time) (*DashInvite, error) {
	res, err := s.db.ExecContext(ctx, `UPDATE dashboard_invites SET used_ms = ? WHERE token_hash = ? AND used_ms = 0 AND expires_ms > ?`, ms(now), tokenHash, ms(now))
	if err != nil {
		return nil, err
	}
	if n, _ := res.RowsAffected(); n != 1 {
		return nil, ErrNotFound
	}
	return scanDashInvite(s.db.QueryRowContext(ctx, `SELECT `+dashInviteCols+` FROM dashboard_invites WHERE token_hash = ?`, tokenHash))
}

func (s *SQLite) ListDashInvites(ctx context.Context, tenant string, now time.Time) ([]DashInvite, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT `+dashInviteCols+` FROM dashboard_invites WHERE tenant_id = ? AND used_ms = 0 AND expires_ms > ? ORDER BY created_ms DESC`, tenant, ms(now))
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []DashInvite
	for rows.Next() {
		v, err := scanDashInvite(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, *v)
	}
	return out, rows.Err()
}

func (s *SQLite) RevokeDashInvite(ctx context.Context, tenant, tokenHash string) error {
	res, err := s.db.ExecContext(ctx, `DELETE FROM dashboard_invites WHERE tenant_id = ? AND token_hash = ? AND used_ms = 0`, tenant, tokenHash)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return ErrNotFound
	}
	return nil
}

const dashSessionCols = `id_hash, tenant_id, user_id, kind, created_ms, last_seen_ms, expires_ms, ip, user_agent`

func scanDashSession(r rowScanner) (*DashSession, error) {
	var x DashSession
	var created, seen, expires int64
	err := r.Scan(&x.IDHash, &x.TenantID, &x.UserID, &x.Kind, &created, &seen, &expires, &x.IP, &x.UserAgent)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	x.CreatedAt, x.LastSeenAt, x.ExpiresAt = fromMS(created), fromMS(seen), fromMS(expires)
	return &x, nil
}

func (s *SQLite) PutDashSession(ctx context.Context, x *DashSession) error {
	_, err := s.db.ExecContext(ctx, `INSERT INTO dashboard_sessions (`+dashSessionCols+`) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		x.IDHash, x.TenantID, x.UserID, x.Kind, ms(x.CreatedAt), ms(x.LastSeenAt), ms(x.ExpiresAt), x.IP, x.UserAgent)
	return err
}

func (s *SQLite) GetDashSession(ctx context.Context, idHash string) (*DashSession, error) {
	return scanDashSession(s.db.QueryRowContext(ctx, `SELECT `+dashSessionCols+` FROM dashboard_sessions WHERE id_hash = ?`, idHash))
}

func (s *SQLite) TouchDashSession(ctx context.Context, idHash string, at time.Time) error {
	_, err := s.db.ExecContext(ctx, `UPDATE dashboard_sessions SET last_seen_ms = ? WHERE id_hash = ?`, ms(at), idHash)
	return err
}

func (s *SQLite) DeleteDashSession(ctx context.Context, idHash string) error {
	_, err := s.db.ExecContext(ctx, `DELETE FROM dashboard_sessions WHERE id_hash = ?`, idHash)
	return err
}

func (s *SQLite) DeleteDashSessions(ctx context.Context, tenant string, userID int64, exceptHash string) (int, error) {
	res, err := s.db.ExecContext(ctx, `DELETE FROM dashboard_sessions WHERE tenant_id = ? AND user_id = ? AND id_hash <> ?`, tenant, userID, exceptHash)
	if err != nil {
		return 0, err
	}
	n, _ := res.RowsAffected()
	return int(n), nil
}

func (s *SQLite) ListDashSessions(ctx context.Context, tenant string, userID int64, now time.Time) ([]DashSession, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT `+dashSessionCols+` FROM dashboard_sessions WHERE tenant_id = ? AND user_id = ? AND expires_ms > ? ORDER BY last_seen_ms DESC`, tenant, userID, ms(now))
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []DashSession
	for rows.Next() {
		x, err := scanDashSession(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, *x)
	}
	return out, rows.Err()
}

func (s *SQLite) PruneDashSessions(ctx context.Context, now time.Time) error {
	_, err := s.db.ExecContext(ctx, `DELETE FROM dashboard_sessions WHERE expires_ms <= ?`, ms(now))
	return err
}

func (s *SQLite) GetTenantSettings(ctx context.Context, tenant string) (TenantSettings, error) {
	var t TenantSettings
	err := s.db.QueryRowContext(ctx, `SELECT require_totp FROM dashboard_tenant_settings WHERE tenant_id = ?`, tenant).Scan(&t.RequireTOTP)
	if errors.Is(err, sql.ErrNoRows) {
		return TenantSettings{}, nil
	}
	return t, err
}

func (s *SQLite) PutTenantSettings(ctx context.Context, tenant string, t TenantSettings) error {
	_, err := s.db.ExecContext(ctx, `INSERT INTO dashboard_tenant_settings (tenant_id, require_totp) VALUES (?, ?)
		ON CONFLICT (tenant_id) DO UPDATE SET require_totp = excluded.require_totp`, tenant, t.RequireTOTP)
	return err
}

// AppendAudit takes the write lock before it reads the previous hash, so two writers (the
// gateway and the command line, which is another process) cannot both chain onto the same
// entry.
func (s *SQLite) AppendAudit(ctx context.Context, e *AuditEntry) error {
	conn, err := s.db.Conn(ctx)
	if err != nil {
		return err
	}
	defer conn.Close()
	if _, err := conn.ExecContext(ctx, `BEGIN IMMEDIATE`); err != nil {
		return err
	}
	done := false
	defer func() {
		if !done {
			_, _ = conn.ExecContext(context.WithoutCancel(ctx), `ROLLBACK`)
		}
	}()
	var prev string
	err = conn.QueryRowContext(ctx, `SELECT hash FROM dashboard_audit WHERE tenant_id = ? ORDER BY id DESC LIMIT 1`, e.TenantID).Scan(&prev)
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return err
	}
	e.At = fromMS(ms(e.At))
	e.PrevHash, e.Hash = prev, auditHash(prev, e)
	res, err := conn.ExecContext(ctx, `INSERT INTO dashboard_audit (tenant_id, at_ms, actor_id, actor, ip, action, target, detail, prev_hash, hash) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		e.TenantID, ms(e.At), e.ActorID, e.Actor, e.IP, e.Action, e.Target, e.Detail, e.PrevHash, e.Hash)
	if err != nil {
		return err
	}
	if e.ID, err = res.LastInsertId(); err != nil {
		return err
	}
	if _, err := conn.ExecContext(ctx, `COMMIT`); err != nil {
		return err
	}
	done = true
	return nil
}

const auditCols = `id, tenant_id, at_ms, actor_id, actor, ip, action, target, detail, prev_hash, hash`

func scanAudit(r rowScanner) (*AuditEntry, error) {
	var e AuditEntry
	var at int64
	if err := r.Scan(&e.ID, &e.TenantID, &at, &e.ActorID, &e.Actor, &e.IP, &e.Action, &e.Target, &e.Detail, &e.PrevHash, &e.Hash); err != nil {
		return nil, err
	}
	e.At = fromMS(at)
	return &e, nil
}

func (s *SQLite) ListAudit(ctx context.Context, tenant string, f AuditFilter) ([]AuditEntry, error) {
	q := `SELECT ` + auditCols + ` FROM dashboard_audit WHERE tenant_id = ?`
	args := []any{tenant}
	if f.BeforeID > 0 {
		q += ` AND id < ?`
		args = append(args, f.BeforeID)
	}
	if len(f.ActionPrefixes) > 0 {
		var ors []string
		for _, p := range f.ActionPrefixes {
			ors = append(ors, `substr(action, 1, ?) = ?`)
			args = append(args, len(p), p)
		}
		q += ` AND (` + strings.Join(ors, ` OR `) + `)`
	}
	q += ` ORDER BY id DESC LIMIT ?`
	args = append(args, limitOr(f.Limit, 100))
	rows, err := s.db.QueryContext(ctx, q, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []AuditEntry
	for rows.Next() {
		e, err := scanAudit(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, *e)
	}
	return out, rows.Err()
}

func (s *SQLite) VerifyAudit(ctx context.Context, tenant string) (int, int64, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT `+auditCols+` FROM dashboard_audit WHERE tenant_id = ? ORDER BY id`, tenant)
	if err != nil {
		return 0, 0, err
	}
	defer rows.Close()
	n, prev := 0, ""
	for rows.Next() {
		e, err := scanAudit(rows)
		if err != nil {
			return n, 0, err
		}
		n++
		if e.PrevHash != prev || e.Hash != auditHash(prev, e) {
			return n, e.ID, nil
		}
		prev = e.Hash
	}
	return n, 0, rows.Err()
}
