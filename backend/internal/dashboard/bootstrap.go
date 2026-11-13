package dashboard

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"carthago/backend/internal/store"
)

// Bootstrap is what the gateway's command line does to dashboard accounts, straight on
// the store and without a running dashboard: create a studio's first admin, and get an
// admin back in who lost their password or their phone. Whoever can run it can already
// read and write the database, so it asks for no credentials; every use is written to the
// studio's audit log as "command line".
type Bootstrap struct {
	Store store.AuthStore
	Now   func() time.Time
}

const (
	bootstrapActor = "command line"
	// BootstrapLinkTTL is how long a link made on the command line stays valid.
	BootstrapLinkTTL = 24 * time.Hour
)

func (b Bootstrap) now() time.Time {
	if b.Now != nil {
		return b.Now()
	}
	return time.Now()
}

func (b Bootstrap) audit(ctx context.Context, tenant, action, target, detail string) error {
	return b.Store.AppendAudit(ctx, &store.AuditEntry{TenantID: tenant, At: b.now(), Actor: bootstrapActor, IP: "local", Action: action, Target: target, Detail: detail})
}

func checkAccountName(tenant, name string) (string, string, error) {
	tenant, name = strings.TrimSpace(tenant), normName(name)
	if tenant == "" || len(tenant) > 128 || cleanLine(tenant, 128) != tenant {
		return "", "", errors.New("the tenant id is empty or not a plain name")
	}
	if !userNameRE.MatchString(name) {
		return "", "", errors.New("a user name is 3 to 32 characters: a to z, 0 to 9, dot, dash and underscore")
	}
	return tenant, name, nil
}

// InviteAdmin makes a one-time link with which the person named chooses their password and
// becomes an admin of tenant. It returns the link's token (the path is /invite/<token>).
func (b Bootstrap) InviteAdmin(ctx context.Context, tenant, name string) (token string, expires time.Time, err error) {
	if tenant, name, err = checkAccountName(tenant, name); err != nil {
		return "", time.Time{}, err
	}
	if _, err := b.Store.GetDashUserByName(ctx, tenant, name); err == nil {
		return "", time.Time{}, fmt.Errorf("tenant %q already has a user %q", tenant, name)
	} else if !errors.Is(err, store.ErrNotFound) {
		return "", time.Time{}, err
	}
	if token, err = newToken(); err != nil {
		return "", time.Time{}, err
	}
	now := b.now()
	inv := &store.DashInvite{TokenHash: hashToken(token), TenantID: tenant, Kind: store.InviteNew, Name: name, Role: store.RoleAdmin,
		CreatedBy: bootstrapActor, CreatedAt: now, ExpiresAt: now.Add(BootstrapLinkTTL)}
	if err := b.Store.CreateDashInvite(ctx, inv); err != nil {
		return "", time.Time{}, err
	}
	return token, inv.ExpiresAt, b.audit(ctx, tenant, "user.invite", name, "invited as Admin from the gateway command line")
}

// CreateAdmin creates the admin account directly with the given password, for scripted
// installs. The password must pass the same policy as one typed into the dashboard.
func (b Bootstrap) CreateAdmin(ctx context.Context, tenant, name, password string) (err error) {
	if tenant, name, err = checkAccountName(tenant, name); err != nil {
		return err
	}
	if msg := checkPassword(password, name, tenant); msg != "" {
		return errors.New(msg)
	}
	hash, err := hashPassword(password, defaultArgon)
	if err != nil {
		return err
	}
	now := b.now()
	u := &store.DashUser{TenantID: tenant, Name: name, Role: store.RoleAdmin, PasswordHash: hash, CreatedAt: now, CreatedBy: bootstrapActor, PasswordChangedAt: now}
	if err := b.Store.CreateDashUser(ctx, u); err != nil {
		if errors.Is(err, store.ErrConflict) {
			return fmt.Errorf("tenant %q already has a user %q", tenant, name)
		}
		return err
	}
	return b.audit(ctx, tenant, "user.create", name, "account created as Admin from the gateway command line")
}

func (b Bootstrap) find(ctx context.Context, tenant, name string) (*store.DashUser, error) {
	tenant, name, err := checkAccountName(tenant, name)
	if err != nil {
		return nil, err
	}
	u, err := b.Store.GetDashUserByName(ctx, tenant, name)
	if errors.Is(err, store.ErrNotFound) {
		return nil, fmt.Errorf("tenant %q has no user %q", tenant, name)
	}
	return u, err
}

// ResetPassword makes a one-time link with which the user chooses a new password.
func (b Bootstrap) ResetPassword(ctx context.Context, tenant, name string) (token string, expires time.Time, err error) {
	u, err := b.find(ctx, tenant, name)
	if err != nil {
		return "", time.Time{}, err
	}
	if token, err = newToken(); err != nil {
		return "", time.Time{}, err
	}
	now := b.now()
	inv := &store.DashInvite{TokenHash: hashToken(token), TenantID: u.TenantID, Kind: store.InviteReset, Name: u.Name, Role: u.Role, UserID: u.ID,
		CreatedBy: bootstrapActor, CreatedAt: now, ExpiresAt: now.Add(BootstrapLinkTTL)}
	if err := b.Store.CreateDashInvite(ctx, inv); err != nil {
		return "", time.Time{}, err
	}
	return token, inv.ExpiresAt, b.audit(ctx, u.TenantID, "user.reset_link", u.Name, "password reset link made from the gateway command line")
}

// ResetTwoFactor removes the user's authenticator app and recovery codes and ends their
// sessions, for an admin who lost their phone and has nobody to ask.
func (b Bootstrap) ResetTwoFactor(ctx context.Context, tenant, name string) error {
	u, err := b.find(ctx, tenant, name)
	if err != nil {
		return err
	}
	var none []byte
	if err := b.Store.UpdateDashUser(ctx, u.TenantID, u.ID, store.DashUserChange{TOTPSecret: &none}); err != nil {
		return err
	}
	if err := b.Store.SetRecoveryCodes(ctx, u.ID, nil); err != nil {
		return err
	}
	if _, err := b.Store.DeleteDashSessions(ctx, u.TenantID, u.ID, ""); err != nil {
		return err
	}
	return b.audit(ctx, u.TenantID, "totp.reset", u.Name, "two-factor sign-in and recovery codes removed from the gateway command line")
}

// AccountLine is one account as the command line lists it.
type AccountLine struct {
	Name      string
	Role      string
	TwoFactor bool
	Disabled  bool
	LastLogin time.Time
}

func (b Bootstrap) List(ctx context.Context, tenant string) ([]AccountLine, error) {
	users, err := b.Store.ListDashUsers(ctx, strings.TrimSpace(tenant))
	if err != nil {
		return nil, err
	}
	out := make([]AccountLine, len(users))
	for i, u := range users {
		out[i] = AccountLine{Name: u.Name, Role: roleOf(u.Role).Label(), TwoFactor: len(u.TOTPSecret) > 0, Disabled: u.Disabled, LastLogin: u.LastLoginAt}
	}
	return out, nil
}
