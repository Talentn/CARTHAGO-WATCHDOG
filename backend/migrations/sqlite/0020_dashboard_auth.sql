-- Dashboard accounts, sign-in sessions, invites and the audit log. Times are Unix
-- milliseconds. Every table is scoped by tenant_id; no secret is stored in a usable form:
-- passwords are argon2id hashes, recovery codes and tokens are hashes, and the two-factor
-- secret is sealed with a key that is kept in a file next to the database, not in it.

CREATE TABLE dashboard_users (
    id                  INTEGER PRIMARY KEY AUTOINCREMENT,
    tenant_id           TEXT NOT NULL,
    name                TEXT NOT NULL,              -- lower case, unique in the tenant
    role                TEXT NOT NULL,              -- admin | reviewer | read_only
    password_hash       TEXT NOT NULL,              -- argon2id, PHC string
    totp_secret         BLOB,                       -- sealed; NULL until two-factor is enrolled
    totp_last_step      BIGINT NOT NULL DEFAULT 0,  -- last accepted time step: a code works once
    disabled            BOOLEAN NOT NULL DEFAULT FALSE,
    created_ms          BIGINT NOT NULL,
    created_by          TEXT NOT NULL DEFAULT '',
    password_changed_ms BIGINT NOT NULL,
    last_login_ms       BIGINT NOT NULL DEFAULT 0,
    UNIQUE (tenant_id, name)
);

CREATE TABLE dashboard_recovery_codes (
    user_id   INTEGER NOT NULL REFERENCES dashboard_users (id),
    code_hash TEXT NOT NULL,
    PRIMARY KEY (user_id, code_hash)
);

-- One-time links: an invitation to create an account, or a password reset for user_id.
CREATE TABLE dashboard_invites (
    token_hash TEXT PRIMARY KEY,
    tenant_id  TEXT NOT NULL,
    kind       TEXT NOT NULL,              -- invite | reset
    name       TEXT NOT NULL,
    role       TEXT NOT NULL DEFAULT '',
    user_id    INTEGER NOT NULL DEFAULT 0,
    created_by TEXT NOT NULL,
    created_ms BIGINT NOT NULL,
    expires_ms BIGINT NOT NULL,
    used_ms    BIGINT NOT NULL DEFAULT 0
);
CREATE INDEX dashboard_invites_tenant ON dashboard_invites (tenant_id, expires_ms);

-- A row per signed-in browser. id_hash is the SHA-256 of the cookie value, so a copy of
-- this table cannot be used to sign in. user_id 0 is the shared demo login.
CREATE TABLE dashboard_sessions (
    id_hash      TEXT PRIMARY KEY,
    tenant_id    TEXT NOT NULL,
    user_id      INTEGER NOT NULL DEFAULT 0,
    kind         TEXT NOT NULL,            -- full | code (password accepted, code pending) | enrol
    created_ms   BIGINT NOT NULL,
    last_seen_ms BIGINT NOT NULL,
    expires_ms   BIGINT NOT NULL,
    ip           TEXT NOT NULL DEFAULT '',
    user_agent   TEXT NOT NULL DEFAULT ''
);
CREATE INDEX dashboard_sessions_user ON dashboard_sessions (tenant_id, user_id);

CREATE TABLE dashboard_tenant_settings (
    tenant_id    TEXT PRIMARY KEY,
    require_totp BOOLEAN NOT NULL DEFAULT FALSE
);

-- Append-only: the triggers refuse every UPDATE and DELETE. Each row carries the hash of
-- the row before it for the same tenant, so a row changed or removed behind the gateway's
-- back breaks the chain from that point on.
CREATE TABLE dashboard_audit (
    id        INTEGER PRIMARY KEY AUTOINCREMENT,
    tenant_id TEXT NOT NULL,
    at_ms     BIGINT NOT NULL,
    actor_id  INTEGER NOT NULL DEFAULT 0,
    actor     TEXT NOT NULL,
    ip        TEXT NOT NULL DEFAULT '',
    action    TEXT NOT NULL,
    target    TEXT NOT NULL DEFAULT '',
    detail    TEXT NOT NULL DEFAULT '',
    prev_hash TEXT NOT NULL,
    hash      TEXT NOT NULL
);
CREATE INDEX dashboard_audit_tenant ON dashboard_audit (tenant_id, id);

CREATE TRIGGER dashboard_audit_no_update BEFORE UPDATE ON dashboard_audit
BEGIN
    SELECT RAISE(ABORT, 'the dashboard audit log is append-only');
END;

CREATE TRIGGER dashboard_audit_no_delete BEFORE DELETE ON dashboard_audit
BEGIN
    SELECT RAISE(ABORT, 'the dashboard audit log is append-only');
END;
