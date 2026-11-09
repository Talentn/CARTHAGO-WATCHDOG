-- Gateway schema v1. Times are Unix milliseconds. The Postgres migration (Phase 1) keeps the
-- same tables and columns, with BYTEA for BLOB and TIMESTAMPTZ for the *_ms columns.

CREATE TABLE IF NOT EXISTS devices (
    device_id        TEXT PRIMARY KEY,
    tenant_id        TEXT NOT NULL,
    key_alg          INTEGER NOT NULL,
    public_key       BLOB NOT NULL,
    ak_public        BLOB,
    ek_public_sha256 TEXT NOT NULL DEFAULT '',
    ek_cert_matches  BOOLEAN NOT NULL DEFAULT FALSE,
    bound_via        TEXT NOT NULL DEFAULT '',
    first_seen_ms    BIGINT NOT NULL,
    last_seen_ms     BIGINT NOT NULL
);
CREATE INDEX IF NOT EXISTS devices_tenant ON devices (tenant_id);

CREATE TABLE IF NOT EXISTS sessions (
    session_id        TEXT PRIMARY KEY,
    tenant_id         TEXT NOT NULL,
    player_hash       TEXT NOT NULL,
    device_id         TEXT NOT NULL REFERENCES devices (device_id),
    trust_level       INTEGER NOT NULL,
    attest_flags      BIGINT NOT NULL,
    state             TEXT NOT NULL,
    kick_reason       TEXT NOT NULL DEFAULT '',
    created_ms        BIGINT NOT NULL,
    expires_ms        BIGINT NOT NULL,
    last_heartbeat_ms BIGINT NOT NULL,
    heartbeats        BIGINT NOT NULL DEFAULT 0
);
CREATE INDEX IF NOT EXISTS sessions_player ON sessions (tenant_id, player_hash);

-- Derived booleans only (plan §10): raw boot logs are not retained.
CREATE TABLE IF NOT EXISTS attestations (
    session_id     TEXT NOT NULL REFERENCES sessions (session_id),
    device_id      TEXT NOT NULL REFERENCES devices (device_id),
    verified_ms    BIGINT NOT NULL,
    quote_ok       BOOLEAN NOT NULL,
    secure_boot    BOOLEAN NOT NULL,
    hvci           BOOLEAN NOT NULL,
    test_signing   BOOLEAN NOT NULL,
    kernel_debug   BOOLEAN NOT NULL,
    boot_debug     BOOLEAN NOT NULL,
    code_integrity TEXT NOT NULL,
    ranked_policy  BOOLEAN NOT NULL,
    failures       TEXT NOT NULL DEFAULT ''
);
