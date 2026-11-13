-- Bans: per studio, an account and the device key it was last seen with are refused at the
-- handshake. Times are Unix milliseconds.

-- One row per ban. A ban names the player account (player_hash) and, when it was made from
-- a session, that session's device key (device_id). Either one matching refuses a
-- handshake. effective_ms is later than banned_ms for an automatic ban made while the
-- studio has a delay set: the ban is pending until then. lifted_ms is 0 while the ban
-- stands; a lifted ban is kept as history.
CREATE TABLE IF NOT EXISTS bans (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    tenant_id    TEXT NOT NULL,
    ref          TEXT NOT NULL, -- the reference a banned player is shown
    player_hash  TEXT NOT NULL,
    device_id    TEXT NOT NULL DEFAULT '',
    device_tpm   BOOLEAN NOT NULL DEFAULT FALSE, -- the device key lives in a TPM
    reason       TEXT NOT NULL DEFAULT '',
    rule         TEXT NOT NULL DEFAULT '', -- the rule or category behind it, if any
    session_id   TEXT NOT NULL DEFAULT '',
    banned_by    TEXT NOT NULL, -- a dashboard account, or "automatic"
    banned_ms    BIGINT NOT NULL,
    effective_ms BIGINT NOT NULL,
    lifted_by    TEXT NOT NULL DEFAULT '',
    lifted_ms    BIGINT NOT NULL DEFAULT 0,
    lift_note    TEXT NOT NULL DEFAULT ''
);
CREATE INDEX IF NOT EXISTS bans_player ON bans (tenant_id, player_hash, lifted_ms);
CREATE INDEX IF NOT EXISTS bans_device ON bans (tenant_id, device_id, lifted_ms);
CREATE INDEX IF NOT EXISTS bans_tenant ON bans (tenant_id, id);

-- Per studio: how long an automatic ban waits before it takes effect.
CREATE TABLE IF NOT EXISTS ban_settings (
    tenant_id      TEXT PRIMARY KEY,
    auto_delay_min INTEGER NOT NULL DEFAULT 0
);
