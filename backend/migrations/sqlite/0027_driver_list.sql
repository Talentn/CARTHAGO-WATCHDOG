-- The driver list of a session: what the client sent of Windows' signed list of kernel
-- drivers loaded since boot, and how the gateway read it. One row per session, written at
-- the handshake, also when the client had no list to send.
--   status   'verified'    the signature checked out under the signing key of the
--                          session's verified boot record
--            'unverified'  the list parsed and there was no such key to check it with
--            'unavailable' the client could not get a list from Windows; reason says why
--            'rejected'    the package is malformed, for another handshake, or badly signed
--            'not_sent'    a client that predates the driver list
--   drivers  the list as JSON, in load order, each driver with the flags raised for it
CREATE TABLE IF NOT EXISTS session_drivers (
    tenant_id    TEXT NOT NULL,
    session_id   TEXT NOT NULL,
    player_hash  TEXT NOT NULL,
    trust_level  INTEGER NOT NULL DEFAULT 0,
    status       TEXT NOT NULL,
    reason       TEXT NOT NULL DEFAULT '',
    overflowed   BOOLEAN NOT NULL DEFAULT FALSE,
    test_signing BOOLEAN NOT NULL DEFAULT FALSE,
    flagged      INTEGER NOT NULL DEFAULT 0,
    drivers      TEXT NOT NULL DEFAULT '[]',
    received_ms  BIGINT NOT NULL,
    PRIMARY KEY (tenant_id, session_id)
);
CREATE INDEX IF NOT EXISTS session_drivers_player ON session_drivers (tenant_id, player_hash, received_ms);

-- Per studio: whether the game-server status call also says "attested" or "unattested"
-- per player. Off unless a row says otherwise.
CREATE TABLE IF NOT EXISTS attestation_settings (
    tenant_id       TEXT PRIMARY KEY,
    unattested_pool BOOLEAN NOT NULL DEFAULT FALSE
);
