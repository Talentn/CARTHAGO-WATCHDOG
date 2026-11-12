-- Telemetry v2: map geometry, raw gameplay batches and per-slot summaries. Times are Unix
-- milliseconds.

-- Uploaded map geometry. A version is immutable: the gateway refuses a second upload of the
-- same (map_id, version) with a different hash.
CREATE TABLE IF NOT EXISTS maps (
    tenant_id  TEXT NOT NULL,
    map_id     TEXT NOT NULL,
    version    INTEGER NOT NULL,
    hash       TEXT NOT NULL,
    geometry   BLOB NOT NULL,
    created_ms BIGINT NOT NULL,
    PRIMARY KEY (tenant_id, map_id, version)
);

-- Raw v2 batches, kept for a short retention window so a flag can be re-scored and replayed.
-- Positions, view directions and sounds only: no chat, no voice, no client memory.
CREATE TABLE IF NOT EXISTS gameplay_batches (
    tenant_id   TEXT NOT NULL,
    match_id    TEXT NOT NULL,
    batch_seq   BIGINT NOT NULL,
    received_ms BIGINT NOT NULL,
    data        BLOB NOT NULL,
    PRIMARY KEY (tenant_id, match_id, batch_seq)
);
CREATE INDEX IF NOT EXISTS gameplay_batches_received ON gameplay_batches (received_ms);

-- One row per match slot: what v2 telemetry arrived and, after match_over, the leak score.
CREATE TABLE IF NOT EXISTS gameplay_sessions (
    tenant_id      TEXT NOT NULL,
    match_id       TEXT NOT NULL,
    slot           INTEGER NOT NULL,
    session_id     TEXT NOT NULL DEFAULT '',
    player_hash    TEXT NOT NULL DEFAULT '',
    team           INTEGER NOT NULL DEFAULT 0,
    device         TEXT NOT NULL DEFAULT '',
    aim_assist     BOOLEAN NOT NULL DEFAULT FALSE,
    mode           TEXT NOT NULL DEFAULT '',
    map_id         TEXT NOT NULL DEFAULT '',
    map_version    INTEGER NOT NULL DEFAULT 0,
    schema_version INTEGER NOT NULL DEFAULT 0,
    batches        BIGINT NOT NULL DEFAULT 0,
    motion_samples BIGINT NOT NULL DEFAULT 0,
    sounds         BIGINT NOT NULL DEFAULT 0,
    team_info      BIGINT NOT NULL DEFAULT 0,
    shots          BIGINT NOT NULL DEFAULT 0,
    dropped_events BIGINT NOT NULL DEFAULT 0,
    leak_scored    BOOLEAN NOT NULL DEFAULT FALSE,
    leak_score     REAL NOT NULL DEFAULT 0,
    leak_flagged   BOOLEAN NOT NULL DEFAULT FALSE,
    updated_ms     BIGINT NOT NULL,
    PRIMARY KEY (tenant_id, match_id, slot)
);
CREATE INDEX IF NOT EXISTS gameplay_sessions_session ON gameplay_sessions (tenant_id, session_id);
