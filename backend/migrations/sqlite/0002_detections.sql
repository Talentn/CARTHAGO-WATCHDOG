-- Phase 1 detections: evidence from client findings and gameplay rules, per-session scanner
-- telemetry, and match ingest progress. Times are Unix milliseconds.

-- One row per (rule verdict, player). Client evidence keeps the raw finding fields in raw;
-- gameplay evidence keeps the match id. Never stores memory contents or file paths beyond a
-- module base name (plan §10).
CREATE TABLE IF NOT EXISTS evidence (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    tenant_id   TEXT NOT NULL,
    player_hash TEXT NOT NULL,
    session_id  TEXT NOT NULL DEFAULT '',
    match_id    TEXT NOT NULL DEFAULT '',
    source      TEXT NOT NULL, -- client | gameplay
    rule        TEXT NOT NULL,
    severity    INTEGER NOT NULL, -- 0 info .. 4 critical
    score       REAL NOT NULL,
    integrity   BOOLEAN NOT NULL,
    summary     TEXT NOT NULL,
    raw         TEXT NOT NULL DEFAULT '',
    observed_ms BIGINT NOT NULL
);
CREATE INDEX IF NOT EXISTS evidence_tenant_time ON evidence (tenant_id, observed_ms);
CREATE INDEX IF NOT EXISTS evidence_player ON evidence (tenant_id, player_hash, observed_ms);
CREATE INDEX IF NOT EXISTS evidence_session ON evidence (session_id);

-- Latest scanner health per session, overwritten on each heartbeat.
CREATE TABLE IF NOT EXISTS session_telemetry (
    session_id          TEXT PRIMARY KEY,
    updated_ms          BIGINT NOT NULL,
    activity            INTEGER NOT NULL,
    worker_cpu_ns       BIGINT NOT NULL,
    slices              BIGINT NOT NULL,
    slice_cpu_max_ns    BIGINT NOT NULL,
    slice_overruns      BIGINT NOT NULL,
    frames              BIGINT NOT NULL,
    jobs_quarantined    INTEGER NOT NULL,
    findings_dropped    BIGINT NOT NULL,
    findings_total      BIGINT NOT NULL,
    input_thread_cpu_ns BIGINT NOT NULL,
    mouse_events        BIGINT NOT NULL,
    injected_events     BIGINT NOT NULL,
    mitigations_applied BIGINT NOT NULL,
    mitigations_failed  BIGINT NOT NULL,
    coverage            TEXT NOT NULL DEFAULT ''
);

-- Gameplay ingest progress: batch_seq is strictly increasing per match, so a retried batch
-- is recognised and acknowledged without being analysed twice.
CREATE TABLE IF NOT EXISTS matches (
    tenant_id      TEXT NOT NULL,
    match_id       TEXT NOT NULL,
    last_batch_seq BIGINT NOT NULL,
    started_ms     BIGINT NOT NULL,
    updated_ms     BIGINT NOT NULL,
    over           BOOLEAN NOT NULL DEFAULT FALSE,
    PRIMARY KEY (tenant_id, match_id)
);

CREATE INDEX IF NOT EXISTS sessions_tenant_time ON sessions (tenant_id, created_ms);
