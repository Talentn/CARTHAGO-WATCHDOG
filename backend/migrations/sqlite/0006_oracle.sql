-- Carthago Oracle: the behaviour model's score per session, the analyst's advisory verdict,
-- per-tenant analyst usage and human review labels. Times are Unix milliseconds.
--
-- Nothing here is evidence: these rows never add to a player's risk and never kick. The
-- features and case_file columns are for the gateway only (re-scoring, review, dataset
-- export); the dashboard does not render them.

-- One row per session: the score of its highest-scoring match together with its client
-- evidence, or of its client evidence alone when it has played no match.
CREATE TABLE IF NOT EXISTS oracle_scores (
    tenant_id       TEXT NOT NULL,
    session_id      TEXT NOT NULL,
    player_hash     TEXT NOT NULL,
    match_id        TEXT NOT NULL DEFAULT '',
    model_id        TEXT NOT NULL,
    feature_version INTEGER NOT NULL,
    score           REAL NOT NULL,
    band            TEXT NOT NULL, -- clear | watch | review
    signals         TEXT NOT NULL DEFAULT '', -- JSON: the top contributing signals, by label
    features        TEXT NOT NULL DEFAULT '', -- JSON: the feature vector
    updated_ms      BIGINT NOT NULL,
    PRIMARY KEY (tenant_id, session_id)
);
CREATE INDEX IF NOT EXISTS oracle_scores_player ON oracle_scores (tenant_id, player_hash, updated_ms);

-- The analyst's latest verdict per session. An opinion for a reviewer, shown next to the
-- evidence it cites.
CREATE TABLE IF NOT EXISTS oracle_verdicts (
    tenant_id      TEXT NOT NULL,
    session_id     TEXT NOT NULL,
    player_hash    TEXT NOT NULL,
    case_hash      TEXT NOT NULL,
    status         TEXT NOT NULL, -- ok | unavailable
    reason         TEXT NOT NULL DEFAULT '',
    provider       TEXT NOT NULL DEFAULT '',
    analyst_model  TEXT NOT NULL DEFAULT '',
    prompt_version TEXT NOT NULL DEFAULT '',
    cheat_type     TEXT NOT NULL DEFAULT '',
    confidence     INTEGER NOT NULL DEFAULT 0, -- 0..100
    action         TEXT NOT NULL DEFAULT '',
    summary        TEXT NOT NULL DEFAULT '',
    cited          TEXT NOT NULL DEFAULT '', -- JSON list of evidence ids
    case_file      TEXT NOT NULL DEFAULT '', -- the pseudonymised case the analyst saw
    latency_ms     BIGINT NOT NULL DEFAULT 0,
    tokens_in      BIGINT NOT NULL DEFAULT 0,
    tokens_out     BIGINT NOT NULL DEFAULT 0,
    created_ms     BIGINT NOT NULL,
    PRIMARY KEY (tenant_id, session_id)
);
CREATE INDEX IF NOT EXISTS oracle_verdicts_player ON oracle_verdicts (tenant_id, player_hash, created_ms);

-- Analyst calls and tokens per tenant and UTC day, for the per-tenant caps.
CREATE TABLE IF NOT EXISTS oracle_usage (
    tenant_id TEXT NOT NULL,
    day       TEXT NOT NULL, -- YYYY-MM-DD, UTC
    cases     BIGINT NOT NULL DEFAULT 0,
    tokens    BIGINT NOT NULL DEFAULT 0,
    PRIMARY KEY (tenant_id, day)
);

-- A reviewer's own conclusion about a case, for exporting a tuning dataset.
CREATE TABLE IF NOT EXISTS oracle_reviews (
    tenant_id   TEXT NOT NULL,
    session_id  TEXT NOT NULL,
    case_hash   TEXT NOT NULL,
    cheat_type  TEXT NOT NULL,
    action      TEXT NOT NULL DEFAULT '',
    note        TEXT NOT NULL DEFAULT '',
    reviewed_ms BIGINT NOT NULL,
    PRIMARY KEY (tenant_id, session_id)
);
