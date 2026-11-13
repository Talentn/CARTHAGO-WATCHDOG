-- Carthago Oracle: the behaviour model's score per session, the analyst's advisory verdict,
-- per-tenant analyst usage and reviewers' session labels. Times are Unix milliseconds.
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

-- A reviewer's label on a session: what a person concluded after looking at it. It is the
-- ground truth a studio's own tuning data is built from. A label is a note for the studio:
-- it never kicks or bans, and adds nothing to a player's risk.
CREATE TABLE IF NOT EXISTS session_labels (
    tenant_id   TEXT NOT NULL,
    session_id  TEXT NOT NULL,
    player_hash TEXT NOT NULL,
    label       TEXT NOT NULL, -- confirmed_cheat | cleared | unsure
    cheat_type  TEXT NOT NULL DEFAULT '',
    note        TEXT NOT NULL DEFAULT '',
    reviewer    TEXT NOT NULL DEFAULT '', -- the name the reviewer gave
    labelled_ms BIGINT NOT NULL,
    PRIMARY KEY (tenant_id, session_id)
);
CREATE INDEX IF NOT EXISTS session_labels_player ON session_labels (tenant_id, player_hash, labelled_ms);

-- Every change to a label, in order, never rewritten: who set what, when and from where.
CREATE TABLE IF NOT EXISTS session_label_audit (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    tenant_id  TEXT NOT NULL,
    session_id TEXT NOT NULL,
    action     TEXT NOT NULL, -- set | accept_suggestion | remove
    label      TEXT NOT NULL DEFAULT '',
    cheat_type TEXT NOT NULL DEFAULT '',
    note       TEXT NOT NULL DEFAULT '',
    reviewer   TEXT NOT NULL DEFAULT '',
    remote     TEXT NOT NULL DEFAULT '', -- address the request came from
    at_ms      BIGINT NOT NULL
);
CREATE INDEX IF NOT EXISTS session_label_audit_session ON session_label_audit (tenant_id, session_id, id);
