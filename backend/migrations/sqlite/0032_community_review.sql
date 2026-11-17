-- Community review: players watch the anonymised replay of a suspicious match and give a
-- verdict (internal/review). Everything here is advice for the studio's reviewers. No
-- rule, no ban, no shadow pool and no Oracle baseline reads these tables.

-- One row per studio; no row means off, with the defaults.
CREATE TABLE IF NOT EXISTS review_settings (
    tenant_id     TEXT PRIMARY KEY,
    enabled       INTEGER NOT NULL DEFAULT 0,
    quorum        INTEGER NOT NULL DEFAULT 5,
    agreement     REAL NOT NULL DEFAULT 0.7,
    report_weight REAL NOT NULL DEFAULT 1.0,
    updated_ms    BIGINT NOT NULL DEFAULT 0
);

-- A case is one suspect in one recorded match.
--   source      oracle | reports | finding | calibration
--   calibration 1 for a case with a known answer (expected), mixed in to score reviewers
--   state       open | decided | undecided
--   verdict     what the reviewers agreed on: cheating | toxic | insufficient
--   kind        for cheating, the kind most of them named: aim | walls | other
--   decision    what the studio made of a decided case: confirmed | dismissed
CREATE TABLE IF NOT EXISTS review_cases (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    tenant_id   TEXT NOT NULL,
    match_id    TEXT NOT NULL,
    suspect     TEXT NOT NULL,
    source      TEXT NOT NULL,
    calibration INTEGER NOT NULL DEFAULT 0,
    expected    TEXT NOT NULL DEFAULT '',
    state       TEXT NOT NULL DEFAULT 'open',
    verdict     TEXT NOT NULL DEFAULT '',
    kind        TEXT NOT NULL DEFAULT '',
    agreement   REAL NOT NULL DEFAULT 0,
    created_ms  BIGINT NOT NULL,
    closed_ms   BIGINT NOT NULL DEFAULT 0,
    decision    TEXT NOT NULL DEFAULT '',
    decided_by  TEXT NOT NULL DEFAULT '',
    decided_ms  BIGINT NOT NULL DEFAULT 0
);
CREATE UNIQUE INDEX IF NOT EXISTS review_cases_once ON review_cases (tenant_id, match_id, suspect);
CREATE INDEX IF NOT EXISTS review_cases_state ON review_cases (tenant_id, state, created_ms);

-- A case handed to one reviewer, and that reviewer's verdict once given.
--   verdict  cheating_aim | cheating_walls | cheating_other | toxic | insufficient; '' until given
--   weight   the reviewer's weight when the verdict was given
--   outcome  correct | wrong once the answer is known (calibration, or the studio's decision)
CREATE TABLE IF NOT EXISTS review_assignments (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    tenant_id   TEXT NOT NULL,
    case_id     INTEGER NOT NULL,
    reviewer    TEXT NOT NULL,
    suspect     TEXT NOT NULL,
    calibration INTEGER NOT NULL DEFAULT 0,
    assigned_ms BIGINT NOT NULL,
    expires_ms  BIGINT NOT NULL,
    verdict     TEXT NOT NULL DEFAULT '',
    weight      REAL NOT NULL DEFAULT 0,
    voted_ms    BIGINT NOT NULL DEFAULT 0,
    outcome     TEXT NOT NULL DEFAULT ''
);
CREATE UNIQUE INDEX IF NOT EXISTS review_assignments_once ON review_assignments (tenant_id, case_id, reviewer);
CREATE INDEX IF NOT EXISTS review_assignments_reviewer ON review_assignments (tenant_id, reviewer, assigned_ms);

-- A badge a reviewer earned. delivered_ms is set when the studio's game server says it
-- has seen the badge, so it can grant whatever it grants once.
CREATE TABLE IF NOT EXISTS review_badges (
    tenant_id    TEXT NOT NULL,
    reviewer     TEXT NOT NULL,
    badge        TEXT NOT NULL,
    earned_ms    BIGINT NOT NULL,
    delivered_ms BIGINT NOT NULL DEFAULT 0,
    PRIMARY KEY (tenant_id, reviewer, badge)
);
