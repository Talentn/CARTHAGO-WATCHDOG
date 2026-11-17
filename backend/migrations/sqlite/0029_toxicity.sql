-- Behaviour findings: team damage, team kills, standing idle, leaving early and feeding,
-- read from what the game server reports about a match. Advice for a studio's community
-- team. This table is separate from evidence on purpose: nothing that scores, kicks, bans
-- or pools a player reads it.
--   count     hits, kills, idle seconds, percent of the match missed, or deaths
--   match_ms  the moment in the match to look at
CREATE TABLE IF NOT EXISTS toxicity_findings (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    tenant_id   TEXT NOT NULL,
    player_hash TEXT NOT NULL,
    session_id  TEXT NOT NULL DEFAULT '',
    match_id    TEXT NOT NULL,
    slot        INTEGER NOT NULL,
    kind        TEXT NOT NULL,
    count       INTEGER NOT NULL DEFAULT 0,
    match_ms    BIGINT NOT NULL DEFAULT 0,
    summary     TEXT NOT NULL,
    bot         BOOLEAN NOT NULL DEFAULT FALSE,
    observed_ms BIGINT NOT NULL
);
CREATE INDEX IF NOT EXISTS toxicity_player ON toxicity_findings (tenant_id, player_hash, observed_ms);
CREATE INDEX IF NOT EXISTS toxicity_match ON toxicity_findings (tenant_id, match_id);
CREATE INDEX IF NOT EXISTS toxicity_time ON toxicity_findings (observed_ms);

-- A studio's own limits for the behaviour findings, as JSON. No row: the defaults.
CREATE TABLE IF NOT EXISTS toxicity_settings (
    tenant_id  TEXT PRIMARY KEY,
    limits     TEXT NOT NULL,
    updated_ms BIGINT NOT NULL
);
