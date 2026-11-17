-- Reports players make about other players, sent by the studio's game server. Advice for
-- reviewers: nothing that scores, kicks, bans or pools a player reads this table.
--   match_ms  the moment in the match the report is about, -1 when none was given
--   note      free text a player typed: personal data, capped, deleted with the row
--   state     open, reviewed or dismissed
-- One report per reporter, reported player and match.
CREATE TABLE IF NOT EXISTS player_reports (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    tenant_id  TEXT NOT NULL,
    reporter   TEXT NOT NULL,
    reported   TEXT NOT NULL,
    match_id   TEXT NOT NULL,
    match_ms   BIGINT NOT NULL DEFAULT -1,
    reason     TEXT NOT NULL,
    note       TEXT NOT NULL DEFAULT '',
    state      TEXT NOT NULL DEFAULT 'open',
    created_ms BIGINT NOT NULL,
    decided_by TEXT NOT NULL DEFAULT '',
    decided_ms BIGINT NOT NULL DEFAULT 0
);
CREATE UNIQUE INDEX IF NOT EXISTS player_reports_once ON player_reports (tenant_id, reporter, reported, match_id);
CREATE INDEX IF NOT EXISTS player_reports_reported ON player_reports (tenant_id, reported, created_ms);
CREATE INDEX IF NOT EXISTS player_reports_state ON player_reports (tenant_id, state, created_ms);
CREATE INDEX IF NOT EXISTS player_reports_time ON player_reports (created_ms);
