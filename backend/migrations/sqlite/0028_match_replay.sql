-- The top-down recording of a match, for the dashboard's replay page. One row per match
-- that sent player positions; data is gzip-compressed JSON, capped in size by the gateway.
CREATE TABLE IF NOT EXISTS match_replays (
    tenant_id   TEXT NOT NULL,
    match_id    TEXT NOT NULL,
    started_ms  BIGINT NOT NULL,
    updated_ms  BIGINT NOT NULL,
    duration_ms BIGINT NOT NULL DEFAULT 0,
    samples     INTEGER NOT NULL DEFAULT 0,
    truncated   BOOLEAN NOT NULL DEFAULT FALSE,
    data        BLOB NOT NULL,
    PRIMARY KEY (tenant_id, match_id)
);
CREATE INDEX IF NOT EXISTS match_replays_updated ON match_replays (updated_ms);

-- Who played in a recorded match, so a player's and a session's recordings can be listed.
CREATE TABLE IF NOT EXISTS match_replay_players (
    tenant_id   TEXT NOT NULL,
    match_id    TEXT NOT NULL,
    slot        INTEGER NOT NULL,
    player_hash TEXT NOT NULL,
    session_id  TEXT NOT NULL DEFAULT '',
    bot         BOOLEAN NOT NULL DEFAULT FALSE,
    PRIMARY KEY (tenant_id, match_id, slot)
);
CREATE INDEX IF NOT EXISTS match_replay_players_player ON match_replay_players (tenant_id, player_hash);
CREATE INDEX IF NOT EXISTS match_replay_players_session ON match_replay_players (tenant_id, session_id);

-- The replay page lists a match's evidence.
CREATE INDEX IF NOT EXISTS evidence_match ON evidence (tenant_id, match_id, observed_ms);
