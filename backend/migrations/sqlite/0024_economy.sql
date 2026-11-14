-- Economy ledger: what a studio's game servers report about in-game money and items, kept
-- per player and currency so that money nobody reported can be told from money that was
-- earned. Amounts are whole numbers of the currency's smallest unit. Times are Unix
-- milliseconds.

-- One row per reported change. event_id is the game server's own id for the change and
-- makes a repeated report harmless. dirty is the part of a credit that should not exist:
-- money no report explains, or money received from a banned player (dirty_from).
CREATE TABLE IF NOT EXISTS economy_entries (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    tenant_id    TEXT NOT NULL,
    event_id     TEXT NOT NULL,
    player_hash  TEXT NOT NULL,
    currency     TEXT NOT NULL,
    amount       BIGINT NOT NULL, -- positive: received, negative: spent or given
    source       TEXT NOT NULL DEFAULT '',
    counterparty TEXT NOT NULL DEFAULT '',
    at_ms        BIGINT NOT NULL, -- the game server's time of the change
    received_ms  BIGINT NOT NULL,
    dirty        BIGINT NOT NULL DEFAULT 0,
    dirty_from   TEXT NOT NULL DEFAULT '',
    UNIQUE (tenant_id, event_id)
);
CREATE INDEX IF NOT EXISTS economy_entries_player ON economy_entries (tenant_id, player_hash, currency, at_ms);
CREATE INDEX IF NOT EXISTS economy_entries_counterparty ON economy_entries (tenant_id, counterparty, at_ms);
CREATE INDEX IF NOT EXISTS economy_entries_dirty ON economy_entries (tenant_id, dirty_from) WHERE dirty > 0;

-- What the ledger found. certain flags ban through the ban service; the others are for a
-- person to look at.
CREATE TABLE IF NOT EXISTS economy_flags (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    tenant_id   TEXT NOT NULL,
    player_hash TEXT NOT NULL,
    rule        TEXT NOT NULL,
    certain     BOOLEAN NOT NULL DEFAULT FALSE,
    currency    TEXT NOT NULL DEFAULT '',
    amount      BIGINT NOT NULL DEFAULT 0,
    source      TEXT NOT NULL DEFAULT '',
    summary     TEXT NOT NULL DEFAULT '',
    event_id    TEXT NOT NULL DEFAULT '',
    ban_ref     TEXT NOT NULL DEFAULT '',
    at_ms       BIGINT NOT NULL
);
CREATE INDEX IF NOT EXISTS economy_flags_tenant ON economy_flags (tenant_id, id);
CREATE INDEX IF NOT EXISTS economy_flags_player ON economy_flags (tenant_id, player_hash, id);

-- The studio's earning limits per source and currency; 0 is no limit. A row also makes
-- its source a known one.
CREATE TABLE IF NOT EXISTS economy_limits (
    tenant_id TEXT NOT NULL,
    source    TEXT NOT NULL,
    currency  TEXT NOT NULL,
    per_hour  BIGINT NOT NULL DEFAULT 0,
    per_day   BIGINT NOT NULL DEFAULT 0,
    PRIMARY KEY (tenant_id, source, currency)
);

-- Per studio: how far a reported balance may be from the ledger.
CREATE TABLE IF NOT EXISTS economy_settings (
    tenant_id TEXT PRIMARY KEY,
    tolerance BIGINT NOT NULL DEFAULT 0
);
