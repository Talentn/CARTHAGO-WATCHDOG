-- Known cheat files: per studio, the SHA-256 of a file that is a cheat. A module of the
-- game whose file has one of these hashes is certain evidence, whatever the file is
-- called and wherever it sits. The list stays on the server. Times are Unix milliseconds.
CREATE TABLE IF NOT EXISTS known_cheats (
    id        INTEGER PRIMARY KEY AUTOINCREMENT,
    tenant_id TEXT NOT NULL,
    sha256    TEXT NOT NULL, -- 64 lower-case hex digits
    name      TEXT NOT NULL, -- what the cheat is called
    note      TEXT NOT NULL DEFAULT '',
    added_by  TEXT NOT NULL,
    added_ms  BIGINT NOT NULL,
    UNIQUE (tenant_id, sha256)
);
