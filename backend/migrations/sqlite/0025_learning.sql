-- Learning from bans. A session label can come from a ban instead of a reviewer: it then
-- names the ban, and lifting the ban removes it.
ALTER TABLE session_labels ADD COLUMN source TEXT NOT NULL DEFAULT ''; -- '' a reviewer | ban
ALTER TABLE session_labels ADD COLUMN ban_ref TEXT NOT NULL DEFAULT '';

-- Proposed known cheats: files seen only in banned accounts. A proposal is worked out from
-- the stored evidence when it is asked for; what is kept is the studio's threshold and
-- the proposals a reviewer dismissed. Times are Unix milliseconds.
CREATE TABLE IF NOT EXISTS cheat_proposal_settings (
    tenant_id    TEXT PRIMARY KEY,
    min_accounts INTEGER NOT NULL -- distinct banned accounts a file must be seen in
);
CREATE TABLE IF NOT EXISTS cheat_proposal_dismissals (
    tenant_id    TEXT NOT NULL,
    sha256       TEXT NOT NULL,
    dismissed_by TEXT NOT NULL,
    dismissed_ms BIGINT NOT NULL,
    PRIMARY KEY (tenant_id, sha256)
);
