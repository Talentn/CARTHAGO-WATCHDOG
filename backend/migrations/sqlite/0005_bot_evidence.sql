-- Gameplay evidence about Computer-controlled slots (MatchPlayer.bot). Kept for review, excluded from
-- every risk, flag and session count.
ALTER TABLE evidence ADD COLUMN bot BOOLEAN NOT NULL DEFAULT FALSE;
