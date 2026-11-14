-- The shadow pool. While a studio's shadow period is on, an automatic ban does not refuse
-- the player at once: it is made with effective_ms at the end of the period and shadow = 1,
-- and until then the player is in the pool. landed_ms is when the gateway applied the ban
-- (the end of the period, or a reviewer's "Ban now"); 0 while the player is in the pool.
-- shadow_of is empty for the player who was caught; for another account that connected
-- from that player's device key it is the reference of that player's ban.
ALTER TABLE bans ADD COLUMN shadow BOOLEAN NOT NULL DEFAULT FALSE;
ALTER TABLE bans ADD COLUMN shadow_of TEXT NOT NULL DEFAULT '';
ALTER TABLE bans ADD COLUMN landed_ms BIGINT NOT NULL DEFAULT 0;
CREATE INDEX IF NOT EXISTS bans_shadow ON bans (shadow, lifted_ms, landed_ms);

-- Per studio: the shadow period in seconds. 0 is off: an automatic ban is immediate, or
-- waits auto_delay_min.
ALTER TABLE ban_settings ADD COLUMN shadow_s BIGINT NOT NULL DEFAULT 0;
