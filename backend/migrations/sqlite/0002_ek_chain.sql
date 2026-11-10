-- EK certificate chain verification against bundled manufacturer roots. Devices bound
-- before this migration keep '' and are re-checked on their next handshake.
ALTER TABLE devices ADD COLUMN ek_chain TEXT NOT NULL DEFAULT '';
ALTER TABLE devices ADD COLUMN ek_chain_root TEXT NOT NULL DEFAULT '';
