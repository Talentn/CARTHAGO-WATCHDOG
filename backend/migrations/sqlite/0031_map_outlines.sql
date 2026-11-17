-- The outline of a map a studio registered for the match replay: its walls as line
-- segments, or a picture with the world rectangle it covers. A drawing aid: no rule
-- reads it.
--   kind      lines or image
--   lines     JSON [[x0,y0,x1,y1],...] in centimetres (kind lines)
--   png       the picture as the gateway wrote it out again (kind image)
--   min_x..   the world rectangle: of the picture, or around the lines
CREATE TABLE IF NOT EXISTS map_outlines (
    tenant_id  TEXT NOT NULL,
    map_id     TEXT NOT NULL,
    kind       TEXT NOT NULL,
    lines      TEXT NOT NULL DEFAULT '',
    segments   INTEGER NOT NULL DEFAULT 0,
    png        BLOB,
    width      INTEGER NOT NULL DEFAULT 0,
    height     INTEGER NOT NULL DEFAULT 0,
    min_x      INTEGER NOT NULL DEFAULT 0,
    min_y      INTEGER NOT NULL DEFAULT 0,
    max_x      INTEGER NOT NULL DEFAULT 0,
    max_y      INTEGER NOT NULL DEFAULT 0,
    updated_by TEXT NOT NULL DEFAULT '',
    updated_ms BIGINT NOT NULL,
    PRIMARY KEY (tenant_id, map_id)
);
