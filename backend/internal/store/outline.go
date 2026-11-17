package store

import (
	"context"
	"database/sql"
	"errors"
	"sort"
	"time"
)

// MapOutline is the outline of one map a studio registered for the match replay
// (internal/outline). A drawing aid: no rule reads it.
type MapOutline struct {
	TenantID string
	MapID    string
	Kind     string // OutlineLines or OutlineImage
	// Lines is JSON [[x0,y0,x1,y1],...] in centimetres and Segments their number (lines).
	Lines    string
	Segments int
	// PNG is the picture as the gateway wrote it out again, Width x Height pixels (image).
	PNG           []byte
	Width, Height int
	// Rect is the world rectangle, min x, min y, max x, max y in centimetres: the one the
	// picture covers, or the one around the lines.
	Rect      [4]int32
	UpdatedBy string
	UpdatedAt time.Time
}

const (
	OutlineLines = "lines"
	OutlineImage = "image"
)

// MapOutlineStore keeps one outline per studio and map.
type MapOutlineStore interface {
	// PutMapOutline stores an outline, replacing the map's previous one.
	PutMapOutline(ctx context.Context, o *MapOutline) error
	GetMapOutline(ctx context.Context, tenant, mapID string) (*MapOutline, error)
	// ListMapOutlines returns a studio's outlines by map name, without lines or picture.
	ListMapOutlines(ctx context.Context, tenant string) ([]MapOutline, error)
	// DeleteMapOutline removes an outline; ErrNotFound when the studio has none for the map.
	DeleteMapOutline(ctx context.Context, tenant, mapID string) error
}

var (
	_ MapOutlineStore = (*SQLite)(nil)
	_ MapOutlineStore = (*Memory)(nil)
)

func (s *SQLite) PutMapOutline(ctx context.Context, o *MapOutline) error {
	_, err := s.db.ExecContext(ctx, `INSERT INTO map_outlines (tenant_id, map_id, kind, lines, segments, png, width, height, min_x, min_y, max_x, max_y, updated_by, updated_ms)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
		ON CONFLICT (tenant_id, map_id) DO UPDATE SET kind = excluded.kind, lines = excluded.lines, segments = excluded.segments, png = excluded.png,
			width = excluded.width, height = excluded.height, min_x = excluded.min_x, min_y = excluded.min_y, max_x = excluded.max_x, max_y = excluded.max_y,
			updated_by = excluded.updated_by, updated_ms = excluded.updated_ms`,
		o.TenantID, o.MapID, o.Kind, o.Lines, o.Segments, o.PNG, o.Width, o.Height, o.Rect[0], o.Rect[1], o.Rect[2], o.Rect[3], o.UpdatedBy, ms(o.UpdatedAt))
	return err
}

func (s *SQLite) GetMapOutline(ctx context.Context, tenant, mapID string) (*MapOutline, error) {
	o := MapOutline{TenantID: tenant, MapID: mapID}
	var at int64
	err := s.db.QueryRowContext(ctx, `SELECT kind, lines, segments, png, width, height, min_x, min_y, max_x, max_y, updated_by, updated_ms
		FROM map_outlines WHERE tenant_id = ? AND map_id = ?`, tenant, mapID).
		Scan(&o.Kind, &o.Lines, &o.Segments, &o.PNG, &o.Width, &o.Height, &o.Rect[0], &o.Rect[1], &o.Rect[2], &o.Rect[3], &o.UpdatedBy, &at)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	o.UpdatedAt = fromMS(at)
	return &o, nil
}

func (s *SQLite) ListMapOutlines(ctx context.Context, tenant string) ([]MapOutline, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT map_id, kind, segments, width, height, min_x, min_y, max_x, max_y, updated_by, updated_ms
		FROM map_outlines WHERE tenant_id = ? ORDER BY map_id`, tenant)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []MapOutline
	for rows.Next() {
		o := MapOutline{TenantID: tenant}
		var at int64
		if err := rows.Scan(&o.MapID, &o.Kind, &o.Segments, &o.Width, &o.Height, &o.Rect[0], &o.Rect[1], &o.Rect[2], &o.Rect[3], &o.UpdatedBy, &at); err != nil {
			return nil, err
		}
		o.UpdatedAt = fromMS(at)
		out = append(out, o)
	}
	return out, rows.Err()
}

func (s *SQLite) DeleteMapOutline(ctx context.Context, tenant, mapID string) error {
	res, err := s.db.ExecContext(ctx, `DELETE FROM map_outlines WHERE tenant_id = ? AND map_id = ?`, tenant, mapID)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return ErrNotFound
	}
	return nil
}

func (m *Memory) PutMapOutline(_ context.Context, o *MapOutline) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.outlines == nil {
		m.outlines = map[[2]string]MapOutline{}
	}
	c := *o
	c.PNG = append([]byte(nil), o.PNG...)
	m.outlines[[2]string{o.TenantID, o.MapID}] = c
	return nil
}

func (m *Memory) GetMapOutline(_ context.Context, tenant, mapID string) (*MapOutline, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	o, ok := m.outlines[[2]string{tenant, mapID}]
	if !ok {
		return nil, ErrNotFound
	}
	if len(o.PNG) == 0 {
		o.PNG = nil
	}
	return &o, nil
}

func (m *Memory) ListMapOutlines(_ context.Context, tenant string) ([]MapOutline, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	var out []MapOutline
	for k, o := range m.outlines {
		if k[0] == tenant {
			o.Lines, o.PNG = "", nil
			out = append(out, o)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].MapID < out[j].MapID })
	return out, nil
}

func (m *Memory) DeleteMapOutline(_ context.Context, tenant, mapID string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	k := [2]string{tenant, mapID}
	if _, ok := m.outlines[k]; !ok {
		return ErrNotFound
	}
	delete(m.outlines, k)
	return nil
}
