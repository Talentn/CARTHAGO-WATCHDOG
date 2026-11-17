package gateway

import (
	"errors"
	"io"
	"mime"
	"net/http"

	"carthago/backend/internal/outline"
	"carthago/backend/internal/store"
)

// POST /v1/maps registers the outline of one map for the match replay, under the tenant's
// server key like /v1/reports ("Authorization: Bearer <key>"). One outline per map; a
// second upload replaces the first. Two forms, told apart by Content-Type and nothing else:
//
//	application/json  {"map":"name","lines":[[x0,y0,x1,y1],...]}   wall lines, centimetres
//	image/png         ?map=name&rect=min_x,min_y,max_x,max_y       a picture and the world
//	                                                               rectangle it covers
//
// It answers 201 {"map","kind","segments" or "width","height","rect"}, 400 for an outline
// it does not take, 413 for one over the size cap and 415 for any other content type. An
// outline is drawn under the replay and changes nothing else.
func (g *Gateway) handleMapPut(w http.ResponseWriter, r *http.Request) {
	tenant, ok := g.economyTenant(w, r)
	if !ok {
		return
	}
	kind, _, _ := mime.ParseMediaType(r.Header.Get("Content-Type"))
	limit := int64(0)
	switch kind {
	case "application/json":
		limit = outline.MaxLinesBytes
	case "image/png":
		limit = outline.MaxPNGBytes
	default:
		economyError(w, http.StatusUnsupportedMediaType, "send wall lines as application/json or a picture as image/png")
		return
	}
	body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, limit))
	if err != nil {
		var tooBig *http.MaxBytesError
		if errors.As(err, &tooBig) {
			economyError(w, http.StatusRequestEntityTooLarge, "the outline is larger than this call takes")
			return
		}
		economyError(w, http.StatusBadRequest, "the body could not be read")
		return
	}
	q := r.URL.Query()
	var o *store.MapOutline
	if kind == "application/json" {
		o, err = outline.Lines(q.Get("map"), body)
	} else {
		var rect [4]int32
		if rect, err = outline.ParseRect(q.Get("rect")); err == nil {
			o, err = outline.Picture(q.Get("map"), body, rect)
		}
	}
	if err == nil {
		err = outline.Put(r.Context(), g.cfg.Maps, tenant, o, "game server", g.cfg.Now())
	}
	if msg, bad := outline.IsError(err); bad {
		economyError(w, http.StatusBadRequest, msg)
		return
	}
	if err != nil {
		g.log.Warn("map outline", "tenant", tenant, "err", err)
		economyError(w, http.StatusInternalServerError, "the outline could not be stored; send it again")
		return
	}
	g.log.Info("map outline", "tenant", tenant, "map", o.MapID, "kind", o.Kind, "segments", o.Segments, "width", o.Width, "height", o.Height)
	economyJSON(w, http.StatusCreated, mapJSON(o))
}

type mapOut struct {
	Map      string   `json:"map"`
	Kind     string   `json:"kind"`
	Segments int      `json:"segments,omitempty"`
	Width    int      `json:"width,omitempty"`
	Height   int      `json:"height,omitempty"`
	Rect     [4]int32 `json:"rect"`
}

func mapJSON(o *store.MapOutline) mapOut {
	return mapOut{Map: o.MapID, Kind: o.Kind, Segments: o.Segments, Width: o.Width, Height: o.Height, Rect: o.Rect}
}

// GET /v1/maps answers {"maps":[...]}: the tenant's outlines, without lines or pictures.
func (g *Gateway) handleMapList(w http.ResponseWriter, r *http.Request) {
	tenant, ok := g.economyTenant(w, r)
	if !ok {
		return
	}
	rows, err := g.cfg.Maps.ListMapOutlines(r.Context(), tenant)
	if err != nil {
		economyError(w, http.StatusInternalServerError, "the outlines could not be read")
		return
	}
	out := make([]mapOut, 0, len(rows))
	for i := range rows {
		out = append(out, mapJSON(&rows[i]))
	}
	economyJSON(w, http.StatusOK, map[string]any{"maps": out})
}

// DELETE /v1/maps?map=name removes the tenant's outline of a map: 204, or 404 for none.
func (g *Gateway) handleMapDelete(w http.ResponseWriter, r *http.Request) {
	tenant, ok := g.economyTenant(w, r)
	if !ok {
		return
	}
	err := g.cfg.Maps.DeleteMapOutline(r.Context(), tenant, r.URL.Query().Get("map"))
	switch {
	case errors.Is(err, store.ErrNotFound):
		economyError(w, http.StatusNotFound, "no outline for that map")
	case err != nil:
		economyError(w, http.StatusInternalServerError, "the outline could not be removed")
	default:
		g.log.Info("map outline removed", "tenant", tenant, "map", r.URL.Query().Get("map"))
		w.WriteHeader(http.StatusNoContent)
	}
}
