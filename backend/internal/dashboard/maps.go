package dashboard

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strconv"

	"carthago/backend/internal/outline"
	"carthago/backend/internal/replay"
	"carthago/backend/internal/store"
)

// Map outlines (internal/outline) are what the match replay draws under the players. This
// file lists a studio's outlines, takes an admin's uploads and serves a match's outline
// to the replay script. An outline is a drawing aid: nothing here writes evidence, a ban
// or the shadow pool, and a shot across a wall line is worked out when the match page is
// opened and stored nowhere.

// uploadLimits are the pages whose form carries a file, with the most their body may be:
// the file's own cap and room for the form around it.
var uploadLimits = map[string]int64{
	"/maps/lines":   outline.MaxLinesBytes + 16<<10,
	"/maps/picture": outline.MaxPNGBytes + 16<<10,
}

// maxCrossings bounds the shots across a wall line listed for one match.
const maxCrossings = 200

type mapsData struct {
	Rows    []store.MapOutline
	CanEdit bool
	Notice  string
	Error   string
	// The caps, for the page's own words.
	MaxLines, MaxPNGMB, MaxSide int
}

func (s *Server) mapsPage(w http.ResponseWriter, r *http.Request, tenant string) {
	notice := ""
	switch r.URL.Query().Get("ok") {
	case "saved":
		notice = "Outline saved"
	case "removed":
		notice = "Outline removed"
	}
	s.renderMaps(w, r, http.StatusOK, tenant, notice, "")
}

func (s *Server) renderMaps(w http.ResponseWriter, r *http.Request, status int, tenant, notice, errText string) {
	rows, err := s.st.ListMapOutlines(r.Context(), tenant)
	if err != nil {
		s.fail(w, err)
		return
	}
	d := mapsData{Rows: rows, Notice: notice, Error: errText, MaxLines: outline.MaxLines, MaxPNGMB: outline.MaxPNGBytes >> 20, MaxSide: outline.MaxSide}
	if st := stateOf(r); st != nil {
		d.CanEdit = st.viewer.Can(RoleAdmin)
	}
	s.render(w, status, "maps", page{Title: "Maps", Nav: "maps", Tenant: tenant, Data: d})
}

// uploaded reads the file of an upload form, up to max bytes.
func uploaded(r *http.Request, max int64) ([]byte, error) {
	f, _, err := r.FormFile("file")
	if err != nil {
		return nil, &outline.Error{Msg: "choose a file to upload"}
	}
	defer f.Close()
	body, err := io.ReadAll(io.LimitReader(f, max+1))
	if err != nil {
		return nil, &outline.Error{Msg: "the file could not be read"}
	}
	return body, nil
}

func (s *Server) saveOutline(w http.ResponseWriter, r *http.Request, v Viewer, o *store.MapOutline, err error) {
	if err == nil {
		by := v.Name
		if v.Demo {
			by = "demo login"
		}
		err = outline.Put(r.Context(), s.st, v.Tenant, o, by, s.now())
	}
	if msg, bad := outline.IsError(err); bad {
		s.Audit(r, "map.outline", r.PostFormValue("map"), "refused: "+msg)
		s.renderMaps(w, r, http.StatusBadRequest, v.Tenant, "", msg)
		return
	}
	if err != nil {
		s.fail(w, err)
		return
	}
	detail := fmt.Sprintf("%d wall lines", o.Segments)
	if o.Kind == store.OutlineImage {
		detail = fmt.Sprintf("picture %d x %d over %d,%d to %d,%d cm", o.Width, o.Height, o.Rect[0], o.Rect[1], o.Rect[2], o.Rect[3])
	}
	s.Audit(r, "map.outline", o.MapID, detail)
	http.Redirect(w, r, "/maps?ok=saved", http.StatusSeeOther)
}

func (s *Server) putMapLines(w http.ResponseWriter, r *http.Request, v Viewer) {
	body, err := uploaded(r, outline.MaxLinesBytes)
	var o *store.MapOutline
	if err == nil {
		name := r.PostFormValue("map")
		if name == "" {
			err = &outline.Error{Msg: "name the map as your game server names it in a match"}
		} else {
			o, err = outline.Lines(name, body)
		}
	}
	s.saveOutline(w, r, v, o, err)
}

func (s *Server) putMapPicture(w http.ResponseWriter, r *http.Request, v Viewer) {
	body, err := uploaded(r, outline.MaxPNGBytes)
	var o *store.MapOutline
	if err == nil {
		var rect [4]int32
		for i, f := range []string{"min_x", "min_y", "max_x", "max_y"} {
			n, perr := strconv.ParseInt(r.PostFormValue(f), 10, 32)
			if perr != nil && err == nil {
				err = &outline.Error{Msg: "the world rectangle is four whole numbers of centimetres"}
			}
			rect[i] = int32(n)
		}
		if err == nil {
			o, err = outline.Picture(r.PostFormValue("map"), body, rect)
		}
	}
	s.saveOutline(w, r, v, o, err)
}

func (s *Server) removeMap(w http.ResponseWriter, r *http.Request, v Viewer) {
	name := r.PostFormValue("map")
	err := s.st.DeleteMapOutline(r.Context(), v.Tenant, name)
	if err != nil {
		s.fail(w, err)
		return
	}
	s.Audit(r, "map.outline_remove", name, "outline removed")
	http.Redirect(w, r, "/maps?ok=removed", http.StatusSeeOther)
}

// wallShot is a shot whose line crosses a wall line, as the match page lists it.
type wallShot struct {
	Ms             int64
	At             string
	Slot, Target   int
	Player, Victim string
	Hit, Kill      bool
}

// matchOutline is the outline of the match's map, or nil when the match names no map or
// the studio has no outline for it, with the wall lines of a lines outline.
func (s *Server) matchOutline(ctx context.Context, tenant string, data *replay.Data) (*store.MapOutline, [][4]int32, error) {
	if data.Map == "" {
		return nil, nil, nil
	}
	o, err := s.st.GetMapOutline(ctx, tenant, data.Map)
	if errors.Is(err, store.ErrNotFound) {
		return nil, nil, nil
	}
	if err != nil {
		return nil, nil, err
	}
	lines, err := outline.StoredLines(o)
	return o, lines, err
}

// matchOutlineJSON serves the outline of a match's map to the replay script: the wall
// lines with the shots that cross one, or where the picture is and what it covers.
func (s *Server) matchOutlineJSON(w http.ResponseWriter, r *http.Request, tenant string) {
	rec, err := s.st.GetMatchReplay(r.Context(), tenant, r.PathValue("id"))
	if err != nil {
		s.fail(w, err)
		return
	}
	data, err := replay.Decode(rec.Data)
	if err != nil {
		s.fail(w, err)
		return
	}
	o, lines, err := s.matchOutline(r.Context(), tenant, data)
	if err != nil {
		s.fail(w, err)
		return
	}
	if o == nil {
		http.Error(w, "not found", http.StatusNotFound)
		return
	}
	out := struct {
		Kind      string     `json:"kind"`
		Rect      [4]int32   `json:"rect"`
		Lines     [][4]int32 `json:"lines,omitempty"`
		Crossings []int      `json:"crossings,omitempty"`
		Src       string     `json:"src,omitempty"`
	}{Kind: o.Kind, Rect: o.Rect, Lines: lines}
	if o.Kind == store.OutlineImage {
		out.Src = matchURL(rec.MatchID) + "/map.png"
	}
	for _, c := range outline.Crossings(data, lines, maxCrossings) {
		out.Crossings = append(out.Crossings, c.Shot)
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(out)
}

// matchMapPNG serves the picture of a match's map: the PNG the gateway wrote out itself
// when the picture was uploaded.
func (s *Server) matchMapPNG(w http.ResponseWriter, r *http.Request, tenant string) {
	rec, err := s.st.GetMatchReplay(r.Context(), tenant, r.PathValue("id"))
	if err != nil {
		s.fail(w, err)
		return
	}
	data, err := replay.Decode(rec.Data)
	if err != nil {
		s.fail(w, err)
		return
	}
	o, _, err := s.matchOutline(r.Context(), tenant, data)
	if err != nil {
		s.fail(w, err)
		return
	}
	if o == nil || o.Kind != store.OutlineImage || len(o.PNG) == 0 {
		http.Error(w, "not found", http.StatusNotFound)
		return
	}
	w.Header().Set("Content-Type", "image/png")
	w.Header().Set("Content-Length", strconv.Itoa(len(o.PNG)))
	_, _ = w.Write(o.PNG)
}
