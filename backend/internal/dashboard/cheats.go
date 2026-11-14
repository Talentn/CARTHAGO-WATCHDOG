package dashboard

import (
	"encoding/json"
	"errors"
	"net/http"
	"strconv"

	"carthago/backend/internal/analyzer"
	"carthago/backend/internal/store"
)

type cheatsData struct {
	Rows []store.KnownCheat
	// CanAct: the viewer may add and remove.
	CanAct bool
	// What the add form starts with: a hash and a module name carried over from an
	// evidence row, or what a refused form held.
	SHA256, Name, Note string
	Problem            string
	Added, Removed     bool
}

func (s *Server) cheatsPage(w http.ResponseWriter, r *http.Request, tenant string) {
	q := r.URL.Query()
	d := cheatsData{Added: q.Get("added") == "1", Removed: q.Get("removed") == "1"}
	if sum, ok := store.CleanSHA256(q.Get("sha256")); ok {
		d.SHA256, d.Note = sum, cleanText(q.Get("module"), 64)
		if d.Note != "" {
			d.Note = "seen loaded as " + d.Note
		}
	}
	s.renderCheats(w, r, tenant, http.StatusOK, d)
}

func (s *Server) renderCheats(w http.ResponseWriter, r *http.Request, tenant string, status int, d cheatsData) {
	list, err := s.st.ListKnownCheats(r.Context(), tenant)
	if err != nil {
		s.fail(w, err)
		return
	}
	d.Rows = list
	if v, ok := s.CurrentViewer(r); ok {
		d.CanAct = v.Reviewer()
	}
	s.render(w, status, "cheats", page{Title: "Known cheats", Nav: "cheats", Tenant: tenant, Data: d})
}

// addCheat puts one file hash on the studio's list of known cheat files.
func (s *Server) addCheat(w http.ResponseWriter, r *http.Request, v Viewer) {
	d := cheatsData{SHA256: cleanText(r.PostFormValue("sha256"), 80), Name: cleanText(r.PostFormValue("name"), 80), Note: cleanText(r.PostFormValue("note"), 280)}
	sum, ok := store.CleanSHA256(d.SHA256)
	switch {
	case !ok:
		d.Problem = "The SHA-256 of a file is 64 hex digits."
	case d.Name == "":
		d.Problem = "Give the cheat a name: it is what the evidence and the ban will say."
	}
	if d.Problem == "" {
		c := store.KnownCheat{TenantID: v.Tenant, SHA256: sum, Name: d.Name, Note: d.Note, AddedBy: bannedBy(v), AddedAt: s.now()}
		err := s.st.AddKnownCheat(r.Context(), &c)
		switch {
		case errors.Is(err, store.ErrDuplicate):
			d.Problem = "That file is already on the list."
		case err != nil:
			s.fail(w, err)
			return
		default:
			s.Audit(r, "cheat.add", "known cheat "+c.Name, "SHA-256 "+c.SHA256)
			s.log.Info("dashboard known cheat added", "tenant", v.Tenant, "name", c.Name, "sha256", c.SHA256, "by", v.Name, "remote", s.clientAddr(r))
			http.Redirect(w, r, "/cheats?added=1", http.StatusSeeOther)
			return
		}
	}
	s.renderCheats(w, r, v.Tenant, http.StatusBadRequest, d)
}

func (s *Server) removeCheat(w http.ResponseWriter, r *http.Request, v Viewer) {
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil {
		http.NotFound(w, r)
		return
	}
	c, err := s.st.RemoveKnownCheat(r.Context(), v.Tenant, id)
	if err != nil {
		s.fail(w, err)
		return
	}
	s.Audit(r, "cheat.remove", "known cheat "+c.Name, "SHA-256 "+c.SHA256)
	s.log.Info("dashboard known cheat removed", "tenant", v.Tenant, "name", c.Name, "sha256", c.SHA256, "by", v.Name, "remote", s.clientAddr(r))
	http.Redirect(w, r, "/cheats?removed=1", http.StatusSeeOther)
}

// moduleFile is the file behind a piece of client evidence about a module, for the "Add
// to known cheats" link next to it: its SHA-256 and the name it was loaded under. Empty
// for other evidence, and for a file that is on the list already.
type moduleFile struct{ SHA256, Module string }

func fileOf(e store.Evidence) *moduleFile {
	if e.Source != store.SourceClient || e.Rule == analyzer.RuleKnownCheat || e.Raw == "" {
		return nil
	}
	var raw struct {
		SHA256 string `json:"sha256"`
		Detail string `json:"detail"`
	}
	if json.Unmarshal([]byte(e.Raw), &raw) != nil {
		return nil
	}
	sum, ok := store.CleanSHA256(raw.SHA256)
	if !ok {
		return nil
	}
	return &moduleFile{SHA256: sum, Module: raw.Detail}
}
