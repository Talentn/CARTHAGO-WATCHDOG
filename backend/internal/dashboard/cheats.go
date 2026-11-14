package dashboard

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"strings"

	"carthago/backend/internal/analyzer"
	"carthago/backend/internal/learning"
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

	// Proposed: files only banned accounts were seen to load. A reviewer approves or
	// dismisses each; nothing is added by itself.
	Proposed  *learning.Proposals
	Approved  bool
	Dismissed bool
	Saved     bool
	// CanSet: the viewer may change the studio's threshold.
	CanSet bool
}

func (s *Server) cheatsPage(w http.ResponseWriter, r *http.Request, tenant string) {
	q := r.URL.Query()
	d := cheatsData{Added: q.Get("added") == "1", Removed: q.Get("removed") == "1", Approved: q.Get("approved") == "1", Dismissed: q.Get("dismissed") == "1", Saved: q.Get("saved") == "1"}
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
	if d.Proposed, err = learning.FindProposals(r.Context(), s.st, tenant); err != nil {
		s.fail(w, err)
		return
	}
	if v, ok := s.CurrentViewer(r); ok {
		d.CanAct, d.CanSet = v.Reviewer(), v.Admin()
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

// approveProposal puts a proposed file on the list of known cheats. Only a file that is
// proposed right now can be approved here; any other hash goes through the add form.
func (s *Server) approveProposal(w http.ResponseWriter, r *http.Request, v Viewer) {
	sum, ok := store.CleanSHA256(r.PostFormValue("sha256"))
	name := cleanText(r.PostFormValue("name"), 80)
	if !ok || name == "" {
		http.Error(w, "approving needs the file's SHA-256 and a name for the cheat", http.StatusBadRequest)
		return
	}
	proposed, err := learning.FindProposals(r.Context(), s.st, v.Tenant)
	if err != nil {
		s.fail(w, err)
		return
	}
	p := proposed.Proposed(sum)
	if p == nil {
		http.Error(w, "that file is not proposed any more", http.StatusConflict)
		return
	}
	seen := "loaded by " + plural(p.BannedAccounts, "banned account", "banned accounts") + " and by no account that is not banned"
	c := store.KnownCheat{TenantID: v.Tenant, SHA256: sum, Name: name, Note: "approved proposal: " + seen + "; seen as " + strings.Join(p.Names, ", "), AddedBy: bannedBy(v), AddedAt: s.now()}
	if len(c.Note) > 280 {
		c.Note = c.Note[:280]
	}
	if err := s.st.AddKnownCheat(r.Context(), &c); err != nil && !errors.Is(err, store.ErrDuplicate) {
		s.fail(w, err)
		return
	}
	s.Audit(r, "cheat.approve", "known cheat "+c.Name, "SHA-256 "+c.SHA256+"; "+seen)
	s.log.Info("dashboard proposed cheat approved", "tenant", v.Tenant, "name", c.Name, "sha256", c.SHA256, "by", v.Name, "remote", s.clientAddr(r))
	http.Redirect(w, r, "/cheats?approved=1", http.StatusSeeOther)
}

// dismissProposal keeps a file from being proposed again.
func (s *Server) dismissProposal(w http.ResponseWriter, r *http.Request, v Viewer) {
	sum, ok := store.CleanSHA256(r.PostFormValue("sha256"))
	if !ok {
		http.Error(w, "dismissing needs the file's SHA-256", http.StatusBadRequest)
		return
	}
	if err := s.st.DismissCheatProposal(r.Context(), v.Tenant, sum, bannedBy(v), s.now()); err != nil {
		s.fail(w, err)
		return
	}
	s.Audit(r, "cheat.dismiss", "proposed known cheat", "SHA-256 "+sum)
	http.Redirect(w, r, "/cheats?dismissed=1#proposed", http.StatusSeeOther)
}

// setProposalAccounts sets in how many distinct banned accounts a file must be seen
// before it is proposed.
func (s *Server) setProposalAccounts(w http.ResponseWriter, r *http.Request, v Viewer) {
	n, err := strconv.Atoi(strings.TrimSpace(r.PostFormValue("accounts")))
	if err != nil || n < 1 || n > store.MaxProposalAccounts {
		http.Error(w, fmt.Sprintf("the number of banned accounts is from 1 to %d", store.MaxProposalAccounts), http.StatusBadRequest)
		return
	}
	if err := s.st.SetCheatProposalAccounts(r.Context(), v.Tenant, n); err != nil {
		s.fail(w, err)
		return
	}
	s.Audit(r, "cheat.proposals", "proposed known cheats", fmt.Sprintf("proposed after %d banned accounts", n))
	http.Redirect(w, r, "/cheats?saved=1#proposed", http.StatusSeeOther)
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
