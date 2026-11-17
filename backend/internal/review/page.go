package review

import (
	"bytes"
	"crypto/sha256"
	_ "embed"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"html/template"
	"net/http"
	"strconv"
	"time"

	"carthago/backend/internal/replay"
	"carthago/backend/internal/store"
)

// The review page is what a player opens with a review link. The gateway serves it, not
// the dashboard: it has no sign-in, sets and reads no cookie, and every path under it
// needs the link's signed token. Without a valid token there is one answer, the same for
// a token that was never signed, one that expired and one of a case that is gone, so the
// page cannot be used to find out which cases or matches exist.

//go:embed page.html
var pageHTML string

//go:embed review.css
var pageCSS []byte

var pageTmpl = template.Must(template.New("review").Parse(pageHTML))

// PageCSP is the policy of the review page, the same as the dashboard's match page: this
// origin's stylesheet, script and recording, nothing inline and nothing from elsewhere.
const PageCSP = "default-src 'none'; script-src 'self'; connect-src 'self'; style-src 'self'; img-src 'self'; form-action 'self'; frame-ancestors 'none'; base-uri 'none'"

// maxVerdictBody bounds the body of the verdict form.
const maxVerdictBody = 2 << 10

type verdictOption struct{ Value, Label, Hint string }

var verdictOptions = []verdictOption{
	{VerdictAim, "Cheating: aim", "The aim snaps to targets or tracks them in a way a hand does not"},
	{VerdictWalls, "Cheating: sees through walls", "The suspect follows or waits for players they could not see or hear"},
	{VerdictOther, "Cheating: something else", "Speed, movement or anything else the game does not allow"},
	{VerdictToxic, "Toxic behaviour", "Hurting their own team, throwing the match, standing idle on purpose"},
	{VerdictInsufficient, "Not enough evidence", "Nothing here that I can call cheating or toxic"},
}

type pageData struct {
	View       string // watch | message
	Title      string
	Text       string
	Base       string
	Expires    string
	Duration   string
	DurationMs int64
	Outline    bool
	Verdicts   []verdictOption
}

func clock(ms int64) string {
	s := ms / 1000
	if s >= 3600 {
		return fmt.Sprintf("%d:%02d:%02d", s/3600, s/60%60, s%60)
	}
	return fmt.Sprintf("%02d:%02d", s/60, s%60)
}

// Handler serves the review page under /review/.
func (s *Service) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /review/static/review.css", staticFile("text/css; charset=utf-8", pageCSS))
	mux.HandleFunc("GET /review/static/replay.js", staticFile("text/javascript; charset=utf-8", replay.PlayerJS))
	mux.HandleFunc("GET /review/{token}", s.page)
	mux.HandleFunc("GET /review/{token}/replay.json", s.recording)
	mux.HandleFunc("GET /review/{token}/outline.json", s.outlineJSON)
	mux.HandleFunc("GET /review/{token}/map.png", s.mapPNG)
	mux.HandleFunc("POST /review/{token}/verdict", s.verdict)
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h := w.Header()
		h.Set("Content-Security-Policy", PageCSP)
		h.Set("X-Content-Type-Options", "nosniff")
		h.Set("X-Frame-Options", "DENY")
		// The link is in the page's address: it must not travel in a Referer.
		h.Set("Referrer-Policy", "no-referrer")
		h.Set("Cross-Origin-Opener-Policy", "same-origin")
		h.Set("Cross-Origin-Resource-Policy", "same-origin")
		h.Set("Permissions-Policy", "camera=(), microphone=(), geolocation=(), payment=(), usb=()")
		h.Set("X-Robots-Tag", "noindex, nofollow")
		h.Set("Cache-Control", "no-store")
		mux.ServeHTTP(w, r)
	})
}

func staticFile(ctype string, body []byte) http.HandlerFunc {
	sum := sha256.Sum256(body)
	tag := `"` + hex.EncodeToString(sum[:12]) + `"`
	return func(w http.ResponseWriter, r *http.Request) {
		h := w.Header()
		h.Set("Content-Type", ctype)
		h.Set("ETag", tag)
		h.Set("Cache-Control", "no-cache")
		http.ServeContent(w, r, "", time.Time{}, bytes.NewReader(body))
	}
}

func (s *Service) message(w http.ResponseWriter, status int, title, text string) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(status)
	_ = pageTmpl.ExecuteTemplate(w, "page", pageData{View: "message", Title: title, Text: text})
}

// session opens the link of a request, or answers for it and returns nil.
func (s *Service) session(w http.ResponseWriter, r *http.Request) *Session {
	sess, err := s.Open(r.Context(), r.PathValue("token"))
	if err != nil {
		// One answer for every link that does not open, also when the store failed.
		s.message(w, http.StatusNotFound, "This link does not open a review", "It is not a review link, or it has expired. Ask for a new one in the game.")
		return nil
	}
	return sess
}

func (s *Service) page(w http.ResponseWriter, r *http.Request) {
	sess := s.session(w, r)
	if sess == nil {
		return
	}
	a, c := sess.Assignment, sess.Case
	if a.Verdict != "" {
		s.message(w, http.StatusOK, "Your verdict is in", "Thank you. This link has given its verdict and does nothing more.")
		return
	}
	if !c.Calibration && c.State != store.ReviewOpen {
		s.message(w, http.StatusOK, "This review is closed", "Enough other players gave their verdict before you. Ask for a new link in the game.")
		return
	}
	rec, err := s.st.GetMatchReplay(r.Context(), c.TenantID, c.MatchID)
	if err != nil {
		s.message(w, http.StatusNotFound, "This link does not open a review", "It is not a review link, or it has expired. Ask for a new one in the game.")
		return
	}
	d := pageData{View: "watch", Title: "Review a match", Base: "/review/" + r.PathValue("token"), Expires: a.ExpiresAt.UTC().Format("15:04"),
		Duration: clock(rec.DurationMs), DurationMs: rec.DurationMs, Verdicts: verdictOptions}
	if o, _, err := s.Outline(r.Context(), c); err == nil && o != nil {
		d.Outline = true
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_ = pageTmpl.ExecuteTemplate(w, "page", d)
}

// open is session for the files of the page: no page to show, only found or not.
func (s *Service) open(w http.ResponseWriter, r *http.Request) *Session {
	sess, err := s.Open(r.Context(), r.PathValue("token"))
	if err != nil || sess.Assignment.Verdict != "" || (!sess.Case.Calibration && sess.Case.State != store.ReviewOpen) {
		http.Error(w, "not found", http.StatusNotFound)
		return nil
	}
	return sess
}

func (s *Service) recording(w http.ResponseWriter, r *http.Request) {
	sess := s.open(w, r)
	if sess == nil {
		return
	}
	data, err := s.Recording(r.Context(), sess.Case)
	if err != nil {
		http.Error(w, "not found", http.StatusNotFound)
		return
	}
	h := w.Header()
	h.Set("Content-Type", "application/json")
	h.Set("Content-Encoding", "gzip")
	h.Set("Content-Length", strconv.Itoa(len(data)))
	_, _ = w.Write(data)
}

func (s *Service) outlineJSON(w http.ResponseWriter, r *http.Request) {
	sess := s.open(w, r)
	if sess == nil {
		return
	}
	o, lines, err := s.Outline(r.Context(), sess.Case)
	if err != nil {
		http.Error(w, "not found", http.StatusNotFound)
		return
	}
	out := struct {
		Kind  string     `json:"kind"`
		Rect  [4]int32   `json:"rect"`
		Lines [][4]int32 `json:"lines,omitempty"`
		Src   string     `json:"src,omitempty"`
	}{Kind: o.Kind, Rect: o.Rect, Lines: lines}
	if o.Kind == store.OutlineImage {
		out.Src = "/review/" + r.PathValue("token") + "/map.png"
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(out)
}

func (s *Service) mapPNG(w http.ResponseWriter, r *http.Request) {
	sess := s.open(w, r)
	if sess == nil {
		return
	}
	o, _, err := s.Outline(r.Context(), sess.Case)
	if err != nil || o.Kind != store.OutlineImage || len(o.PNG) == 0 {
		http.Error(w, "not found", http.StatusNotFound)
		return
	}
	w.Header().Set("Content-Type", "image/png")
	w.Header().Set("Content-Length", strconv.Itoa(len(o.PNG)))
	_, _ = w.Write(o.PNG)
}

func (s *Service) verdict(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, maxVerdictBody)
	// A form another site posts here is refused; the link itself is the only credential,
	// so this is a second lock, not the first.
	if site := r.Header.Get("Sec-Fetch-Site"); site != "" && site != "same-origin" && site != "none" {
		s.message(w, http.StatusForbidden, "That did not come from the review page", "Open your review link and give the verdict there.")
		return
	}
	err := s.Vote(r.Context(), r.PathValue("token"), r.PostFormValue("verdict"))
	var bad *InvalidError
	switch {
	case err == nil:
		s.message(w, http.StatusOK, "Your verdict is in", "Thank you. It counts with the verdicts of other players, and the studio's reviewers decide.")
	case errors.Is(err, ErrVoted):
		s.message(w, http.StatusConflict, "Your verdict is in", "This link has already given its verdict. It cannot be changed.")
	case errors.Is(err, ErrClosed):
		s.message(w, http.StatusConflict, "This review is closed", "Enough other players gave their verdict before you. Ask for a new link in the game.")
	case errors.As(err, &bad):
		s.message(w, http.StatusBadRequest, "Pick one of the verdicts", "Go back, choose one answer and give your verdict again.")
	default:
		s.message(w, http.StatusNotFound, "This link does not open a review", "It is not a review link, or it has expired. Ask for a new one in the game.")
	}
}
