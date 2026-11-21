package sig

import (
	"context"
	"errors"
	"fmt"
	"html/template"
	"io/fs"
	"log/slog"
	"net/http"
	"os"
	"strings"

	"github.com/go-chi/chi/v5"

	"github.com/chrobson/hacknation-agh/internal/store"
	"github.com/chrobson/hacknation-agh/internal/web"
)

// Permissions used by the signature pages.
const (
	PermRead  = "results.read"
	PermWrite = "signatures.write"
)

// Authorize wraps a handler so that it requires perm. The integrator sets it
// (e.g. to auth.Require). When nil every signature route answers 403: the
// pages fail closed until authorization is wired.
var Authorize func(perm string) func(http.Handler) http.Handler

// TemplateFS is the root of web/templates (must contain base.html and
// sig/*.html). nil = os.DirFS(ASI_TEMPLATES_DIR or "web/templates").
var TemplateFS fs.FS

// Can reports whether the request's user holds perm; used only to hide
// buttons the user may not use. The integrator sets it; nil shows them.
var Can func(r *http.Request, perm string) bool

// OnChange is called after a signature was created, edited, toggled or
// deleted, so the running engine can reload (optional).
var OnChange func(ctx context.Context)

// SignatureRow is a row of the signatures table.
type SignatureRow = store.SignatureRow

// Store is what the signature pages need from the database.
type Store interface {
	List(ctx context.Context) ([]SignatureRow, error)
	Get(ctx context.Context, id string) (SignatureRow, error)
	Create(ctx context.Context, s *Signature) error
	Update(ctx context.Context, id string, s *Signature) error
	SetEnabled(ctx context.Context, id string, enabled bool) error
	Delete(ctx context.Context, id string) error
}

// Errors returned by Store implementations.
var (
	ErrNotFound = store.ErrSignatureNotFound
	ErrBuiltin  = store.ErrSignatureBuiltin
)

// Mount registers the signature pages:
//
//	GET  /signatures               list            (results.read)
//	GET  /signatures/{id}          view YAML       (results.read)
//	GET  /signatures/new           create form     (signatures.write)
//	POST /signatures               create          (signatures.write)
//	POST /signatures/validate      htmx validation (signatures.write)
//	GET  /signatures/{id}/edit     edit form       (signatures.write)
//	POST /signatures/{id}          update          (signatures.write)
//	POST /signatures/{id}/toggle   enable/disable  (signatures.write)
//	POST /signatures/{id}/delete   delete custom   (signatures.write)
func Mount(r chi.Router, d web.Deps) {
	var st Store
	if d.DB != nil {
		st = NewDBStore(d.DB)
	}
	MountStore(r, st, d.Log)
}

// MountStore is Mount with an explicit store (tests, alternative backends).
func MountStore(r chi.Router, st Store, log *slog.Logger) {
	if log == nil {
		log = slog.Default()
	}
	h := &handler{st: st, log: log}
	h.tmpl, h.tmplErr = loadTemplates(TemplateFS)
	if h.tmplErr != nil {
		log.Error("signature templates", "err", h.tmplErr)
	}
	r.Group(func(r chi.Router) {
		r.Use(require(PermRead))
		r.Get("/signatures", h.list)
	})
	r.Group(func(r chi.Router) {
		r.Use(require(PermWrite))
		r.Get("/signatures/new", h.newForm)
		r.Post("/signatures", h.create)
		r.Post("/signatures/validate", h.validate)
		r.Get("/signatures/{id}/edit", h.editForm)
		r.Post("/signatures/{id}", h.update)
		r.Post("/signatures/{id}/toggle", h.toggle)
		r.Post("/signatures/{id}/delete", h.remove)
	})
	r.Group(func(r chi.Router) {
		r.Use(require(PermRead))
		r.Get("/signatures/{id}", h.view)
	})
}

func require(perm string) func(http.Handler) http.Handler {
	if Authorize != nil {
		return Authorize(perm)
	}
	return func(http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			http.Error(w, "Brak uprawnień (autoryzacja nie jest skonfigurowana)", http.StatusForbidden)
		})
	}
}

var pages = []string{"list.html", "view.html", "form.html", "validate.html"}

func loadTemplates(fsys fs.FS) (map[string]*template.Template, error) {
	if fsys == nil {
		dir := os.Getenv("ASI_TEMPLATES_DIR")
		if dir == "" {
			dir = "web/templates"
		}
		fsys = os.DirFS(dir)
	}
	base, err := template.New("").Funcs(template.FuncMap{"join": strings.Join, "catLabel": catLabel}).ParseFS(fsys, "base.html")
	if err != nil {
		return nil, err
	}
	out := map[string]*template.Template{}
	for _, p := range pages {
		files := []string{"sig/" + p}
		if p != "validate.html" {
			files = append(files, "sig/validate.html") // shared "validation" block
		}
		c, err := base.Clone()
		if err != nil {
			return nil, err
		}
		t, err := c.ParseFS(fsys, files...)
		if err != nil {
			return nil, err
		}
		out[p] = t
	}
	return out, nil
}

type handler struct {
	st      Store
	log     *slog.Logger
	tmpl    map[string]*template.Template
	tmplErr error
}

type listRow struct {
	SignatureRow
	Category   string
	Confidence int
	Types      []string
	Paths      []string
	Invalid    string
}

type pageData struct {
	Title      string
	Rows       []listRow
	Sig        SignatureRow
	Parsed     *Signature
	YAML       string
	Errors     []string
	IsNew      bool
	Message    string
	Categories []string
	Types      []string
	CanWrite   bool // the viewer has signatures.write: show write buttons
}

func (h *handler) render(w http.ResponseWriter, r *http.Request, status int, page, name string, data pageData) {
	data.CanWrite = Can == nil || Can(r, PermWrite)
	if h.tmplErr != nil {
		http.Error(w, "Błąd szablonów: "+h.tmplErr.Error(), http.StatusInternalServerError)
		return
	}
	data.Categories, data.Types = Categories, MatcherTypes
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(status)
	if err := h.tmpl[page].ExecuteTemplate(w, name, data); err != nil {
		h.log.Error("render", "page", page, "err", err)
	}
}

func (h *handler) fail(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, ErrNotFound):
		http.Error(w, "Nie znaleziono sygnatury", http.StatusNotFound)
	case errors.Is(err, ErrBuiltin):
		http.Error(w, "Sygnatury wbudowanej nie można modyfikować ani usuwać", http.StatusConflict)
	default:
		h.log.Error("signatures", "err", err)
		http.Error(w, "Błąd serwera", http.StatusInternalServerError)
	}
}

func (h *handler) ready(w http.ResponseWriter) bool {
	if h.st == nil {
		http.Error(w, "Magazyn sygnatur nie jest skonfigurowany", http.StatusServiceUnavailable)
		return false
	}
	return true
}

func (h *handler) list(w http.ResponseWriter, r *http.Request) {
	if !h.ready(w) {
		return
	}
	rows, err := h.st.List(r.Context())
	if err != nil {
		h.fail(w, err)
		return
	}
	data := pageData{Title: "Sygnatury", Message: flashMessages[r.URL.Query().Get("msg")]}
	for _, row := range rows {
		lr := listRow{SignatureRow: row}
		if s, err := Parse([]byte(row.YAML)); err != nil {
			lr.Invalid = err.Error()
		} else {
			lr.Category, lr.Confidence = s.Category, s.Confidence
			for _, m := range s.Matchers {
				if !contains(lr.Types, m.Type) {
					lr.Types = append(lr.Types, m.Type)
				}
				if m.Type == TypePath && !contains(lr.Paths, m.Path) {
					lr.Paths = append(lr.Paths, m.Path)
				}
			}
		}
		data.Rows = append(data.Rows, lr)
	}
	h.render(w, r, http.StatusOK, "list.html", "base", data)
}

func (h *handler) view(w http.ResponseWriter, r *http.Request) {
	if !h.ready(w) {
		return
	}
	row, err := h.st.Get(r.Context(), chi.URLParam(r, "id"))
	if err != nil {
		h.fail(w, err)
		return
	}
	s, perr := Parse([]byte(row.YAML))
	data := pageData{Title: "Sygnatura " + row.ID, Sig: row, Parsed: s, YAML: row.YAML}
	if perr != nil {
		data.Errors = problems(perr)
	}
	h.render(w, r, http.StatusOK, "view.html", "base", data)
}

const newTemplate = `id: my-signature
name: Moja sygnatura
category: other   # cms|framework|server|iot|admin-panel|staging|other
confidence: 70
description: Opis wykrywanej technologii.
condition: or     # or|and
matchers:
  - type: header
    name: Server
    regex: 'MyServer/(?P<version>[0-9.]+)'
  - type: path        # tylko GET/HEAD, maks. 3 ścieżki, bez body i nagłówków auth
    path: /version
    status: [200]
    regex: '"version"'
`

func (h *handler) newForm(w http.ResponseWriter, r *http.Request) {
	h.render(w, r, http.StatusOK, "form.html", "base", pageData{Title: "Nowa sygnatura", IsNew: true, YAML: newTemplate})
}

func (h *handler) editForm(w http.ResponseWriter, r *http.Request) {
	if !h.ready(w) {
		return
	}
	row, err := h.st.Get(r.Context(), chi.URLParam(r, "id"))
	if err != nil {
		h.fail(w, err)
		return
	}
	if row.Builtin {
		h.fail(w, ErrBuiltin)
		return
	}
	h.render(w, r, http.StatusOK, "form.html", "base", pageData{Title: "Edycja: " + row.ID, Sig: row, YAML: row.YAML})
}

// flashMessages maps the fixed ?msg= codes to text, so the query string can
// never inject arbitrary content into the page.
var flashMessages = map[string]string{
	"created": "Zapisano nową sygnaturę.",
	"deleted": "Usunięto sygnaturę.",
}

var errFormTooLarge = fmt.Errorf("formularz jest za duży (maks. %d KB YAML)", MaxYAMLBytes>>10)

func formYAML(w http.ResponseWriter, r *http.Request) (string, error) {
	r.Body = http.MaxBytesReader(w, r.Body, MaxYAMLBytes+4096)
	if err := r.ParseForm(); err != nil {
		return "", errFormTooLarge
	}
	return strings.ReplaceAll(r.PostFormValue("yaml"), "\r\n", "\n"), nil
}

// parseForm reads and validates the submitted YAML.
func parseForm(w http.ResponseWriter, r *http.Request) (string, *Signature, error) {
	src, err := formYAML(w, r)
	if err != nil {
		return src, nil, err
	}
	s, err := Parse([]byte(src))
	return src, s, err
}

func problems(err error) []string {
	var ve *ValidationError
	if errors.As(err, &ve) {
		return ve.Problems
	}
	return []string{err.Error()}
}

func (h *handler) validate(w http.ResponseWriter, r *http.Request) {
	src, s, err := parseForm(w, r)
	data := pageData{YAML: src}
	if err != nil {
		data.Errors = problems(err)
	} else {
		data.Parsed = s
	}
	h.render(w, r, http.StatusOK, "validate.html", "validation", data)
}

func (h *handler) create(w http.ResponseWriter, r *http.Request) {
	if !h.ready(w) {
		return
	}
	src, s, err := parseForm(w, r)
	if err == nil {
		if _, gerr := h.st.Get(r.Context(), s.ID); gerr == nil {
			err = errors.New("sygnatura o identyfikatorze " + s.ID + " już istnieje")
		} else if !errors.Is(gerr, ErrNotFound) {
			h.fail(w, gerr)
			return
		}
	}
	if err == nil {
		err = h.st.Create(r.Context(), s)
	}
	if err != nil {
		h.render(w, r, http.StatusUnprocessableEntity, "form.html", "base",
			pageData{Title: "Nowa sygnatura", IsNew: true, YAML: src, Errors: problems(err)})
		return
	}
	h.changed(r.Context())
	h.log.Info("signature created", "id", s.ID)
	http.Redirect(w, r, "/signatures?msg=created", http.StatusSeeOther)
}

func (h *handler) update(w http.ResponseWriter, r *http.Request) {
	if !h.ready(w) {
		return
	}
	id := chi.URLParam(r, "id")
	row, err := h.st.Get(r.Context(), id)
	if err != nil {
		h.fail(w, err)
		return
	}
	if row.Builtin {
		h.fail(w, ErrBuiltin)
		return
	}
	src, s, err := parseForm(w, r)
	if err == nil && s.ID != id {
		err = errors.New("nie można zmienić identyfikatora sygnatury (" + id + ")")
	}
	if err == nil {
		err = h.st.Update(r.Context(), id, s)
	}
	if err != nil {
		if errors.Is(err, ErrBuiltin) || errors.Is(err, ErrNotFound) {
			h.fail(w, err)
			return
		}
		h.render(w, r, http.StatusUnprocessableEntity, "form.html", "base",
			pageData{Title: "Edycja: " + id, Sig: row, YAML: src, Errors: problems(err)})
		return
	}
	h.changed(r.Context())
	h.log.Info("signature updated", "id", id)
	http.Redirect(w, r, "/signatures/"+id, http.StatusSeeOther)
}

func (h *handler) toggle(w http.ResponseWriter, r *http.Request) {
	if !h.ready(w) {
		return
	}
	id := chi.URLParam(r, "id")
	row, err := h.st.Get(r.Context(), id)
	if err == nil {
		err = h.st.SetEnabled(r.Context(), id, !row.Enabled)
	}
	if err != nil {
		h.fail(w, err)
		return
	}
	h.changed(r.Context())
	http.Redirect(w, r, "/signatures", http.StatusSeeOther)
}

func (h *handler) remove(w http.ResponseWriter, r *http.Request) {
	if !h.ready(w) {
		return
	}
	id := chi.URLParam(r, "id")
	if err := h.st.Delete(r.Context(), id); err != nil {
		h.fail(w, err)
		return
	}
	h.changed(r.Context())
	h.log.Info("signature deleted", "id", id)
	http.Redirect(w, r, "/signatures?msg=deleted", http.StatusSeeOther)
}

func (h *handler) changed(ctx context.Context) {
	if OnChange != nil {
		OnChange(ctx)
	}
}

var catLabels = map[string]string{
	"cms": "CMS", "framework": "Framework", "server": "Serwer", "iot": "IoT",
	"admin-panel": "Panel administracyjny", "staging": "Środowisko testowe", "other": "Inne",
}

// catLabel is the Polish label of a signature category (as on the results pages).
func catLabel(c string) string {
	if l, ok := catLabels[c]; ok {
		return l
	}
	return c
}
