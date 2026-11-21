package target

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"html/template"
	"io"
	"io/fs"
	"log/slog"
	"net/http"
	"net/netip"
	"strconv"
	"strings"

	"github.com/go-chi/chi/v5"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/chrobson/hacknation-agh/internal/model"
	"github.com/chrobson/hacknation-agh/internal/store"
	"github.com/chrobson/hacknation-agh/internal/web"
	tpl "github.com/chrobson/hacknation-agh/web/templates/targets"
)

// Permissions used by this module.
const (
	PermRead  = "targets.read"
	PermWrite = "targets.write"
)

// Authorizer answers permission checks for a request. The auth module
// provides the real implementation at integration (assign Authz before
// calling Mount); it also wraps the routes with its own middleware.
type Authorizer interface {
	Allowed(r *http.Request, perm string) bool
	// UserID returns the logged-in user, used for created_by and audit_log.
	UserID(r *http.Request) (int64, bool)
}

type openAuthorizer struct{}

func (openAuthorizer) Allowed(*http.Request, string) bool { return true }
func (openAuthorizer) UserID(*http.Request) (int64, bool) { return 0, false }

type denyAuthorizer struct{}

func (denyAuthorizer) Allowed(*http.Request, string) bool { return false }
func (denyAuthorizer) UserID(*http.Request) (int64, bool) { return 0, false }

// AllowAll grants every permission with no user. Use it only in tests or
// local development; never in production wiring.
var AllowAll Authorizer = openAuthorizer{}

// Authz is the authorizer used by Mount. The integrator must set it before
// calling Mount. It fails closed: while nil, every targets route answers 403
// (an error is logged at Mount), so a missing wiring is noticed at once
// instead of silently opening write access.
var Authz Authorizer

// BaseTemplates, when set, must contain base.html (the shared layout). When
// nil a built-in copy of the layout is used.
var BaseTemplates fs.FS

// Store is the persistence the web handler needs.
type Store interface {
	List(ctx context.Context, tag string) ([]model.Target, error)
	Tags(ctx context.Context) ([]string, error)
	// Insert stores targets (skipping existing values) and returns how many
	// were inserted.
	Insert(ctx context.Context, ts []model.Target, by *int64) (int, error)
	UpdateTags(ctx context.Context, id int64, tags []string, by *int64) (model.Target, error)
	Delete(ctx context.Context, id int64, by *int64) error
}

// ErrNotFound is returned by Store implementations for a missing target.
var ErrNotFound = store.ErrTargetNotFound

// Mount registers the targets routes (GET/POST /targets ...).
func Mount(r chi.Router, d web.Deps) {
	log := d.Log
	if log == nil {
		log = slog.Default()
	}
	if Authz == nil {
		log.Error("targets: target.Authz is not set; all targets routes will answer 403")
	}
	h, err := NewHandler(PGStore{DB: d.DB}, Importer{Allow: NewAllowlist(d.Config.AllowedCIDRs)}, Authz, log)
	if err != nil {
		panic(fmt.Errorf("targets templates: %w", err)) // embedded templates: a build bug
	}
	h.Routes(r)
}

// Handler serves the targets UI.
type Handler struct {
	Store    Store
	Importer Importer
	Authz    Authorizer
	Log      *slog.Logger

	allowed []netip.Prefix
	tpl     *template.Template
}

// NewHandler builds a handler with parsed templates. A nil authorizer
// denies everything.
func NewHandler(st Store, im Importer, az Authorizer, log *slog.Logger) (*Handler, error) {
	if az == nil {
		az = denyAuthorizer{}
	}
	if log == nil {
		log = slog.Default()
	}
	t, err := ParseTemplates()
	if err != nil {
		return nil, err
	}
	return &Handler{Store: st, Importer: im, Authz: az, Log: log, allowed: im.Allow.prefixes, tpl: t}, nil
}

// Routes registers the handler on r.
func (h *Handler) Routes(r chi.Router) {
	r.Get("/targets", h.need(PermRead, h.list))
	r.Get("/targets/export", h.need(PermRead, h.export))
	r.Post("/targets", h.need(PermWrite, h.addForm))
	r.Post("/targets/upload", h.need(PermWrite, h.upload))
	r.Post("/targets/{id}/tags", h.need(PermWrite, h.updateTags))
	r.Post("/targets/{id}/delete", h.need(PermWrite, h.delete))
	r.Delete("/targets/{id}", h.need(PermWrite, h.delete))
}

func (h *Handler) need(perm string, next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !h.Authz.Allowed(r, perm) {
			http.Error(w, "Brak uprawnień ("+perm+")", http.StatusForbidden)
			return
		}
		next(w, r)
	}
}

func (h *Handler) user(r *http.Request) *int64 {
	if id, ok := h.Authz.UserID(r); ok {
		return &id
	}
	return nil
}

// Counts summarizes the listed targets.
type Counts struct {
	IP, CIDR, Domain int
	Addresses        uint64
}

type pageData struct {
	Targets  []model.Target
	AllTags  []string
	Filter   string
	Report   *Report
	Error    string
	CanWrite bool
	Counts   Counts
	Allowed  []netip.Prefix
}

func (h *Handler) render(w http.ResponseWriter, r *http.Request, status int, rep *Report, msg string) {
	filter := tagFilter(r)
	d := pageData{Filter: filter, Report: rep, Error: msg, CanWrite: h.Authz.Allowed(r, PermWrite), Allowed: h.allowed}
	var err error
	if d.Targets, err = h.Store.List(r.Context(), filter); err == nil {
		d.AllTags, err = h.Store.Tags(r.Context())
	}
	if err != nil {
		h.Log.Error("targets: list", "err", err)
		http.Error(w, "Błąd bazy danych", http.StatusInternalServerError)
		return
	}
	for _, t := range d.Targets {
		switch t.Kind {
		case model.TargetIP:
			d.Counts.IP++
		case model.TargetCIDR:
			d.Counts.CIDR++
		case model.TargetDomain:
			d.Counts.Domain++
		}
		if p, ok := TargetPrefix(t); ok {
			d.Counts.Addresses = satAdd(d.Counts.Addresses, AddrCount(p))
		}
	}
	// The same URL serves a full page or an htmx fragment.
	w.Header().Add("Vary", "HX-Request")
	name := "base"
	if r.Header.Get("HX-Request") == "true" && r.Header.Get("HX-Boosted") != "true" &&
		r.Header.Get("HX-History-Restore-Request") != "true" {
		name = "targets/page"
	}
	h.exec(w, status, name, d)
}

func (h *Handler) exec(w http.ResponseWriter, status int, name string, data any) {
	var buf bytes.Buffer
	if err := h.tpl.ExecuteTemplate(&buf, name, data); err != nil {
		h.Log.Error("targets: template", "name", name, "err", err)
		http.Error(w, "Błąd szablonu", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(status)
	_, _ = buf.WriteTo(w)
}

func (h *Handler) list(w http.ResponseWriter, r *http.Request) {
	h.render(w, r, http.StatusOK, nil, "")
}

func (h *Handler) addForm(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, MaxImportBytes)
	if err := r.ParseForm(); err != nil {
		h.fail(w, r, http.StatusBadRequest, "Nieprawidłowy formularz: "+err.Error())
		return
	}
	entries, err := ParseLines(strings.NewReader(r.PostFormValue("values")), SplitTags(r.PostFormValue("tags")))
	if err != nil {
		h.fail(w, r, http.StatusBadRequest, "Nie udało się odczytać listy: "+errLabel(err.Error()))
		return
	}
	h.importEntries(w, r, entries, "form")
}

func (h *Handler) upload(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, MaxImportBytes+64<<10)
	if err := r.ParseMultipartForm(1 << 20); err != nil {
		h.fail(w, r, http.StatusBadRequest, "Nie udało się odebrać pliku (limit 5 MB): "+err.Error())
		return
	}
	f, fh, err := r.FormFile("file")
	if err != nil {
		h.fail(w, r, http.StatusBadRequest, "Wybierz plik CSV lub JSON.")
		return
	}
	defer f.Close()
	data, err := io.ReadAll(io.LimitReader(f, MaxImportBytes+1))
	if err != nil || len(data) > MaxImportBytes {
		h.fail(w, r, http.StatusRequestEntityTooLarge, "Plik jest za duży (limit 5 MB).")
		return
	}
	entries, err := ParseInput(DetectFormat(fh.Filename, data), data)
	if err != nil {
		h.fail(w, r, http.StatusBadRequest, "Nie udało się odczytać pliku: "+err.Error())
		return
	}
	if extra := SplitTags(r.FormValue("tags")); len(extra) > 0 {
		for i := range entries {
			entries[i].Tags = append(entries[i].Tags, extra...)
		}
	}
	h.importEntries(w, r, entries, "file:"+fh.Filename)
}

func (h *Handler) importEntries(w http.ResponseWriter, r *http.Request, entries []Entry, source string) {
	ts, rep := h.Importer.Prepare(r.Context(), entries)
	n, err := h.Store.Insert(r.Context(), ts, h.user(r))
	if err != nil {
		h.Log.Error("targets: insert", "err", err)
		h.fail(w, r, http.StatusInternalServerError, "Błąd zapisu do bazy danych.")
		return
	}
	rep.Finish(len(ts), n)
	h.Log.Info("targets imported", "source", source, "imported", rep.Imported, "duplicates", rep.Duplicates, "errors", len(rep.Errors))
	if wantsJSON(r) {
		writeJSON(w, http.StatusOK, rep)
		return
	}
	h.render(w, r, http.StatusOK, &rep, "")
}

func (h *Handler) fail(w http.ResponseWriter, r *http.Request, status int, msg string) {
	if wantsJSON(r) {
		writeJSON(w, status, map[string]string{"error": msg})
		return
	}
	if r.Header.Get("HX-Request") == "true" {
		// htmx ignores non-2xx bodies by default; show the message in place.
		status = http.StatusOK
	}
	h.render(w, r, status, nil, msg)
}

func (h *Handler) updateTags(w http.ResponseWriter, r *http.Request) {
	id, ok := pathID(w, r)
	if !ok {
		return
	}
	if err := r.ParseForm(); err != nil {
		http.Error(w, "Nieprawidłowy formularz", http.StatusBadRequest)
		return
	}
	tags, err := NormalizeTags(SplitTags(r.PostFormValue("tags")))
	if err != nil {
		http.Error(w, "Nieprawidłowe tagi: "+err.Error(), http.StatusBadRequest)
		return
	}
	t, err := h.Store.UpdateTags(r.Context(), id, tags, h.user(r))
	if errors.Is(err, ErrNotFound) {
		http.Error(w, "Nie znaleziono celu", http.StatusNotFound)
		return
	}
	if err != nil {
		h.Log.Error("targets: update tags", "err", err)
		http.Error(w, "Błąd bazy danych", http.StatusInternalServerError)
		return
	}
	if r.Header.Get("HX-Request") == "true" {
		h.exec(w, http.StatusOK, "targets/row", rowData{T: t, CanWrite: true})
		return
	}
	http.Redirect(w, r, "/targets", http.StatusSeeOther)
}

func (h *Handler) delete(w http.ResponseWriter, r *http.Request) {
	id, ok := pathID(w, r)
	if !ok {
		return
	}
	err := h.Store.Delete(r.Context(), id, h.user(r))
	if err != nil && !errors.Is(err, ErrNotFound) {
		h.Log.Error("targets: delete", "err", err)
		http.Error(w, "Błąd bazy danych", http.StatusInternalServerError)
		return
	}
	if r.Header.Get("HX-Request") == "true" || r.Method == http.MethodDelete {
		w.WriteHeader(http.StatusOK) // htmx swaps the row with nothing
		return
	}
	http.Redirect(w, r, "/targets", http.StatusSeeOther)
}

func (h *Handler) export(w http.ResponseWriter, r *http.Request) {
	ts, err := h.Store.List(r.Context(), tagFilter(r))
	if err != nil {
		h.Log.Error("targets: export", "err", err)
		http.Error(w, "Błąd bazy danych", http.StatusInternalServerError)
		return
	}
	switch r.URL.Query().Get("format") {
	case "json":
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Content-Disposition", `attachment; filename="targets.json"`)
		_ = WriteJSON(w, ts)
	default:
		w.Header().Set("Content-Type", "text/csv; charset=utf-8")
		w.Header().Set("Content-Disposition", `attachment; filename="targets.csv"`)
		_ = WriteCSV(w, ts)
	}
}

// tagFilter returns the ?tag= filter normalized like stored tags.
func tagFilter(r *http.Request) string {
	return strings.ToLower(strings.TrimSpace(r.URL.Query().Get("tag")))
}

func pathID(w http.ResponseWriter, r *http.Request) (int64, bool) {
	id, err := strconv.ParseInt(chi.URLParam(r, "id"), 10, 64)
	if err != nil || id <= 0 {
		http.Error(w, "Nieprawidłowy identyfikator", http.StatusBadRequest)
		return 0, false
	}
	return id, true
}

func wantsJSON(r *http.Request) bool {
	return strings.Contains(r.Header.Get("Accept"), "application/json")
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func satAdd(a, b uint64) uint64 {
	if a+b < a {
		return ^uint64(0)
	}
	return a + b
}

type rowData struct {
	T        model.Target
	CanWrite bool
}

// errLabels translates report errors (kept in English in the JSON report,
// see testdata/import/report.example.json) to Polish UI labels.
var errLabels = []struct{ prefix, pl string }{
	{ErrNotAllowed.Error(), "poza dozwolonymi sieciami (allowlista)"},
	{ErrEmpty.Error(), "pusta wartość"},
	{ErrZone.Error(), "strefy IPv6 są niedozwolone"},
	{ErrInvalidTarget.Error(), "to nie jest poprawny adres IP, zakres CIDR ani domena"},
	{ErrInvalidDomain.Error(), "niepoprawna nazwa domeny"},
	{ErrNoAddresses.Error(), "domena nie wskazuje żadnego adresu"},
	{"resolve ", "nie udało się rozwiązać nazwy domeny"},
	{ErrTooManyEntries.Error(), fmt.Sprintf("za dużo wpisów (limit %d)", MaxImportEntries)},
	{"tag", "niepoprawne tagi"},
}

func errLabel(msg string) string {
	for _, l := range errLabels {
		if strings.HasPrefix(msg, l.prefix) {
			if msg == l.prefix {
				return l.pl
			}
			return l.pl + " (" + msg + ")"
		}
	}
	return msg
}

var kindLabels = map[model.TargetKind]string{
	model.TargetIP:     "adres IP",
	model.TargetCIDR:   "zakres CIDR",
	model.TargetDomain: "domena",
}

// ParseTemplates parses the layout and the module templates.
func ParseTemplates() (*template.Template, error) {
	t := template.New("targets").Funcs(template.FuncMap{
		"join":      strings.Join,
		"kindLabel": func(k model.TargetKind) string { return kindLabels[k] },
		"errLabel":  errLabel,
		"row":       func(t model.Target, w bool) rowData { return rowData{T: t, CanWrite: w} },
		"addrs": func(t model.Target) string {
			p, ok := TargetPrefix(t)
			if !ok {
				return "–"
			}
			return strconv.FormatUint(AddrCount(p), 10)
		},
	})
	var err error
	if BaseTemplates != nil {
		t, err = t.ParseFS(BaseTemplates, "base.html")
	} else {
		t, err = t.Parse(fallbackBase)
	}
	if err != nil {
		return nil, err
	}
	return t.ParseFS(tpl.FS, "*.html")
}

// fallbackBase mirrors web/templates/base.html for standalone use.
const fallbackBase = `{{define "base"}}<!doctype html>
<html lang="pl">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>{{block "title" .}}Attack Surface Intelligence{{end}}</title>
<link rel="stylesheet" href="/static/app.css">
<script src="/static/htmx.min.js" defer></script>
</head>
<body>
<header class="top">
  <a class="brand" href="/">Attack Surface Intelligence</a>
  <nav class="main" hx-get="/nav" hx-trigger="load" hx-swap="innerHTML"></nav>
</header>
<nav class="sub">{{block "nav" .}}{{end}}</nav>
<main>{{block "content" .}}{{end}}</main>
</body>
</html>{{end}}`

// PGStore implements Store on PostgreSQL. Writes run in one transaction
// together with their audit_log row.
type PGStore struct {
	DB *pgxpool.Pool
}

func (s PGStore) List(ctx context.Context, tag string) ([]model.Target, error) {
	return store.ListTargets(ctx, s.DB, tag)
}

func (s PGStore) Tags(ctx context.Context) ([]string, error) {
	return store.TargetTags(ctx, s.DB)
}

func (s PGStore) Insert(ctx context.Context, ts []model.Target, by *int64) (int, error) {
	if len(ts) == 0 {
		return 0, nil
	}
	n := 0
	err := pgx.BeginFunc(ctx, s.DB, func(tx pgx.Tx) error {
		var err error
		if n, err = store.InsertTargets(ctx, tx, ts, by); err != nil {
			return err
		}
		return store.AuditTargets(ctx, tx, by, "targets.import", map[string]int{"submitted": len(ts), "inserted": n})
	})
	return n, err
}

func (s PGStore) UpdateTags(ctx context.Context, id int64, tags []string, by *int64) (model.Target, error) {
	var out model.Target
	err := pgx.BeginFunc(ctx, s.DB, func(tx pgx.Tx) error {
		if err := store.UpdateTargetTags(ctx, tx, id, tags); err != nil {
			return err
		}
		ts, err := store.TargetsByIDs(ctx, tx, []int64{id})
		if err != nil {
			return err
		}
		if len(ts) == 0 {
			return ErrNotFound
		}
		out = ts[0]
		return store.AuditTargets(ctx, tx, by, "targets.tags", map[string]any{"id": id, "value": out.Value, "tags": tags})
	})
	return out, err
}

func (s PGStore) Delete(ctx context.Context, id int64, by *int64) error {
	return pgx.BeginFunc(ctx, s.DB, func(tx pgx.Tx) error {
		v, err := store.DeleteTarget(ctx, tx, id)
		if err != nil {
			return err
		}
		return store.AuditTargets(ctx, tx, by, "targets.delete", map[string]any{"id": id, "value": v})
	})
}
