package diff

import (
	"bytes"
	"errors"
	"fmt"
	"html/template"
	"io/fs"
	"log/slog"
	"net/http"
	"net/netip"
	"net/url"
	"slices"
	"strconv"
	"strings"
	"time"
	"unicode"

	"github.com/go-chi/chi/v5"
	"github.com/jackc/pgx/v5"

	"github.com/chrobson/hacknation-agh/internal/model"
	"github.com/chrobson/hacknation-agh/internal/store"
	"github.com/chrobson/hacknation-agh/internal/web"
	"github.com/chrobson/hacknation-agh/web/templates/changes"
)

// Permissions used by this module.
const (
	PermRead = "results.read"
	PermEdit = "results.edit"
)

// Access connects this module to internal/auth. web.Deps carries no auth
// hooks yet (see CONTRACT_REQUESTS.md), so the integrator sets Auth before
// calling Mount. A zero Access denies every request (fail closed).
type Access struct {
	// Require returns middleware answering 403 unless the user has perm.
	Require func(perm string) func(http.Handler) http.Handler
	// Can reports whether the request's user has perm (used to hide links).
	Can func(r *http.Request, perm string) bool
	// UserID returns the logged-in user's id, 0 if unknown.
	UserID func(r *http.Request) int64
}

// Auth is the access hook used by Mount.
var Auth Access

// BaseTemplates, when set, must contain base.html (the shared layout, i.e. an
// FS rooted at web/templates). When nil a built-in copy of the layout is used.
// The module's own templates are always embedded (web/templates/changes).
var BaseTemplates fs.FS

func (a Access) require(perm string) func(http.Handler) http.Handler {
	if a.Require != nil {
		return a.Require(perm)
	}
	return func(http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			http.Error(w, "Brak uprawnień", http.StatusForbidden)
		})
	}
}

func (a Access) can(r *http.Request, perm string) bool { return a.Can != nil && a.Can(r, perm) }

func (a Access) userID(r *http.Request) int64 {
	if a.UserID == nil {
		return 0
	}
	return a.UserID(r)
}

type handler struct {
	d     web.Deps
	auth  Access
	pages map[string]*template.Template
	log   *slog.Logger
}

var pageFiles = []string{"index.html", "run.html", "hosts.html", "annotations.html", "annotation_form.html"}

// Mount registers the changes, host state and annotation routes:
//
//	GET  /changes             runs with change counts        results.read
//	GET  /changes/{run}       changes of one run by kind     results.read
//	GET  /host-states         host lifecycle states          results.read
//	GET  /annotations         all annotations                results.read
//	GET  /annotations/cell    annotation fragment for a key  results.read
//	GET  /annotations/edit    edit form for a key            results.edit
//	POST /annotations         create/replace annotation      results.edit
//	POST /annotations/delete  delete annotation              results.edit
func Mount(r chi.Router, d web.Deps) {
	if Auth.Require == nil {
		moduleLog(d).Error("diff: Auth.Require is not set; every changes/annotations route answers 403")
	}
	h, err := newHandler(d, Auth, BaseTemplates)
	if err != nil {
		panic(fmt.Sprintf("diff: templates: %v", err))
	}
	h.routes(r)
}

func moduleLog(d web.Deps) *slog.Logger {
	if d.Log != nil {
		return d.Log
	}
	return slog.Default()
}

func newHandler(d web.Deps, a Access, base fs.FS) (*handler, error) {
	h := &handler{d: d, auth: a, pages: map[string]*template.Template{}, log: moduleLog(d)}
	for _, p := range pageFiles {
		t := template.New(p).Funcs(funcs)
		var err error
		if base != nil {
			t, err = t.ParseFS(base, "base.html")
		} else {
			t, err = t.Parse(fallbackBase)
		}
		if err != nil {
			return nil, err
		}
		if t, err = t.ParseFS(changes.FS, "_shared.html", p); err != nil {
			return nil, err
		}
		h.pages[p] = t
	}
	return h, nil
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

func (h *handler) routes(r chi.Router) {
	r.Group(func(r chi.Router) {
		r.Use(h.auth.require(PermRead))
		r.Get("/changes", h.index)
		r.Get("/changes/{run}", h.run)
		r.Get("/host-states", h.hosts)
		r.Get("/annotations", h.annotations)
		r.Get("/annotations/cell", h.annotationCell)
	})
	r.Group(func(r chi.Router) {
		r.Use(h.auth.require(PermEdit))
		r.Get("/annotations/edit", h.annotationEdit)
		r.Post("/annotations", h.annotationSave)
		r.Post("/annotations/delete", h.annotationDelete)
	})
}

// ------------------------------------------------------------- render ---

func (h *handler) render(w http.ResponseWriter, page, name string, status int, data any) {
	var buf bytes.Buffer
	if err := h.pages[page].ExecuteTemplate(&buf, name, data); err != nil {
		h.log.Error("render", "page", page, "err", err)
		http.Error(w, "Błąd renderowania strony", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(status)
	_, _ = buf.WriteTo(w)
}

func (h *handler) fail(w http.ResponseWriter, err error) {
	h.log.Error("diff handler", "err", err)
	http.Error(w, "Błąd serwera", http.StatusInternalServerError)
}

func isHTMX(r *http.Request) bool { return r.Header.Get("HX-Request") == "true" }

// ------------------------------------------------------------ changes ---

type indexData struct {
	Runs        []store.ChangeRun
	Kinds       []model.ChangeKind
	StateCounts map[model.HostStateKind]int
	States      []model.HostStateKind
}

func (h *handler) index(w http.ResponseWriter, r *http.Request) {
	runs, err := store.ListChangeRuns(r.Context(), h.d.DB, 100)
	if err != nil {
		h.fail(w, err)
		return
	}
	counts, err := store.HostStateCounts(r.Context(), h.d.DB)
	if err != nil {
		h.fail(w, err)
		return
	}
	h.render(w, "index.html", "base", http.StatusOK, indexData{
		Runs: runs, Kinds: KindOrder, StateCounts: counts, States: hostStates,
	})
}

// ChangeGroup is a set of changes of one kind on the run page.
type ChangeGroup struct {
	Kind model.ChangeKind
	Rows []ChangeRow
}

// ChangeRow is one change with the analyst annotation of its key, if any.
type ChangeRow struct {
	model.Change
	Ann *store.Annotation
}

type runData struct {
	Run     store.ChangeRun
	Total   int
	Groups  []ChangeGroup
	CanEdit bool
	Return  string
}

// GroupChanges groups changes by kind in KindOrder, dropping empty groups.
func GroupChanges(cs []model.Change, anns map[model.AssetKey]store.Annotation) []ChangeGroup {
	by := map[model.ChangeKind][]ChangeRow{}
	for _, c := range cs {
		row := ChangeRow{Change: c}
		if a, ok := anns[c.Key]; ok {
			row.Ann = &a
		}
		by[c.Kind] = append(by[c.Kind], row)
	}
	var out []ChangeGroup
	for _, k := range KindOrder {
		if rows := by[k]; len(rows) > 0 {
			out = append(out, ChangeGroup{Kind: k, Rows: rows})
		}
	}
	return out
}

func (h *handler) run(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.ParseInt(chi.URLParam(r, "run"), 10, 64)
	if err != nil || id <= 0 {
		http.Error(w, "Nieprawidłowy numer przebiegu", http.StatusBadRequest)
		return
	}
	cr, err := store.GetChangeRun(r.Context(), h.d.DB, id)
	if errors.Is(err, pgx.ErrNoRows) {
		http.Error(w, "Nie znaleziono przebiegu", http.StatusNotFound)
		return
	} else if err != nil {
		h.fail(w, err)
		return
	}
	cs, err := store.ListChanges(r.Context(), h.d.DB, id)
	if err != nil {
		h.fail(w, err)
		return
	}
	SortChanges(cs)
	var ips []netip.Addr
	for _, c := range cs {
		if len(ips) == 0 || ips[len(ips)-1] != c.Key.IP {
			ips = append(ips, c.Key.IP)
		}
	}
	anns, err := store.AnnotationsByIPs(r.Context(), h.d.DB, ips)
	if err != nil {
		h.fail(w, err)
		return
	}
	h.render(w, "run.html", "base", http.StatusOK, runData{
		Run: cr, Total: len(cs), Groups: GroupChanges(cs, anns),
		CanEdit: h.auth.can(r, PermEdit), Return: r.URL.RequestURI(),
	})
}

// ------------------------------------------------------------- hosts ---

var hostStates = []model.HostStateKind{model.HostUp, model.HostDown, model.HostUnstable, model.HostInactive}

type hostsData struct {
	Hosts  []model.HostState
	Filter string
	States []model.HostStateKind
	Counts map[model.HostStateKind]int
	Cfg    Config
}

func (h *handler) hosts(w http.ResponseWriter, r *http.Request) {
	filter := r.URL.Query().Get("state")
	if filter != "" && !slices.Contains(hostStates, model.HostStateKind(filter)) {
		filter = ""
	}
	hs, err := store.ListHostStates(r.Context(), h.d.DB, filter)
	if err != nil {
		h.fail(w, err)
		return
	}
	counts, err := store.HostStateCounts(r.Context(), h.d.DB)
	if err != nil {
		h.fail(w, err)
		return
	}
	h.render(w, "hosts.html", "base", http.StatusOK, hostsData{
		Hosts: hs, Filter: filter, States: hostStates, Counts: counts,
		Cfg: FromConfig(h.d.Config.Unstable),
	})
}

// -------------------------------------------------------- annotations ---

type annotationsData struct {
	Items   []store.Annotation
	IP      string
	CanEdit bool
	Return  string
}

func (h *handler) annotations(w http.ResponseWriter, r *http.Request) {
	var ip netip.Addr
	ipStr := strings.TrimSpace(r.URL.Query().Get("ip"))
	if ipStr != "" {
		var err error
		if ip, err = netip.ParseAddr(ipStr); err != nil {
			http.Error(w, "Nieprawidłowy adres IP", http.StatusBadRequest)
			return
		}
	}
	items, err := store.ListAnnotations(r.Context(), h.d.DB, ip)
	if err != nil {
		h.fail(w, err)
		return
	}
	h.render(w, "annotations.html", "base", http.StatusOK, annotationsData{
		Items: items, IP: ipStr, CanEdit: h.auth.can(r, PermEdit), Return: r.URL.RequestURI(),
	})
}

// CellData feeds the "annotation_cell" fragment.
type CellData struct {
	Key     model.AssetKey
	Ann     *store.Annotation
	CanEdit bool
	Return  string
}

func (h *handler) loadCell(r *http.Request, k model.AssetKey) (CellData, error) {
	cd := CellData{Key: k, CanEdit: h.auth.can(r, PermEdit), Return: safeReturn(r.FormValue("return"))}
	a, err := store.GetAnnotation(r.Context(), h.d.DB, k)
	switch {
	case errors.Is(err, store.ErrAnnotationNotFound):
	case err != nil:
		return cd, err
	default:
		cd.Ann = &a
	}
	return cd, nil
}

func (h *handler) annotationCell(w http.ResponseWriter, r *http.Request) {
	k, err := ParseKey(r.URL.Query())
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	cd, err := h.loadCell(r, k)
	if err != nil {
		h.fail(w, err)
		return
	}
	h.render(w, "annotations.html", "annotation_cell", http.StatusOK, cd)
}

type formData struct {
	Key        model.AssetKey
	Ann        store.Annotation
	Exists     bool
	Return     string
	Error      string
	Severities []model.Severity
}

var severities = []model.Severity{model.SevInfo, model.SevLow, model.SevMedium, model.SevHigh, model.SevCritical}

func (h *handler) annotationEdit(w http.ResponseWriter, r *http.Request) {
	k, err := ParseKey(r.URL.Query())
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	fd := formData{Key: k, Return: safeReturn(r.URL.Query().Get("return")), Severities: severities}
	a, err := store.GetAnnotation(r.Context(), h.d.DB, k)
	switch {
	case errors.Is(err, store.ErrAnnotationNotFound):
		fd.Ann = store.Annotation{Key: k}
	case err != nil:
		h.fail(w, err)
		return
	default:
		fd.Ann, fd.Exists = a, true
	}
	h.renderForm(w, r, http.StatusOK, fd)
}

func (h *handler) renderForm(w http.ResponseWriter, r *http.Request, status int, fd formData) {
	name := "base"
	if isHTMX(r) {
		name = "annotation_form"
	}
	h.render(w, "annotation_form.html", name, status, fd)
}

func (h *handler) annotationSave(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		http.Error(w, "Nieprawidłowy formularz", http.StatusBadRequest)
		return
	}
	k, err := ParseKey(r.PostForm)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	a, err := ParseAnnotation(k, r.PostForm)
	ret := safeReturn(r.PostForm.Get("return"))
	if err != nil {
		// htmx does not swap 4xx responses by default, so answer 200 to
		// htmx requests to show the validation message in place.
		status := http.StatusUnprocessableEntity
		if isHTMX(r) {
			status = http.StatusOK
		}
		h.renderForm(w, r, status, formData{
			Key: k, Ann: a, Return: ret, Error: err.Error(), Severities: severities,
		})
		return
	}
	a.UpdatedBy = h.auth.userID(r)
	var saved store.Annotation
	err = pgx.BeginFunc(r.Context(), h.d.DB, func(tx pgx.Tx) error {
		var err error
		saved, err = store.UpsertAnnotation(r.Context(), tx, a)
		return err
	})
	if err != nil {
		h.fail(w, err)
		return
	}
	if isHTMX(r) {
		h.render(w, "annotations.html", "annotation_cell", http.StatusOK,
			CellData{Key: k, Ann: &saved, CanEdit: true, Return: ret})
		return
	}
	http.Redirect(w, r, ret, http.StatusSeeOther)
}

func (h *handler) annotationDelete(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		http.Error(w, "Nieprawidłowy formularz", http.StatusBadRequest)
		return
	}
	k, err := ParseKey(r.PostForm)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	uid := h.auth.userID(r)
	err = pgx.BeginFunc(r.Context(), h.d.DB, func(tx pgx.Tx) error {
		return store.DeleteAnnotation(r.Context(), tx, k, uid)
	})
	if err != nil && !errors.Is(err, store.ErrAnnotationNotFound) {
		h.fail(w, err)
		return
	}
	ret := safeReturn(r.PostForm.Get("return"))
	if isHTMX(r) {
		h.render(w, "annotations.html", "annotation_cell", http.StatusOK,
			CellData{Key: k, CanEdit: true, Return: ret})
		return
	}
	http.Redirect(w, r, ret, http.StatusSeeOther)
}

// ------------------------------------------------------------ parsing ---

// ParseKey reads an asset key from ip, port, proto and vhost values.
// port empty or 0 means a host-level key (proto must then be empty).
func ParseKey(v url.Values) (model.AssetKey, error) {
	var k model.AssetKey
	ip, err := netip.ParseAddr(strings.TrimSpace(v.Get("ip")))
	if err != nil {
		return k, errors.New("Nieprawidłowy adres IP")
	}
	k.IP = ip.Unmap()
	if p := strings.TrimSpace(v.Get("port")); p != "" {
		n, err := strconv.ParseUint(p, 10, 16)
		if err != nil {
			return k, errors.New("Nieprawidłowy port")
		}
		k.Port = uint16(n)
	}
	k.Proto = strings.ToLower(strings.TrimSpace(v.Get("proto")))
	switch {
	case k.Port == 0 && k.Proto != "":
		return k, errors.New("Adnotacja hosta (port 0) nie może mieć protokołu")
	case k.Port != 0 && k.Proto != "tcp" && k.Proto != "udp":
		return k, errors.New("Protokół musi być tcp lub udp")
	}
	k.VHost = strings.ToLower(strings.TrimSpace(v.Get("vhost")))
	if len(k.VHost) > 253 || strings.ContainsFunc(k.VHost, func(r rune) bool { return unicode.IsSpace(r) || unicode.IsControl(r) }) {
		return k, errors.New("Nieprawidłowy vhost")
	}
	return k, nil
}

// Limits on annotation input.
const (
	maxComment = 4000
	maxTags    = 20
	maxTagLen  = 64
)

// ParseAnnotation reads comment, tags (comma separated), severity and
// false_positive. On error it still returns the parsed values for re-display.
func ParseAnnotation(k model.AssetKey, v url.Values) (store.Annotation, error) {
	a := store.Annotation{
		Key:           k,
		Comment:       strings.TrimSpace(strings.ReplaceAll(v.Get("comment"), "\r\n", "\n")),
		Severity:      strings.TrimSpace(v.Get("severity")),
		FalsePositive: v.Get("false_positive") != "",
		Tags:          []string{},
	}
	for _, t := range strings.Split(v.Get("tags"), ",") {
		t = strings.TrimSpace(t)
		if t != "" && !slices.Contains(a.Tags, t) {
			a.Tags = append(a.Tags, t)
		}
	}
	switch {
	case len([]rune(a.Comment)) > maxComment:
		return a, fmt.Errorf("Komentarz może mieć najwyżej %d znaków", maxComment)
	case len(a.Tags) > maxTags:
		return a, fmt.Errorf("Najwyżej %d tagów", maxTags)
	case a.Severity != "" && !slices.Contains(severities, model.Severity(a.Severity)):
		return a, errors.New("Nieznany poziom ważności")
	}
	for _, t := range a.Tags {
		if len([]rune(t)) > maxTagLen {
			return a, fmt.Errorf("Tag może mieć najwyżej %d znaków", maxTagLen)
		}
	}
	return a, nil
}

// safeReturn accepts only local absolute paths, defaulting to /annotations.
// Backslashes and control characters are rejected outright: browsers turn
// "\\" into "/" and drop tabs/newlines, so "/\\evil" or "/\t/evil" would
// otherwise become a protocol-relative redirect.
func safeReturn(s string) string {
	const def = "/annotations"
	if len(s) > 2048 || !strings.HasPrefix(s, "/") || strings.HasPrefix(s, "//") ||
		strings.ContainsFunc(s, func(r rune) bool { return r == '\\' || r < 0x20 || r == 0x7f }) {
		return def
	}
	u, err := url.Parse(s)
	if err != nil || u.Scheme != "" || u.Host != "" || u.User != nil {
		return def
	}
	return s
}

// ------------------------------------------------------ template funcs ---

var kindLabels = map[model.ChangeKind]string{
	model.ChangeHostUp:   "Nowe lub ponownie aktywne hosty",
	model.ChangeHostDown: "Hosty, które przestały odpowiadać",
	model.ChangeUnstable: "Hosty niestabilne",
	model.ChangeNew:      "Nowe usługi",
	model.ChangeGone:     "Zniknięte usługi",
	model.ChangeChanged:  "Zmienione usługi",
}

var kindShort = map[model.ChangeKind]string{
	model.ChangeHostUp:   "host up",
	model.ChangeHostDown: "host down",
	model.ChangeUnstable: "niestabilne",
	model.ChangeNew:      "nowe",
	model.ChangeGone:     "zniknięte",
	model.ChangeChanged:  "zmienione",
}

var stateLabels = map[model.HostStateKind]string{
	model.HostUp:       "aktywny",
	model.HostDown:     "nie odpowiada",
	model.HostInactive: "nieaktywny",
	model.HostUnstable: "niestabilny",
}

var fieldLabels = map[string]string{
	"product": "produkt", "version": "wersja", "extrainfo": "informacje dodatkowe",
	"cpe": "CPE", "banner": "baner", "flips": "zmiany stanu",
}

var funcs = template.FuncMap{
	"kindLabel":  func(k model.ChangeKind) string { return kindLabels[k] },
	"kindShort":  func(k model.ChangeKind) string { return kindShort[k] },
	"stateLabel": func(s model.HostStateKind) string { return stateLabels[s] },
	"fieldLabel": func(f string) string {
		if l, ok := fieldLabels[f]; ok {
			return l
		}
		return f
	},
	"keyStr":   KeyString,
	"keyQuery": keyQuery,
	"keyID":    keyID,
	"countOf":  func(m map[model.ChangeKind]int, k model.ChangeKind) int { return m[k] },
	"stateCount": func(m map[model.HostStateKind]int, k model.HostStateKind) int {
		return m[k]
	},
	"fmtTime": func(t any) string {
		switch v := t.(type) {
		case time.Time:
			if v.IsZero() {
				return "—"
			}
			return v.Local().Format("2006-01-02 15:04")
		case *time.Time:
			if v == nil || v.IsZero() {
				return "—"
			}
			return v.Local().Format("2006-01-02 15:04")
		}
		return "—"
	},
	"join": strings.Join,
	"cell": func(k model.AssetKey, ann any, canEdit bool, ret string) CellData {
		cd := CellData{Key: k, CanEdit: canEdit, Return: ret}
		switch a := ann.(type) {
		case *store.Annotation:
			cd.Ann = a
		case store.Annotation:
			cd.Ann = &a
		}
		return cd
	},
	"transitions": func(fs []model.Flip) int { return Transitions(fs) },
	"withReturn": func(q template.URL, ret string) template.URL {
		return template.URL(string(q) + "&return=" + url.QueryEscape(ret))
	},
}

// KeyString formats a key as ip, ip:port/proto or ip:port/proto (vhost).
func KeyString(k model.AssetKey) string {
	if k.Port == 0 {
		return k.IP.String()
	}
	s := netip.AddrPortFrom(k.IP, k.Port).String() + "/" + k.Proto
	if k.VHost != "" {
		s += " (" + k.VHost + ")"
	}
	return s
}

func keyQuery(k model.AssetKey) template.URL {
	v := url.Values{}
	v.Set("ip", k.IP.String())
	v.Set("port", strconv.Itoa(int(k.Port)))
	v.Set("proto", k.Proto)
	v.Set("vhost", k.VHost)
	return template.URL(v.Encode())
}

// keyID is a DOM id unique per key.
func keyID(k model.AssetKey) string {
	return fmt.Sprintf("ann-%x", KeyString(k))
}
