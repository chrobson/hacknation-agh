package export

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
	"os"
	"strconv"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/chrobson/hacknation-agh/internal/dojo"
	"github.com/chrobson/hacknation-agh/internal/store"
	"github.com/chrobson/hacknation-agh/internal/web"
	exporttpl "github.com/chrobson/hacknation-agh/web/templates/export"
)

// PermExport is the RBAC permission required for every route of this module.
const PermExport = "export"

// RequirePerm wraps handlers with an RBAC check. The integrator sets it to
// the auth module's middleware. The default fails closed (403) so the
// routes are never exposed without authorization.
var RequirePerm = func(perm string) func(http.Handler) http.Handler {
	return func(http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			http.Error(w, "Brak uprawnień ("+perm+"): autoryzacja nie jest skonfigurowana", http.StatusForbidden)
		})
	}
}

// CurrentUserID returns the logged-in user id for audit entries. The
// integrator sets it from the auth module; nil means unknown.
var CurrentUserID = func(r *http.Request) *int64 { return nil }

// BaseTemplates is an FS rooted at web/templates that contains base.html
// (same convention as target.BaseTemplates and diff.BaseTemplates). nil
// uses the built-in copy of base.html. Module pages are always embedded
// (web/templates/export), so the binary needs no files on disk.
var BaseTemplates fs.FS

// AfterImport runs after an import run is committed. The integrator sets it
// to the diff hook (diff.ApplyRun) so imports are compared like scans.
var AfterImport func(ctx context.Context, pool *pgxpool.Pool, runID int64) error

// DojoToken returns the DefectDojo API token. Default: ASI_DOJO_TOKEN, or
// an empty token with ASI_DOJO_USER / ASI_DOJO_PASSWORD used to obtain one
// via api-token-auth. TODO(W1-5): read the token from the encrypted
// secrets table once the auth module exposes it.
var DojoToken = func(ctx context.Context) (token, user, password string, err error) {
	return os.Getenv("ASI_DOJO_TOKEN"), os.Getenv("ASI_DOJO_USER"), os.Getenv("ASI_DOJO_PASSWORD"), nil
}

type handler struct {
	d     web.Deps
	pages map[string]*template.Template
	log   *slog.Logger
}

// Mount registers the export/import routes:
//
//	GET  /export                  page with export buttons and DefectDojo push
//	GET  /export/services.csv     CSV of services with detections (?run=ID)
//	GET  /export/services.json    JSON of services with detections (?run=ID)
//	GET  /export/defectdojo.json  DefectDojo Generic Findings (?run=ID)
//	POST /export/defectdojo/push  push to DefectDojo (only if ASI_DOJO_PUSH=true)
//	GET  /import                  upload form
//	POST /import                  import nmap XML or Generic Findings JSON
//
// All routes require the "export" permission.
func Mount(r chi.Router, d web.Deps) {
	h, err := newHandler(d)
	if err != nil {
		panic(fmt.Sprintf("export: %v", err))
	}
	r.Group(func(r chi.Router) {
		r.Use(RequirePerm(PermExport))
		r.Get("/export", h.index)
		r.Get("/export/services.csv", h.csv)
		r.Get("/export/services.json", h.json)
		r.Get("/export/defectdojo.json", h.dojo)
		r.Post("/export/defectdojo/push", h.push)
		r.Get("/import", h.importForm)
		r.Post("/import", h.importUpload)
	})
}

func newHandler(d web.Deps) (*handler, error) {
	log := d.Log
	if log == nil {
		log = slog.Default()
	}
	pages, err := parsePages(BaseTemplates)
	if err != nil {
		return nil, err
	}
	return &handler{d: d, pages: pages, log: log}, nil
}

// parsePages parses each page with base.html in its own set, because every
// page defines the same "title"/"content" blocks.
func parsePages(base fs.FS) (map[string]*template.Template, error) {
	pages := map[string]*template.Template{}
	for _, name := range []string{"index", "import"} {
		t := template.New(name).Funcs(funcs)
		var err error
		if base != nil {
			t, err = t.ParseFS(base, "base.html")
		} else {
			t, err = t.Parse(fallbackBase)
		}
		if err != nil {
			return nil, fmt.Errorf("base template: %w", err)
		}
		if t, err = t.ParseFS(exporttpl.FS, name+".html"); err != nil {
			return nil, err
		}
		pages[name] = t
	}
	return pages, nil
}

// fallbackBase is a copy of web/templates/base.html used when the
// integrator does not provide BaseTemplates.
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
  <nav>{{block "nav" .}}{{end}}</nav>
</header>
<main>{{block "content" .}}{{end}}</main>
</body>
</html>{{end}}`

var funcs = template.FuncMap{
	"fmtTime": func(v any) string {
		switch t := v.(type) {
		case time.Time:
			return t.UTC().Format("2006-01-02 15:04 UTC")
		case *time.Time:
			if t != nil {
				return t.UTC().Format("2006-01-02 15:04 UTC")
			}
		}
		return ""
	},
}

// snapshot loads the requested run (?run=ID) or the latest finished one.
func (h *handler) snapshot(ctx context.Context, r *http.Request) (Snapshot, error) {
	if h.d.DB == nil {
		return Snapshot{}, store.ErrNoRun
	}
	var id int64
	if v := r.URL.Query().Get("run"); v != "" {
		var err error
		if id, err = strconv.ParseInt(v, 10, 64); err != nil || id <= 0 {
			return Snapshot{}, store.ErrNoRun
		}
	}
	return LoadSnapshot(ctx, h.d.DB, id)
}

func (h *handler) snapshotOrError(w http.ResponseWriter, r *http.Request) (Snapshot, bool) {
	s, err := h.snapshot(r.Context(), r)
	if errors.Is(err, store.ErrNoRun) {
		http.Error(w, "Brak zakończonego przebiegu skanu do eksportu", http.StatusNotFound)
		return s, false
	}
	if err != nil {
		h.log.Error("export snapshot", "err", err)
		http.Error(w, "Błąd odczytu wyników", http.StatusInternalServerError)
		return s, false
	}
	return s, true
}

func attachment(w http.ResponseWriter, ctype, name string) {
	w.Header().Set("Content-Type", ctype)
	w.Header().Set("Content-Disposition", `attachment; filename="`+name+`"`)
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("X-Content-Type-Options", "nosniff")
}

func (h *handler) audit(r *http.Request, action string, details any) {
	if h.d.DB == nil {
		return
	}
	if err := store.DojoAudit(r.Context(), h.d.DB, CurrentUserID(r), action, "export", details); err != nil {
		h.log.Warn("audit", "action", action, "err", err)
	}
}

func (h *handler) csv(w http.ResponseWriter, r *http.Request) {
	s, ok := h.snapshotOrError(w, r)
	if !ok {
		return
	}
	var buf bytes.Buffer
	if err := WriteCSV(&buf, s); err != nil {
		http.Error(w, "Błąd eksportu", http.StatusInternalServerError)
		return
	}
	h.audit(r, "export.csv", map[string]any{"run_id": s.RunID})
	attachment(w, "text/csv; charset=utf-8", fmt.Sprintf("asi-run-%d-services.csv", s.RunID))
	_, _ = buf.WriteTo(w)
}

func (h *handler) json(w http.ResponseWriter, r *http.Request) {
	s, ok := h.snapshotOrError(w, r)
	if !ok {
		return
	}
	var buf bytes.Buffer
	if err := WriteJSON(&buf, s); err != nil {
		http.Error(w, "Błąd eksportu", http.StatusInternalServerError)
		return
	}
	h.audit(r, "export.json", map[string]any{"run_id": s.RunID})
	attachment(w, "application/json", fmt.Sprintf("asi-run-%d-services.json", s.RunID))
	_, _ = buf.WriteTo(w)
}

func (h *handler) dojo(w http.ResponseWriter, r *http.Request) {
	s, ok := h.snapshotOrError(w, r)
	if !ok {
		return
	}
	b, err := s.Dojo()
	if err != nil {
		h.log.Error("dojo export", "err", err)
		http.Error(w, "Błąd generowania pliku DefectDojo", http.StatusInternalServerError)
		return
	}
	h.audit(r, "export.defectdojo", map[string]any{"run_id": s.RunID})
	attachment(w, "application/json", fmt.Sprintf("asi-run-%d-defectdojo.json", s.RunID))
	_, _ = w.Write(b)
}

type indexData struct {
	Run        *store.ExportRun
	Services   int
	Findings   int
	PushOn     bool
	DojoURL    string
	Pushes     []store.DojoPush
	Message    string
	Error      string
	PushResult *dojo.ImportResult
}

func (h *handler) indexData(r *http.Request) indexData {
	data := indexData{PushOn: h.d.Config.DojoPush && h.d.Config.DojoURL != "", DojoURL: h.d.Config.DojoURL}
	s, err := h.snapshot(r.Context(), r)
	switch {
	case err == nil:
		run := store.ExportRun{ID: s.RunID, Kind: s.RunKind}
		t := s.Date
		run.FinishedAt = &t
		data.Run = &run
		data.Services = len(s.Services)
		data.Findings = len(s.Findings())
	case !errors.Is(err, store.ErrNoRun):
		h.log.Error("export index", "err", err)
		data.Error = "Błąd odczytu wyników"
	}
	if h.d.DB != nil {
		if p, err := store.DojoRecentPushes(r.Context(), h.d.DB, 10); err == nil {
			data.Pushes = p
		}
	}
	return data
}

func (h *handler) render(w http.ResponseWriter, name string, data any) {
	var buf bytes.Buffer
	t, ok := h.pages[name]
	if !ok {
		http.Error(w, "Błąd szablonu", http.StatusInternalServerError)
		return
	}
	if err := t.ExecuteTemplate(&buf, name+".html", data); err != nil {
		h.log.Error("render", "template", name, "err", err)
		http.Error(w, "Błąd szablonu", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_, _ = buf.WriteTo(w)
}

func (h *handler) index(w http.ResponseWriter, r *http.Request) {
	h.render(w, "index", h.indexData(r))
}

func (h *handler) push(w http.ResponseWriter, r *http.Request) {
	cfg := h.d.Config
	if !cfg.DojoPush || cfg.DojoURL == "" {
		http.Error(w, "Wysyłka do DefectDojo jest wyłączona (ASI_DOJO_PUSH=false)", http.StatusForbidden)
		return
	}
	s, ok := h.snapshotOrError(w, r)
	if !ok {
		return
	}
	b, err := s.Dojo()
	if err != nil {
		http.Error(w, "Błąd generowania pliku DefectDojo", http.StatusInternalServerError)
		return
	}
	token, user, pass, err := DojoToken(r.Context())
	data := h.indexData(r)
	if err == nil {
		c := &dojo.Client{BaseURL: cfg.DojoURL, Token: token, Username: user, Password: pass}
		ctx, cancel := context.WithTimeout(r.Context(), 3*time.Minute)
		var res dojo.ImportResult
		res, err = c.Push(ctx, dojo.PushParams{ScanDate: s.Date}, b)
		cancel()
		rec := store.DojoPush{RunID: &s.RunID, Endpoint: res.Endpoint, Findings: len(s.Findings()), OK: err == nil, Statistics: res.Statistics}
		if id := int64(res.ID()); id != 0 {
			rec.TestID = &id
		}
		if err != nil {
			rec.Error = err.Error()
		}
		if rerr := store.DojoRecordPush(r.Context(), h.d.DB, rec); rerr != nil {
			h.log.Warn("record push", "err", rerr)
		}
		if err == nil {
			data.PushResult = &res
		}
	}
	h.audit(r, "export.defectdojo.push", map[string]any{"run_id": s.RunID, "ok": err == nil})
	if err != nil {
		h.log.Error("dojo push", "err", err)
		data.Error = "Wysyłka do DefectDojo nie powiodła się: " + err.Error()
	} else {
		data.Message = fmt.Sprintf("Wysłano %d findingów do DefectDojo.", len(s.Findings()))
	}
	if p, err := store.DojoRecentPushes(r.Context(), h.d.DB, 10); err == nil {
		data.Pushes = p
	}
	h.render(w, "index", data)
}

type importData struct {
	Report *Report
	Error  string
	MaxMB  int
}

func (h *handler) importForm(w http.ResponseWriter, r *http.Request) {
	h.render(w, "import", importData{MaxMB: MaxImportSize >> 20})
}

// importUpload reads the multipart upload with MultipartReader so the file
// stays in memory (ParseMultipartForm would spill large files to disk).
func (h *handler) importUpload(w http.ResponseWriter, r *http.Request) {
	data := importData{MaxMB: MaxImportSize >> 20}
	body, err := readUpload(w, r, "file", MaxImportSize)
	if err != nil {
		data.Error = err.Error()
		w.WriteHeader(http.StatusBadRequest)
		h.render(w, "import", data)
		return
	}
	rep, err := Import(r.Context(), h.d.DB, body)
	h.audit(r, "import", map[string]any{"format": rep.Format, "run_id": rep.RunID, "ok": err == nil, "bytes": len(body)})
	if err != nil {
		h.log.Warn("import", "err", err)
		data.Error = "Import nie powiódł się: " + err.Error()
		if len(rep.Errors) > 0 {
			data.Report = &rep
		}
		w.WriteHeader(http.StatusBadRequest)
		h.render(w, "import", data)
		return
	}
	if AfterImport != nil {
		if err := AfterImport(r.Context(), h.d.DB, rep.RunID); err != nil {
			h.log.Error("after import", "run_id", rep.RunID, "err", err)
			rep.Errors = append(rep.Errors, "porównanie z poprzednim przebiegiem nie powiodło się: "+err.Error())
		}
	}
	data.Report = &rep
	if r.Header.Get("Accept") == "application/json" {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(rep)
		return
	}
	h.render(w, "import", data)
}

func readUpload(w http.ResponseWriter, r *http.Request, field string, limit int64) ([]byte, error) {
	r.Body = http.MaxBytesReader(w, r.Body, limit+1<<20)
	mr, err := r.MultipartReader()
	if err != nil {
		return nil, errors.New("oczekiwano formularza multipart/form-data")
	}
	for {
		part, err := mr.NextPart()
		if err == io.EOF {
			return nil, errors.New("brak pliku w formularzu")
		}
		if err != nil {
			return nil, errors.New("nieprawidłowy formularz lub plik za duży")
		}
		if part.FormName() != field {
			_ = part.Close()
			continue
		}
		b, err := io.ReadAll(io.LimitReader(part, limit+1))
		_ = part.Close()
		if err != nil {
			return nil, errors.New("nie udało się odczytać pliku")
		}
		if int64(len(b)) > limit {
			return nil, fmt.Errorf("plik większy niż %d MB", limit>>20)
		}
		if len(b) == 0 {
			return nil, errors.New("plik jest pusty")
		}
		return b, nil
	}
}
