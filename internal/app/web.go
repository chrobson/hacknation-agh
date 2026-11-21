package app

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"html/template"
	"io/fs"
	"log/slog"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/jackc/pgx/v5"

	"github.com/chrobson/hacknation-agh/internal/auth"
	"github.com/chrobson/hacknation-agh/internal/config"
	"github.com/chrobson/hacknation-agh/internal/httpfp"
	"github.com/chrobson/hacknation-agh/internal/model"
	"github.com/chrobson/hacknation-agh/internal/runner"
	"github.com/chrobson/hacknation-agh/internal/store"
	"github.com/chrobson/hacknation-agh/internal/web"
)

// Pages serves the integrator-owned pages: shared navigation, dashboard,
// scan configurations and results.
type Pages struct {
	Deps   web.Deps
	Runner *runner.Runner  // nil: scans cannot be started from the UI
	Base   context.Context // lifetime of runs started from the UI
	tmpl   map[string]*template.Template
}

// NewPages parses the templates (fsys rooted at web/templates).
func NewPages(d web.Deps, rn *runner.Runner, base context.Context, fsys fs.FS) (*Pages, error) {
	p := &Pages{Deps: d, Runner: rn, Base: base, tmpl: map[string]*template.Template{}}
	funcs := auth.Funcs()
	for k, v := range tmplFuncs {
		funcs[k] = v
	}
	for _, name := range []string{"dashboard", "scans", "scan_form", "results", "service"} {
		t, err := template.New(name).Funcs(funcs).ParseFS(fsys, "base.html", "app/_parts.html", "app/"+name+".html")
		if err != nil {
			return nil, fmt.Errorf("template %s: %w", name, err)
		}
		p.tmpl[name] = t
	}
	t, err := template.New("nav").Funcs(funcs).ParseFS(fsys, "app/nav.html")
	if err != nil {
		return nil, fmt.Errorf("template nav: %w", err)
	}
	p.tmpl["nav"] = t
	return p, nil
}

var tmplFuncs = template.FuncMap{
	"fmtTime": func(v any) string {
		switch t := v.(type) {
		case time.Time:
			if t.IsZero() {
				return "–"
			}
			return t.Local().Format("2006-01-02 15:04:05")
		case *time.Time:
			if t == nil || t.IsZero() {
				return "–"
			}
			return t.Local().Format("2006-01-02 15:04:05")
		}
		return "–"
	},
	"catLabel":   catLabel,
	"kindLabel":  kindLabel,
	"stateLabel": stateLabel,
	"runLabel":   runLabel,
	"hhmm": func(d *time.Duration) string {
		if d == nil {
			return ""
		}
		return fmt.Sprintf("%02d:%02d", int(d.Hours()), int(d.Minutes())%60)
	},
	"deref": func(p *int) string {
		if p == nil {
			return ""
		}
		return strconv.Itoa(*p)
	},
	"hasID": func(ids []int64, id int64) bool {
		for _, x := range ids {
			if x == id {
				return true
			}
		}
		return false
	},
	"q": url.QueryEscape,
}

func catLabel(c string) string {
	switch c {
	case "cms":
		return "CMS"
	case "framework":
		return "Framework"
	case "server":
		return "Serwer"
	case "iot":
		return "IoT"
	case "admin-panel":
		return "Panel administracyjny"
	case "staging":
		return "Środowisko testowe"
	case "other":
		return "Inne"
	}
	return c
}

func kindLabel(k string) string {
	switch k {
	case "new":
		return "nowa usługa"
	case "gone":
		return "usługa zniknęła"
	case "changed":
		return "zmiana usługi"
	case "host_up":
		return "host pojawił się"
	case "host_down":
		return "host zniknął"
	case "unstable":
		return "host niestabilny"
	}
	return k
}

func stateLabel(s string) string {
	switch s {
	case "up":
		return "aktywny"
	case "down":
		return "nie odpowiada"
	case "inactive":
		return "nieaktywny"
	case "unstable":
		return "niestabilny"
	}
	return s
}

func runLabel(s string) string {
	switch s {
	case "queued":
		return "w kolejce"
	case "running":
		return "trwa"
	case "paused":
		return "wstrzymany (czeka na okno)"
	case "done":
		return "zakończony"
	case "failed":
		return "błąd"
	}
	return s
}

// Mount registers the pages. The auth middleware must already be applied.
func (p *Pages) Mount(r chi.Router) {
	r.Get("/nav", p.nav)
	r.Get("/healthz", func(w http.ResponseWriter, r *http.Request) {
		if err := p.Deps.DB.Ping(r.Context()); err != nil {
			http.Error(w, "db: "+err.Error(), http.StatusServiceUnavailable)
			return
		}
		_, _ = w.Write([]byte("ok\n"))
	})
	r.With(auth.RequireAuth).Get("/", p.dashboard)
	r.Group(func(r chi.Router) {
		r.Use(auth.Require(auth.PermResultsRead))
		r.Get("/scans", p.scans)
		r.Get("/results", p.results)
		r.Get("/results/services/{id}", p.service)
	})
	r.Group(func(r chi.Router) {
		r.Use(auth.Require(auth.PermScansRun))
		r.Get("/scans/new", p.scanForm)
		r.Get("/scans/{id}/edit", p.scanForm)
		r.Post("/scans", p.scanSave)
		r.Post("/scans/{id}", p.scanSave)
		r.Post("/scans/{id}/run", p.scanRun)
		r.Post("/scans/{id}/delete", p.scanDelete)
		r.Post("/runs/{id}/stop", p.runStop)
		r.Post("/runs/{id}/resume", p.runResume)
	})
}

type page struct {
	User    *auth.User
	Message string
	Error   string
	Data    any
}

func (p *Pages) render(w http.ResponseWriter, r *http.Request, name string, status int, pg page) {
	pg.User = auth.UserFrom(r.Context())
	if pg.Message == "" {
		pg.Message = flashText(r.URL.Query().Get("ok"))
	}
	if pg.Error == "" {
		pg.Error = r.URL.Query().Get("err")
		if len(pg.Error) > 300 {
			pg.Error = pg.Error[:300]
		}
	}
	var buf bytes.Buffer
	if err := p.tmpl[name].ExecuteTemplate(&buf, "base", pg); err != nil {
		p.log().Error("render", "page", name, "err", err)
		http.Error(w, "błąd szablonu", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(status)
	_, _ = buf.WriteTo(w)
}

func flashText(code string) string {
	switch code {
	case "saved":
		return "Zapisano konfigurację skanu."
	case "started":
		return "Skan uruchomiony."
	case "stopped":
		return "Skan zatrzymany. Harmonogram go nie wznowi, dopóki nie klikniesz „Wznów”."
	case "resumed":
		return "Skan zostanie wznowiony przy najbliższym cyklu harmonogramu (w oknie czasowym)."
	case "deleted":
		return "Usunięto konfigurację."
	}
	return ""
}

func (p *Pages) log() *slog.Logger {
	if p.Deps.Log != nil {
		return p.Deps.Log
	}
	return slog.Default()
}

func (p *Pages) fail(w http.ResponseWriter, r *http.Request, err error) {
	p.log().Error("page error", "path", r.URL.Path, "err", err)
	http.Error(w, "błąd serwera", http.StatusInternalServerError)
}

// navItem is one entry of the shared navigation.
type navItem struct {
	Href, Label, Perm string
}

var navItems = []navItem{
	{"/", "Pulpit", ""},
	{"/targets", "Cele", auth.PermTargetsRead},
	{"/scans", "Skany", auth.PermResultsRead},
	{"/results", "Wyniki", auth.PermResultsRead},
	{"/changes", "Zmiany", auth.PermResultsRead},
	{"/host-states", "Hosty", auth.PermResultsRead},
	{"/annotations", "Adnotacje", auth.PermResultsRead},
	{"/signatures", "Sygnatury", auth.PermResultsRead},
	{"/export", "Eksport", auth.PermExport},
	{"/import", "Import", auth.PermScansRun},
	{"/admin/users", "Administracja", auth.PermUsersAdmin},
}

func (p *Pages) nav(w http.ResponseWriter, r *http.Request) {
	u := auth.UserFrom(r.Context())
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Add("Vary", "Cookie")
	if u == nil {
		return
	}
	var items []navItem
	for _, it := range navItems {
		if it.Perm == "" || u.Can(it.Perm) {
			items = append(items, it)
		}
	}
	cur := r.Header.Get("HX-Current-URL")
	if cu, err := url.Parse(cur); err == nil {
		cur = cu.Path
	}
	if err := p.tmpl["nav"].ExecuteTemplate(w, "app/nav", map[string]any{"User": u, "Items": items, "Current": cur}); err != nil {
		p.log().Error("render nav", "err", err)
	}
}

func (p *Pages) dashboard(w http.ResponseWriter, r *http.Request) {
	// The dashboard shows results; a role without results.read is sent to
	// the first page it may open instead of seeing the counts.
	if u := auth.UserFrom(r.Context()); u != nil && !u.Can(auth.PermResultsRead) {
		for _, it := range navItems {
			if it.Perm != "" && it.Perm != string(auth.PermResultsRead) && u.Can(it.Perm) {
				http.Redirect(w, r, it.Href, http.StatusSeeOther)
				return
			}
		}
		http.Error(w, "Brak uprawnienia: "+string(auth.PermResultsRead), http.StatusForbidden)
		return
	}
	d, err := LoadDashboard(r.Context(), p.Deps.DB)
	if err != nil {
		p.fail(w, r, err)
		return
	}
	p.markActive(d.ActiveRuns)
	p.render(w, r, "dashboard", http.StatusOK, page{Data: d})
}

func (p *Pages) markActive(rs []RunRow) {
	if p.Runner == nil {
		return
	}
	act := map[int64]bool{}
	for _, id := range p.Runner.ActiveRuns() {
		act[id] = true
	}
	for i := range rs {
		rs[i].Active = act[rs[i].ID]
	}
}

// --- scans -------------------------------------------------------------

type scansData struct {
	Configs   []configRow
	Runs      []RunRow
	CanRun    bool
	Exclude   string
	Allowed   string
	HasRunner bool
}

type configRow struct {
	store.ScanConfig
	TargetsLabel string
	PortsLabel   string
	LastRun      *RunRow
}

func (p *Pages) scans(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	st := store.NewScanStore(p.Deps.DB)
	cfgs, err := st.Configs(ctx)
	if err != nil {
		p.fail(w, r, err)
		return
	}
	runs, err := ListRuns(ctx, p.Deps.DB, 30)
	if err != nil {
		p.fail(w, r, err)
		return
	}
	p.markActive(runs)
	d := scansData{Runs: runs, HasRunner: p.Runner != nil}
	if u := auth.UserFrom(ctx); u != nil {
		d.CanRun = u.Can(auth.PermScansRun)
	}
	for _, c := range cfgs {
		row := configRow{ScanConfig: c, TargetsLabel: "wszystkie cele", PortsLabel: portsLabel(c, p.Deps.Config.AllPortsMaxAddrs)}
		if len(c.TargetIDs) > 0 {
			row.TargetsLabel = fmt.Sprintf("%d wybranych", len(c.TargetIDs))
		}
		for i := range runs {
			if runs[i].ConfigID != nil && *runs[i].ConfigID == c.ID {
				row.LastRun = &runs[i]
				break
			}
		}
		d.Configs = append(d.Configs, row)
	}
	var ex, al []string
	for _, a := range p.Deps.Config.ScanExclude {
		ex = append(ex, a.String())
	}
	for _, a := range p.Deps.Config.AllowedCIDRs {
		al = append(al, a.String())
	}
	d.Exclude, d.Allowed = strings.Join(ex, ", "), strings.Join(al, ", ")
	p.render(w, r, "scans", http.StatusOK, page{Data: d})
}

type scanFormData struct {
	Config       store.ScanConfig
	New          bool
	Targets      []model.Target
	MaxRate      int    // ASI_MAX_RATE
	AllowedPorts string // ASI_SCAN_PORTS as entered, "" = no restriction
	Profiles     []string
	AllPortsMax  int // ASI_ALL_PORTS_MAX_ADDRS (auto profile)
}

func (p *Pages) scanForm(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	d := scanFormData{New: true, Config: store.ScanConfig{TopPorts: 1000, MaxRate: min(1000, p.maxRate()), Workers: 4, Enabled: true, ExtraPorts: true, PortProfile: runner.ProfileAuto}}
	if idS := chi.URLParam(r, "id"); idS != "" {
		id, err := strconv.ParseInt(idS, 10, 64)
		if err != nil {
			http.NotFound(w, r)
			return
		}
		c, err := store.NewScanStore(p.Deps.DB).Config(ctx, id)
		if errors.Is(err, pgx.ErrNoRows) {
			http.NotFound(w, r)
			return
		}
		if err != nil {
			p.fail(w, r, err)
			return
		}
		d.Config, d.New = c, false
	}
	ts, err := store.ListTargets(ctx, p.Deps.DB, "")
	if err != nil {
		p.fail(w, r, err)
		return
	}
	d.Targets = ts
	d.MaxRate, d.AllowedPorts = p.maxRate(), config.FormatPorts(p.Deps.Config.ScanPorts)
	d.Profiles, d.AllPortsMax = runner.Profiles, p.Deps.Config.AllPortsMaxAddrs
	d.Config.PortProfile = runner.ProfileOf(d.Config)
	p.render(w, r, "scan_form", http.StatusOK, page{Data: d})
}

func parseClock(s string) (*time.Duration, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return nil, nil
	}
	t, err := time.Parse("15:04", s)
	if err != nil {
		return nil, fmt.Errorf("niepoprawna godzina %q (HH:MM)", s)
	}
	d := time.Duration(t.Hour())*time.Hour + time.Duration(t.Minute())*time.Minute
	return &d, nil
}

func formInt(r *http.Request, name string, def, lo, hi int) (int, error) {
	v := strings.TrimSpace(r.PostFormValue(name))
	if v == "" {
		return def, nil
	}
	n, err := strconv.Atoi(v)
	if err != nil || n < lo || n > hi {
		return 0, fmt.Errorf("pole %s: liczba od %d do %d", name, lo, hi)
	}
	return n, nil
}

func (p *Pages) scanSave(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	if err := r.ParseForm(); err != nil {
		http.Error(w, "zły formularz", http.StatusBadRequest)
		return
	}
	var id int64
	if idS := chi.URLParam(r, "id"); idS != "" {
		var err error
		if id, err = strconv.ParseInt(idS, 10, 64); err != nil {
			http.NotFound(w, r)
			return
		}
	}
	back := "/scans/new"
	if id != 0 {
		back = fmt.Sprintf("/scans/%d/edit", id)
	}
	bad := func(err error) { http.Redirect(w, r, back+"?err="+url.QueryEscape(err.Error()), http.StatusSeeOther) }
	name := strings.TrimSpace(r.PostFormValue("name"))
	if name == "" || len(name) > 100 {
		bad(errors.New("nazwa jest wymagana (do 100 znaków)"))
		return
	}
	top, err := formInt(r, "top_ports", 1000, 1, 65535)
	if err != nil {
		bad(err)
		return
	}
	maxRate := p.maxRate()
	rate, err := formInt(r, "max_rate", min(1000, maxRate), 1, maxRate)
	if err != nil {
		bad(err)
		return
	}
	ports := strings.TrimSpace(r.PostFormValue("ports"))
	if len(ports) > 2000 {
		bad(errors.New("lista portów jest za długa"))
		return
	}
	if _, err := runner.EffectivePorts(ports, p.Deps.Config.ScanPorts); err != nil {
		bad(fmt.Errorf("porty: %v", err))
		return
	}
	extraPorts := r.PostFormValue("extra_ports") != ""
	profile := strings.TrimSpace(r.PostFormValue("port_profile"))
	if profile == "" {
		profile = runner.ProfileOf(store.ScanConfig{Ports: ports})
	}
	extraList := strings.TrimSpace(r.PostFormValue("extra_port_list"))
	if len(extraList) > 2000 {
		bad(errors.New("lista dodatkowych portów jest za długa"))
		return
	}
	if _, err := runner.ResolvePorts(store.ScanConfig{PortProfile: profile, Ports: ports, ExtraPortList: extraList, ExtraPorts: extraPorts},
		0, 0, p.Deps.Config.ScanPorts, nil); err != nil {
		bad(fmt.Errorf("porty: %v", err))
		return
	}
	workers, err := formInt(r, "workers", 4, 1, 64)
	if err != nil {
		bad(err)
		return
	}
	ws, err := parseClock(r.PostFormValue("window_start"))
	if err != nil {
		bad(err)
		return
	}
	we, err := parseClock(r.PostFormValue("window_end"))
	if err != nil {
		bad(err)
		return
	}
	if (ws == nil) != (we == nil) {
		bad(errors.New("okno wymaga godziny początku i końca"))
		return
	}
	var every *int
	if v := strings.TrimSpace(r.PostFormValue("every_minutes")); v != "" {
		n, err := strconv.Atoi(v)
		if err != nil || n < 5 || n > 60*24*31 {
			bad(errors.New("częstotliwość: od 5 minut do 31 dni"))
			return
		}
		every = &n
	}
	ids := []int64{}
	if r.PostFormValue("all_targets") == "" {
		for _, v := range r.PostForm["target_ids"] {
			n, err := strconv.ParseInt(v, 10, 64)
			if err != nil {
				bad(errors.New("niepoprawny cel"))
				return
			}
			ids = append(ids, n)
		}
		if len(ids) == 0 {
			bad(errors.New("wybierz cele albo zaznacz „wszystkie cele”"))
			return
		}
	}
	enabled := r.PostFormValue("enabled") != ""
	toTime := func(d *time.Duration) any {
		if d == nil {
			return nil
		}
		return fmt.Sprintf("%02d:%02d", int(d.Hours()), int(d.Minutes())%60)
	}
	if id == 0 {
		err = p.Deps.DB.QueryRow(ctx, `INSERT INTO scan_configs (name, target_ids, top_ports, max_rate, workers, window_start, window_end, every_minutes, enabled, ports, extra_ports, port_profile, extra_port_list)
			VALUES ($1,$2,$3,$4,$5,$6::time,$7::time,$8,$9,$10,$11,$12,$13) RETURNING id`, name, ids, top, rate, workers, toTime(ws), toTime(we), every, enabled, ports, extraPorts, profile, extraList).Scan(&id)
	} else {
		_, err = p.Deps.DB.Exec(ctx, `UPDATE scan_configs SET name=$2, target_ids=$3, top_ports=$4, max_rate=$5, workers=$6,
			window_start=$7::time, window_end=$8::time, every_minutes=$9, enabled=$10, ports=$11, extra_ports=$12,
			port_profile=$13, extra_port_list=$14 WHERE id=$1`,
			id, name, ids, top, rate, workers, toTime(ws), toTime(we), every, enabled, ports, extraPorts, profile, extraList)
	}
	if err != nil {
		if strings.Contains(err.Error(), "scan_configs_name_key") {
			bad(errors.New("konfiguracja o tej nazwie już istnieje"))
			return
		}
		p.fail(w, r, err)
		return
	}
	p.audit(r, "scan_config.save", fmt.Sprintf("scan_config:%d", id), map[string]any{"name": name, "targets": len(ids)})
	http.Redirect(w, r, "/scans?ok=saved", http.StatusSeeOther)
}

// portsLabel describes a config's port profile in the scans list.
func portsLabel(c store.ScanConfig, allMax int) string {
	switch runner.ProfileOf(c) {
	case runner.ProfileAll:
		return "wszystkie (-p-)"
	case runner.ProfileList:
		return "lista " + c.Ports
	case runner.ProfileTop:
		s := fmt.Sprintf("top %d", c.TopPorts)
		if c.ExtraPorts {
			s += " + typowe"
		}
		if c.ExtraPortList != "" {
			s += " + " + c.ExtraPortList
		}
		return s
	default:
		if allMax > 0 {
			return fmt.Sprintf("auto: -p- dla celów do %d adresów, większe: top %d", allMax, c.TopPorts)
		}
		return fmt.Sprintf("auto: top %d", c.TopPorts)
	}
}

// maxRate is the packets/s cap of a scan config (ASI_MAX_RATE).
func (p *Pages) maxRate() int {
	if p.Deps.Config.MaxRate > 0 {
		return p.Deps.Config.MaxRate
	}
	return config.DefaultMaxRate
}

func (p *Pages) audit(r *http.Request, action, entity string, details any) {
	var uid *int64
	if u := auth.UserFrom(r.Context()); u != nil {
		uid = &u.ID
	}
	if err := store.InsertAudit(r.Context(), p.Deps.DB, uid, action, entity, details); err != nil {
		p.log().Warn("audit", "err", err)
	}
}

func (p *Pages) scanRun(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.ParseInt(chi.URLParam(r, "id"), 10, 64)
	if err != nil {
		http.NotFound(w, r)
		return
	}
	if p.Runner == nil {
		http.Redirect(w, r, "/scans?err="+url.QueryEscape("skaner niedostępny w tym procesie"), http.StatusSeeOther)
		return
	}
	runID, err := p.Runner.StartConfig(p.Base, id)
	if err != nil {
		http.Redirect(w, r, "/scans?err="+url.QueryEscape(err.Error()), http.StatusSeeOther)
		return
	}
	p.audit(r, "scan.start", fmt.Sprintf("scan_run:%d", runID), map[string]any{"config": id})
	http.Redirect(w, r, "/scans?ok=started", http.StatusSeeOther)
}

func (p *Pages) runStop(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.ParseInt(chi.URLParam(r, "id"), 10, 64)
	if err != nil {
		http.NotFound(w, r)
		return
	}
	// Mark the run stopped first so the scheduler does not resume it after
	// the cancelled run persists itself as paused.
	tag, err := p.Deps.DB.Exec(r.Context(), `UPDATE scan_runs SET stopped = true
		WHERE id = $1 AND kind = 'scan' AND status IN ('queued','running','paused')`, id)
	if err != nil {
		p.fail(w, r, err)
		return
	}
	active := p.Runner != nil && p.Runner.Stop(id)
	if tag.RowsAffected() == 0 && !active {
		http.Redirect(w, r, "/scans?err="+url.QueryEscape("ten przebieg nie jest wykonywany"), http.StatusSeeOther)
		return
	}
	p.audit(r, "scan.stop", fmt.Sprintf("scan_run:%d", id), nil)
	http.Redirect(w, r, "/scans?ok=stopped", http.StatusSeeOther)
}

// runResume lets the scheduler continue a run stopped by a user (at its next
// tick, inside the config's window).
func (p *Pages) runResume(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.ParseInt(chi.URLParam(r, "id"), 10, 64)
	if err != nil {
		http.NotFound(w, r)
		return
	}
	tag, err := p.Deps.DB.Exec(r.Context(), `UPDATE scan_runs SET stopped = false
		WHERE id = $1 AND stopped AND status IN ('queued','paused')`, id)
	if err != nil {
		p.fail(w, r, err)
		return
	}
	if tag.RowsAffected() == 0 {
		http.Redirect(w, r, "/scans?err="+url.QueryEscape("tego przebiegu nie można wznowić"), http.StatusSeeOther)
		return
	}
	p.audit(r, "scan.resume", fmt.Sprintf("scan_run:%d", id), nil)
	http.Redirect(w, r, "/scans?ok=resumed", http.StatusSeeOther)
}

func (p *Pages) scanDelete(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.ParseInt(chi.URLParam(r, "id"), 10, 64)
	if err != nil {
		http.NotFound(w, r)
		return
	}
	// Runs keep their results; only the configuration goes away.
	if _, err := p.Deps.DB.Exec(r.Context(), `UPDATE scan_runs SET config_id = NULL WHERE config_id = $1 AND status IN ('done','failed')`, id); err != nil {
		p.fail(w, r, err)
		return
	}
	if _, err := p.Deps.DB.Exec(r.Context(), `DELETE FROM scan_configs WHERE id = $1`, id); err != nil {
		http.Redirect(w, r, "/scans?err="+url.QueryEscape("nie można usunąć konfiguracji z niezakończonym przebiegiem"), http.StatusSeeOther)
		return
	}
	p.audit(r, "scan_config.delete", fmt.Sprintf("scan_config:%d", id), nil)
	http.Redirect(w, r, "/scans?ok=deleted", http.StatusSeeOther)
}

// --- results ------------------------------------------------------------

type resultsData struct {
	Filter     ResultFilter
	Run        *RunRow
	Runs       []RunRow
	Services   []ServiceRow
	Categories []string
	Hosts      int
}

func (p *Pages) results(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	f := ResultFilter{Category: r.URL.Query().Get("cat"), Query: strings.TrimSpace(r.URL.Query().Get("q"))}
	if len(f.Query) > 100 {
		f.Query = f.Query[:100]
	}
	if v := r.URL.Query().Get("run"); v != "" {
		f.RunID, _ = strconv.ParseInt(v, 10, 64)
	}
	var err error
	if f.RunID == 0 {
		if f.RunID, err = LatestDoneRun(ctx, p.Deps.DB); err != nil {
			p.fail(w, r, err)
			return
		}
	}
	d := resultsData{Filter: f, Categories: []string{"admin-panel", "staging", "cms", "framework", "server", "iot", "other"}}
	runs, err := ListRuns(ctx, p.Deps.DB, 50)
	if err != nil {
		p.fail(w, r, err)
		return
	}
	for _, rr := range runs {
		if rr.Status == "done" {
			d.Runs = append(d.Runs, rr)
		}
		if rr.ID == f.RunID {
			x := rr
			d.Run = &x
		}
	}
	if f.RunID != 0 {
		if d.Services, err = ListServices(ctx, p.Deps.DB, f); err != nil {
			p.fail(w, r, err)
			return
		}
		seen := map[string]bool{}
		for _, s := range d.Services {
			seen[s.IP] = true
		}
		d.Hosts = len(seen)
	}
	p.render(w, r, "results", http.StatusOK, page{Data: d})
}

type serviceData struct {
	Service    ServiceDetail
	HTTP       *model.HTTPObs
	Detections []model.Detection
	Legacy     *httpfp.LegacyTLS
	Return     string
}

func (p *Pages) service(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	id, err := strconv.ParseInt(chi.URLParam(r, "id"), 10, 64)
	if err != nil {
		http.NotFound(w, r)
		return
	}
	s, err := GetService(ctx, p.Deps.DB, id)
	if errors.Is(err, pgx.ErrNoRows) {
		http.NotFound(w, r)
		return
	}
	if err != nil {
		p.fail(w, r, err)
		return
	}
	d := serviceData{Service: s, Return: r.URL.Path}
	if h, err := store.GetHTTPObs(ctx, p.Deps.DB, id); err == nil {
		d.HTTP = &h
	} else if !errors.Is(err, pgx.ErrNoRows) {
		p.fail(w, r, err)
		return
	}
	if d.Detections, err = store.ListDetections(ctx, p.Deps.DB, id); err != nil {
		p.fail(w, r, err)
		return
	}
	if lt, err := store.GetLegacyTLS(ctx, p.Deps.DB, id); err == nil {
		d.Legacy = &lt
	}
	p.render(w, r, "service", http.StatusOK, page{Data: d})
}
