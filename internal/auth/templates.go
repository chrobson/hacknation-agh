package auth

import (
	"bytes"
	"html/template"
	"io/fs"
	"net/http"
	"os"
	"sync"
)

var (
	tmplMu    sync.Mutex
	tmplCache = map[string]*template.Template{}
	// tmplFS is the root of web/templates (base.html + admin/*.html).
	tmplFS fs.FS = os.DirFS("web/templates")
)

// SetTemplateFS sets the root of web/templates (must contain base.html and
// admin/*.html). The default is os.DirFS("web/templates") relative to the
// working directory; the integrator may pass an embedded FS instead.
func SetTemplateFS(fsys fs.FS) {
	tmplMu.Lock()
	defer tmplMu.Unlock()
	tmplFS = fsys
	tmplCache = map[string]*template.Template{}
}

// pageData is the template payload for every auth/admin page.
type pageData struct {
	User    *User
	Message string
	Error   string
	Next    string
	Login   string

	Users    []userRow
	Roles    []roleRow
	AllPerms []PermInfo
	Audit    []auditRow
}

func loadTemplate(name string) (*template.Template, error) {
	tmplMu.Lock()
	defer tmplMu.Unlock()
	if t, ok := tmplCache[name]; ok {
		return t, nil
	}
	t, err := template.New(name).Funcs(Funcs()).ParseFS(tmplFS, "base.html", "admin/_nav.html", "admin/"+name)
	if err != nil {
		return nil, err
	}
	tmplCache[name] = t
	return t, nil
}

func render(w http.ResponseWriter, name string, data pageData) {
	renderStatus(w, http.StatusOK, name, data)
}

func renderStatus(w http.ResponseWriter, code int, name string, data pageData) {
	t, err := loadTemplate(name)
	var buf bytes.Buffer
	if err == nil {
		err = t.ExecuteTemplate(&buf, "base", data)
	}
	if err != nil {
		// Fall back to plain text so a missing template never hides the status.
		msg := data.Message
		if msg == "" {
			msg = http.StatusText(code)
		}
		http.Error(w, msg, code)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(code)
	_, _ = buf.WriteTo(w)
}
