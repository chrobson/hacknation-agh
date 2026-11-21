package auth

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"html/template"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/bcrypt"
)

func TestMain(m *testing.M) {
	bcryptCost = bcrypt.MinCost
	SetTemplateFS(os.DirFS("../../web/templates"))
	os.Exit(m.Run())
}

func roleUser(role string) *User {
	return &User{ID: 1, Login: "u", RoleName: role, Perms: BuiltinRoles[role]}
}

var okHandler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
	w.WriteHeader(http.StatusOK)
	_, _ = io.WriteString(w, "ok")
})

// expectedMatrix is written out independently of BuiltinRoles, straight from
// docs/ARCHITECTURE.md, so a typo in either place fails the test.
var expectedMatrix = map[string]map[string]bool{
	RoleAdmin: {"targets.read": true, "targets.write": true, "scans.run": true, "results.read": true,
		"results.edit": true, "signatures.write": true, "export": true, "users.admin": true},
	RoleEditor: {"targets.read": true, "targets.write": true, "scans.run": true, "results.read": true,
		"results.edit": true, "signatures.write": true, "export": true, "users.admin": false},
	RoleAnalyst: {"targets.read": true, "targets.write": false, "scans.run": false, "results.read": true,
		"results.edit": true, "signatures.write": false, "export": true, "users.admin": false},
	RoleViewer: {"targets.read": true, "targets.write": false, "scans.run": false, "results.read": true,
		"results.edit": false, "signatures.write": false, "export": false, "users.admin": false},
}

func TestPermissionMatrix(t *testing.T) {
	if len(AllPerms) != 8 {
		t.Fatalf("want 8 permissions, got %d", len(AllPerms))
	}
	if len(BuiltinRoles) != 4 {
		t.Fatalf("want 4 built-in roles, got %d", len(BuiltinRoles))
	}
	for role, perms := range expectedMatrix {
		for _, p := range AllPerms {
			want, ok := perms[p.Name]
			if !ok {
				t.Fatalf("matrix lacks %s/%s", role, p.Name)
			}
			u := roleUser(role)
			if got := u.Can(p.Name); got != want {
				t.Errorf("%s Can(%s) = %v, want %v", role, p.Name, got, want)
			}
			// Same decision through the HTTP middleware.
			rec := httptest.NewRecorder()
			req := httptest.NewRequest(http.MethodGet, "/x", nil)
			req = req.WithContext(WithUser(req.Context(), u))
			Require(p.Name)(okHandler).ServeHTTP(rec, req)
			wantCode := http.StatusForbidden
			if want {
				wantCode = http.StatusOK
			}
			if rec.Code != wantCode {
				t.Errorf("%s Require(%s): status %d, want %d", role, p.Name, rec.Code, wantCode)
			}
		}
	}
}

func TestNilUserCannot(t *testing.T) {
	var u *User
	if u.Can(PermTargetsRead) || can(nil, PermTargetsRead) {
		t.Fatal("nil user must have no permissions")
	}
}

func TestValidPerm(t *testing.T) {
	if !ValidPerm("export") || ValidPerm("root") || ValidPerm("") {
		t.Fatal("ValidPerm wrong")
	}
}

func TestRequire403Formats(t *testing.T) {
	viewer := roleUser(RoleViewer)
	cases := []struct {
		name     string
		path     string
		hdr      map[string]string
		wantJSON bool
	}{
		{"page", "/targets/new", nil, false},
		{"htmx", "/targets/new", map[string]string{"HX-Request": "true"}, true},
		{"api", "/api/targets", nil, true},
		{"accept-json", "/targets", map[string]string{"Accept": "application/json"}, true},
		{"browser-accept", "/targets", map[string]string{"Accept": "text/html,application/json;q=0.9"}, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodPost, tc.path, nil)
			for k, v := range tc.hdr {
				req.Header.Set(k, v)
			}
			req = req.WithContext(WithUser(req.Context(), viewer))
			rec := httptest.NewRecorder()
			Require(PermTargetsWrite)(okHandler).ServeHTTP(rec, req)
			if rec.Code != http.StatusForbidden {
				t.Fatalf("status %d, want 403", rec.Code)
			}
			ct := rec.Header().Get("Content-Type")
			if tc.wantJSON {
				if !strings.HasPrefix(ct, "application/json") {
					t.Fatalf("content-type %q, want JSON", ct)
				}
				var body map[string]string
				if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
					t.Fatal(err)
				}
				if body["error"] != "forbidden" || body["perm"] != PermTargetsWrite {
					t.Fatalf("body %v", body)
				}
				return
			}
			if !strings.HasPrefix(ct, "text/html") {
				t.Fatalf("content-type %q, want HTML", ct)
			}
			b := rec.Body.String()
			if !strings.Contains(b, "Brak dostępu (403)") || !strings.Contains(b, "targets.write") {
				t.Fatalf("unexpected page: %s", b)
			}
			// The viewer's nav must not offer admin links.
			if strings.Contains(b, "/admin/users") {
				t.Fatal("viewer sees admin link")
			}
		})
	}
}

func TestRequireUnauthenticated(t *testing.T) {
	for _, mw := range []func(http.Handler) http.Handler{RequireAuth, Require(PermTargetsRead)} {
		rec := httptest.NewRecorder()
		mw(okHandler).ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/targets?tag=a", nil))
		if rec.Code != http.StatusSeeOther {
			t.Fatalf("page: status %d, want 303", rec.Code)
		}
		if loc := rec.Header().Get("Location"); loc != "/login?next=%2Ftargets%3Ftag%3Da" {
			t.Fatalf("location %q", loc)
		}

		rec = httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodGet, "/targets", nil)
		req.Header.Set("HX-Request", "true")
		mw(okHandler).ServeHTTP(rec, req)
		if rec.Code != http.StatusUnauthorized || rec.Header().Get("HX-Redirect") != "/login" {
			t.Fatalf("htmx: status %d hx-redirect %q", rec.Code, rec.Header().Get("HX-Redirect"))
		}
	}
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req = req.WithContext(WithUser(req.Context(), roleUser(RoleViewer)))
	RequireAuth(okHandler).ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("authenticated: status %d", rec.Code)
	}
}

func TestCSRFCrossOriginRejected(t *testing.T) {
	h := CSRF(okHandler)
	cases := []struct {
		name   string
		method string
		hdr    map[string]string
		want   int
	}{
		{"cross-site POST (Sec-Fetch-Site)", http.MethodPost, map[string]string{"Sec-Fetch-Site": "cross-site"}, 403},
		{"same-site POST from sibling", http.MethodPost, map[string]string{"Sec-Fetch-Site": "same-site"}, 403},
		{"cross-origin POST (Origin only)", http.MethodPost, map[string]string{"Origin": "http://evil.example"}, 403},
		{"cross-site htmx DELETE", http.MethodDelete, map[string]string{"Sec-Fetch-Site": "cross-site", "HX-Request": "true"}, 403},
		{"same-origin POST", http.MethodPost, map[string]string{"Sec-Fetch-Site": "same-origin"}, 200},
		{"same-origin POST (Origin only)", http.MethodPost, map[string]string{"Origin": "http://asi.local"}, 200},
		{"non-browser POST", http.MethodPost, nil, 200},
		{"cross-site GET", http.MethodGet, map[string]string{"Sec-Fetch-Site": "cross-site"}, 200},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			req := httptest.NewRequest(tc.method, "http://asi.local/targets", strings.NewReader("value=10.20.0.1"))
			req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
			for k, v := range tc.hdr {
				req.Header.Set(k, v)
			}
			rec := httptest.NewRecorder()
			h.ServeHTTP(rec, req)
			if rec.Code != tc.want {
				t.Fatalf("status %d, want %d", rec.Code, tc.want)
			}
		})
	}
}

// TestCSRFOverRealServer sends a forged cross-origin form POST to an httptest
// server running the full middleware chain.
func TestCSRFOverRealServer(t *testing.T) {
	mw := func(next http.Handler) http.Handler {
		return CSRF(loadSession(func(context.Context, []byte) (*User, error) { return roleUser(RoleAdmin), nil },
			slog.New(slog.NewTextHandler(io.Discard, nil)), next))
	}
	srv := httptest.NewServer(mw(Require(PermUsersAdmin)(okHandler)))
	defer srv.Close()

	post := func(origin string) int {
		req, _ := http.NewRequest(http.MethodPost, srv.URL+"/admin/users", strings.NewReader("login=x"))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		req.Header.Set("Origin", origin)
		req.AddCookie(&http.Cookie{Name: CookieName, Value: "tok"})
		resp, err := srv.Client().Do(req)
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		return resp.StatusCode
	}
	if c := post("http://attacker.example"); c != http.StatusForbidden {
		t.Fatalf("forged POST: %d, want 403", c)
	}
	if c := post(srv.URL); c != http.StatusOK {
		t.Fatalf("same-origin POST: %d, want 200", c)
	}
}

func TestLoadSession(t *testing.T) {
	var gotHash []byte
	lookup := func(_ context.Context, h []byte) (*User, error) {
		gotHash = h
		if bytes.Equal(h, hashToken("good")) {
			return roleUser(RoleAnalyst), nil
		}
		return nil, nil
	}
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	var seen *User
	h := loadSession(lookup, log, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seen = UserFrom(r.Context())
	}))

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.AddCookie(&http.Cookie{Name: CookieName, Value: "good"})
	h.ServeHTTP(httptest.NewRecorder(), req)
	if seen == nil || seen.RoleName != RoleAnalyst {
		t.Fatalf("user not loaded: %+v", seen)
	}
	if bytes.Equal(gotHash, []byte("good")) {
		t.Fatal("raw token passed to the store instead of its hash")
	}

	seen = nil
	req = httptest.NewRequest(http.MethodGet, "/", nil)
	req.AddCookie(&http.Cookie{Name: CookieName, Value: "bad"})
	h.ServeHTTP(httptest.NewRecorder(), req)
	if seen != nil {
		t.Fatal("unknown token produced a user")
	}

	failing := loadSession(func(context.Context, []byte) (*User, error) { return nil, errors.New("db down") }, log, okHandler)
	rec := httptest.NewRecorder()
	failing.ServeHTTP(rec, req)
	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("lookup error: status %d", rec.Code)
	}
}

func TestSessionCookieFlags(t *testing.T) {
	for _, useTLS := range []bool{false, true} {
		req := httptest.NewRequest(http.MethodPost, "/login", nil)
		if useTLS {
			req.TLS = &tls.ConnectionState{}
		}
		rec := httptest.NewRecorder()
		setSessionCookie(rec, req, newToken(), time.Now().Add(time.Hour))
		cs := rec.Result().Cookies()
		if len(cs) != 1 {
			t.Fatalf("cookies: %v", cs)
		}
		c := cs[0]
		if !c.HttpOnly || c.SameSite != http.SameSiteLaxMode || c.Secure != useTLS || c.Path != "/" {
			t.Fatalf("tls=%v: bad cookie %+v", useTLS, c)
		}
		if len(c.Value) < 40 {
			t.Fatalf("token too short: %q", c.Value)
		}
	}
	req := httptest.NewRequest(http.MethodPost, "/login", nil)
	req.Header.Set("X-Forwarded-Proto", "https")
	rec := httptest.NewRecorder()
	clearSessionCookie(rec, req)
	c := rec.Result().Cookies()[0]
	if !c.Secure || c.MaxAge >= 0 {
		t.Fatalf("clear cookie: %+v", c)
	}
}

func TestNewTokenUnique(t *testing.T) {
	if newToken() == newToken() {
		t.Fatal("tokens repeat")
	}
}

func TestSafeNext(t *testing.T) {
	for in, want := range map[string]string{
		"":                     "/",
		"/targets?x=1":         "/targets?x=1",
		"//evil.example":       "/",
		"/\\evil.example":      "/",
		"https://evil.example": "/",
		"/a\r\nSet-Cookie: x":  "/",
	} {
		if got := safeNext(in); got != want {
			t.Errorf("safeNext(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestPasswordHashing(t *testing.T) {
	if _, err := HashPassword("short"); !errors.Is(err, ErrWeakPassword) {
		t.Fatalf("short password: %v", err)
	}
	h, err := HashPassword("correct horse")
	if err != nil {
		t.Fatal(err)
	}
	if !CheckPassword(h, "correct horse") || CheckPassword(h, "wrong horse") {
		t.Fatal("bcrypt check wrong")
	}
	if !strings.HasPrefix(h, "$2") {
		t.Fatalf("not a bcrypt hash: %s", h)
	}
}

func TestAESGCMRoundtrip(t *testing.T) {
	key := bytes.Repeat([]byte{7}, 32)
	s, err := NewSealer(key)
	if err != nil {
		t.Fatal(err)
	}
	secret := []byte("dojo-api-token-1234567890")
	a := s.Seal("dojo_token", secret)
	b := s.Seal("dojo_token", secret)
	if bytes.Equal(a, b) {
		t.Fatal("nonce reuse: equal ciphertexts")
	}
	if bytes.Contains(a, secret) {
		t.Fatal("plaintext visible in ciphertext")
	}
	got, err := s.Open("dojo_token", a)
	if err != nil || !bytes.Equal(got, secret) {
		t.Fatalf("roundtrip: %q %v", got, err)
	}
	// Bound to the name (AAD).
	if _, err := s.Open("other", a); err == nil {
		t.Fatal("opened under a different name")
	}
	// Tampering detected.
	bad := append([]byte(nil), a...)
	bad[len(bad)-1] ^= 1
	if _, err := s.Open("dojo_token", bad); err == nil {
		t.Fatal("tampered ciphertext accepted")
	}
	if _, err := s.Open("dojo_token", a[:5]); err == nil {
		t.Fatal("truncated ciphertext accepted")
	}
	// Wrong key.
	s2, _ := NewSealer(bytes.Repeat([]byte{8}, 32))
	if _, err := s2.Open("dojo_token", a); err == nil {
		t.Fatal("opened with the wrong key")
	}
	// Empty plaintext works too.
	e, err := s.Open("x", s.Seal("x", nil))
	if err != nil || len(e) != 0 {
		t.Fatalf("empty: %q %v", e, err)
	}
}

func TestSealerKeyErrors(t *testing.T) {
	if _, err := NewSealer(nil); !errors.Is(err, ErrNoSecretKey) {
		t.Fatalf("missing key: %v", err)
	}
	if _, err := NewSealer(make([]byte, 16)); err == nil {
		t.Fatal("16-byte key accepted")
	}
}

func TestTemplatesRender(t *testing.T) {
	admin := roleUser(RoleAdmin)
	data := pageData{
		User: admin, Message: "OK", Next: "/", AllPerms: AllPerms,
		Users: []userRow{{ID: 1, Login: "admin", RoleID: 1, RoleName: RoleAdmin, Self: true},
			{ID: 2, Login: "viewer", RoleID: 4, RoleName: RoleViewer}},
		Roles: []roleRow{{ID: 1, Name: RoleAdmin, Builtin: true, Perms: AllPerms, Users: 1},
			{ID: 5, Name: "Audytor <x>", Perms: AllPerms[:1]}},
		Audit: []auditRow{{At: "2026-11-21 10:00:00", Login: "admin", Action: "login", Details: `{"ip":"127.0.0.1"}`}},
	}
	for _, name := range []string{"login.html", "users.html", "roles.html", "audit.html", "forbidden.html"} {
		t.Run(name, func(t *testing.T) {
			rec := httptest.NewRecorder()
			render(rec, name, data)
			if rec.Code != http.StatusOK || !strings.HasPrefix(rec.Header().Get("Content-Type"), "text/html") {
				t.Fatalf("status %d ct %q body %s", rec.Code, rec.Header().Get("Content-Type"), rec.Body.String())
			}
			if !strings.Contains(rec.Body.String(), "<!doctype html>") {
				t.Fatal("base layout not applied")
			}
		})
	}
	rec := httptest.NewRecorder()
	render(rec, "roles.html", data)
	b := rec.Body.String()
	if strings.Contains(b, "Audytor <x>") {
		t.Fatal("role name not escaped")
	}
	if strings.Count(b, `name="perm"`) != 8 {
		t.Fatal("want 8 permission checkboxes")
	}
	if !strings.Contains(b, `/admin/roles/5/delete`) || strings.Contains(b, `/admin/roles/1/delete`) {
		t.Fatal("delete button must appear only for custom, unused roles")
	}
}

func TestCanFuncInTemplates(t *testing.T) {
	tpl := template.Must(template.New("t").Funcs(Funcs()).Parse(
		`{{if can .User "targets.write"}}ADD{{end}}|{{if .User.Can "results.read"}}READ{{end}}`))
	for role, want := range map[string]string{RoleAdmin: "ADD|READ", RoleViewer: "|READ"} {
		var buf bytes.Buffer
		if err := tpl.Execute(&buf, map[string]any{"User": roleUser(role)}); err != nil {
			t.Fatal(err)
		}
		if buf.String() != want {
			t.Errorf("%s: %q, want %q", role, buf.String(), want)
		}
	}
	var buf bytes.Buffer
	if err := tpl.Execute(&buf, map[string]any{"User": (*User)(nil)}); err != nil || buf.String() != "|" {
		t.Fatalf("anonymous: %q %v", buf.String(), err)
	}
}

func TestMissingTemplateFallsBack(t *testing.T) {
	rec := httptest.NewRecorder()
	renderStatus(rec, http.StatusForbidden, "nope.html", pageData{Message: "Brak"})
	if rec.Code != http.StatusForbidden || !strings.Contains(rec.Body.String(), "Brak") {
		t.Fatalf("fallback: %d %q", rec.Code, rec.Body.String())
	}
}

func TestAuthzAdapter(t *testing.T) {
	var a Authz
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	if a.Allowed(r, PermTargetsRead) {
		t.Fatal("anonymous request allowed")
	}
	if _, ok := a.UserID(r); ok {
		t.Fatal("anonymous request has user id")
	}
	u := roleUser(RoleViewer)
	u.ID = 7
	r = r.WithContext(WithUser(r.Context(), u))
	if !a.Allowed(r, PermTargetsRead) || a.Allowed(r, PermTargetsWrite) {
		t.Fatal("viewer permissions wrong via Authz")
	}
	if id, ok := a.UserID(r); !ok || id != 7 {
		t.Fatalf("UserID = %d, %v", id, ok)
	}
}

func TestPasswordTooLong(t *testing.T) {
	if _, err := HashPassword(strings.Repeat("a", 73)); !errors.Is(err, ErrLongPassword) {
		t.Fatalf("err = %v, want ErrLongPassword", err)
	}
	if _, err := HashPassword(strings.Repeat("a", 72)); err != nil {
		t.Fatalf("72 bytes: %v", err)
	}
}
