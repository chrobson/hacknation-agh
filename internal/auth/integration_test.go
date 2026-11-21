//go:build integration

package auth

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"os"
	"slices"
	"strconv"
	"strings"
	"testing"

	"github.com/go-chi/chi/v5"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/chrobson/hacknation-agh/internal/config"
	"github.com/chrobson/hacknation-agh/internal/db"
	"github.com/chrobson/hacknation-agh/internal/store"
	"github.com/chrobson/hacknation-agh/internal/web"
)

// testPool migrates a fresh schema in ASI_TEST_DATABASE_URL and drops it after.
func testPool(t *testing.T) *pgxpool.Pool {
	t.Helper()
	dsn := os.Getenv("ASI_TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("ASI_TEST_DATABASE_URL not set")
	}
	ctx := context.Background()
	b := make([]byte, 4)
	_, _ = rand.Read(b)
	schema := "asi_auth_test_" + hex.EncodeToString(b)

	admin, err := pgx.Connect(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := admin.Exec(ctx, "CREATE SCHEMA "+schema); err != nil {
		t.Fatal(err)
	}
	cfg, err := pgxpool.ParseConfig(dsn)
	if err != nil {
		t.Fatal(err)
	}
	cfg.ConnConfig.RuntimeParams["search_path"] = schema
	pool, err := pgxpool.NewWithConfig(ctx, cfg)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		pool.Close()
		_, _ = admin.Exec(context.Background(), "DROP SCHEMA "+schema+" CASCADE")
		_ = admin.Close(context.Background())
	})
	if _, err := db.Migrate(ctx, pool); err != nil {
		t.Fatal(err)
	}
	return pool
}

func TestIntegrationBuiltinRolesMatchSQL(t *testing.T) {
	pool := testPool(t)
	roles, err := store.ListRoles(context.Background(), pool)
	if err != nil {
		t.Fatal(err)
	}
	if len(roles) != 4 {
		t.Fatalf("want 4 roles, got %d", len(roles))
	}
	for _, r := range roles {
		want := slices.Clone(BuiltinRoles[r.Name])
		slices.Sort(want)
		if !r.Builtin || !slices.Equal(r.Perms, want) {
			t.Errorf("role %q: builtin=%v perms=%v, want %v", r.Name, r.Builtin, r.Perms, want)
		}
	}
}

var seedPasswords = map[string]string{
	"ASI_SEED_PASSWORD_ADMIN":  "admin-pass-123",
	"ASI_SEED_PASSWORD_EDITOR": "editor-pass-123",
	"ASI_SEED_PASSWORD_VIEWER": "viewer-pass-123",
	// analyst: generated
}

func TestIntegrationSeed(t *testing.T) {
	pool := testPool(t)
	ctx := context.Background()
	var out bytes.Buffer
	created, err := seed(ctx, pool, func(k string) string { return seedPasswords[k] }, &out)
	if err != nil || !created {
		t.Fatalf("seed: %v %v", created, err)
	}
	if !strings.Contains(out.String(), `"analyst"`) || strings.Contains(out.String(), `"admin"`) {
		t.Fatalf("only the generated password must be printed: %q", out.String())
	}
	users, err := store.ListUsers(ctx, pool)
	if err != nil || len(users) != 4 {
		t.Fatalf("users: %v %v", users, err)
	}
	for _, su := range SeedUsers {
		u, err := store.UserByLogin(ctx, pool, su.Login)
		if err != nil || u.RoleName != su.Role {
			t.Fatalf("%s: %+v %v", su.Login, u, err)
		}
		if pw := seedPasswords[su.EnvVar]; pw != "" && !CheckPassword(u.PassHash, pw) {
			t.Fatalf("%s: env password not used", su.Login)
		}
	}
	out.Reset()
	created, err = seed(ctx, pool, func(string) string { return "" }, &out)
	if err != nil || created || out.Len() != 0 {
		t.Fatalf("second seed must be a no-op: %v %v %q", created, err, out.String())
	}
}

func TestIntegrationSecrets(t *testing.T) {
	pool := testPool(t)
	ctx := context.Background()
	if err := PutSecret(ctx, pool, config.Config{}, "dojo_token", "x"); !errors.Is(err, ErrNoSecretKey) {
		t.Fatalf("missing key: %v", err)
	}
	cfg := config.Config{SecretKey: bytes.Repeat([]byte{1}, 32)}
	if err := PutSecret(ctx, pool, cfg, "dojo_token", "tok-1"); err != nil {
		t.Fatal(err)
	}
	if err := PutSecret(ctx, pool, cfg, "dojo_token", "tok-2"); err != nil {
		t.Fatal(err)
	}
	got, err := GetSecret(ctx, pool, cfg, "dojo_token")
	if err != nil || got != "tok-2" {
		t.Fatalf("get: %q %v", got, err)
	}
	raw, _ := store.GetSecretEnc(ctx, pool, "dojo_token")
	if bytes.Contains(raw, []byte("tok-2")) {
		t.Fatal("secret stored in clear text")
	}
	if _, err := GetSecret(ctx, pool, cfg, "absent"); !errors.Is(err, pgx.ErrNoRows) {
		t.Fatalf("absent: %v", err)
	}
}

type client struct {
	t   *testing.T
	srv *httptest.Server
	c   *http.Client
}

func newClient(t *testing.T, srv *httptest.Server) *client {
	jar, _ := cookiejar.New(nil)
	// srv.Client() is shared; each test client needs its own cookie jar.
	c := &http.Client{
		Transport:     srv.Client().Transport,
		Jar:           jar,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}
	return &client{t: t, srv: srv, c: c}
}

func (c *client) do(method, path string, form url.Values) (*http.Response, string) {
	c.t.Helper()
	var body io.Reader
	if form != nil {
		body = strings.NewReader(form.Encode())
	}
	req, _ := http.NewRequest(method, c.srv.URL+path, body)
	if form != nil {
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		req.Header.Set("Origin", c.srv.URL)
	}
	resp, err := c.c.Do(req)
	if err != nil {
		c.t.Fatal(err)
	}
	b, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	return resp, string(b)
}

func (c *client) login(login, pw string) *http.Response {
	resp, _ := c.do(http.MethodPost, "/login", url.Values{"login": {login}, "password": {pw}, "next": {"/admin/users"}})
	return resp
}

func TestIntegrationHTTPFlow(t *testing.T) {
	pool := testPool(t)
	ctx := context.Background()
	if _, err := seed(ctx, pool, func(k string) string { return seedPasswords[k] }, io.Discard); err != nil {
		t.Fatal(err)
	}
	d := web.Deps{DB: pool, Log: slog.New(slog.NewTextHandler(io.Discard, nil))}
	r := chi.NewRouter()
	r.Use(Middleware(d))
	Mount(r, d)
	r.With(Require(PermTargetsWrite)).Post("/targets", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusCreated)
	})
	srv := httptest.NewServer(r)
	defer srv.Close()

	// Anonymous: admin pages redirect to login.
	anon := newClient(t, srv)
	if resp, _ := anon.do(http.MethodGet, "/admin/users", nil); resp.StatusCode != http.StatusSeeOther ||
		!strings.HasPrefix(resp.Header.Get("Location"), "/login?next=") {
		t.Fatalf("anonymous: %d %s", resp.StatusCode, resp.Header.Get("Location"))
	}
	if resp, body := anon.do(http.MethodGet, "/login", nil); resp.StatusCode != 200 || !strings.Contains(body, "Logowanie") {
		t.Fatalf("login page: %d", resp.StatusCode)
	}
	if resp := anon.login("admin", "wrong-password"); resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("bad password: %d", resp.StatusCode)
	}
	if resp := anon.login("nobody", "whatever-123"); resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("unknown user: %d", resp.StatusCode)
	}

	// Viewer: logged in, but 403 on admin and on targets.write.
	viewer := newClient(t, srv)
	if resp := viewer.login("viewer", "viewer-pass-123"); resp.StatusCode != http.StatusSeeOther {
		t.Fatalf("viewer login: %d", resp.StatusCode)
	}
	if resp, body := viewer.do(http.MethodGet, "/admin/users", nil); resp.StatusCode != http.StatusForbidden ||
		!strings.Contains(body, "Brak dostępu") {
		t.Fatalf("viewer admin: %d", resp.StatusCode)
	}
	if resp, _ := viewer.do(http.MethodPost, "/targets", url.Values{"v": {"1"}}); resp.StatusCode != http.StatusForbidden {
		t.Fatalf("viewer targets.write: %d", resp.StatusCode)
	}

	// Admin.
	admin := newClient(t, srv)
	resp := admin.login("admin", "admin-pass-123")
	if resp.StatusCode != http.StatusSeeOther || resp.Header.Get("Location") != "/admin/users" {
		t.Fatalf("admin login: %d %s", resp.StatusCode, resp.Header.Get("Location"))
	}
	var sc *http.Cookie
	for _, c := range resp.Cookies() {
		if c.Name == CookieName {
			sc = c
		}
	}
	if sc == nil || !sc.HttpOnly || sc.SameSite != http.SameSiteLaxMode {
		t.Fatalf("session cookie: %+v", sc)
	}
	if resp, body := admin.do(http.MethodGet, "/admin/users", nil); resp.StatusCode != 200 || !strings.Contains(body, "viewer") {
		t.Fatalf("users page: %d", resp.StatusCode)
	}
	if resp, _ := admin.do(http.MethodPost, "/targets", url.Values{"v": {"1"}}); resp.StatusCode != http.StatusCreated {
		t.Fatalf("admin targets.write: %d", resp.StatusCode)
	}

	// Cross-origin POST with a valid session is rejected.
	req, _ := http.NewRequest(http.MethodPost, srv.URL+"/admin/users", strings.NewReader("login=evil&password=evilpass1&role_id=1"))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Origin", "http://attacker.example")
	req.Header.Set("Sec-Fetch-Site", "cross-site")
	if resp, err := admin.c.Do(req); err != nil || resp.StatusCode != http.StatusForbidden {
		t.Fatalf("csrf: %v %v", resp, err)
	}
	if _, err := store.UserByLogin(ctx, pool, "evil"); !errors.Is(err, pgx.ErrNoRows) {
		t.Fatal("cross-origin POST created a user")
	}

	// Custom role with checkboxes.
	resp, _ = admin.do(http.MethodPost, "/admin/roles", url.Values{"name": {"Audytor"}, "perm": {"results.read", "export"}})
	if loc := resp.Header.Get("Location"); loc != "/admin/roles?ok=role_created" {
		t.Fatalf("create role: %s", loc)
	}
	resp, _ = admin.do(http.MethodPost, "/admin/roles", url.Values{"name": {"Zła"}, "perm": {"root"}})
	if loc := resp.Header.Get("Location"); loc != "/admin/roles?err=bad_input" {
		t.Fatalf("invalid perm: %s", loc)
	}
	audID, err := store.RoleIDByName(ctx, pool, "Audytor")
	if err != nil {
		t.Fatal(err)
	}
	if perms, _ := store.RolePerms(ctx, pool, audID); !slices.Equal(perms, []string{"export", "results.read"}) {
		t.Fatalf("role perms: %v", perms)
	}

	// Create user with that role, then move them to Odczyt.
	resp, _ = admin.do(http.MethodPost, "/admin/users", url.Values{
		"login": {"jan"}, "password": {"jan-pass-123"}, "role_id": {itoa(audID)}})
	if loc := resp.Header.Get("Location"); loc != "/admin/users?ok=user_created" {
		t.Fatalf("create user: %s", loc)
	}
	resp, _ = admin.do(http.MethodPost, "/admin/users", url.Values{
		"login": {"jan"}, "password": {"jan-pass-123"}, "role_id": {itoa(audID)}})
	if loc := resp.Header.Get("Location"); loc != "/admin/users?err=login_taken" {
		t.Fatalf("duplicate user: %s", loc)
	}
	jan := newClient(t, srv)
	if resp := jan.login("jan", "jan-pass-123"); resp.StatusCode != http.StatusSeeOther {
		t.Fatalf("jan login: %d", resp.StatusCode)
	}

	// Role in use cannot be deleted.
	resp, _ = admin.do(http.MethodPost, "/admin/roles/"+itoa(audID)+"/delete", url.Values{})
	if loc := resp.Header.Get("Location"); loc != "/admin/roles?err=role_in_use" {
		t.Fatalf("delete used role: %s", loc)
	}
	viewerRole, _ := store.RoleIDByName(ctx, pool, RoleViewer)
	janUser, _ := store.UserByLogin(ctx, pool, "jan")
	resp, _ = admin.do(http.MethodPost, "/admin/users/"+itoa(janUser.ID)+"/role", url.Values{"role_id": {itoa(viewerRole)}})
	if loc := resp.Header.Get("Location"); loc != "/admin/users?ok=role_changed" {
		t.Fatalf("change role: %s", loc)
	}
	// Permissions are re-read from the DB on every request (no cached perms).
	if u, _ := store.UserByLogin(ctx, pool, "jan"); slices.Contains(u.Perms, "export") {
		t.Fatal("role change not applied")
	}
	adminUser, _ := store.UserByLogin(ctx, pool, "admin")
	resp, _ = admin.do(http.MethodPost, "/admin/users/"+itoa(adminUser.ID)+"/role", url.Values{"role_id": {itoa(viewerRole)}})
	if loc := resp.Header.Get("Location"); loc != "/admin/users?err=self_role" {
		t.Fatalf("self role change: %s", loc)
	}
	resp, _ = admin.do(http.MethodPost, "/admin/roles/"+itoa(audID)+"/delete", url.Values{})
	if loc := resp.Header.Get("Location"); loc != "/admin/roles?ok=role_deleted" {
		t.Fatalf("delete role: %s", loc)
	}
	adminRole, _ := store.RoleIDByName(ctx, pool, RoleAdmin)
	resp, _ = admin.do(http.MethodPost, "/admin/roles/"+itoa(adminRole)+"/delete", url.Values{})
	if loc := resp.Header.Get("Location"); loc != "/admin/roles?err=role_builtin" {
		t.Fatalf("delete builtin: %s", loc)
	}
	if resp, body := admin.do(http.MethodGet, "/admin/roles", nil); resp.StatusCode != 200 || strings.Count(body, `name="perm"`) != 8 {
		t.Fatalf("roles page: %d", resp.StatusCode)
	}

	// Audit trail.
	if resp, body := admin.do(http.MethodGet, "/admin/audit", nil); resp.StatusCode != 200 || !strings.Contains(body, "role.delete") {
		t.Fatalf("audit page: %d", resp.StatusCode)
	}
	entries, err := store.ListAudit(ctx, pool, 500)
	if err != nil {
		t.Fatal(err)
	}
	seen := map[string]int{}
	for _, e := range entries {
		seen[e.Action]++
	}
	for _, a := range []string{"user.seed", "login", "login.failed", "role.create", "user.create", "user.role", "role.delete"} {
		if seen[a] == 0 {
			t.Errorf("no audit entry %q (have %v)", a, seen)
		}
	}

	// Logout invalidates the server-side session.
	resp, _ = admin.do(http.MethodPost, "/logout", url.Values{})
	if resp.StatusCode != http.StatusSeeOther {
		t.Fatalf("logout: %d", resp.StatusCode)
	}
	replay := newClient(t, srv)
	u, _ := url.Parse(srv.URL)
	replay.c.Jar.SetCookies(u, []*http.Cookie{{Name: CookieName, Value: sc.Value}})
	if resp, _ := replay.do(http.MethodGet, "/admin/users", nil); resp.StatusCode != http.StatusSeeOther {
		t.Fatalf("old cookie still valid after logout: %d", resp.StatusCode)
	}
	var n int
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM audit_log WHERE action = 'logout'`).Scan(&n); err != nil || n != 1 {
		t.Fatalf("logout audit: %d %v", n, err)
	}
}

func itoa(n int64) string { return strconv.FormatInt(n, 10) }
