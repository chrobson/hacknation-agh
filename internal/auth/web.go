package auth

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"

	"github.com/chrobson/hacknation-agh/internal/store"
	"github.com/chrobson/hacknation-agh/internal/web"
)

type handlers struct {
	d   web.Deps
	log *slog.Logger
}

type userRow struct {
	ID        int64
	Login     string
	RoleID    int64
	RoleName  string
	CreatedAt string
	Self      bool
}

type roleRow struct {
	ID      int64
	Name    string
	Builtin bool
	Perms   []PermInfo
	Users   int
}

type auditRow struct {
	At      string
	Login   string
	Action  string
	Entity  string
	Details string
}

// flash codes -> messages; codes (not free text) travel in the redirect URL
// so a crafted link cannot display arbitrary text.
var flashOK = map[string]string{
	"user_created": "Użytkownik został utworzony.",
	"role_changed": "Rola użytkownika została zmieniona.",
	"role_created": "Rola została utworzona.",
	"role_deleted": "Rola została usunięta.",
	"logged_out":   "Wylogowano.",
}

var flashErr = map[string]string{
	"bad_input":     "Nieprawidłowe dane formularza.",
	"login_taken":   "Użytkownik o tym loginie już istnieje.",
	"weak_password": "Hasło musi mieć co najmniej 8 znaków.",
	"long_password": "Hasło może mieć najwyżej 72 bajty.",
	"self_role":     "Nie można zmienić własnej roli.",
	"role_taken":    "Rola o tej nazwie już istnieje.",
	"no_perms":      "Zaznacz co najmniej jedno uprawnienie.",
	"role_builtin":  "Ról wbudowanych nie można usuwać.",
	"role_in_use":   "Rola jest przypisana do użytkowników.",
	"not_found":     "Nie znaleziono obiektu.",
}

// Mount registers /login, /logout and the /admin pages (users.admin only).
// auth.Middleware must already be applied on r.
func Mount(r chi.Router, d web.Deps) {
	h := &handlers{d: d, log: d.Log}
	if h.log == nil {
		h.log = slog.Default()
	}
	r.Get("/login", h.loginPage)
	r.Post("/login", h.login)
	r.Post("/logout", h.logout)
	r.Route("/admin", func(ar chi.Router) {
		ar.Use(Require(PermUsersAdmin))
		ar.Get("/", func(w http.ResponseWriter, r *http.Request) {
			http.Redirect(w, r, "/admin/users", http.StatusSeeOther)
		})
		ar.Get("/users", h.usersPage)
		ar.Post("/users", h.createUser)
		ar.Post("/users/{id}/role", h.changeRole)
		ar.Get("/roles", h.rolesPage)
		ar.Post("/roles", h.createRole)
		ar.Post("/roles/{id}/delete", h.deleteRole)
		ar.Get("/audit", h.auditPage)
	})
}

func (h *handlers) fail(w http.ResponseWriter, r *http.Request, err error) {
	h.log.Error("auth handler", "path", r.URL.Path, "err", err)
	http.Error(w, "Błąd serwera", http.StatusInternalServerError)
}

func (h *handlers) audit(ctx context.Context, u *User, action, entity string, details map[string]any) {
	var uid *int64
	if u != nil {
		uid = &u.ID
	}
	if err := store.InsertAudit(ctx, h.d.DB, uid, action, entity, details); err != nil {
		h.log.Error("audit log", "action", action, "err", err)
	}
}

func flash(r *http.Request) (msg, errMsg string) {
	q := r.URL.Query()
	return flashOK[q.Get("ok")], flashErr[q.Get("err")]
}

func redirectFlash(w http.ResponseWriter, r *http.Request, path, kind, code string) {
	http.Redirect(w, r, path+"?"+kind+"="+code, http.StatusSeeOther)
}

// safeNext accepts only local absolute paths to prevent open redirects.
func safeNext(s string) string {
	if s == "" || !strings.HasPrefix(s, "/") || strings.HasPrefix(s, "//") ||
		strings.HasPrefix(s, "/\\") || strings.ContainsAny(s, "\r\n") {
		return "/"
	}
	return s
}

// --- login / logout ---------------------------------------------------------

func (h *handlers) loginPage(w http.ResponseWriter, r *http.Request) {
	if UserFrom(r.Context()) != nil {
		http.Redirect(w, r, safeNext(r.URL.Query().Get("next")), http.StatusSeeOther)
		return
	}
	msg, _ := flash(r)
	render(w, "login.html", pageData{Next: safeNext(r.URL.Query().Get("next")), Message: msg})
}

func (h *handlers) login(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	login := strings.TrimSpace(r.PostFormValue("login"))
	pw := r.PostFormValue("password")
	next := safeNext(r.PostFormValue("next"))

	au, err := store.UserByLogin(ctx, h.d.DB, login)
	if err != nil && !errors.Is(err, pgx.ErrNoRows) {
		h.fail(w, r, err)
		return
	}
	ok := false
	if err == nil {
		ok = CheckPassword(au.PassHash, pw)
	} else {
		CheckPassword(string(dummyHash), pw) // equalize timing
	}
	if !ok {
		logged := login
		if len(logged) > 64 {
			logged = strings.ToValidUTF8(logged[:64], "")
		}
		h.audit(ctx, nil, "login.failed", "user:"+logged, map[string]any{"login": logged, "ip": clientIP(r)})
		renderStatus(w, http.StatusUnauthorized, "login.html", pageData{
			Next: next, Login: login, Error: "Nieprawidłowy login lub hasło.",
		})
		return
	}
	tok := newToken()
	exp := time.Now().Add(SessionTTL)
	if err := store.CreateSession(ctx, h.d.DB, hashToken(tok), au.ID, exp); err != nil {
		h.fail(w, r, err)
		return
	}
	if _, err := store.DeleteExpiredSessions(ctx, h.d.DB); err != nil {
		h.log.Warn("delete expired sessions", "err", err)
	}
	setSessionCookie(w, r, tok, exp)
	h.audit(ctx, userFromStore(au), "login", "user:"+au.Login, map[string]any{"ip": clientIP(r)})
	http.Redirect(w, r, next, http.StatusSeeOther)
}

func (h *handlers) logout(w http.ResponseWriter, r *http.Request) {
	if c, err := r.Cookie(CookieName); err == nil && c.Value != "" {
		if err := store.DeleteSession(r.Context(), h.d.DB, hashToken(c.Value)); err != nil {
			h.fail(w, r, err)
			return
		}
	}
	if u := UserFrom(r.Context()); u != nil {
		h.audit(r.Context(), u, "logout", "user:"+u.Login, nil)
	}
	clearSessionCookie(w, r)
	if r.Header.Get("HX-Request") == "true" {
		w.Header().Set("HX-Redirect", "/login?ok=logged_out")
		w.WriteHeader(http.StatusNoContent)
		return
	}
	redirectFlash(w, r, "/login", "ok", "logged_out")
}

func clientIP(r *http.Request) string {
	host := r.RemoteAddr
	if i := strings.LastIndexByte(host, ':'); i > 0 {
		host = host[:i]
	}
	return strings.Trim(host, "[]")
}

// --- users ------------------------------------------------------------------

func (h *handlers) usersPage(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	me := UserFrom(ctx)
	users, err := store.ListUsers(ctx, h.d.DB)
	if err != nil {
		h.fail(w, r, err)
		return
	}
	roles, err := h.roleRows(ctx)
	if err != nil {
		h.fail(w, r, err)
		return
	}
	data := pageData{User: me, Roles: roles}
	data.Message, data.Error = flash(r)
	for _, u := range users {
		data.Users = append(data.Users, userRow{
			ID: u.ID, Login: u.Login, RoleID: u.RoleID, RoleName: u.RoleName,
			CreatedAt: u.CreatedAt.Local().Format("2006-01-02 15:04"), Self: u.ID == me.ID,
		})
	}
	render(w, "users.html", data)
}

func (h *handlers) createUser(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	login := strings.TrimSpace(r.PostFormValue("login"))
	roleID, err := strconv.ParseInt(r.PostFormValue("role_id"), 10, 64)
	if login == "" || len(login) > 64 || err != nil {
		redirectFlash(w, r, "/admin/users", "err", "bad_input")
		return
	}
	hash, err := HashPassword(r.PostFormValue("password"))
	if errors.Is(err, ErrWeakPassword) {
		redirectFlash(w, r, "/admin/users", "err", "weak_password")
		return
	}
	if errors.Is(err, ErrLongPassword) {
		redirectFlash(w, r, "/admin/users", "err", "long_password")
		return
	}
	if err != nil {
		h.fail(w, r, err)
		return
	}
	id, err := store.CreateUser(ctx, h.d.DB, login, hash, roleID)
	if code := pgCode(err); code == "23505" {
		redirectFlash(w, r, "/admin/users", "err", "login_taken")
		return
	} else if code == "23503" {
		redirectFlash(w, r, "/admin/users", "err", "not_found")
		return
	}
	if err != nil {
		h.fail(w, r, err)
		return
	}
	h.audit(ctx, UserFrom(ctx), "user.create", "user:"+login, map[string]any{"user_id": id, "role_id": roleID})
	redirectFlash(w, r, "/admin/users", "ok", "user_created")
}

func (h *handlers) changeRole(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	me := UserFrom(ctx)
	uid, err1 := strconv.ParseInt(chi.URLParam(r, "id"), 10, 64)
	roleID, err2 := strconv.ParseInt(r.PostFormValue("role_id"), 10, 64)
	if err1 != nil || err2 != nil {
		redirectFlash(w, r, "/admin/users", "err", "bad_input")
		return
	}
	if uid == me.ID {
		redirectFlash(w, r, "/admin/users", "err", "self_role")
		return
	}
	before, err := store.UserByID(ctx, h.d.DB, uid)
	if errors.Is(err, pgx.ErrNoRows) {
		redirectFlash(w, r, "/admin/users", "err", "not_found")
		return
	}
	if err != nil {
		h.fail(w, r, err)
		return
	}
	err = store.SetUserRole(ctx, h.d.DB, uid, roleID)
	if pgCode(err) == "23503" || errors.Is(err, pgx.ErrNoRows) {
		redirectFlash(w, r, "/admin/users", "err", "not_found")
		return
	}
	if err != nil {
		h.fail(w, r, err)
		return
	}
	h.audit(ctx, me, "user.role", "user:"+before.Login, map[string]any{
		"user_id": uid, "old_role_id": before.RoleID, "old_role": before.RoleName, "new_role_id": roleID,
	})
	redirectFlash(w, r, "/admin/users", "ok", "role_changed")
}

// --- roles ------------------------------------------------------------------

func (h *handlers) roleRows(ctx context.Context) ([]roleRow, error) {
	roles, err := store.ListRoles(ctx, h.d.DB)
	if err != nil {
		return nil, err
	}
	out := make([]roleRow, 0, len(roles))
	for _, ro := range roles {
		row := roleRow{ID: ro.ID, Name: ro.Name, Builtin: ro.Builtin, Users: ro.Users}
		for _, p := range AllPerms {
			for _, have := range ro.Perms {
				if have == p.Name {
					row.Perms = append(row.Perms, p)
				}
			}
		}
		out = append(out, row)
	}
	return out, nil
}

func (h *handlers) rolesPage(w http.ResponseWriter, r *http.Request) {
	roles, err := h.roleRows(r.Context())
	if err != nil {
		h.fail(w, r, err)
		return
	}
	data := pageData{User: UserFrom(r.Context()), Roles: roles, AllPerms: AllPerms}
	data.Message, data.Error = flash(r)
	render(w, "roles.html", data)
}

func (h *handlers) createRole(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	if err := r.ParseForm(); err != nil {
		redirectFlash(w, r, "/admin/roles", "err", "bad_input")
		return
	}
	name := strings.TrimSpace(r.PostForm.Get("name"))
	if name == "" || len(name) > 64 {
		redirectFlash(w, r, "/admin/roles", "err", "bad_input")
		return
	}
	var perms []string
	seen := map[string]bool{}
	for _, p := range r.PostForm["perm"] {
		if !ValidPerm(p) {
			redirectFlash(w, r, "/admin/roles", "err", "bad_input")
			return
		}
		if !seen[p] {
			seen[p] = true
			perms = append(perms, p)
		}
	}
	if len(perms) == 0 {
		redirectFlash(w, r, "/admin/roles", "err", "no_perms")
		return
	}
	tx, err := h.d.DB.Begin(ctx)
	if err != nil {
		h.fail(w, r, err)
		return
	}
	defer func() { _ = tx.Rollback(ctx) }()
	id, err := store.CreateRole(ctx, tx, name, perms)
	if pgCode(err) == "23505" {
		redirectFlash(w, r, "/admin/roles", "err", "role_taken")
		return
	}
	if err == nil {
		err = tx.Commit(ctx)
	}
	if err != nil {
		h.fail(w, r, err)
		return
	}
	h.audit(ctx, UserFrom(ctx), "role.create", "role:"+name, map[string]any{"role_id": id, "perms": perms})
	redirectFlash(w, r, "/admin/roles", "ok", "role_created")
}

func (h *handlers) deleteRole(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	id, err := strconv.ParseInt(chi.URLParam(r, "id"), 10, 64)
	if err != nil {
		redirectFlash(w, r, "/admin/roles", "err", "bad_input")
		return
	}
	name, err := store.DeleteRole(ctx, h.d.DB, id)
	switch {
	case errors.Is(err, pgx.ErrNoRows):
		redirectFlash(w, r, "/admin/roles", "err", "not_found")
	case errors.Is(err, store.ErrRoleBuiltin):
		redirectFlash(w, r, "/admin/roles", "err", "role_builtin")
	case errors.Is(err, store.ErrRoleInUse):
		redirectFlash(w, r, "/admin/roles", "err", "role_in_use")
	case err != nil:
		h.fail(w, r, err)
	default:
		h.audit(ctx, UserFrom(ctx), "role.delete", "role:"+name, map[string]any{"role_id": id})
		redirectFlash(w, r, "/admin/roles", "ok", "role_deleted")
	}
}

// --- audit ------------------------------------------------------------------

func (h *handlers) auditPage(w http.ResponseWriter, r *http.Request) {
	entries, err := store.ListAudit(r.Context(), h.d.DB, 200)
	if err != nil {
		h.fail(w, r, err)
		return
	}
	data := pageData{User: UserFrom(r.Context())}
	for _, e := range entries {
		data.Audit = append(data.Audit, auditRow{
			At: e.At.Local().Format("2006-01-02 15:04:05"), Login: e.Login,
			Action: e.Action, Entity: e.Entity, Details: e.Details,
		})
	}
	render(w, "audit.html", data)
}

func pgCode(err error) string {
	var pgErr *pgconn.PgError
	if errors.As(err, &pgErr) {
		return pgErr.Code
	}
	return ""
}
