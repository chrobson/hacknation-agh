// Package auth implements sessions, bcrypt passwords, RBAC, CSRF protection
// and AES-GCM encryption of application secrets.
//
// Integration (cmd/asi serve):
//
//	r := chi.NewRouter()
//	r.Use(auth.Middleware(deps))          // CSRF + session -> request context
//	auth.Mount(r, deps)                    // /login, /logout, /admin/*
//	r.With(auth.Require(auth.PermTargetsWrite)).Post("/targets", ...)
//
// Templates use the "can" func from Funcs() (or User.Can) to hide buttons:
//
//	{{if can .User "targets.write"}}<button>Dodaj</button>{{end}}
package auth

import (
	"net/http"
	"slices"
)

// Perm is a permission name stored in role_permissions.perm.
type Perm = string

// The fixed permission list (docs/ARCHITECTURE.md).
const (
	PermTargetsRead     Perm = "targets.read"
	PermTargetsWrite    Perm = "targets.write"
	PermScansRun        Perm = "scans.run"
	PermResultsRead     Perm = "results.read"
	PermResultsEdit     Perm = "results.edit"
	PermSignaturesWrite Perm = "signatures.write"
	PermExport          Perm = "export"
	PermUsersAdmin      Perm = "users.admin"
)

// PermInfo describes a permission for the admin UI.
type PermInfo struct {
	Name  Perm
	Label string // Polish UI label
}

// AllPerms is the ordered, fixed list of permissions.
var AllPerms = []PermInfo{
	{PermTargetsRead, "Odczyt celów"},
	{PermTargetsWrite, "Dodawanie, usuwanie i edycja celów"},
	{PermScansRun, "Uruchamianie skanów i import wyników"},
	{PermResultsRead, "Odczyt wyników"},
	{PermResultsEdit, "Edycja wyników (adnotacje, false positive)"},
	{PermSignaturesWrite, "Zarządzanie sygnaturami"},
	{PermExport, "Eksport (DefectDojo, CSV)"},
	{PermUsersAdmin, "Administracja użytkownikami i rolami"},
}

// ValidPerm reports whether p is on the fixed permission list.
func ValidPerm(p string) bool {
	for _, i := range AllPerms {
		if i.Name == p {
			return true
		}
	}
	return false
}

// Built-in role names (seeded by migrations/0001_init.sql).
const (
	RoleAdmin   = "Administracja"
	RoleEditor  = "Dodawanie, usuwanie, modyfikacja"
	RoleAnalyst = "Modyfikacja i odczyt"
	RoleViewer  = "Odczyt"
)

// BuiltinRoles mirrors the built-in role permissions inserted by
// migrations/0001_init.sql. The integration test checks they agree.
var BuiltinRoles = map[string][]Perm{
	RoleAdmin: {PermTargetsRead, PermTargetsWrite, PermScansRun, PermResultsRead,
		PermResultsEdit, PermSignaturesWrite, PermExport, PermUsersAdmin},
	RoleEditor: {PermTargetsRead, PermTargetsWrite, PermScansRun, PermResultsRead,
		PermResultsEdit, PermSignaturesWrite, PermExport},
	RoleAnalyst: {PermTargetsRead, PermResultsRead, PermResultsEdit, PermExport},
	RoleViewer:  {PermTargetsRead, PermResultsRead},
}

// User is the authenticated principal stored in the request context.
type User struct {
	ID       int64
	Login    string
	RoleID   int64
	RoleName string
	Perms    []Perm
}

// Can reports whether the user holds perm. A nil user can do nothing.
func (u *User) Can(perm string) bool {
	return u != nil && slices.Contains(u.Perms, perm)
}

// can is the template helper: {{if can .User "targets.write"}}.
func can(u *User, perm string) bool { return u.Can(perm) }

// Authz adapts the request-context user to modules that take a small
// authorizer interface (e.g. target.Authz):
//
//	target.Authz = auth.Authz{}
type Authz struct{}

// Allowed reports whether the request's user holds perm.
func (Authz) Allowed(r *http.Request, perm string) bool {
	return UserFrom(r.Context()).Can(perm)
}

// UserID returns the request's user id, if logged in.
func (Authz) UserID(r *http.Request) (int64, bool) {
	if u := UserFrom(r.Context()); u != nil {
		return u.ID, true
	}
	return 0, false
}
