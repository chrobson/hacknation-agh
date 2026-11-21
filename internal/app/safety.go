package app

import (
	"encoding/json"
	"errors"
	"net/http"
	"strconv"

	"github.com/go-chi/chi/v5"

	"github.com/chrobson/hacknation-agh/internal/safety"
)

var safetyLabels = map[string]string{
	"nmap_rate":    "Tempo pakietów nmap ≤ max_rate",
	"http_methods": "Tylko GET i HEAD",
	"http_auth":    "Bez poświadczeń (Authorization, Cookie)",
	"http_rate":    "Tempo HTTP ≤ limit",
	"allowlist":    "Wszystkie adresy na liście dozwolonych",
}

func safetyLabel(name string) string {
	if l, ok := safetyLabels[name]; ok {
		return l
	}
	return name
}

func shortHash(h string) string {
	if len(h) > 12 {
		return h[:12]
	}
	return h
}

func (p *Pages) loadSafety(r *http.Request) (safety.Report, bool, int, error) {
	id, err := strconv.ParseInt(chi.URLParam(r, "id"), 10, 64)
	if err != nil || id <= 0 {
		return safety.Report{}, false, http.StatusBadRequest, errors.New("bad run id")
	}
	rc, err := safety.Load(r.Context(), p.Deps.DB, id)
	if errors.Is(err, safety.ErrNoReceipt) {
		return safety.Report{}, true, http.StatusNotFound, err
	}
	if err != nil {
		return safety.Report{}, false, http.StatusInternalServerError, err
	}
	return safety.BuildReport(rc), false, http.StatusOK, nil
}

// safetyJSON serves GET /runs/{id}/safety.json, the same JSON as `asi audit`.
func (p *Pages) safetyJSON(w http.ResponseWriter, r *http.Request) {
	rep, _, status, err := p.loadSafety(r)
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	if err != nil {
		_ = json.NewEncoder(w).Encode(map[string]string{"error": err.Error()})
		return
	}
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	_ = enc.Encode(rep)
}

// safetyCard serves GET /runs/{id}/safety, the card fragment loaded by the
// run page.
func (p *Pages) safetyCard(w http.ResponseWriter, r *http.Request) {
	rep, missing, status, err := p.loadSafety(r)
	if err != nil && !missing {
		http.Error(w, err.Error(), status)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if err := p.tmpl["safety"].ExecuteTemplate(w, "app/safety", map[string]any{"Report": rep, "Missing": missing}); err != nil {
		p.log().Error("render", "page", "safety", "err", err)
	}
}
