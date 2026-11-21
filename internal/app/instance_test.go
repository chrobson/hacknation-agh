package app

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/chrobson/hacknation-agh/internal/config"
	"github.com/chrobson/hacknation-agh/internal/model"
)

func TestInstanceID(t *testing.T) {
	a := config.Config{SecretKey: []byte("0123456789abcdef0123456789abcdef"), DatabaseURL: "postgres://a@db/asi"}
	b := a
	b.DatabaseURL = "postgres://a@127.0.0.1:55432/asi" // same key, other process view
	if InstanceID(a) != InstanceID(b) || len(InstanceID(a)) != 24 {
		t.Fatalf("instance id must depend on the key only: %q %q", InstanceID(a), InstanceID(b))
	}
	c := a
	c.SecretKey = []byte("fedcba9876543210fedcba9876543210")
	if InstanceID(a) == InstanceID(c) {
		t.Fatal("different keys, same id")
	}
	noKey := config.Config{DatabaseURL: "postgres://a@db/asi"}
	other := config.Config{DatabaseURL: "postgres://b@db/asi"}
	if InstanceID(noKey) == InstanceID(other) || InstanceID(noKey) == "" {
		t.Fatal("without a key the id must follow the database URL")
	}
}

func TestOwnUIIsRecognised(t *testing.T) {
	id := InstanceID(config.Config{DatabaseURL: "postgres://a@db/asi"})
	h := instanceHeader(id)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest("GET", "/login", nil))
	// The prober stores response headers under their canonical names.
	obs := model.HTTPObs{Status: 200, Headers: map[string][]string(rec.Header())}
	if !isSelf(obs, id) {
		t.Fatalf("own UI not recognised, headers %v", rec.Header())
	}
	if isSelf(obs, "another-installation") {
		t.Fatal("another installation taken for this one")
	}
	if isSelf(model.HTTPObs{Status: 200}, id) || isSelf(obs, "") {
		t.Fatal("service without the header (or no self id) taken for the own UI")
	}
}
