package main

import (
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"go.yaml.in/yaml/v3"
)

// Deploy files live at the repository root, two levels above this package.
const repoRoot = "../.."

type composeService struct {
	Image       string   `yaml:"image"`
	Command     []string `yaml:"command"`
	NetworkMode string   `yaml:"network_mode"`
	Ports       []string `yaml:"ports"`
}

type composeFile struct {
	Name     string                    `yaml:"name"`
	Services map[string]composeService `yaml:"services"`
}

func loadCompose(t *testing.T, name string) composeFile {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(repoRoot, name))
	if err != nil {
		t.Fatal(err)
	}
	var f composeFile
	if err := yaml.Unmarshal(b, &f); err != nil {
		t.Fatalf("%s: %v", name, err)
	}
	return f
}

// Merge tags need Compose >= 2.24; the jury may run an older distribution
// package, so no compose file may use them.
func TestComposeNoMergeTags(t *testing.T) {
	files, err := filepath.Glob(filepath.Join(repoRoot, "compose*.yml"))
	if err != nil || len(files) == 0 {
		t.Fatalf("no compose files: %v", err)
	}
	for _, f := range files {
		b, err := os.ReadFile(f)
		if err != nil {
			t.Fatal(err)
		}
		for _, tag := range []string{"!reset", "!override"} {
			if strings.Contains(string(b), tag) {
				t.Errorf("%s uses %s", filepath.Base(f), tag)
			}
		}
	}
}

// compose.host.yml is standalone: its database must stay the one of
// compose.yml (same project and volumes, so switching modes keeps the data).
func TestComposeHostStandalone(t *testing.T) {
	base := loadCompose(t, "compose.yml")
	host := loadCompose(t, "compose.host.yml")
	if host.Name != base.Name || host.Name == "" {
		t.Errorf("project name: host %q, base %q", host.Name, base.Name)
	}
	bdb, hdb := base.Services["db"], host.Services["db"]
	if bdb.Image == "" || bdb.Image != hdb.Image {
		t.Errorf("db image: host %q, base %q", hdb.Image, bdb.Image)
	}
	if len(bdb.Command) == 0 || !reflect.DeepEqual(bdb.Command, hdb.Command) {
		t.Errorf("db command: host %q, base %q", hdb.Command, bdb.Command)
	}
	app, ok := host.Services["app"]
	if !ok {
		t.Fatal("compose.host.yml has no app service")
	}
	if app.NetworkMode != "host" {
		t.Errorf("app network_mode = %q, want host", app.NetworkMode)
	}
	if len(app.Ports) != 0 {
		t.Errorf("app ports = %q, want none with host networking", app.Ports)
	}
	if _, ok := host.Services["keys-init"]; !ok {
		t.Error("compose.host.yml has no keys-init service")
	}
}
