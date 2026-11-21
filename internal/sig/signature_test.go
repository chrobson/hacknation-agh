package sig

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestBuiltinSignaturesLoad(t *testing.T) {
	sigs, err := Builtin()
	if err != nil {
		t.Fatal(err)
	}
	if len(sigs) < 20 || len(sigs) > 25 {
		t.Fatalf("got %d built-in signatures, want 20-25", len(sigs))
	}
	required := []string{"wordpress", "joomla", "drupal", "nginx", "apache-httpd", "iis", "tomcat", "tomcat-manager",
		"jenkins", "grafana", "gitlab", "phpmyadmin", "kibana", "admin-panel", "login-page", "spring-boot-actuator",
		"apache-server-status", "staging-env", "mosquitto-mqtt", "iot-webui", "tls-self-signed", "tls-expired"}
	ids := map[string]*Signature{}
	for _, s := range sigs {
		ids[s.ID] = s
		if s.Raw == "" || s.Description == "" {
			t.Errorf("%s: missing raw yaml or description", s.ID)
		}
	}
	for _, id := range required {
		if ids[id] == nil {
			t.Errorf("missing built-in signature %q", id)
		}
	}
	// Builtins also live on disk for the container image (/etc/asi/signatures).
	disk, err := LoadDir("../../signatures")
	if err != nil || len(disk) != len(sigs) {
		t.Fatalf("LoadDir: %d sigs, err %v", len(disk), err)
	}
}

func TestValidGoldenFiles(t *testing.T) {
	sigs, err := LoadDir("testdata/valid")
	if err != nil {
		t.Fatal(err)
	}
	if len(sigs) != 2 {
		t.Fatalf("loaded %d", len(sigs))
	}
	for _, s := range sigs {
		for _, m := range s.Matchers {
			if m.Type == TypePath && m.Method == "" {
				t.Errorf("%s: method not defaulted", s.ID)
			}
		}
	}
}

// Every file in testdata/invalid starts with "# want: <substring>" naming
// the validator error it must produce.
func TestInvalidGoldenFiles(t *testing.T) {
	files, _ := filepath.Glob("testdata/invalid/*.yaml")
	if len(files) < 15 {
		t.Fatalf("only %d invalid fixtures", len(files))
	}
	for _, f := range files {
		t.Run(filepath.Base(f), func(t *testing.T) {
			b, err := os.ReadFile(f)
			if err != nil {
				t.Fatal(err)
			}
			first, _, _ := strings.Cut(string(b), "\n")
			want, ok := strings.CutPrefix(first, "# want: ")
			if !ok {
				t.Fatal("fixture must start with '# want: '")
			}
			_, err = Parse(b)
			if err == nil {
				t.Fatalf("accepted, want error containing %q", want)
			}
			if !strings.Contains(err.Error(), want) {
				t.Fatalf("error %q does not contain %q", err, want)
			}
		})
	}
}

func TestLoadFSRejectsDuplicates(t *testing.T) {
	dir := t.TempDir()
	doc := "id: dup\nname: D\ncategory: other\nconfidence: 5\nmatchers:\n  - {type: title, regex: x}\n"
	for _, n := range []string{"a.yaml", "b.yml"} {
		if err := os.WriteFile(filepath.Join(dir, n), []byte(doc), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	sigs, err := LoadDir(dir)
	if err == nil || !strings.Contains(err.Error(), "duplicate id") || len(sigs) != 1 {
		t.Fatalf("sigs=%d err=%v", len(sigs), err)
	}
}

func TestParseRejectsHugeDocument(t *testing.T) {
	if _, err := Parse(make([]byte, MaxYAMLBytes+1)); err == nil {
		t.Fatal("accepted oversized document")
	}
	if _, err := Parse(nil); err == nil {
		t.Fatal("accepted empty document")
	}
}
