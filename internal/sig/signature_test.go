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
	if len(sigs) < 20 || len(sigs) > 60 {
		t.Fatalf("got %d built-in signatures, want 20-60", len(sigs))
	}
	required := []string{"wordpress", "joomla", "drupal", "nginx", "apache-httpd", "iis", "tomcat", "tomcat-manager",
		"jenkins", "grafana", "gitlab", "phpmyadmin", "kibana", "admin-panel", "login-page", "spring-boot-actuator",
		"apache-server-status", "staging-env", "mosquitto-mqtt", "iot-webui", "tls-self-signed", "tls-expired",
		"adminer", "gitea", "dvwa", "nginx-proxy-manager", "traefik-dashboard", "toxiproxy-api", "rabbitmq-management",
		"rabbitmq-amqp", "httpbin", "redis", "redis-noauth", "ftp", "vsftpd", "postgresql", "mysql"}
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

const metaBase = `id: meta-test
name: Meta test
category: server
confidence: 80
matchers:
  - type: title
    regex: 'x'
`

func TestSignatureMetaValid(t *testing.T) {
	s, err := Parse([]byte(metaBase + `cwe: [306, 668]
attack: [T1190, T1078.001]
remediation: 'Włącz   uwierzytelnianie.'
references:
  - https://redis.io/docs/latest/operate/oss_and_stack/management/security/
  - http://example.test/a
`))
	if err != nil {
		t.Fatal(err)
	}
	m := s.Meta()
	if m == nil || m.CWE[0] != 306 || m.Attack[1] != "T1078.001" || m.Remediation != "Włącz uwierzytelnianie." || len(m.References) != 2 {
		t.Fatalf("meta = %+v", m)
	}
	// Without the optional fields the signature loads unchanged and has no meta.
	plain, err := Parse([]byte(metaBase))
	if err != nil || plain.Meta() != nil {
		t.Fatalf("plain signature: %v, meta %+v", err, plain.Meta())
	}
}

func TestSignatureMetaInvalid(t *testing.T) {
	cases := map[string]string{
		"attack: [T190]":                      "MITRE ATT&CK technique id",
		"attack: [t1190]":                     "MITRE ATT&CK technique id",
		"attack: [T1190.1]":                   "MITRE ATT&CK technique id",
		"references: [ftp://x.test/a]":        "http:// or https:// URL",
		"references: ['javascript:alert(1)']": "http:// or https:// URL",
		"references: [/relative]":             "http:// or https:// URL",
		"cwe: [0]":                            "CWE number",
		"cwe: [CWE-306]":                      "yaml",
		"mitigation: x":                       "yaml", // unknown key stays rejected
	}
	for extra, want := range cases {
		_, err := Parse([]byte(metaBase + extra + "\n"))
		if err == nil || !strings.Contains(err.Error(), want) {
			t.Errorf("%s: err = %v, want it to mention %q", extra, err, want)
		}
	}
}

func TestBuiltinMetaCoverage(t *testing.T) {
	sigs, err := Builtin()
	if err != nil {
		t.Fatal(err)
	}
	with := 0
	for _, s := range sigs {
		if m := s.Meta(); m != nil && len(m.CWE) > 0 && m.Remediation != "" {
			with++
		}
	}
	if with*10 < len(sigs)*8 {
		t.Errorf("only %d of %d built-in signatures have cwe and remediation", with, len(sigs))
	}
	for _, id := range []string{"redis-noauth", "traefik-dashboard"} {
		for _, s := range sigs {
			if s.ID == id && (len(s.CWE) == 0 || s.CWE[0] != 306) {
				t.Errorf("%s: cwe = %v, want 306 first", id, s.CWE)
			}
		}
	}
}
