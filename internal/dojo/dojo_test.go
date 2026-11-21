package dojo

import (
	"bytes"
	"encoding/json"
	"flag"
	"net/netip"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/chrobson/hacknation-agh/internal/model"
)

var update = flag.Bool("update", false, "rewrite golden files in testdata/dojo")

const testdataDir = "../../testdata/dojo"

func key(ip string, port uint16, proto string) model.AssetKey {
	return model.AssetKey{IP: netip.MustParseAddr(ip), Port: port, Proto: proto}
}

// fixture mirrors a small lab run: plain services, an admin panel, a
// staging app, a CMS, a false positive and a severity override.
func fixture() ([]Service, []Annotation) {
	svcs := []Service{
		{ServiceObs: model.ServiceObs{ID: 1, RunID: 7, Key: key("10.20.0.11", 443, "tcp"), Product: "nginx", Version: "1.27.4",
			CPE: "cpe:/a:f5:nginx:1.27.4"}, Hostname: "web.lab.test",
			HTTP: &HTTPSummary{URL: "https://10.20.0.11/", Status: 200, Title: "Welcome"},
			Detections: []model.Detection{
				{ServiceID: 1, SignatureID: "wordpress", Name: "WordPress", Category: "cms", Confidence: 90,
					Evidence: map[string]string{"meta_generator": "WordPress 6.5"}},
			}},
		{ServiceObs: model.ServiceObs{ID: 2, RunID: 7, Key: key("10.20.0.11", 22, "tcp"), Product: "OpenSSH", Version: "9.6p1",
			ExtraInfo: "protocol 2.0", Banner: "SSH-2.0-OpenSSH_9.6p1"}},
		{ServiceObs: model.ServiceObs{ID: 3, RunID: 7, Key: key("10.20.0.14", 80, "tcp"), Product: "Apache httpd", Version: "2.4.62"},
			HTTP: &HTTPSummary{URL: "http://10.20.0.14/", Status: 200, Title: "phpMyAdmin"},
			Detections: []model.Detection{
				{ServiceID: 3, SignatureID: "phpmyadmin", Name: "phpMyAdmin", Category: "admin-panel", Confidence: 100,
					Evidence: map[string]string{"title": "phpMyAdmin"},
					Meta: &model.SignatureMeta{CWE: []int{668}, Attack: []string{"T1078", "T1190"},
						Remediation: "Ogranicz phpMyAdmina do sieci administracyjnej.",
						References:  []string{"https://docs.phpmyadmin.net/en/latest/setup.html#securing-your-phpmyadmin-installation"}}},
			}},
		{ServiceObs: model.ServiceObs{ID: 4, RunID: 7, Key: key("10.20.0.21", 8080, "tcp"), Product: "Jetty"},
			HTTP: &HTTPSummary{URL: "http://10.20.0.21:8080/", Status: 200, Title: "STAGING - shop"},
			Detections: []model.Detection{
				{ServiceID: 4, SignatureID: "staging-banner", Name: "Staging banner", Category: "staging", Confidence: 80},
			}},
		{ServiceObs: model.ServiceObs{ID: 5, RunID: 7, Key: key("10.20.0.30", 53, "udp"), Product: "dnsmasq", Version: "2.90"}},
		// False positive at service level: dropped with its detection.
		{ServiceObs: model.ServiceObs{ID: 6, RunID: 7, Key: key("10.20.0.31", 8443, "tcp")},
			Detections: []model.Detection{{ServiceID: 6, SignatureID: "grafana", Name: "Grafana", Category: "admin-panel", Confidence: 60}}},
		// Host-level false positive: every service of the host is dropped.
		{ServiceObs: model.ServiceObs{ID: 7, RunID: 7, Key: key("10.20.0.40", 21, "tcp"), Product: "vsftpd"}},
	}
	anns := []Annotation{
		{Key: key("10.20.0.31", 8443, "tcp"), FalsePositive: true, Comment: "honeypot"},
		{Key: model.AssetKey{IP: netip.MustParseAddr("10.20.0.40")}, FalsePositive: true},
		{Key: key("10.20.0.11", 22, "tcp"), Severity: "Low", Tags: []string{"Legacy SSH", "owner:ops"}, Comment: "Do wyłączenia po migracji."},
	}
	return svcs, anns
}

var runDate = time.Date(2026, 11, 21, 18, 30, 0, 0, time.UTC)

func TestGoldenFindings(t *testing.T) {
	svcs, anns := fixture()
	b, err := NewCodec().Marshal(BuildFindings(runDate, svcs, anns))
	if err != nil {
		t.Fatal(err)
	}
	golden := filepath.Join(testdataDir, "golden_findings.json")
	if *update {
		if err := os.WriteFile(golden, b, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	want, err := os.ReadFile(golden)
	if err != nil {
		t.Fatalf("read golden (run with -update to create): %v", err)
	}
	if !bytes.Equal(b, want) {
		t.Fatalf("output differs from %s (run go test ./internal/dojo -update)\n--- got\n%s", golden, b)
	}
}

func TestBuildRules(t *testing.T) {
	svcs, anns := fixture()
	fs := BuildFindings(runDate, svcs, anns)
	by := map[string]model.Finding{}
	for _, f := range fs {
		by[f.UniqueIDFromTool] = f
	}
	cases := []struct {
		uid      string
		severity model.Severity
		title    string
	}{
		{"asi:svc:10.20.0.11:443/tcp", model.SevInfo, "Open service 443/tcp nginx 1.27.4"},
		{"asi:svc:10.20.0.11:22/tcp", model.SevLow, "Open service 22/tcp OpenSSH 9.6p1"},
		{"asi:sig:10.20.0.11:443:wordpress", model.SevInfo, "Technology detected: WordPress"},
		{"asi:sig:10.20.0.14:80:phpmyadmin", model.SevMedium, "Admin panel detected: phpMyAdmin"},
		{"asi:sig:10.20.0.21:8080:staging-banner", model.SevMedium, "Staging environment detected: Staging banner"},
		{"asi:svc:10.20.0.30:53/udp", model.SevInfo, "Open service 53/udp dnsmasq 2.90"},
	}
	for _, c := range cases {
		f, ok := by[c.uid]
		if !ok {
			t.Errorf("missing finding %s", c.uid)
			continue
		}
		if f.Severity != c.severity || f.Title != c.title {
			t.Errorf("%s: got %q/%s, want %q/%s", c.uid, f.Title, f.Severity, c.title, c.severity)
		}
		if !f.Date.Equal(time.Date(2026, 11, 21, 0, 0, 0, 0, time.UTC)) {
			t.Errorf("%s: date %v", c.uid, f.Date)
		}
	}
	for _, uid := range []string{"asi:svc:10.20.0.31:8443/tcp", "asi:sig:10.20.0.31:8443:grafana", "asi:svc:10.20.0.40:21/tcp"} {
		if _, ok := by[uid]; ok {
			t.Errorf("false positive %s was exported", uid)
		}
	}
	ssh := by["asi:svc:10.20.0.11:22/tcp"]
	if !reflect.DeepEqual(ssh.Tags, []string{"asi", "legacy-ssh", "owner:ops", "service"}) {
		t.Errorf("annotation tags: %v", ssh.Tags)
	}
	if !strings.Contains(ssh.Description, "Do wyłączenia po migracji.") {
		t.Errorf("description lacks the analyst comment:\n%s", ssh.Description)
	}
	if strings.Contains(ssh.Description, "SSH-2.0-OpenSSH_9.6p1") {
		t.Errorf("description must not carry the volatile banner:\n%s", ssh.Description)
	}
	if by["asi:sig:10.20.0.14:80:phpmyadmin"].VulnIDFromTool != "phpmyadmin" {
		t.Error("vuln_id_from_tool not set to signature id")
	}
	if len(fs) != 8 { // 5 services + 3 detections
		t.Errorf("got %d findings, want 8", len(fs))
	}
}

// Titles and the whole file must not depend on time of day, run id or
// input order: DefectDojo dedupes on hash(title, severity, endpoints).
func TestDeterministic(t *testing.T) {
	svcs, anns := fixture()
	a, err := NewCodec().Marshal(BuildFindings(runDate, svcs, anns))
	if err != nil {
		t.Fatal(err)
	}
	svcs2, anns2 := fixture()
	for i := range svcs2 {
		svcs2[i].RunID = 99
		svcs2[i].ID += 100
	}
	for i, j := 0, len(svcs2)-1; i < j; i, j = i+1, j-1 {
		svcs2[i], svcs2[j] = svcs2[j], svcs2[i]
	}
	b, err := NewCodec().Marshal(BuildFindings(runDate.Add(3*time.Hour), svcs2, anns2))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(a, b) {
		t.Fatalf("output not deterministic:\n%s\n---\n%s", a, b)
	}
	for _, f := range BuildFindings(runDate, svcs, anns) {
		if strings.Contains(f.Title, "2026") || strings.Contains(f.Title, "#") {
			t.Errorf("title contains time or run id: %q", f.Title)
		}
	}
}

func TestRoundTrip(t *testing.T) {
	in := []model.Finding{
		{Title: "Admin panel detected: phpMyAdmin", Severity: model.SevMedium, Description: "d1",
			Date: time.Date(2026, 11, 21, 0, 0, 0, 0, time.UTC), UniqueIDFromTool: "asi:sig:10.20.0.14:80:phpmyadmin",
			VulnIDFromTool: "phpmyadmin", Endpoints: []model.AssetKey{key("10.20.0.14", 80, "tcp")}, Tags: []string{"admin-panel", "asi"}},
		{Title: "Open service 22/tcp OpenSSH", Severity: model.SevInfo, Description: "d2",
			Date: time.Date(2026, 11, 21, 0, 0, 0, 0, time.UTC), UniqueIDFromTool: "asi:svc:10.20.0.11:22/tcp",
			Endpoints: []model.AssetKey{key("10.20.0.11", 22, "tcp")}, Tags: []string{"asi", "service"}},
		{Title: "Open service 53/udp", Severity: model.SevInfo, Description: "d3",
			UniqueIDFromTool: "asi:svc:2001:db8::1:53/udp", Endpoints: []model.AssetKey{key("2001:db8::1", 53, "udp")}},
	}
	c := NewCodec()
	b, err := c.Marshal(in)
	if err != nil {
		t.Fatal(err)
	}
	out, err := c.Unmarshal(b)
	if err != nil {
		t.Fatal(err)
	}
	// Marshal sorts by unique id.
	want := in
	if !reflect.DeepEqual(out, want) {
		t.Fatalf("round trip mismatch\ngot  %+v\nwant %+v", out, want)
	}
	b2, err := c.Marshal(out)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(b, b2) {
		t.Fatal("second marshal differs")
	}
}

func TestMarshalRejectsDuplicateIDs(t *testing.T) {
	f := model.Finding{Title: "x", Severity: model.SevInfo, Description: "d", UniqueIDFromTool: "asi:svc:10.20.0.1:80/tcp"}
	if _, err := NewCodec().Marshal([]model.Finding{f, f}); err == nil {
		t.Fatal("expected duplicate id error")
	}
}

func TestUnmarshalLenient(t *testing.T) {
	doc := `{"findings":[{"title":"t","severity":"informational","description":"d","cwe":79,
		"date":"2026-11-21T10:00:00Z","endpoints":["https://10.20.0.5/login","admin.lab.test:8443",{"host":"10.20.0.6","port":"8080","protocol":"http"}]}]}`
	fs, err := NewCodec().Unmarshal([]byte(doc))
	if err != nil {
		t.Fatal(err)
	}
	f := fs[0]
	if f.Severity != model.SevInfo || f.Date.Format(dateLayout) != "2026-11-21" {
		t.Errorf("severity/date: %s %v", f.Severity, f.Date)
	}
	want := []model.AssetKey{
		key("10.20.0.5", 443, "tcp"),
		{Port: 8443, Proto: "tcp", VHost: "admin.lab.test"},
		key("10.20.0.6", 8080, "tcp"),
	}
	if !reflect.DeepEqual(f.Endpoints, want) {
		t.Errorf("endpoints %+v", f.Endpoints)
	}
	if _, err := NewCodec().Unmarshal([]byte(`{"findings":[{"title":"t","severity":"Info"}]}`)); err == nil {
		t.Error("missing description accepted")
	}
	if _, err := NewCodec().Unmarshal([]byte(`{"findings":[{"title":"t","severity":"Severe","description":"d"}]}`)); err == nil {
		t.Error("unknown severity accepted")
	}
}

func TestValidateExampleAndGolden(t *testing.T) {
	for _, name := range []string{"generic_findings.example.json", "golden_findings.json"} {
		b, err := os.ReadFile(filepath.Join(testdataDir, name))
		if err != nil {
			t.Fatal(err)
		}
		if err := Validate(b); err != nil {
			t.Errorf("%s: %v", name, err)
		}
	}
}

func TestValidateRejects(t *testing.T) {
	base := func() map[string]any {
		return map[string]any{
			"title": "t", "severity": "Info", "description": "d", "date": "2026-11-21",
			"unique_id_from_tool": "asi:svc:10.20.0.1:80/tcp",
			"endpoints":           []any{map[string]any{"host": "10.20.0.1", "port": 80, "protocol": "http"}},
			"tags":                []any{"asi"},
		}
	}
	enc := func(top map[string]any) []byte {
		b, _ := json.Marshal(top)
		return b
	}
	one := func(mut func(map[string]any)) []byte {
		f := base()
		mut(f)
		return enc(map[string]any{"findings": []any{f}})
	}
	if err := Validate(one(func(map[string]any) {})); err != nil {
		t.Fatalf("baseline rejected: %v", err)
	}
	cases := map[string][]byte{
		"extra finding key":   one(func(f map[string]any) { f["cvssv3"] = "AV:N" }),
		"unknown finding key": one(func(f map[string]any) { f["hostname"] = "x" }),
		"extra top-level key": enc(map[string]any{"findings": []any{base()}, "name": "asi"}),
		"duplicate ids":       enc(map[string]any{"findings": []any{base(), base()}}),
		"missing title":       one(func(f map[string]any) { delete(f, "title") }),
		"empty description":   one(func(f map[string]any) { f["description"] = " " }),
		"bad severity":        one(func(f map[string]any) { f["severity"] = "info" }),
		"bad date":            one(func(f map[string]any) { f["date"] = "21.11.2026" }),
		"missing unique id":   one(func(f map[string]any) { delete(f, "unique_id_from_tool") }),
		"endpoint extra key":  one(func(f map[string]any) { f["endpoints"] = []any{map[string]any{"host": "h", "ip": "1"}} }),
		"endpoint no host":    one(func(f map[string]any) { f["endpoints"] = []any{map[string]any{"port": 80}} }),
		"endpoint bad port":   one(func(f map[string]any) { f["endpoints"] = []any{map[string]any{"host": "h", "port": 70000}} }),
		"endpoint string":     one(func(f map[string]any) { f["endpoints"] = []any{"http://h/"} }),
		"tags not strings":    one(func(f map[string]any) { f["tags"] = []any{1} }),
		"title not string":    one(func(f map[string]any) { f["title"] = 5 }),
		"no findings key":     []byte(`{}`),
		"not json":            []byte(`{"findings":`),
		"trailing data":       append(one(func(map[string]any) {}), []byte(`{}`)...),
	}
	for name, b := range cases {
		if err := Validate(b); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	err := Validate(enc(map[string]any{"findings": []any{base(), base()}}))
	if err == nil || !strings.Contains(err.Error(), "duplicate unique_id_from_tool") {
		t.Errorf("duplicate error message: %v", err)
	}
}

func TestUniqueIDs(t *testing.T) {
	k := key("10.20.0.11", 443, "tcp")
	if got := UniqueServiceID(k); got != "asi:svc:10.20.0.11:443/tcp" {
		t.Error(got)
	}
	if got := UniqueSignatureID(k, "wordpress"); got != "asi:sig:10.20.0.11:443:wordpress" {
		t.Error(got)
	}
	k.VHost = "shop.lab.test"
	if got := UniqueServiceID(k); got != "asi:svc:10.20.0.11:443/tcp@shop.lab.test" {
		t.Error(got)
	}
	for uid, want := range map[string]string{
		"asi:svc:10.20.0.11:443/tcp":                "10.20.0.11:443",
		"asi:svc:10.20.0.11:443/tcp@shop.lab.test":  "10.20.0.11:443",
		"asi:sig:10.20.0.14:80:phpmyadmin":          "10.20.0.14:80",
		"asi:sig:10.20.0.14:80:phpmyadmin@a.b.test": "10.20.0.14:80",
		"asi:svc:2001:db8::1:53/udp":                "[2001:db8::1]:53",
	} {
		ip, port, ok := ParseUniqueID(uid)
		if !ok || netip.AddrPortFrom(ip, port).String() != want {
			t.Errorf("%s: %v %d %v", uid, ip, port, ok)
		}
	}
	if _, _, ok := ParseUniqueID("nessus:123"); ok {
		t.Error("foreign id parsed")
	}
}

func TestVHostEndpoint(t *testing.T) {
	k := key("10.20.0.11", 443, "tcp")
	k.VHost = "shop.lab.test"
	e := endpointFromKey(k)
	if e.Host != "shop.lab.test" || e.Port != 443 || e.Protocol != "https" {
		t.Errorf("%+v", e)
	}
	if got := endpointFromKey(key("10.20.0.1", 5432, "tcp")).Protocol; got != "tcp" {
		t.Error(got)
	}
}

// DefectDojo hashes Generic Findings by title+description by default, so a
// banner that changes between runs must not change the finding.
func TestDescriptionIgnoresBanner(t *testing.T) {
	k := model.AssetKey{IP: netip.MustParseAddr("10.20.0.25"), Port: 25, Proto: "tcp"}
	mk := func(banner string) model.Finding {
		s := Service{ServiceObs: model.ServiceObs{Key: k, Product: "Postfix smtpd", Banner: banner}}
		fs := BuildFindings(time.Date(2026, 11, 21, 9, 0, 0, 0, time.UTC), []Service{s}, nil)
		if len(fs) != 1 {
			t.Fatalf("got %d findings", len(fs))
		}
		return fs[0]
	}
	a := mk("220 mail ESMTP Postfix Sat, 21 Nov 2026 09:00:01 +0000")
	b := mk("220 mail ESMTP Postfix Sat, 21 Nov 2026 10:13:44 +0000")
	if a.Title != b.Title || a.Description != b.Description {
		t.Errorf("banner changed the finding:\n%s\n---\n%s", a.Description, b.Description)
	}
}

// A host-level annotation applies even when stored with a proto/vhost.
func TestHostAnnotationKeyNormalised(t *testing.T) {
	ip := netip.MustParseAddr("10.20.0.26")
	s := Service{ServiceObs: model.ServiceObs{Key: model.AssetKey{IP: ip, Port: 80, Proto: "tcp"}}}
	anns := []Annotation{{Key: model.AssetKey{IP: ip, Proto: "tcp"}, FalsePositive: true}}
	if fs := BuildFindings(time.Time{}, []Service{s}, anns); len(fs) != 0 {
		t.Errorf("host-level false positive ignored: %d findings", len(fs))
	}
}

func TestSignatureMetaExported(t *testing.T) {
	svcs, anns := fixture()
	fs := BuildFindings(runDate, svcs, anns)
	var got model.Finding
	for _, f := range fs {
		if f.VulnIDFromTool == "phpmyadmin" {
			got = f
		}
		if f.VulnIDFromTool == "staging-banner" && (f.CWE != 0 || f.Mitigation != "" || f.References != "") {
			t.Errorf("detection without meta got cwe/mitigation/references: %+v", f)
		}
	}
	if got.CWE != 668 || got.Mitigation != "Ogranicz phpMyAdmina do sieci administracyjnej." {
		t.Fatalf("cwe/mitigation not exported: %+v", got)
	}
	wantRefs := "https://docs.phpmyadmin.net/en/latest/setup.html#securing-your-phpmyadmin-installation\n" +
		"https://cwe.mitre.org/data/definitions/668.html\n" +
		"https://attack.mitre.org/techniques/T1078/\n" +
		"https://attack.mitre.org/techniques/T1190/"
	if got.References != wantRefs {
		t.Errorf("references = %q, want %q", got.References, wantRefs)
	}
	if got.UniqueIDFromTool != "asi:sig:10.20.0.14:80:phpmyadmin" {
		t.Errorf("unique_id_from_tool changed: %q", got.UniqueIDFromTool)
	}
	tags := strings.Join(got.Tags, ",")
	if !strings.Contains(tags, "attack-t1078") || !strings.Contains(tags, "attack-t1190") {
		t.Errorf("attack tags missing: %v", got.Tags)
	}
	// Round trip through the codec keeps the three fields.
	b, err := NewCodec().Marshal([]model.Finding{got})
	if err != nil {
		t.Fatal(err)
	}
	back, err := NewCodec().Unmarshal(b)
	if err != nil {
		t.Fatal(err)
	}
	if back[0].CWE != 668 || back[0].Mitigation != got.Mitigation || back[0].References != got.References {
		t.Errorf("round trip lost metadata: %+v", back[0])
	}
}

func TestValidateCWEType(t *testing.T) {
	ok := `{"findings":[{"title":"t","severity":"Info","description":"d","unique_id_from_tool":"u","cwe":306,"mitigation":"m","references":"https://a"}]}`
	if err := Validate([]byte(ok)); err != nil {
		t.Fatalf("valid cwe rejected: %v", err)
	}
	for _, bad := range []string{
		`{"findings":[{"title":"t","severity":"Info","description":"d","unique_id_from_tool":"u","cwe":"CWE-306"}]}`,
		`{"findings":[{"title":"t","severity":"Info","description":"d","unique_id_from_tool":"u","cwe":-1}]}`,
		`{"findings":[{"title":"t","severity":"Info","description":"d","unique_id_from_tool":"u","mitigation":5}]}`,
	} {
		if err := Validate([]byte(bad)); err == nil {
			t.Errorf("accepted %s", bad)
		}
	}
}
