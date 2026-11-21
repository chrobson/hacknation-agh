package export

import (
	"bytes"
	"encoding/csv"
	"encoding/json"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"os"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/go-chi/chi/v5"

	"github.com/chrobson/hacknation-agh/internal/dojo"
	"github.com/chrobson/hacknation-agh/internal/model"
	"github.com/chrobson/hacknation-agh/internal/store"
	"github.com/chrobson/hacknation-agh/internal/web"
)

func key(ip string, port uint16, proto string) model.AssetKey {
	return model.AssetKey{IP: netip.MustParseAddr(ip), Port: port, Proto: proto}
}

func snapshot() Snapshot {
	return Snapshot{
		RunID: 7, RunKind: "scan", Date: time.Date(2026, 11, 21, 18, 0, 0, 0, time.UTC),
		Services: []dojo.Service{
			{ServiceObs: model.ServiceObs{Key: key("10.20.0.14", 80, "tcp"), Product: "Apache httpd"},
				HTTP: &dojo.HTTPSummary{URL: "http://10.20.0.14/", Status: 200, Title: "=HYPERLINK(\"x\")"},
				Detections: []model.Detection{
					{SignatureID: "phpmyadmin", Name: "phpMyAdmin", Category: "admin-panel", Confidence: 100},
					{SignatureID: "apache", Name: "Apache", Category: "server", Confidence: 90},
				}},
			{ServiceObs: model.ServiceObs{Key: key("10.20.0.11", 22, "tcp"), Product: "OpenSSH", Version: "9.6p1"}, Hostname: "web.lab.test"},
		},
		Annotations: []dojo.Annotation{
			{Key: key("10.20.0.11", 22, "tcp"), Severity: "Low", Tags: []string{"ops"}, Comment: "stary"},
			{Key: model.AssetKey{IP: netip.MustParseAddr("10.20.0.11")}, Tags: []string{"dmz"}},
		},
	}
}

func TestWriteCSV(t *testing.T) {
	var buf bytes.Buffer
	if err := WriteCSV(&buf, snapshot()); err != nil {
		t.Fatal(err)
	}
	rows, err := csv.NewReader(&buf).ReadAll()
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(rows[0], CSVHeader) || len(rows) != 3 {
		t.Fatalf("rows: %v", rows)
	}
	col := func(row []string, name string) string {
		for i, h := range CSVHeader {
			if h == name {
				return row[i]
			}
		}
		t.Fatalf("no column %s", name)
		return ""
	}
	ssh, web := rows[1], rows[2] // sorted by IP
	if col(ssh, "ip") != "10.20.0.11" || col(ssh, "severity") != "Low" || col(ssh, "tags") != "dmz;ops" || col(ssh, "hostname") != "web.lab.test" {
		t.Errorf("ssh row %v", ssh)
	}
	if col(web, "detections") != "apache;phpmyadmin" || col(web, "categories") != "admin-panel;server" {
		t.Errorf("web row %v", web)
	}
	if got := col(web, "http_title"); !strings.HasPrefix(got, "'=") {
		t.Errorf("formula not neutralised: %q", got)
	}
}

func TestWriteJSON(t *testing.T) {
	var buf bytes.Buffer
	if err := WriteJSON(&buf, snapshot()); err != nil {
		t.Fatal(err)
	}
	var doc Document
	if err := json.Unmarshal(buf.Bytes(), &doc); err != nil {
		t.Fatal(err)
	}
	if doc.RunID != 7 || len(doc.Services) != 2 || doc.Services[1].IP != "10.20.0.14" {
		t.Fatalf("doc %+v", doc)
	}
	if len(doc.Services[1].Detections) != 2 || doc.Services[1].Detections[0].SignatureID != "apache" {
		t.Errorf("detections %+v", doc.Services[1].Detections)
	}
	if a := doc.Services[0].Annotation; a == nil || a.Severity != "Low" || a.FalsePositive {
		t.Errorf("annotation %+v", a)
	}
	if doc.Services[0].Detections == nil {
		t.Error("detections must be [] not null")
	}
}

func TestSnapshotDojoValid(t *testing.T) {
	b, err := snapshot().Dojo()
	if err != nil {
		t.Fatal(err)
	}
	if err := dojo.Validate(b); err != nil {
		t.Fatal(err)
	}
}

func TestParseNmapXML(t *testing.T) {
	b, err := os.ReadFile("../../testdata/dojo/nmap_sample.xml")
	if err != nil {
		t.Fatal(err)
	}
	f, obs, err := Parse(b)
	if err != nil || f != FormatNmapXML {
		t.Fatalf("parse: %v %v", f, err)
	}
	if len(obs.Hosts) != 3 || obs.Hosts[0].Hostname != "web.lab.test" || obs.Hosts[2].Up {
		t.Errorf("hosts %+v", obs.Hosts)
	}
	want := []model.ServiceObs{
		{Key: key("10.20.0.11", 22, "tcp"), Product: "OpenSSH", Version: "9.6p1", ExtraInfo: "protocol 2.0", CPE: "cpe:/a:openbsd:openssh:9.6p1"},
		{Key: key("10.20.0.11", 443, "tcp"), Product: "nginx", Version: "1.27.4", CPE: "cpe:/a:f5:nginx:1.27.4"},
		{Key: key("10.20.0.14", 80, "tcp"), Product: "http", Banner: "HTTP/1.1 200 OK"},
		{Key: key("10.20.0.14", 53, "udp"), Product: "dnsmasq", Version: "2.90"},
	}
	if !reflect.DeepEqual(obs.Services, want) {
		t.Errorf("services\ngot  %+v\nwant %+v", obs.Services, want)
	}
	if _, err := ParseNmapXML([]byte(`<nmaprun><host>`)); err == nil {
		t.Error("truncated XML accepted")
	}
}

// An ASI export imported back yields the same services and detections.
func TestGenericFindingsImportRoundTrip(t *testing.T) {
	b, err := os.ReadFile("../../testdata/dojo/golden_findings.json")
	if err != nil {
		t.Fatal(err)
	}
	f, obs, err := Parse(b)
	if err != nil || f != FormatGeneric {
		t.Fatalf("parse: %v %v", f, err)
	}
	if len(obs.Errors) != 0 {
		t.Errorf("errors: %v", obs.Errors)
	}
	svc := map[model.AssetKey]model.ServiceObs{}
	for _, s := range obs.Services {
		svc[s.Key] = s
	}
	if s := svc[key("10.20.0.11", 443, "tcp")]; s.Product != "nginx" || s.Version != "1.27.4" {
		t.Errorf("nginx service %+v", s)
	}
	if _, ok := svc[key("10.20.0.30", 53, "udp")]; !ok {
		t.Error("udp service lost")
	}
	if len(obs.Services) != 5 || len(obs.Hosts) != 4 {
		t.Errorf("services %d hosts %d", len(obs.Services), len(obs.Hosts))
	}
	dets := map[string]ImportedDetection{}
	for _, d := range obs.Detections {
		dets[d.SignatureID] = d
	}
	if d := dets["phpmyadmin"]; d.Category != "admin-panel" || d.Name != "phpMyAdmin" || d.Key != key("10.20.0.14", 80, "tcp") {
		t.Errorf("phpmyadmin %+v", d)
	}
	if d := dets["wordpress"]; d.Category != "cms" || d.Name != "WordPress" {
		t.Errorf("wordpress %+v", d)
	}
}

func TestFromFindingsVHostAndForeign(t *testing.T) {
	fs := []model.Finding{
		{Title: "Open service 443/tcp", Severity: model.SevInfo, Description: "d", UniqueIDFromTool: "asi:svc:10.20.0.11:443/tcp@shop.lab.test",
			Endpoints: []model.AssetKey{{Port: 443, Proto: "tcp", VHost: "shop.lab.test"}}},
		{Title: "XSS", Severity: model.SevHigh, Description: "d", UniqueIDFromTool: "zap-1",
			Endpoints: []model.AssetKey{{Port: 443, Proto: "tcp", VHost: "example.test"}}},
		{Title: "no endpoints", Severity: model.SevInfo, Description: "d"},
	}
	obs := FromFindings(fs)
	if len(obs.Services) != 1 || obs.Services[0].Key != (model.AssetKey{IP: netip.MustParseAddr("10.20.0.11"), Port: 443, Proto: "tcp", VHost: "shop.lab.test"}) {
		t.Errorf("services %+v", obs.Services)
	}
	if len(obs.Errors) != 2 {
		t.Errorf("errors %v", obs.Errors)
	}
}

func TestDetectFormat(t *testing.T) {
	for in, want := range map[string]Format{
		"<?xml version=\"1.0\"?>\n<nmaprun>": FormatNmapXML,
		"\xef\xbb\xbf  {\"findings\": []}":   FormatGeneric,
		"value,tags\n10.0.0.1,a":             FormatUnknown,
		"<html></html>":                      FormatUnknown,
	} {
		if got := DetectFormat([]byte(in)); got != want {
			t.Errorf("%q: %q want %q", in, got, want)
		}
	}
}

func passThrough(string) func(http.Handler) http.Handler {
	return func(h http.Handler) http.Handler { return h }
}

func newRouter(t *testing.T) http.Handler {
	t.Helper()
	old := BaseTemplates
	BaseTemplates = os.DirFS("../../web/templates")
	t.Cleanup(func() { BaseTemplates = old })
	r := chi.NewRouter()
	Mount(r, web.Deps{})
	return r
}

func TestRoutesFailClosedWithoutAuth(t *testing.T) {
	r := newRouter(t)
	for _, p := range []string{"/export", "/export/services.csv", "/export/defectdojo.json", "/import"} {
		rec := httptest.NewRecorder()
		r.ServeHTTP(rec, httptest.NewRequest("GET", p, nil))
		if rec.Code != http.StatusForbidden {
			t.Errorf("%s: %d", p, rec.Code)
		}
	}
}

func multipartBody(t *testing.T, field string, content []byte) (*bytes.Buffer, string) {
	var buf bytes.Buffer
	mw := multipart.NewWriter(&buf)
	fw, err := mw.CreateFormFile(field, "scan.xml")
	if err != nil {
		t.Fatal(err)
	}
	_, _ = fw.Write(content)
	_ = mw.Close()
	return &buf, mw.FormDataContentType()
}

func TestImportPage(t *testing.T) {
	old := RequirePerm
	RequirePerm = passThrough
	t.Cleanup(func() { RequirePerm = old })
	r := newRouter(t)

	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, httptest.NewRequest("GET", "/import", nil))
	if rec.Code != 200 || !strings.Contains(rec.Body.String(), "Import wyników") || !strings.Contains(rec.Body.String(), `enctype="multipart/form-data"`) {
		t.Fatalf("GET /import: %d\n%s", rec.Code, rec.Body)
	}

	// Unknown format is rejected before any DB access.
	body, ctype := multipartBody(t, "file", []byte("value,tags\n10.20.0.1,x\n"))
	req := httptest.NewRequest("POST", "/import", body)
	req.Header.Set("Content-Type", ctype)
	rec = httptest.NewRecorder()
	r.ServeHTTP(rec, req)
	if rec.Code != http.StatusBadRequest || !strings.Contains(rec.Body.String(), "unknown import format") {
		t.Errorf("POST bad format: %d\n%s", rec.Code, rec.Body)
	}

	// Missing file field.
	body, ctype = multipartBody(t, "other", []byte("x"))
	req = httptest.NewRequest("POST", "/import", body)
	req.Header.Set("Content-Type", ctype)
	rec = httptest.NewRecorder()
	r.ServeHTTP(rec, req)
	if rec.Code != http.StatusBadRequest || !strings.Contains(rec.Body.String(), "brak pliku") {
		t.Errorf("POST no file: %d\n%s", rec.Code, rec.Body)
	}
}

func TestFallbackBaseMatchesShared(t *testing.T) {
	b, err := os.ReadFile("../../web/templates/base.html")
	if err != nil {
		t.Fatal(err)
	}
	if strings.TrimSpace(string(b)) != strings.TrimSpace(fallbackBase) {
		t.Error("fallbackBase drifted from web/templates/base.html")
	}
	if _, err := parsePages(nil); err != nil {
		t.Fatal(err)
	}
}

func TestReadUploadLimit(t *testing.T) {
	body, ctype := multipartBody(t, "file", bytes.Repeat([]byte("a"), 2048))
	req := httptest.NewRequest("POST", "/import", body)
	req.Header.Set("Content-Type", ctype)
	if _, err := readUpload(httptest.NewRecorder(), req, "file", 1024); err == nil || !strings.Contains(err.Error(), "większy") {
		t.Errorf("limit not enforced: %v", err)
	}
	body, ctype = multipartBody(t, "file", []byte("<nmaprun/>"))
	req = httptest.NewRequest("POST", "/import", body)
	req.Header.Set("Content-Type", ctype)
	b, err := readUpload(httptest.NewRecorder(), req, "file", 1024)
	if err != nil || string(b) != "<nmaprun/>" {
		t.Errorf("read: %q %v", b, err)
	}
}

func TestRenderIndex(t *testing.T) {
	h, err := newHandler(web.Deps{})
	if err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, 11, 21, 18, 0, 0, 0, time.UTC)
	run := int64(7)
	test := int64(42)
	data := indexData{
		Run:      &store.ExportRun{ID: 7, Kind: "import", FinishedAt: &now},
		Services: 3, Findings: 5, PushOn: true, DojoURL: "http://localhost:8081",
		Pushes:  []store.DojoPush{{PushedAt: now, RunID: &run, Endpoint: "reimport-scan", Findings: 5, TestID: &test, OK: true}},
		Message: "Wysłano",
	}
	rec := httptest.NewRecorder()
	h.render(rec, "index", data)
	body := rec.Body.String()
	for _, want := range []string{"Pobierz CSV", "/export/defectdojo.json?run=7", "Wyślij do DefectDojo", "reimport-scan", "#42", "2026-11-21 18:00 UTC", "(import)"} {
		if !strings.Contains(body, want) {
			t.Errorf("index page lacks %q", want)
		}
	}
	rec = httptest.NewRecorder()
	h.render(rec, "index", indexData{})
	if !strings.Contains(rec.Body.String(), "Brak zakończonego przebiegu") {
		t.Error("empty state missing")
	}
}
