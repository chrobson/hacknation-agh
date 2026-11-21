package interest

import (
	"reflect"
	"strings"
	"testing"
)

func hasReason(r Result, label string, pts int) bool {
	for _, x := range r.Reasons {
		if strings.HasPrefix(x.Label, label) && x.Points == pts {
			return true
		}
	}
	return false
}

func TestRules(t *testing.T) {
	cases := []struct {
		name   string
		in     Input
		score  int
		reason string
		points int
	}{
		{"nothing", Input{Port: 80, Service: "http"}, 0, "", 0},
		{"critical full confidence", Input{Detections: []Detection{{Name: "X", Severity: "Critical", Confidence: 100}}}, 60, "detekcja X: poziom Critical", 60},
		{"high weighted by confidence", Input{Detections: []Detection{{Name: "X", Severity: "High", Confidence: 80}}}, 36, "detekcja X: poziom High", 36},
		{"medium", Input{Detections: []Detection{{Name: "X", Severity: "Medium", Confidence: 100}}}, 25, "detekcja X", 25},
		{"low", Input{Detections: []Detection{{Name: "X", Severity: "Low", Confidence: 100}}}, 10, "detekcja X", 10},
		{"info gives nothing", Input{Detections: []Detection{{Name: "X", Severity: "Info", Confidence: 100}}}, 0, "", 0},
		{"highest detection only", Input{Detections: []Detection{
			{Name: "A", Severity: "Low", Confidence: 100}, {Name: "B", Severity: "High", Confidence: 100}}}, 45, "detekcja B", 45},
		{"admin panel category", Input{Detections: []Detection{{Name: "P", Category: "admin-panel", Severity: "Info", Confidence: 90}}}, 20, "panel administracyjny", 20},
		{"category counted once", Input{Detections: []Detection{
			{Name: "P1", Category: "admin-panel", Severity: "Info"}, {Name: "P2", Category: "admin-panel", Severity: "Info"}}}, 20, "panel administracyjny", 20},
		{"staging", Input{Detections: []Detection{{Category: "staging", Severity: "Info"}}}, 15, "środowisko testowe", 15},
		{"iot", Input{Detections: []Detection{{Category: "iot", Severity: "Info"}}}, 15, "urządzenie IoT", 15},
		{"cms", Input{Detections: []Detection{{Category: "cms", Severity: "Info"}}}, 5, "CMS", 5},
		{"outdated", Input{Detections: []Detection{{Severity: "Info", Outdated: "version 4.7 < 6.0"}}}, 15, "nieaktualna wersja (version 4.7 < 6.0)", 15},
		{"telnet", Input{Port: 23, Service: "telnet"}, 30, "telnet (bez szyfrowania)", 30},
		{"docker api by port", Input{Port: 2375, Service: "http"}, 40, "API Dockera", 40},
		{"database by port", Input{Port: 3306}, 20, "baza danych lub cache", 20},
		{"postgres on non-standard port by name", Input{Port: 15432, Service: "postgresql"}, 20, "baza danych lub cache", 20},
		{"redis by name", Input{Port: 16379, Service: "redis"}, 20, "baza danych lub cache", 20},
		{"rdp", Input{Port: 3389, Service: "ms-wbt-server"}, 20, "zdalny pulpit", 20},
		{"vnc", Input{Port: 5901, Service: "vnc"}, 20, "zdalny pulpit", 20},
		{"ftp", Input{Port: 21, Service: "ftp"}, 15, "FTP", 15},
		{"amqp", Input{Port: 5672, Service: "amqp"}, 10, "broker wiadomości", 10},
		{"tls expired", Input{TLSExpired: true}, 10, "wygasły certyfikat", 10},
		{"tls self-signed", Input{TLSSelfSigned: true}, 5, "samopodpisany", 5},
		{"login page over http", Input{Scheme: "http", Detections: []Detection{{Signature: "login-page", Category: "other", Severity: "Info"}}}, 10, "logowanie bez TLS", 10},
		{"login page over https", Input{Scheme: "https", Detections: []Detection{{Signature: "login-page", Category: "other", Severity: "Info"}}}, 0, "", 0},
		{"admin panel over http", Input{Scheme: "http", Detections: []Detection{{Category: "admin-panel", Severity: "Info"}}}, 30, "logowanie bez TLS", 10},
		{"new service", Input{ChangeKinds: []string{"new"}}, 15, "nowa usługa", 15},
		{"changed service", Input{ChangeKinds: []string{"changed"}}, 5, "zmieniona usługa", 5},
		{"unstable change", Input{ChangeKinds: []string{"unstable"}}, 5, "niestabilny host", 5},
		{"unstable host once", Input{ChangeKinds: []string{"unstable"}, HostUnstable: true}, 5, "niestabilny host", 5},
		{"analyst floor", Input{Port: 80, Service: "http", AnalystSeverity: "High"}, 70, "poziom ustawiony przez analityka", 70},
		{"analyst floor tops up", Input{TLSExpired: true, AnalystSeverity: "Medium"}, 40, "poziom ustawiony przez analityka", 30},
		{"analyst floor below score", Input{Port: 23, Service: "telnet", AnalystSeverity: "Low"}, 30, "telnet", 30},
		{"analyst critical", Input{AnalystSeverity: "Critical"}, 90, "poziom ustawiony przez analityka", 90},
		{"analyst info caps", Input{Port: 23, Service: "telnet", AnalystSeverity: "Info"}, 10, "telnet", 30},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			r := Score(c.in)
			if r.Score != c.score {
				t.Fatalf("score = %d, want %d (%+v)", r.Score, c.score, r.Reasons)
			}
			if c.reason != "" && !hasReason(r, c.reason, c.points) {
				t.Fatalf("reason %q +%d missing: %+v", c.reason, c.points, r.Reasons)
			}
			if c.reason == "" && len(r.Reasons) != 0 {
				t.Fatalf("unexpected reasons %+v", r.Reasons)
			}
		})
	}
}

func TestOnlyHighestServiceClass(t *testing.T) {
	// named redis on the docker port: the name wins, one class only
	r := Score(Input{Port: 2375, Service: "redis"})
	if r.Score != 20 || len(r.Reasons) != 1 {
		t.Fatalf("got %+v", r)
	}
}

func TestCap(t *testing.T) {
	r := Score(Input{Port: 2375, Service: "docker", Scheme: "http", TLSExpired: true,
		Detections:  []Detection{{Name: "X", Category: "admin-panel", Severity: "Critical", Confidence: 100, Outdated: "old"}},
		ChangeKinds: []string{"new"}})
	if r.Score != 100 || r.Level != "wysoki" {
		t.Fatalf("got %d %s", r.Score, r.Level)
	}
}

func TestFalsePositive(t *testing.T) {
	r := Score(Input{Port: 2375, Service: "docker", AnalystSeverity: "Critical", FalsePositive: true,
		Detections: []Detection{{Name: "X", Severity: "Critical", Confidence: 100}}})
	if r.Score != 0 || r.Level != "brak" || len(r.Reasons) != 1 || r.Reasons[0].Label != "oznaczone jako fałszywy alarm" {
		t.Fatalf("got %+v", r)
	}
}

func TestLevels(t *testing.T) {
	for score, want := range map[int]string{0: "brak", 1: "niski", 29: "niski", 30: "średni", 59: "średni", 60: "wysoki", 100: "wysoki"} {
		if got := level(score); got != want {
			t.Errorf("level(%d) = %s, want %s", score, got, want)
		}
	}
}

func TestReasonOrderStable(t *testing.T) {
	in := Input{Port: 21, Service: "ftp", TLSSelfSigned: true, ChangeKinds: []string{"changed", "new"}, HostUnstable: true,
		Detections: []Detection{{Name: "W", Category: "cms", Severity: "High", Confidence: 100, Outdated: "v1 < v2"}}}
	first := Score(in)
	for i := 0; i < 20; i++ {
		if got := Score(in); !reflect.DeepEqual(got, first) {
			t.Fatalf("unstable result: %+v vs %+v", got, first)
		}
	}
	for i := 1; i < len(first.Reasons); i++ {
		if first.Reasons[i].Points > first.Reasons[i-1].Points {
			t.Fatalf("not sorted: %+v", first.Reasons)
		}
	}
	// equal points keep rule order: outdated (c) before ftp (d) before new (f)
	var order []string
	for _, r := range first.Reasons {
		if r.Points == 15 {
			order = append(order, r.Label)
		}
	}
	want := []string{"nieaktualna wersja (v1 < v2)", "FTP", "nowa usługa w tym przebiegu"}
	if !reflect.DeepEqual(order, want) {
		t.Fatalf("tie order = %v, want %v", order, want)
	}
}

func TestRanking(t *testing.T) {
	wordpress := Score(Input{Port: 80, Service: "http", Scheme: "http", Detections: []Detection{
		{Signature: "wordpress", Name: "WordPress", Category: "cms", Severity: "High", Confidence: 90, Outdated: "version 4.7 < 6.0"},
		{Signature: "wp-admin", Name: "WordPress admin", Category: "admin-panel", Severity: "Medium", Confidence: 80}}})
	redis := Score(Input{Port: 6379, Service: "redis", Detections: []Detection{
		{Signature: "redis-noauth", Name: "Redis bez uwierzytelniania", Category: "other", Severity: "High", Confidence: 60}}})
	nginx := Score(Input{Port: 80, Service: "http", Scheme: "http", Detections: []Detection{
		{Signature: "nginx", Name: "nginx", Category: "server", Severity: "Info", Confidence: 85}}})
	if !(wordpress.Score > redis.Score && redis.Score > nginx.Score) {
		t.Fatalf("ranking: wordpress %d, redis %d, nginx %d", wordpress.Score, redis.Score, nginx.Score)
	}
	if nginx.Level != "brak" {
		t.Errorf("plain nginx level = %s", nginx.Level)
	}
}

func TestLabels(t *testing.T) {
	r := Result{Reasons: []Reason{{"a", 20}, {"b", 0}}}
	if got := r.Labels(); got != "a (+20); b" {
		t.Fatalf("Labels = %q", got)
	}
	if len(r.Top(1)) != 1 || len(r.Top(5)) != 2 {
		t.Fatal("Top")
	}
}
