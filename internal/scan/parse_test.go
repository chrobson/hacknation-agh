package scan

import (
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/chrobson/hacknation-agh/internal/model"
)

func parseFixture(t *testing.T, name string) Result {
	t.Helper()
	f, err := os.Open(filepath.Join("testdata", name))
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	res, err := Parse(f)
	if err != nil {
		t.Fatalf("Parse(%s): %v", name, err)
	}
	return res
}

func findSvc(res Result, ip string, port uint16) (model.ServiceObs, bool) {
	a := netip.MustParseAddr(ip)
	for _, s := range res.Services {
		if s.Key.IP == a && s.Key.Port == port {
			return s, true
		}
	}
	return model.ServiceObs{}, false
}

// Counts come from the <hosts up=...> summary (discovery) and the <host>
// and "open" port elements of the recorded lab scans (agh-lab
// testdata/nmap). With --open nmap omits hosts without open ports from
// <host> elements, so service runs list fewer hosts than the summary.
func TestParseLabFixtures(t *testing.T) {
	cases := []struct {
		file     string
		up, svcs int
	}{
		{"run1_discovery.xml", 33, 0},
		{"run2_discovery.xml", 32, 0},
		{"run1_services.xml", 27, 31},
		{"run2_services.xml", 27, 31},
	}
	for _, c := range cases {
		t.Run(c.file, func(t *testing.T) {
			res := parseFixture(t, c.file)
			if got := len(res.UpHosts()); got != c.up {
				t.Errorf("up hosts = %d, want %d", got, c.up)
			}
			if got := len(res.Services); got != c.svcs {
				t.Errorf("services = %d, want %d", got, c.svcs)
			}
			for _, s := range res.Services {
				if s.Key.Proto != "tcp" || s.Key.Port == 0 || !s.Key.IP.Is4() || s.Key.VHost != "" {
					t.Errorf("bad key %+v", s.Key)
				}
			}
		})
	}
}

func TestParseLabServiceDetails(t *testing.T) {
	res := parseFixture(t, "run1_services.xml")
	s, ok := findSvc(res, "10.20.0.11", 443)
	if !ok {
		t.Fatal("10.20.0.11:443 missing")
	}
	if s.Product != "nginx" || s.Version != "1.27.3" || s.Banner != "ssl/http" || s.CPE != "cpe:/a:igor_sysoev:nginx:1.27.3" {
		t.Errorf("unexpected 10.20.0.11:443 %+v", s)
	}
	s, ok = findSvc(res, "10.20.0.10", 80)
	if !ok || s.Banner != "http" || s.Product != "nginx" {
		t.Errorf("unexpected 10.20.0.10:80 %+v (ok=%v)", s, ok)
	}
	// Results are sorted by natural key.
	for i := 1; i < len(res.Services); i++ {
		if keyLess(res.Services[i].Key, res.Services[i-1].Key) {
			t.Fatalf("services not sorted at %d", i)
		}
	}
}

func TestParseEdgeCases(t *testing.T) {
	res := parseFixture(t, "edge_services.xml")
	if len(res.Hosts) != 3 {
		t.Fatalf("hosts = %d, want 3 (down host included)", len(res.Hosts))
	}
	h := res.Hosts[0]
	if h.IP != netip.MustParseAddr("192.0.2.10") || !h.Up || h.Hostname != "www.example.test" {
		t.Errorf("host[0] = %+v", h)
	}
	if d := res.Hosts[1]; d.Up || d.Hostname != "down.example.test" {
		t.Errorf("down host = %+v", d)
	}
	if up := res.UpHosts(); len(up) != 2 {
		t.Errorf("UpHosts = %v", up)
	}
	// open only: 22, 443, 9999 tcp, 161 udp on .10; 80 on .12. Not filtered 8080, not open|filtered 53.
	want := "192.0.2.10:22/tcp 192.0.2.10:161/udp 192.0.2.10:443/tcp 192.0.2.10:9999/tcp 192.0.2.12:80/tcp"
	var got []string
	for _, s := range res.Services {
		got = append(got, netip.AddrPortFrom(s.Key.IP, s.Key.Port).String()+"/"+s.Key.Proto)
	}
	if g := strings.Join(got, " "); g != want {
		t.Fatalf("services = %q, want %q", g, want)
	}
	ssh, _ := findSvc(res, "192.0.2.10", 22)
	if ssh.Version != "9.6p1 Ubuntu 3ubuntu13.5" || ssh.ExtraInfo != "Ubuntu Linux; protocol 2.0" || ssh.CPE != "cpe:/a:openbsd:openssh:9.6p1" {
		t.Errorf("ssh = %+v", ssh)
	}
	bare, _ := findSvc(res, "192.0.2.10", 9999)
	if bare.Banner != "" || bare.Product != "" {
		t.Errorf("port without <service> = %+v", bare)
	}
}

func TestParseErrors(t *testing.T) {
	data, err := os.ReadFile(filepath.Join("testdata", "run1_services.xml"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Parse(strings.NewReader(string(data[:len(data)/2]))); err == nil {
		t.Error("truncated XML: want error")
	}
	if _, err := Parse(strings.NewReader("")); err == nil {
		t.Error("empty input: want error")
	}
	failed := `<?xml version="1.0"?><nmaprun><runstats><finished exit="error" errormsg="Failed to open device"/></runstats></nmaprun>`
	if _, err := Parse(strings.NewReader(failed)); err == nil || !strings.Contains(err.Error(), "Failed to open device") {
		t.Errorf("nmap error run: err = %v", err)
	}
}
