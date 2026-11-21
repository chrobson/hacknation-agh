package scan

import (
	"context"
	"net/netip"
	"slices"
	"strings"
	"testing"

	"github.com/chrobson/hacknation-agh/internal/target"
)

const deepLightXML = `<?xml version="1.0"?><nmaprun><host><status state="up"/><address addr="127.0.0.1" addrtype="ipv4"/><ports>
<port protocol="tcp" portid="8787"><state state="open"/><service name="http" product="nginx" version="1.31.9"/></port>
<port protocol="tcp" portid="15432"><state state="open"/><service name="unknown"/></port>
<port protocol="tcp" portid="50000"><state state="open"/><service name="unknown"/></port>
</ports></host></nmaprun>`

const deepXML = `<?xml version="1.0"?><nmaprun><host><status state="up"/><address addr="127.0.0.1" addrtype="ipv4"/><ports>
<port protocol="tcp" portid="15432"><state state="open"/><service name="postgresql" product="PostgreSQL DB"/></port>
<port protocol="tcp" portid="50000"><state state="open"/><service name="unknown"/></port>
</ports></host></nmaprun>`

type scriptedExec struct {
	calls [][]string
	outs  []string
}

func (s *scriptedExec) run(_ context.Context, _ string, args []string) ([]byte, error) {
	s.calls = append(s.calls, args)
	out := s.outs[min(len(s.calls)-1, len(s.outs)-1)]
	return []byte(out), nil
}

func TestDeepUnknownPass(t *testing.T) {
	allow := target.NewAllowlist([]netip.Prefix{netip.MustParsePrefix("127.0.0.0/8")})
	host := []netip.Addr{netip.MustParseAddr("127.0.0.1")}

	fe := &scriptedExec{outs: []string{deepLightXML, deepXML}}
	n := NewNmap("nmap", allow)
	n.Exec = fe.run
	svcs, err := n.Services(context.Background(), host, Opts{Ports: allPortsForTest(), DeepUnknown: true})
	if err != nil {
		t.Fatal(err)
	}
	if len(fe.calls) != 2 {
		t.Fatalf("calls = %d, want light + deep", len(fe.calls))
	}
	deep := strings.Join(fe.calls[1], " ")
	if !strings.Contains(deep, "-p 15432,50000 -sV --version-intensity 4 --open") {
		t.Errorf("deep args: %s", deep)
	}
	got := map[uint16]string{}
	for _, s := range svcs {
		got[s.Key.Port] = s.Product + "|" + s.Banner
	}
	if got[15432] != "PostgreSQL DB|postgresql" || got[8787] != "nginx|http" || got[50000] != "|unknown" || len(got) != 3 {
		t.Errorf("services: %v", got)
	}

	// Without DeepUnknown (large targets) there is no extra pass.
	fe = &scriptedExec{outs: []string{deepLightXML}}
	n.Exec = fe.run
	if _, err := n.Services(context.Background(), host, Opts{Ports: allPortsForTest()}); err != nil {
		t.Fatal(err)
	}
	if len(fe.calls) != 1 || slices.Contains(fe.calls[0], "--version-intensity") {
		t.Errorf("calls without DeepUnknown: %v", fe.calls)
	}
}

// allPortsForTest is 1-65535.
func allPortsForTest() []int {
	ps := make([]int, 65535)
	for i := range ps {
		ps[i] = i + 1
	}
	return ps
}
