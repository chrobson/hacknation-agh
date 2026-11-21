package diff

import (
	"net/netip"
	"testing"

	"github.com/chrobson/hacknation-agh/internal/model"
)

func TestCollapseGateway(t *testing.T) {
	ip := netip.MustParseAddr("127.0.0.1")
	key := func(p uint16) model.AssetKey { return model.AssetKey{IP: ip, Port: p, Proto: "tcp"} }
	prev := []model.ServiceObs{
		{ID: 1, Key: key(8085), Product: "Apache httpd", Version: "2.4.71", Banner: "http"},
		{ID: 2, Key: key(8888), Product: "nginx", Version: "1.27"},
	}
	curr := []model.ServiceObs{
		{ID: 11, Key: key(8085), Product: "Golang net/http server", Banner: "ssl/http"},
		{ID: 12, Key: key(8888), Product: "nginx", Version: "1.29"},
	}
	ch := CompareServices(prev, curr)
	status := map[int64]int{1: 302, 11: 502, 2: 200, 12: 200}
	got := CollapseGateway(prev, curr, status, ch)
	var gw, fp8085, ver8888 int
	for _, c := range got {
		switch {
		case c.Key.Port == 8085 && c.Field == GatewayField:
			gw++
			if c.Old != "302" || c.New != "502" {
				t.Errorf("gateway row %+v", c)
			}
		case c.Key.Port == 8085:
			fp8085++
		case c.Key.Port == 8888 && c.Field == "version":
			ver8888++
		}
	}
	if gw != 1 || fp8085 != 0 {
		t.Errorf("8085: gateway rows %d, fingerprint rows %d; want 1, 0: %+v", gw, fp8085, got)
	}
	if ver8888 != 1 {
		t.Errorf("8888: a real version change (no gateway error) must stay: %+v", got)
	}

	// Recovery (502 -> 302) collapses the same way.
	back := CollapseGateway(curr, prev, map[int64]int{1: 302, 11: 502, 2: 200, 12: 200}, CompareServices(curr, prev))
	for _, c := range back {
		if c.Key.Port == 8085 && c.Field != GatewayField {
			t.Errorf("recovery kept fingerprint row %+v", c)
		}
	}

	// No HTTP status: untouched.
	if n := len(CollapseGateway(prev, curr, nil, CompareServices(prev, curr))); n != len(ch) {
		t.Errorf("without status: %d rows, want %d", n, len(ch))
	}
}
