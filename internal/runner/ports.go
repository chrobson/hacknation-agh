package runner

import (
	"fmt"
	"net/netip"
	"slices"

	"github.com/chrobson/hacknation-agh/internal/config"
	"github.com/chrobson/hacknation-agh/internal/store"
)

// Port profiles of a scan configuration (scan_configs.port_profile).
const (
	ProfileAuto = "auto" // all when the targets are small (AllPortsMaxAddrs), else top
	ProfileTop  = "top"  // --top-ports N plus the extra pass
	ProfileList = "list" // explicit list (-p)
	ProfileAll  = "all"  // every TCP port (-p-)
)

// Profiles lists the valid port profiles in UI order.
var Profiles = []string{ProfileAuto, ProfileTop, ProfileList, ProfileAll}

// AllPorts is every TCP port, 1-65535 (nmap -p-).
var AllPorts = func() []int {
	out := make([]int, 65535)
	for i := range out {
		out[i] = i + 1
	}
	return out
}()

// PortPlan is the phase 2 port selection of one run.
type PortPlan struct {
	Profile string // effective profile: top, list or all (never auto)
	Ports   []int  // explicit -p list; nil = --top-ports
	Extra   []int  // second pass after --top-ports (top only)
}

// ProfileOf returns the stored profile of cfg, defaulting an empty value
// (rows written before migration 0800) to list when it has a port list.
func ProfileOf(cfg store.ScanConfig) string {
	switch {
	case cfg.PortProfile != "":
		return cfg.PortProfile
	case cfg.Ports != "":
		return ProfileList
	default:
		return ProfileAuto
	}
}

// CountAddrs returns the number of addresses covered by the chunks
// (saturating at 1<<62).
func CountAddrs(chunks []netip.Prefix) uint64 {
	var n uint64
	for _, p := range chunks {
		host := p.Addr().BitLen() - p.Bits()
		if host >= 62 || n >= 1<<62 {
			return 1 << 62
		}
		n += 1 << host
	}
	return min(n, 1<<62)
}

// ResolvePorts picks the phase 2 ports of a run of cfg whose targets total
// addrs addresses. allPortsMax is config.AllPortsMaxAddrs (auto profile),
// allowed is ASI_SCAN_PORTS (nil = no restriction) and defaultExtra the
// built-in extra pass (scan.DefaultExtraPorts). A scan never widens past
// allowed: with a restriction, top and all scan exactly the allowed ports.
func ResolvePorts(cfg store.ScanConfig, addrs uint64, allPortsMax int, allowed, defaultExtra []int) (PortPlan, error) {
	profile := ProfileOf(cfg)
	if profile == ProfileAuto {
		profile = ProfileTop
		if allPortsMax > 0 && addrs > 0 && addrs <= uint64(allPortsMax) {
			profile = ProfileAll
		}
	}
	switch profile {
	case ProfileList:
		ports, err := EffectivePorts(cfg.Ports, allowed)
		if err != nil {
			return PortPlan{}, err
		}
		if len(ports) == 0 {
			return PortPlan{}, fmt.Errorf("profil %q wymaga listy portów", ProfileList)
		}
		return PortPlan{Profile: profile, Ports: ports}, nil
	case ProfileAll:
		if len(allowed) > 0 {
			return PortPlan{Profile: profile, Ports: allowed}, nil
		}
		return PortPlan{Profile: profile, Ports: AllPorts}, nil
	case ProfileTop:
		if len(allowed) > 0 {
			return PortPlan{Profile: profile, Ports: allowed}, nil
		}
		own, err := config.ParsePorts(cfg.ExtraPortList)
		if err != nil {
			return PortPlan{}, fmt.Errorf("dodatkowe porty: %w", err)
		}
		var extra []int
		if cfg.ExtraPorts {
			extra = append(extra, defaultExtra...)
		}
		extra = append(extra, own...)
		slices.Sort(extra)
		return PortPlan{Profile: profile, Extra: slices.Compact(extra)}, nil
	default:
		return PortPlan{}, fmt.Errorf("nieznany profil portów %q", profile)
	}
}
