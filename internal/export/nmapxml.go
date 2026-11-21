package export

import (
	"bytes"
	"encoding/xml"
	"fmt"
	"net/netip"
	"strconv"
	"strings"

	"github.com/chrobson/hacknation-agh/internal/model"
)

// TODO(W1-2): dedupe with the scan module's nmap XML parser once it lands
// on main; this minimal parser only covers what an import needs.

type nmapRun struct {
	XMLName xml.Name   `xml:"nmaprun"`
	Hosts   []nmapHost `xml:"host"`
}

type nmapHost struct {
	Status struct {
		State string `xml:"state,attr"`
	} `xml:"status"`
	Addresses []struct {
		Addr     string `xml:"addr,attr"`
		AddrType string `xml:"addrtype,attr"`
	} `xml:"address"`
	Hostnames []struct {
		Name string `xml:"name,attr"`
		Type string `xml:"type,attr"`
	} `xml:"hostnames>hostname"`
	Ports []nmapPort `xml:"ports>port"`
}

type nmapPort struct {
	Protocol string `xml:"protocol,attr"`
	PortID   string `xml:"portid,attr"`
	State    struct {
		State string `xml:"state,attr"`
	} `xml:"state"`
	Service struct {
		Name      string   `xml:"name,attr"`
		Product   string   `xml:"product,attr"`
		Version   string   `xml:"version,attr"`
		ExtraInfo string   `xml:"extrainfo,attr"`
		Tunnel    string   `xml:"tunnel,attr"`
		CPE       []string `xml:"cpe"`
	} `xml:"service"`
	Scripts []struct {
		ID     string `xml:"id,attr"`
		Output string `xml:"output,attr"`
	} `xml:"script"`
}

// Observations is the parsed content of an import file.
type Observations struct {
	Hosts      []model.HostObs
	Services   []model.ServiceObs
	Detections []ImportedDetection
	Errors     []string
}

// ImportedDetection is a detection attached to a service by asset key.
type ImportedDetection struct {
	Key model.AssetKey
	model.Detection
}

// ParseNmapXML parses nmap -oX output: every host with its up/down state and
// every open port with product/version/extrainfo/CPE (and the banner script
// output when present). encoding/xml never resolves external entities.
func ParseNmapXML(b []byte) (Observations, error) {
	var run nmapRun
	dec := xml.NewDecoder(bytes.NewReader(b))
	if err := dec.Decode(&run); err != nil {
		return Observations{}, fmt.Errorf("parse nmap XML: %w", err)
	}
	var obs Observations
	for hi, h := range run.Hosts {
		var ip netip.Addr
		for _, a := range h.Addresses {
			if a.AddrType == "ipv4" || a.AddrType == "ipv6" {
				if p, err := netip.ParseAddr(a.Addr); err == nil {
					ip = p.Unmap()
					break
				}
			}
		}
		if !ip.IsValid() {
			obs.Errors = append(obs.Errors, fmt.Sprintf("host %d: no IP address", hi))
			continue
		}
		hostname := ""
		for _, hn := range h.Hostnames {
			if hostname == "" || hn.Type == "user" {
				hostname = hn.Name
			}
		}
		up := h.Status.State == "up"
		obs.Hosts = append(obs.Hosts, model.HostObs{IP: ip, Hostname: hostname, Up: up})
		for _, p := range h.Ports {
			if p.State.State != "open" {
				continue
			}
			n, err := strconv.ParseUint(p.PortID, 10, 16)
			if err != nil || n == 0 {
				obs.Errors = append(obs.Errors, fmt.Sprintf("host %s: bad port %q", ip, p.PortID))
				continue
			}
			svc := model.ServiceObs{
				Key:       model.AssetKey{IP: ip, Port: uint16(n), Proto: strings.ToLower(p.Protocol)},
				Product:   p.Service.Product,
				Version:   p.Service.Version,
				ExtraInfo: p.Service.ExtraInfo,
			}
			if svc.Product == "" && p.Service.Name != "" {
				svc.Product = p.Service.Name
				if p.Service.Tunnel != "" {
					svc.Product = p.Service.Tunnel + "/" + p.Service.Name
				}
			}
			if len(p.Service.CPE) > 0 {
				svc.CPE = strings.TrimSpace(p.Service.CPE[0])
			}
			for _, s := range p.Scripts {
				if s.ID == "banner" {
					svc.Banner = s.Output
				}
			}
			obs.Services = append(obs.Services, svc)
		}
	}
	return obs, nil
}
