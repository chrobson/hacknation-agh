package app

import (
	"context"
	"errors"
	"testing"

	"github.com/chrobson/hacknation-agh/internal/model"
)

type schemeProber map[string]model.HTTPObs

func (f schemeProber) Probe(_ context.Context, ep model.Endpoint) (model.HTTPObs, error) {
	o, ok := f[ep.Scheme]
	if !ok {
		return model.HTTPObs{}, errors.New("no answer")
	}
	return o, nil
}

func TestProbeScheme(t *testing.T) {
	cases := []struct {
		name   string
		pr     schemeProber
		in     string
		want   string
		status int
	}{
		{"http ok", schemeProber{"http": {Status: 200}}, "http", "http", 200},
		{"http label on TLS port", schemeProber{"https": {Status: 200}}, "http", "https", 200},
		{"https ok", schemeProber{"https": {Status: 200}, "http": {Status: 200, Title: "x"}}, "https", "https", 200},
		{"traefik: empty 404 over TLS, dashboard redirect over http", schemeProber{"https": {Status: 404}, "http": {Status: 301}}, "https", "http", 301},
		{"404 over TLS and over http keeps https", schemeProber{"https": {Status: 404}, "http": {Status: 404}}, "https", "https", 404},
		{"404 with a title over TLS keeps https", schemeProber{"https": {Status: 404, Title: "Not Found"}, "http": {Status: 200}}, "https", "https", 404},
		{"plain http unreachable keeps https", schemeProber{"https": {Status: 404}}, "https", "https", 404},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			o, sch, _ := probeScheme(context.Background(), c.pr, model.Endpoint{Scheme: c.in})
			if sch != c.want || o.Status != c.status {
				t.Fatalf("got %s %d, want %s %d", sch, o.Status, c.want, c.status)
			}
		})
	}
}
