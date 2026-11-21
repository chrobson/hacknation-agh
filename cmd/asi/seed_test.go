package main

import (
	"fmt"
	"testing"

	"github.com/chrobson/hacknation-agh/internal/config"
)

func TestSeedTargets(t *testing.T) {
	for _, tc := range []struct {
		hosts []string
		args  []string
		want  string
	}{
		{nil, nil, "[localhost]"},
		{[]string{"host.docker.internal"}, nil, "[host.docker.internal]"},
		{[]string{"host.docker.internal"}, []string{"127.0.0.1", "::1"}, "[127.0.0.1 ::1]"},
	} {
		got := fmt.Sprint(seedTargets(config.Config{AllowHosts: tc.hosts}, tc.args))
		if got != tc.want {
			t.Errorf("hosts=%v args=%v: got %s want %s", tc.hosts, tc.args, got, tc.want)
		}
	}
}
