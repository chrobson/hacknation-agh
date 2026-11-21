package runner

import (
	"fmt"
	"testing"
)

func TestEffectivePorts(t *testing.T) {
	cases := []struct {
		spec    string
		allowed []int
		want    string
		err     bool
	}{
		{"", nil, "[]", false},
		{"22,80", nil, "[22 80]", false},
		{"", []int{22, 443}, "[22 443]", false},
		{"22,80,443", []int{22, 443}, "[22 443]", false},
		{"80", []int{22, 443}, "", true},
		{"x", nil, "", true},
	}
	for _, c := range cases {
		got, err := EffectivePorts(c.spec, c.allowed)
		if c.err {
			if err == nil {
				t.Errorf("%q %v: expected error", c.spec, c.allowed)
			}
			continue
		}
		if err != nil || fmt.Sprint(got) != c.want {
			t.Errorf("%q %v: got %v %v want %s", c.spec, c.allowed, got, err, c.want)
		}
	}
}
