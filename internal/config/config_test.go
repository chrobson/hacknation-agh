package config

import (
	"fmt"
	"testing"
)

func TestParsePorts(t *testing.T) {
	got, err := ParsePorts(" 443,22, 8000-8002,22")
	if err != nil {
		t.Fatal(err)
	}
	want := []int{22, 443, 8000, 8001, 8002}
	if fmt.Sprint(got) != fmt.Sprint(want) {
		t.Fatalf("got %v want %v", got, want)
	}
	for _, bad := range []string{"0", "65536", "a", "10-5", "1-x"} {
		if _, err := ParsePorts(bad); err == nil {
			t.Errorf("%q: expected error", bad)
		}
	}
	if p, err := ParsePorts(""); err != nil || p != nil {
		t.Errorf("empty: %v %v", p, err)
	}
}
