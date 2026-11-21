package config

import (
	"fmt"
	"testing"
	"time"
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

func TestHTTPTimeoutAndRetries(t *testing.T) {
	t.Setenv("ASI_HTTP_TIMEOUT", "")
	t.Setenv("ASI_HTTP_RETRIES", "")
	c, err := Load()
	if err != nil {
		t.Fatal(err)
	}
	if c.HTTPTimeout != 10*time.Second || c.HTTPRetries != 1 {
		t.Fatalf("defaults: %v, %d", c.HTTPTimeout, c.HTTPRetries)
	}
	t.Setenv("ASI_HTTP_TIMEOUT", "25s")
	t.Setenv("ASI_HTTP_RETRIES", "0")
	if c, err = Load(); err != nil || c.HTTPTimeout != 25*time.Second || c.HTTPRetries != 0 {
		t.Fatalf("custom: %v, %d, %v", c.HTTPTimeout, c.HTTPRetries, err)
	}
	for k, v := range map[string]string{"ASI_HTTP_TIMEOUT": "-1s", "ASI_HTTP_RETRIES": "9"} {
		t.Run(k, func(t *testing.T) {
			t.Setenv(k, v)
			if _, err := Load(); err == nil {
				t.Fatalf("%s=%s accepted", k, v)
			}
		})
	}
}
