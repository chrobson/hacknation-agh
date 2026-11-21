package auth

import (
	"testing"
	"time"
)

func TestThrottle(t *testing.T) {
	now := time.Date(2026, 11, 21, 12, 0, 0, 0, time.UTC)
	th := &throttle{failures: map[string][]time.Time{}, now: func() time.Time { return now }}
	keys := throttleKeys("Admin", "10.0.0.1")
	for i := 0; i < MaxLoginFailures; i++ {
		if b, _ := th.blocked(keys...); b {
			t.Fatalf("blocked after %d failures", i)
		}
		th.fail(keys...)
	}
	if b, wait := th.blocked(throttleKeys("admin", "10.0.0.2")...); !b || wait <= 0 {
		t.Fatal("login key not blocked (case-insensitive)")
	}
	if b, _ := th.blocked(throttleKeys("other", "10.0.0.1")...); !b {
		t.Fatal("ip key not blocked")
	}
	if b, _ := th.blocked(throttleKeys("other", "10.0.0.3")...); b {
		t.Fatal("unrelated login and ip blocked")
	}
	now = now.Add(LoginFailureWindow)
	if b, _ := th.blocked(keys...); b {
		t.Fatal("still blocked after the window")
	}
}
