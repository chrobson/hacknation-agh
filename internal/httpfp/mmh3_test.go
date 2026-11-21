package httpfp

import "testing"

func TestSum32Vectors(t *testing.T) {
	cases := []struct {
		in   string
		seed uint32
		want uint32
	}{
		{"hello", 0, 0x248bfa47},
		{"", 0, 0},
		{"", 1, 0x514e28b7},
		{"The quick brown fox jumps over the lazy dog", 0, 0x2e4ff723},
		{"a", 0, 0x3c2569b2},
		{"ab", 0, 0x9bbfd75f},
		{"abc", 0, 0xb3dd93fa},
		{"abcd", 0, 0x43ed676a},
	}
	for _, c := range cases {
		if got := Sum32([]byte(c.in), c.seed); got != c.want {
			t.Errorf("Sum32(%q, %d) = %#x, want %#x", c.in, c.seed, got, c.want)
		}
	}
}

func TestShodanBase64MatchesPythonEncodebytes(t *testing.T) {
	d := make([]byte, 100)
	for i := range d {
		d[i] = byte(i)
	}
	// python3 -c "import base64; print(repr(base64.encodebytes(bytes(range(100)))))"
	want := "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8gISIjJCUmJygpKissLS4vMDEyMzQ1Njc4\n" +
		"OTo7PD0+P0BBQkNERUZHSElKS0xNTk9QUVJTVFVWV1hZWltcXV5fYGFiYw==\n"
	if got := string(ShodanBase64(d)); got != want {
		t.Fatalf("got %q\nwant %q", got, want)
	}
	// Exactly 76 output chars: a single trailing newline, no empty line.
	want57 := "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\n"
	if got := string(ShodanBase64(make([]byte, 57))); got != want57 {
		t.Fatalf("57 bytes: got %q", got)
	}
	if got := ShodanBase64(nil); len(got) != 0 {
		t.Fatalf("empty input: got %q", got)
	}
}

func TestFaviconHashIsSignedMMH3OfBase64(t *testing.T) {
	raw := []byte("\x00\x00\x01\x00fake-icon")
	want := int32(Sum32(ShodanBase64(raw), 0))
	if got := FaviconHash(raw); got != want {
		t.Fatalf("FaviconHash = %d, want %d", got, want)
	}
}
