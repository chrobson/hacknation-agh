package httpfp

import (
	"bufio"
	"context"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"sync/atomic"
	"testing"
	"time"

	"github.com/chrobson/hacknation-agh/internal/model"
)

func TestProbeRecordsResponseTime(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/" {
			time.Sleep(550 * time.Millisecond) // Toxiproxy "latency" toxic, 500 ms+
		}
		w.Header().Set("Content-Type", "text/html")
		fmt.Fprint(w, "<title>slow</title>")
	}))
	defer srv.Close()
	p := New(Options{SkipFavicon: true})
	obs, err := p.Probe(context.Background(), endpointFor(t, srv.URL, ""))
	if err != nil {
		t.Fatal(err)
	}
	if obs.ResponseMS < 550 || obs.ResponseMS > 5000 {
		t.Fatalf("ResponseMS = %d, want >= 550", obs.ResponseMS)
	}
	if obs.Title != "slow" {
		t.Fatalf("title %q", obs.Title)
	}
}

func TestProbeResponseTimeIsFirstHop(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "/slow", http.StatusFound)
	})
	mux.HandleFunc("/slow", func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(400 * time.Millisecond)
		fmt.Fprint(w, "ok")
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()
	obs, err := New(Options{SkipFavicon: true}).Probe(context.Background(), endpointFor(t, srv.URL, ""))
	if err != nil {
		t.Fatal(err)
	}
	if obs.ResponseMS <= 0 || obs.ResponseMS >= 400 {
		t.Fatalf("ResponseMS = %d, want the fast first hop", obs.ResponseMS)
	}
}

func TestProbeRetriesAfterTimeout(t *testing.T) {
	var n atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if n.Add(1) == 1 {
			time.Sleep(600 * time.Millisecond) // first attempt exceeds the timeout
		}
		fmt.Fprint(w, "<title>second</title>")
	}))
	defer srv.Close()
	p := New(Options{Timeout: 300 * time.Millisecond, RetryBackoff: time.Millisecond, SkipFavicon: true})
	obs, err := p.Probe(context.Background(), endpointFor(t, srv.URL, ""))
	if err != nil {
		t.Fatalf("probe with one retry: %v", err)
	}
	if obs.Title != "second" || n.Load() != 2 {
		t.Fatalf("title %q after %d requests", obs.Title, n.Load())
	}

	n.Store(0)
	p = New(Options{Timeout: 300 * time.Millisecond, Retries: -1, SkipFavicon: true})
	if _, err := p.Probe(context.Background(), endpointFor(t, srv.URL, "")); err == nil {
		t.Fatal("retries disabled: want timeout error")
	}
	if n.Load() != 1 {
		t.Fatalf("retries disabled: %d requests", n.Load())
	}
}

func TestProbeRetriesDroppedConnection(t *testing.T) {
	// A Toxiproxy "reset_peer"/"timeout" toxic closes the first connection
	// without an answer; the retry gets through.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	var n atomic.Int32
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				br := bufio.NewReader(c)
				if _, err := http.ReadRequest(br); err != nil {
					return
				}
				if n.Add(1) == 1 {
					return // hang up without a response
				}
				fmt.Fprint(c, "HTTP/1.1 200 OK\r\nContent-Length: 17\r\nContent-Type: text/html\r\n\r\n<title>ok</title>")
			}(c)
		}
	}()
	p := New(Options{RetryBackoff: time.Millisecond, SkipFavicon: true})
	obs, err := p.Probe(context.Background(), endpointFor(t, "http://"+ln.Addr().String(), ""))
	if err != nil {
		t.Fatal(err)
	}
	if obs.Title != "ok" || n.Load() != 2 {
		t.Fatalf("title %q after %d requests", obs.Title, n.Load())
	}
}

func TestProbeSlowClose(t *testing.T) {
	// Toxiproxy "slow_close": the body is complete but the connection stays
	// open for a while. A close-delimited HTTP/1.0 body waits for the close,
	// which must fit in the timeout.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				if _, err := http.ReadRequest(bufio.NewReader(c)); err != nil {
					return
				}
				fmt.Fprint(c, "HTTP/1.0 200 OK\r\nContent-Type: text/html\r\n\r\n<title>closing slowly</title>")
				time.Sleep(700 * time.Millisecond)
			}(c)
		}
	}()
	obs, err := New(Options{SkipFavicon: true}).Probe(context.Background(), endpointFor(t, "http://"+ln.Addr().String(), ""))
	if err != nil {
		t.Fatal(err)
	}
	if obs.Title != "closing slowly" || obs.ResponseMS < 700 {
		t.Fatalf("title %q, %d ms", obs.Title, obs.ResponseMS)
	}
}

func TestProbeRefusedIsNotRetried(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := ln.Addr().(*net.TCPAddr)
	ln.Close()
	var dials atomic.Int32
	d := &net.Dialer{Timeout: time.Second}
	p := New(Options{SkipFavicon: true, RetryBackoff: time.Second, DialContext: func(ctx context.Context, network, a string) (net.Conn, error) {
		dials.Add(1)
		return d.DialContext(ctx, network, a)
	}})
	ep := model.Endpoint{Scheme: "http", Key: model.AssetKey{IP: netip.MustParseAddr("127.0.0.1"), Port: uint16(addr.Port), Proto: "tcp"}}
	start := time.Now()
	if _, err := p.Probe(context.Background(), ep); err == nil {
		t.Fatal("want connection refused")
	}
	if dials.Load() != 1 || time.Since(start) > 900*time.Millisecond {
		t.Fatalf("refused connection retried: %d dials in %v", dials.Load(), time.Since(start))
	}
}

func TestFetchPathRetries(t *testing.T) {
	var n atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if n.Add(1) == 1 {
			time.Sleep(500 * time.Millisecond)
		}
		fmt.Fprint(w, `{"ok":true}`)
	}))
	defer srv.Close()
	ep := endpointFor(t, srv.URL, "")
	p := New(Options{Timeout: 250 * time.Millisecond, RetryBackoff: time.Millisecond})
	r, err := p.FetchPath(context.Background(), ep.Key.IP.String(), "", BaseURL(ep), "GET", "/proxies", nil)
	if err != nil {
		t.Fatal(err)
	}
	if r.Status != 200 || r.Duration <= 0 {
		t.Fatalf("status %d duration %v", r.Status, r.Duration)
	}
	if p.Timeout() != 250*time.Millisecond {
		t.Fatalf("Timeout() = %v", p.Timeout())
	}
}
