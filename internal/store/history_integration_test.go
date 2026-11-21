//go:build integration

package store_test

import (
	"context"
	"net/netip"
	"testing"
	"time"

	"github.com/chrobson/hacknation-agh/internal/diff"
	"github.com/chrobson/hacknation-agh/internal/model"
	"github.com/chrobson/hacknation-agh/internal/store"
)

func TestHistoryPresence(t *testing.T) {
	pool := testPool(t)
	ctx := context.Background()

	day := netip.MustParseAddr("10.20.0.201")    // up only in daytime runs
	always := netip.MustParseAddr("10.20.0.202") // up in every run
	outside := netip.MustParseAddr("10.99.0.201")
	for _, a := range []netip.Addr{day, always, outside} {
		if _, err := pool.Exec(ctx, `INSERT INTO host_state (ip, state) VALUES ($1::inet, 'up') ON CONFLICT (ip) DO NOTHING`, a.String()); err != nil {
			t.Fatal(err)
		}
	}

	// Six finished scan runs on consecutive days, alternating 10:00 and
	// 23:00 local time, each with a done chunk covering 10.20.0.0/24.
	base := time.Now().In(time.Local)
	var runs []int64
	for i := 0; i < 6; i++ {
		hour := 10
		if i%2 == 1 {
			hour = 23
		}
		started := time.Date(base.Year(), base.Month(), base.Day()-10+i, hour, 0, 0, 0, time.Local)
		var id int64
		if err := pool.QueryRow(ctx, `INSERT INTO scan_runs (kind, status, started_at, finished_at)
			VALUES ('scan', 'done', $1::timestamptz, $1::timestamptz + interval '5 minutes') RETURNING id`, started).Scan(&id); err != nil {
			t.Fatal(err)
		}
		runs = append(runs, id)
		if _, err := pool.Exec(ctx, `INSERT INTO scan_chunks (run_id, cidr, status) VALUES ($1, '10.20.0.0/24', 'done')`, id); err != nil {
			t.Fatal(err)
		}
		dayRun := hour == 10
		for _, h := range []struct {
			ip netip.Addr
			up bool
		}{{day, dayRun}, {always, true}, {outside, true}} {
			if _, err := pool.Exec(ctx, `INSERT INTO host_obs (run_id, ip, up) VALUES ($1, $2::inet, $3)`, id, h.ip.String(), h.up); err != nil {
				t.Fatal(err)
			}
		}
		if dayRun {
			var sid int64
			if err := pool.QueryRow(ctx, `INSERT INTO services (run_id, ip, port, proto, product, version)
				VALUES ($1, $2::inet, 8787, 'tcp', 'Werkzeug', '3.0') RETURNING id`, id, day.String()).Scan(&sid); err != nil {
				t.Fatal(err)
			}
			if _, err := pool.Exec(ctx, `INSERT INTO http_obs (service_id, url, status, title) VALUES ($1, 'http://x/', 200, 'Panel')`, sid); err != nil {
				t.Fatal(err)
			}
		}
		if _, err := pool.Exec(ctx, `INSERT INTO services (run_id, ip, port, proto) VALUES ($1, $2::inet, 22, 'tcp')`, id, always.String()); err != nil {
			t.Fatal(err)
		}
	}
	// An import run is newer but never counts.
	var imp int64
	if err := pool.QueryRow(ctx, `INSERT INTO scan_runs (kind, status, started_at) VALUES ('import', 'done', now()) RETURNING id`).Scan(&imp); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, `INSERT INTO host_obs (run_id, ip, up) VALUES ($1, $2::inet, true)`, imp, day.String()); err != nil {
		t.Fatal(err)
	}

	hosts, err := store.HostPresence(ctx, pool, 6)
	if err != nil {
		t.Fatal(err)
	}
	byKey := map[model.AssetKey]store.AssetPresence{}
	for _, p := range hosts {
		byKey[p.Key] = p
	}
	if _, ok := byKey[model.AssetKey{IP: outside}]; ok {
		t.Errorf("uncovered address has samples: %+v", byKey[model.AssetKey{IP: outside}])
	}
	dp := byKey[model.AssetKey{IP: day}]
	if len(dp.Samples) != 6 || dp.Samples[0].RunID != runs[0] || dp.Samples[5].RunID != runs[5] {
		t.Fatalf("day host samples: %+v", dp.Samples)
	}
	for i, s := range dp.Samples {
		if s.Seen != (i%2 == 0) {
			t.Errorf("day host sample %d seen=%v", i, s.Seen)
		}
	}
	a := diff.Analyze(diff.Samples(dp.Samples), time.Local, diff.DefaultMinPerBand)
	if a.Pattern != diff.PatternTimeOfDay || a.Seen != 3 || a.Total != 6 || a.Label != "odpowiada głównie w godz. 06-12" {
		t.Errorf("day host availability: %+v", a)
	}
	if a := diff.Analyze(diff.Samples(byKey[model.AssetKey{IP: always}].Samples), time.Local, 2); a.Pattern != diff.PatternAlways || a.Total != 6 {
		t.Errorf("always host availability: %+v", a)
	}

	svcs, err := store.ServicePresence(ctx, pool, 6)
	if err != nil {
		t.Fatal(err)
	}
	svcKey := model.AssetKey{IP: day, Port: 8787, Proto: "tcp"}
	var found bool
	for _, p := range svcs {
		if p.Key.IP == outside {
			t.Errorf("uncovered service listed: %+v", p)
		}
		if p.Key == svcKey {
			found = true
			if len(p.Samples) != 6 || !p.Samples[0].Seen || p.Samples[1].Seen {
				t.Errorf("service samples: %+v", p.Samples)
			}
		}
	}
	if !found {
		t.Fatalf("service %v missing from %+v", svcKey, svcs)
	}

	h, err := store.AssetHistory(ctx, pool, svcKey, 6)
	if err != nil {
		t.Fatal(err)
	}
	if len(h.Runs) != 6 || !h.Runs[0].Covered || !h.Runs[0].Seen || h.Runs[1].Seen ||
		h.Runs[0].Product != "Werkzeug" || h.Runs[0].HTTPStatus != 200 || h.Runs[0].HTTPTitle != "Panel" {
		t.Errorf("asset history: %+v", h.Runs)
	}
	oh, err := store.AssetHistory(ctx, pool, model.AssetKey{IP: outside}, 6)
	if err != nil {
		t.Fatal(err)
	}
	for _, r := range oh.Runs {
		if r.Covered {
			t.Errorf("outside host covered in run %d", r.RunID)
		}
	}
	if s := diff.CoveredSamples(oh.Runs); len(s) != 0 {
		t.Errorf("outside host samples: %+v", s)
	}

	series, err := store.RunSeries(ctx, pool, 6)
	if err != nil {
		t.Fatal(err)
	}
	if len(series) != 6 || series[0].RunID != runs[0] || series[5].RunID != runs[5] {
		t.Fatalf("series: %+v", series)
	}
	if series[0].HostsUp < 3 || series[1].HostsUp < 2 || series[0].Services < 2 || series[1].Services < 1 {
		t.Errorf("series counts: %+v", series[:2])
	}
}
