package runner

import (
	"context"
	"errors"
	"net/http"
	"net/netip"
	"testing"
	"time"

	"github.com/chrobson/hacknation-agh/internal/model"
	"github.com/chrobson/hacknation-agh/internal/safety"
	"github.com/chrobson/hacknation-agh/internal/store"
)

func TestReceiptSavedAfterOnDoneAndBestEffort(t *testing.T) {
	for _, failSave := range []bool{false, true} {
		fs, _, r, cfg := setup(t, model.Target{Kind: model.TargetCIDR, Value: "10.20.0.0/24"})
		var got []safety.Receipt
		r.OnDone = func(ctx context.Context, id int64) error {
			// HTTP probes run inside OnDone with the run's meter.
			req, _ := http.NewRequestWithContext(ctx, http.MethodGet, "http://10.20.0.10/", nil)
			safety.From(ctx).CountHTTP(req)
			safety.From(ctx).AddNmap(safety.Invocation{Packets: 100, Elapsed: time.Second,
				Start: time.Unix(0, 0), End: time.Unix(1, 0),
				Targets: []netip.Prefix{netip.MustParsePrefix("10.20.0.0/24"), netip.MustParsePrefix("192.0.2.1/32")}})
			return nil
		}
		r.SaveReceipt = func(_ context.Context, rc safety.Receipt) error {
			got = append(got, rc)
			if failSave {
				return errors.New("db down")
			}
			return nil
		}
		runID, err := r.RunConfig(context.Background(), cfg.ID)
		if err != nil {
			t.Fatalf("failSave=%v: run failed: %v", failSave, err)
		}
		if st := fs.runStatus(runID); st != store.RunDone {
			t.Fatalf("status %s", st)
		}
		if len(got) != 1 {
			t.Fatalf("receipts = %d", len(got))
		}
		rc := got[0]
		if rc.RunID != runID || rc.ConfiguredMaxRate != 1000 || rc.HTTPGet != 1 || rc.NmapPackets != 100 {
			t.Errorf("receipt %+v", rc)
		}
		if rc.TargetsChecked != 257 || rc.TargetsOutsideAllowlist != 1 {
			t.Errorf("allowlist recheck: checked=%d outside=%d", rc.TargetsChecked, rc.TargetsOutsideAllowlist)
		}
	}
}
