package deployment

import (
	"context"
	"encoding/json"
	"errors"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/cosmo-wander-ai/cosmoedge-connect/internal/operator/ledger"
)

func TestFailedCurrentReadDoesNotInventAbsenceOrReplaceSealedFacts(t *testing.T) {
	h := newHarness(t, true)
	ctx := context.Background()
	proposal, err := h.service.Prepare(ctx, "session-a", request(true))
	if err != nil {
		t.Fatal(err)
	}
	if record := confirmAndWait(t, h, proposal); record.State != "completed" {
		t.Fatalf("initial operation=%+v", record)
	}
	first, err := h.service.Status(ctx, "session-a", proposal.ActionRef)
	if err != nil || first.OriginalVerification == nil {
		t.Fatalf("initial read=%+v error=%v", first, err)
	}
	h.client.mu.Lock()
	h.client.deploymentReadErr = context.DeadlineExceeded
	h.client.mu.Unlock()
	failed, err := h.service.Status(ctx, "session-a", proposal.ActionRef)
	if err != nil || failed.Current != nil || !reflect.DeepEqual(failed.OriginalVerification, first.OriginalVerification) || failed.State != "completed" || failed.Dispatches != 1 || failed.DeviceWrites != 1 {
		t.Fatalf("failed read became new facts or changed receipt: %+v error=%v", failed, err)
	}
	observation := h.service.observe(ctx, h.client, metadata{Target: proposal}, false)
	if !observation.ObservedAt.IsZero() {
		t.Fatalf("failed read invented observation time: %+v", observation)
	}

	// A successful read of an actually absent binding is a different fact.
	h.client.mu.Lock()
	h.client.deploymentReadErr = nil
	h.client.state.Exists = false
	h.client.state.TaskID = ""
	h.client.mu.Unlock()
	absent, err := h.service.Status(ctx, "session-a", proposal.ActionRef)
	if err != nil || absent.Current == nil || absent.Current.Exists || absent.Current.ObservedAt.IsZero() || !reflect.DeepEqual(absent.OriginalVerification, first.OriginalVerification) {
		t.Fatalf("verified absence was lost: %+v error=%v", absent, err)
	}
	h.client.mu.Lock()
	defer h.client.mu.Unlock()
	if h.client.writes != 1 || h.client.switches != 1 {
		t.Fatalf("read failure caused a repeat write: writes=%d switches=%d", h.client.writes, h.client.switches)
	}
}

func TestOriginalVerificationSurvivesLaterStopAndStoreReopen(t *testing.T) {
	h := newHarness(t, false)
	ctx := context.Background()
	proposal, err := h.service.Prepare(ctx, "session-a", request(true))
	if err != nil {
		t.Fatal(err)
	}
	confirmed := confirmAndWait(t, h, proposal)
	if confirmed.Reason != "deployment_processing_verified" {
		t.Fatalf("reason=%s", confirmed.Reason)
	}
	first, err := h.service.Status(ctx, "session-a", proposal.ActionRef)
	if err != nil || !first.OriginalVerificationAvailable || first.OriginalVerification == nil {
		t.Fatalf("missing original: %+v %v", first, err)
	}
	original := *first.OriginalVerification
	if original.Enabled != 1 || !original.ConfigurationMatch || original.Runtime != "processing" || len(original.Progress) != 2 || original.ObservedAt.IsZero() || original.SealedAt.Before(original.ObservedAt) {
		t.Fatalf("original=%+v", original)
	}
	h.client.mu.Lock()
	h.client.state.Enabled = 0 // Independent subsequent change; do not invent its cause.
	h.client.mu.Unlock()
	for i := 0; i < 2; i++ {
		later, err := h.service.GetByRequest(ctx, "session-a", "request-one")
		if err != nil || later.Current == nil || later.Current.Enabled != 0 || later.Current.Runtime != "stopped" {
			t.Fatalf("later=%+v err=%v", later, err)
		}
		if !reflect.DeepEqual(later.OriginalVerification, &original) || later.State != "completed" || later.Dispatches != 1 || later.DeviceWrites != 1 || !later.Current.ObservedAt.After(original.ObservedAt) {
			t.Fatalf("historical facts changed: %+v", later)
		}
	}
	if _, err := h.service.Status(ctx, "other-session", proposal.ActionRef); !errors.Is(err, ErrConflict) {
		t.Fatalf("owner boundary=%v", err)
	}
	h.worker.Stop()
	h.service.Close()
	if err := h.store.Close(); err != nil {
		t.Fatal(err)
	}
	reopened, err := ledger.Open(h.dbPath)
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.Close()
	if err := reopened.RecoverInterrupted(ctx, time.Now().UTC()); err != nil {
		t.Fatal(err)
	}
	restarted, err := New(reopened, testProvider{h.client})
	if err != nil {
		t.Fatal(err)
	}
	defer restarted.Close()
	restarted.verifyInterval = time.Millisecond
	afterRestart, err := restarted.GetByRequest(ctx, "session-a", "request-one")
	if err != nil || !reflect.DeepEqual(afterRestart.OriginalVerification, &original) || afterRestart.Current == nil || afterRestart.Current.Enabled != 0 || afterRestart.Dispatches != 1 || afterRestart.DeviceWrites != 1 {
		t.Fatalf("reopened=%+v error=%v", afterRestart, err)
	}
	h.client.mu.Lock()
	h.client.fingerprint = "changed-source"
	h.client.mu.Unlock()
	unavailable, err := restarted.Status(ctx, "session-a", proposal.ActionRef)
	if err != nil || unavailable.Current != nil || !reflect.DeepEqual(unavailable.OriginalVerification, &original) {
		t.Fatalf("unavailable current discarded or replaced original: %+v %v", unavailable, err)
	}
	h.client.mu.Lock()
	defer h.client.mu.Unlock()
	if h.client.writes != 1 || h.client.saves != 1 || h.client.switches != 0 {
		t.Fatalf("read/restart wrote again: %+v", h.client)
	}
}

func TestOriginalVerificationMissingInvalidOrForeignNeverInvented(t *testing.T) {
	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	observation := Observation{SourceID: "source", AlgorithmID: "algorithm", TaskID: "ignored-task", Exists: true, Enabled: 1, ConfigurationMatch: true, Runtime: "processing", Progress: []Progress{{NodeID: "node", Before: 1, After: 2}}, ObservedAt: now}
	raw, _ := json.Marshal(observation)
	base := ledger.EvidenceRecord{Status: "sealed", PayloadJSON: string(raw), ObservedAt: now.Add(time.Second).Format(time.RFC3339Nano), SealedAt: now.Add(time.Second).Format(time.RFC3339Nano)}
	target := Proposal{SourceID: "source", AlgorithmID: "algorithm"}
	if originalVerification(base, target) == nil {
		t.Fatal("valid stored snapshot rejected")
	}
	for _, tc := range []struct {
		name string
		edit func(*ledger.EvidenceRecord)
	}{
		{"missing", func(e *ledger.EvidenceRecord) { e.PayloadJSON = "" }},
		{"legacy empty", func(e *ledger.EvidenceRecord) { e.PayloadJSON = "{}" }},
		{"pending", func(e *ledger.EvidenceRecord) { e.Status = "evidence_pending" }},
		{"foreign source", func(e *ledger.EvidenceRecord) {
			e.PayloadJSON = strings.Replace(e.PayloadJSON, `"sourceId":"source"`, `"sourceId":"other"`, 1)
		}},
		{"foreign algorithm", func(e *ledger.EvidenceRecord) {
			e.PayloadJSON = strings.Replace(e.PayloadJSON, `"algorithmId":"algorithm"`, `"algorithmId":"other"`, 1)
		}},
		{"extra raw native", func(e *ledger.EvidenceRecord) {
			e.PayloadJSON = strings.TrimSuffix(e.PayloadJSON, "}") + `,"native":{"url":"synthetic-private-value"}}`
		}},
		{"missing enabled", func(e *ledger.EvidenceRecord) { e.PayloadJSON = strings.Replace(e.PayloadJSON, `"enabled":1,`, "", 1) }},
		{"null exists", func(e *ledger.EvidenceRecord) {
			e.PayloadJSON = strings.Replace(e.PayloadJSON, `"exists":true`, `"exists":null`, 1)
		}},
		{"runtime text", func(e *ledger.EvidenceRecord) {
			e.PayloadJSON = strings.Replace(e.PayloadJSON, `"runtime":"processing"`, `"runtime":"arbitrary-native-error"`, 1)
		}},
		{"no original time", func(e *ledger.EvidenceRecord) {
			e.PayloadJSON = strings.Replace(e.PayloadJSON, now.Format(time.RFC3339Nano), "0001-01-01T00:00:00Z", 1)
		}},
		{"unsealed", func(e *ledger.EvidenceRecord) { e.SealedAt = "" }},
		{"contradictory seal", func(e *ledger.EvidenceRecord) { e.SealedAt = now.Add(-time.Second).Format(time.RFC3339Nano) }},
		{"invalid growth", func(e *ledger.EvidenceRecord) {
			e.PayloadJSON = strings.Replace(e.PayloadJSON, `"after":2`, `"after":1`, 1)
		}},
		{"trailing value", func(e *ledger.EvidenceRecord) { e.PayloadJSON += "{}" }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			e := base
			tc.edit(&e)
			if got := originalVerification(e, target); got != nil {
				t.Fatalf("invented historical snapshot: %+v", got)
			}
		})
	}
}

func TestUnknownOriginalOutcomeIsNotPromotedBySnapshot(t *testing.T) {
	h := newHarness(t, true)
	h.client.writeErr = errors.New("ambiguous synthetic response")
	h.client.mutateOnError = true
	p, err := h.service.Prepare(context.Background(), "session-a", request(true))
	if err != nil {
		t.Fatal(err)
	}
	confirmAndWait(t, h, p)
	s, err := h.service.Status(context.Background(), "session-a", p.ActionRef)
	if err != nil || s.State != "unknown" || s.Class != "unknown" || s.OriginalVerification == nil || s.OriginalVerification.Runtime != "processing" {
		t.Fatalf("ambiguous dispatch changed classification: %+v %v", s, err)
	}
}
