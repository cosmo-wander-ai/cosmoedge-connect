package devlab

import (
	"context"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/cosmo-wander-ai/cosmoedge-connect/internal/localstate"
)

func TestEvidenceStoreSealsZeroWriteChainAndRejectsProtectedData(t *testing.T) {
	store, err := OpenEvidence(filepath.Join(t.TempDir(), "private-state"))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	now := time.Now().UTC()
	run := EvidenceRun{RunID: "run-test", Device: "***0002", DeviceType: "fixture", Commit: "abc1234", ChangeDigest: strings.Repeat("0", 64), OpenedAt: now, ExpiresAt: now.Add(time.Minute)}
	if err := store.StartRun(context.Background(), run); err != nil {
		t.Fatal(err)
	}
	probe := EvidenceProbe{RunID: run.RunID, ProbeID: "probe-test", Kind: "identity", HypothesisDigest: digestText("is healthy"), PublicJSON: `{"device":"***0002","deviceType":"fixture"}`, ObservedAt: now.Add(time.Second), ReadCount: 2, DeviceWrites: 0}
	if err := store.RecordProbe(context.Background(), probe); err != nil {
		t.Fatal(err)
	}
	if err := store.VerifyRun(context.Background(), run.RunID); err != nil {
		t.Fatal(err)
	}
	if err := store.FinishRun(context.Background(), run.RunID, "passed", now.Add(2*time.Second), 2, 1, 0); err != nil {
		t.Fatal(err)
	}
	for _, suffix := range []string{"", "-wal", "-shm"} {
		if err := localstate.ValidateFile(store.Path() + suffix); err != nil {
			t.Fatalf("evidence file %s: %v", suffix, err)
		}
	}

	bad := probe
	bad.ProbeID = "probe-secret"
	bad.PublicJSON = `{"endpoint":"http://10.42.0.20:8000"}`
	if err := store.RecordProbe(context.Background(), bad); err == nil {
		t.Fatal("protected endpoint entered evidence")
	}
}

func TestEvidenceChainDetectsMutation(t *testing.T) {
	store, err := OpenEvidence(filepath.Join(t.TempDir(), "private-state"))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	now := time.Now().UTC()
	run := EvidenceRun{RunID: "run-tamper", Device: "***0002", DeviceType: "fixture", OpenedAt: now, ExpiresAt: now.Add(time.Minute)}
	if err := store.StartRun(context.Background(), run); err != nil {
		t.Fatal(err)
	}
	probe := EvidenceProbe{RunID: run.RunID, ProbeID: "probe-tamper", Kind: "health", HypothesisDigest: digestText(""), PublicJSON: `{"cpuPercent":10}`, ObservedAt: now, ReadCount: 2}
	if err := store.RecordProbe(context.Background(), probe); err != nil {
		t.Fatal(err)
	}
	if _, err := store.db.Exec(`UPDATE lab_probes SET public_json='{"cpuPercent":99}' WHERE probe_id='probe-tamper'`); err != nil {
		t.Fatal(err)
	}
	if err := store.VerifyRun(context.Background(), run.RunID); err == nil {
		t.Fatal("mutated evidence chain verified")
	}
}
