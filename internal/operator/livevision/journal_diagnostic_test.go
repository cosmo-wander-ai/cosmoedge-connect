package livevision

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/cosmo-wander-ai/cosmoedge-connect/internal/adapter"
	"github.com/cosmo-wander-ai/cosmoedge-connect/internal/inspection/temporary"
	"github.com/cosmo-wander-ai/cosmoedge-connect/internal/safediagnostic"
)

type failingDiagnosticJournal struct {
	beforeCreateErr error
	beforeCancelErr error
	finishErr       error
	allowed         bool
	recorded        []safediagnostic.Diagnostic
}

func (j *failingDiagnosticJournal) BeforeCreate(context.Context, TemporaryTask) error {
	return j.beforeCreateErr
}
func (j *failingDiagnosticJournal) BeforeCancel(context.Context, TemporaryTask) (bool, error) {
	return j.allowed, j.beforeCancelErr
}
func (j *failingDiagnosticJournal) FinishTask(context.Context, TemporaryTask, string) error {
	return j.finishErr
}
func (j *failingDiagnosticJournal) RecordFailure(_ context.Context, _ string, d safediagnostic.Diagnostic) error {
	j.recorded = append(j.recorded, *d.Clone())
	return nil
}

func TestTemporaryCancelJournalStorageFailureDiffersFromStateRejection(t *testing.T) {
	storageErr := errors.New("sqlite private/path: SQL write failed")
	for _, test := range []struct {
		name                 string
		allowed              bool
		beforeErr, finishErr error
		class, code          string
		calls                int
	}{
		{"before-cancel-storage", false, storageErr, nil, safediagnostic.ClassPersistenceFailed, safediagnostic.ValidationJournalFailed, 0},
		{"before-cancel-state", false, nil, nil, safediagnostic.ClassLocalContractRejected, safediagnostic.ValidationBindingInvalid, 0},
		{"finish-storage", true, nil, storageErr, safediagnostic.ClassPersistenceFailed, safediagnostic.ValidationJournalFailed, 1},
	} {
		t.Run(test.name, func(t *testing.T) {
			h := newConnectionHarness(t)
			connection, err := h.provider.(*vaultConnections).connection(context.Background())
			if err != nil {
				t.Fatal(err)
			}
			journal := &failingDiagnosticJournal{allowed: test.allowed, beforeCancelErr: test.beforeErr, finishErr: test.finishErr}
			err = cancelJournaledTask(context.Background(), connection, TemporaryTask{RunID: "test-run", TaskID: "test-task", AlgorithmCode: h.algorithmCode}, journal)
			d := safediagnostic.FromError(err)
			if !errors.Is(err, ErrTemporaryCleanupUnconfirmed) || d == nil || d.Class != test.class || d.ValidationCode != test.code || d.Phase != safediagnostic.PhaseJournal || d.Operation != safediagnostic.OperationPictureCancel {
				t.Fatalf("wrong cancellation diagnostic: %+v", d)
			}
			_, _, cancelled := h.device.operationRequests()
			if len(cancelled) != test.calls {
				t.Fatalf("cancel calls=%d want %d", len(cancelled), test.calls)
			}
			if strings.Contains(err.Error(), "private/path") {
				t.Fatal("SQL text escaped")
			}
		})
	}
}

func TestTemporaryCreateJournalStorageFailuresRemainPersistenceFailures(t *testing.T) {
	storageErr := errors.New("sqlite private/path: SQL write failed")
	for _, finish := range []bool{false, true} {
		name := "before-create"
		if finish {
			name = "finish-not-created"
		}
		t.Run(name, func(t *testing.T) {
			h := newConnectionHarness(t)
			p := h.provider.(*vaultConnections)
			journal := &failingDiagnosticJournal{allowed: true}
			if finish {
				journal.finishErr = storageErr
				h.device.createErr = &adapter.V1Error{BusinessRejected: true}
			} else {
				journal.beforeCreateErr = storageErr
			}
			p.taskJournal, p.diagnostics, p.diagnosticRunID = journal, journal, "test-run"
			h.device.page.Rows[0].AlgorithmID = h.device.detail.AlgorithmCode
			content := h.device.jpegContent()
			_, err := p.analyzeTemporarySnapshot(context.Background(), temporaryVisionAnalysis{runID: "test-run", prompt: "synthetic question", promptSHA256: liveDigest("synthetic question"), evidenceRef: "media_test", evidenceSHA: liveDigest(string(content)), jpeg: content})
			if err == nil {
				t.Fatal("journal failure produced success")
			}
			found := false
			for _, d := range journal.recorded {
				if d.Phase == safediagnostic.PhaseJournal {
					found = true
					if d.Class != safediagnostic.ClassPersistenceFailed || d.Operation != safediagnostic.OperationPictureCreate || d.ValidationCode != safediagnostic.ValidationJournalFailed {
						t.Fatalf("wrong create diagnostic: %+v", d)
					}
				}
			}
			if !found {
				t.Fatal("journal failure diagnostic missing")
			}
			created, detected, cancelled := h.device.operationRequests()
			wantCreate := 0
			if finish {
				wantCreate = 1
			}
			if len(created) != wantCreate || len(detected) != 0 || len(cancelled) != 0 {
				t.Fatalf("unexpected writes create=%d detect=%d cancel=%d", len(created), len(detected), len(cancelled))
			}
			if strings.Contains(err.Error(), "private/path") {
				t.Fatal("SQL text escaped")
			}
		})
	}
}

func TestTemporaryAnalyzerExpiredContextIsNotInvalidInput(t *testing.T) {
	for _, deadline := range []bool{false, true} {
		ctx, cancel := context.WithCancel(context.Background())
		want := error(context.Canceled)
		code := ""
		if deadline {
			cancel()
			ctx, cancel = context.WithDeadline(context.Background(), time.Now().Add(-time.Second))
			want = context.DeadlineExceeded
			code = safediagnostic.ValidationDeadlineExpired
		} else {
			cancel()
		}
		journal := &failingDiagnosticJournal{}
		p := &vaultConnections{diagnosticRunID: "test-run", diagnostics: journal}
		_, err := NewTemporaryAnalyzer(p).Analyze(ctx, temporary.AnalysisRequest{RunID: "test-run"})
		cancel()
		d := safediagnostic.FromError(err)
		if !errors.Is(err, want) || d == nil || d.Operation != safediagnostic.OperationAnalysis || d.Phase != safediagnostic.PhaseBeforeDispatch || d.Class != safediagnostic.ClassUnavailable || d.ValidationCode != code {
			t.Fatalf("wrong context diagnostic: %+v", d)
		}
		if len(journal.recorded) != 1 || journal.recorded[0].ValidationCode != code {
			t.Fatal("wrong persisted context classification")
		}
	}
}
