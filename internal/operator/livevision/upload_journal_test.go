package livevision

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/cosmo-wander-ai/cosmoedge-connect/internal/adapter"
	"github.com/cosmo-wander-ai/cosmoedge-connect/internal/safediagnostic"
)

type uploadJournalFailureStub struct{ failingDiagnosticJournal }

func (*uploadJournalFailureStub) BeforeUpload(context.Context, TemporaryUpload) error { return nil }
func (*uploadJournalFailureStub) RecordUpload(context.Context, TemporaryUpload) error { return nil }
func (j *uploadJournalFailureStub) BeforeUploadCancel(context.Context, TemporaryUpload) (bool, error) {
	return j.allowed, j.beforeCancelErr
}
func (j *uploadJournalFailureStub) FinishUpload(context.Context, TemporaryUpload, string) error {
	return j.finishErr
}

type uploadCancelStub struct{ calls int }

func (*uploadCancelStub) QueryUploadCapabilitiesContext(context.Context) (adapter.UploadCapabilities, error) {
	return adapter.UploadCapabilities{}, nil
}
func (*uploadCancelStub) UploadPictureJPEGContext(context.Context, adapter.StagedPictureUploadRequest) (adapter.StagedPictureUpload, error) {
	return adapter.StagedPictureUpload{}, nil
}
func (c *uploadCancelStub) CancelPictureUploadContext(context.Context, adapter.StagedPictureUpload) error {
	c.calls++
	return nil
}

func TestUploadCancelJournalFailureClassification(t *testing.T) {
	storageErr := errors.New("sqlite private/path: hidden SQL")
	for _, test := range []struct {
		name           string
		allowed        bool
		before, finish error
		class          string
		calls          int
	}{
		{"storage-before", false, storageErr, nil, safediagnostic.ClassPersistenceFailed, 0},
		{"state-not-allowed", false, nil, nil, safediagnostic.ClassLocalContractRejected, 0},
		{"storage-finish", true, nil, storageErr, safediagnostic.ClassPersistenceFailed, 1},
	} {
		t.Run(test.name, func(t *testing.T) {
			journal := &uploadJournalFailureStub{failingDiagnosticJournal{allowed: test.allowed, beforeCancelErr: test.before, finishErr: test.finish}}
			client := &uploadCancelStub{}
			err := cancelJournaledUpload(context.Background(), client, TemporaryUpload{RunID: "test-run"}, journal)
			diagnostic := safediagnostic.FromError(err)
			if err == nil || diagnostic == nil || diagnostic.Operation != safediagnostic.OperationPictureUploadCancel || diagnostic.Phase != safediagnostic.PhaseJournal || diagnostic.Class != test.class || client.calls != test.calls {
				t.Fatalf("wrong cleanup diagnostic/calls: %+v %d", diagnostic, client.calls)
			}
			if strings.Contains(err.Error(), "private/path") {
				t.Fatal("storage text escaped")
			}
		})
	}
}

func TestJournaledObservationCannotFallbackToBase64(t *testing.T) {
	h := newConnectionHarness(t)
	p := h.provider.(*vaultConnections)
	connection, err := p.connection(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	p.uploadJournal = &uploadJournalFailureStub{}
	_, err = p.detectStagedTemporaryPicture(context.Background(), connection, temporaryVisionAnalysis{}, adapter.PictureTaskDetectRequest{JPEG: h.device.jpegContent()})
	if err == nil {
		t.Fatal("missing staged capability silently accepted")
	}
	_, detects, _ := h.device.operationRequests()
	if len(detects) != 0 {
		t.Fatal("missing staged capability fell back to base64 Detect")
	}
	d := safediagnostic.FromError(err)
	if d == nil || d.Operation != safediagnostic.OperationUploadCapabilities {
		t.Fatal("missing staged capability classification lost")
	}
}
