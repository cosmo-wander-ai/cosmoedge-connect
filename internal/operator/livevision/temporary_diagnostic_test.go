package livevision

import (
	"context"
	"errors"
	"fmt"
	"math"
	"strings"
	"testing"

	"github.com/cosmo-wander-ai/cosmoedge-connect/internal/adapter"
	"github.com/cosmo-wander-ai/cosmoedge-connect/internal/operator/inspectionadapter"
	"github.com/cosmo-wander-ai/cosmoedge-connect/internal/safediagnostic"
)

func TestTemporaryLocalFailureClassificationsDoNotRetainModelText(t *testing.T) {
	for _, test := range []struct {
		name string
		raw  []byte
		code string
	}{
		{"encoding", []byte{0xff, 0xfe}, safediagnostic.ValidationEncodingInvalid},
		{"normalization", []byte("是 "), safediagnostic.ValidationNormalizationInvalid},
		{"vocabulary", []byte("maybe"), safediagnostic.ValidationVocabularyInvalid},
	} {
		t.Run(test.name, func(t *testing.T) {
			_, err := validateTemporaryModelAnswer(test.raw)
			d := safediagnostic.FromError(err)
			if d == nil || d.Operation != safediagnostic.OperationAnalysis || d.Phase != safediagnostic.PhaseValidateClosedVocabulary || d.ValidationCode != test.code || !errors.Is(err, inspectionadapter.ErrInvalidResponse) {
				t.Fatalf("lost local validation classification: %+v %v", d, err)
			}
			if strings.Contains(err.Error(), string(test.raw)) {
				t.Fatal("model bytes entered error text")
			}
		})
	}
	for _, test := range []struct {
		name       string
		confidence []adapter.PictureTaskConfidence
		code       string
	}{
		{"empty", nil, safediagnostic.ValidationLabelCountInvalid},
		{"multiple", []adapter.PictureTaskConfidence{{Label: "是", Confidence: 1}, {Label: "否", Confidence: 1}}, safediagnostic.ValidationLabelCountInvalid},
		{"confidence", []adapter.PictureTaskConfidence{{Label: "是", Confidence: math.NaN()}}, safediagnostic.ValidationConfidenceInvalid},
	} {
		t.Run(test.name, func(t *testing.T) {
			_, err := temporaryDetectionText(adapter.PictureTaskDetectResult{Areas: []adapter.PictureTaskArea{{Detected: true, Targets: []adapter.PictureTaskTarget{{Confidence: test.confidence}}}}})
			d := safediagnostic.FromError(err)
			if d == nil || d.Phase != safediagnostic.PhaseExtractLabel || d.ValidationCode != test.code || !errors.Is(err, inspectionadapter.ErrInvalidResponse) {
				t.Fatalf("lost label extraction classification: %+v %v", d, err)
			}
		})
	}
}

func TestSanitizeDeviceErrorPreservesDiagnosticAndSentinelWithoutRawCause(t *testing.T) {
	diagnostic := safediagnostic.Diagnostic{Operation: safediagnostic.OperationPictureDetect, Phase: safediagnostic.PhaseTransport, Class: safediagnostic.ClassOutcomeUnknown}
	input := safediagnostic.Wrap(fmt.Errorf("http://private/secret answer: %w", context.DeadlineExceeded), diagnostic)
	err := sanitizeDeviceError(input)
	if !errors.Is(err, context.DeadlineExceeded) || safediagnostic.FromError(err) == nil || *safediagnostic.FromError(err) != diagnostic {
		t.Fatal("sanitizing dropped diagnostic or deadline sentinel")
	}
	for cause := err; cause != nil; cause = errors.Unwrap(cause) {
		if strings.Contains(cause.Error(), "secret") || strings.Contains(cause.Error(), "answer") {
			t.Fatal("sanitizer retained raw cause")
		}
	}
}
