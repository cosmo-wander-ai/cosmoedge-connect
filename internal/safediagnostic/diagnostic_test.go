package safediagnostic

import (
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"testing"
)

type nativeError struct{ secret string }

func (e *nativeError) Error() string { return e.secret }

func TestDiagnosticWrapPreservesIdentityWithoutExposingText(t *testing.T) {
	rc := 0
	d := Diagnostic{Operation: OperationCameraPicture, Phase: PhaseNativeResponse, Class: ClassNativeRejected, HTTPStatus: 200, ResCode: &rc, MsgCode: "12314"}
	cause := &nativeError{secret: "https://user:password@example.invalid/private?token=secret answer=private"}
	err := Wrap(cause, d)
	var native *nativeError
	if !errors.Is(err, cause) || !errors.As(err, &native) || native != cause {
		t.Fatal("error identity lost")
	}
	if strings.Contains(err.Error(), "private") {
		t.Fatal("error wrapper exposed arbitrary text")
	}
	got := FromError(fmt.Errorf("outer: %w", errors.Join(errors.New("other"), err)))
	if got == nil || got.Validate() != nil || got.MsgCode != "12314" || got.ResCode == nil || *got.ResCode != 0 {
		t.Fatalf("diagnostic = %#v", got)
	}
	data, _ := json.Marshal(got)
	for _, forbidden := range []string{"example.invalid", "password", "private", "secret", "token", "answer"} {
		if strings.Contains(string(data), forbidden) {
			t.Fatalf("diagnostic contains %q", forbidden)
		}
	}
	rc = 20
	*got.ResCode = 30
	if *FromError(err).ResCode != 0 {
		t.Fatal("diagnostic aliases caller or extracted pointer")
	}
	if Wrap(nil, d) != nil || FromError(nil) != nil {
		t.Fatal("nil changed")
	}
}

func TestDiagnosticRejectsNonAllowlistedFields(t *testing.T) {
	base := Diagnostic{Operation: OperationAnalysis, Phase: PhaseExtractLabel, Class: ClassLocalContractRejected}
	cases := map[string]func(*Diagnostic){
		"operation":        func(d *Diagnostic) { d.Operation = "https://user:password@device" },
		"phase":            func(d *Diagnostic) { d.Phase = "answer: private" },
		"class":            func(d *Diagnostic) { d.Class = "custom_failure" },
		"validation":       func(d *Diagnostic) { d.ValidationCode = "/private/image.jpg" },
		"http":             func(d *Diagnostic) { d.HTTPStatus = 12314 },
		"negative-native":  func(d *Diagnostic) { n := -1; d.ResCode = &n },
		"oversize-native":  func(d *Diagnostic) { n := int(uint64(1) << 32); d.ResCode = &n },
		"text-message":     func(d *Diagnostic) { d.MsgCode = "TASK_REJECTED" },
		"oversize-message": func(d *Diagnostic) { d.MsgCode = "4294967296" },
		"unicode-message":  func(d *Diagnostic) { d.MsgCode = "１２３１４" },
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			d := base
			mutate(&d)
			if !errors.Is(d.Validate(), ErrInvalidDiagnostic) {
				t.Fatal("invalid value accepted")
			}
			cause := errors.New("original")
			err := Wrap(cause, d)
			if !errors.Is(err, cause) || !errors.Is(err, ErrInvalidDiagnostic) || FromError(err) != nil {
				t.Fatal("invalid diagnostic escaped or cause lost")
			}
		})
	}
	for _, value := range []string{"0", "12314", "4294967295"} {
		if !NumericCode(value) {
			t.Fatalf("rejected %q", value)
		}
	}
	for _, value := range []string{"", "-1", "+1", "1.0", "1e3", "12314\n", "00000000000"} {
		if NumericCode(value) {
			t.Fatalf("accepted %q", value)
		}
	}
}

type invalidCarrier struct{ error }

func (e invalidCarrier) SafeDiagnostic() *Diagnostic { return &Diagnostic{Operation: "arbitrary"} }
func (e invalidCarrier) Unwrap() error               { return e.error }

func TestFromErrorSkipsInvalidCarrier(t *testing.T) {
	d := Diagnostic{Operation: OperationPictureDetect, Phase: PhaseDecodeJSON, Class: ClassOutcomeUnknown}
	err := invalidCarrier{Wrap(errors.New("cause"), d)}
	if got := FromError(err); got == nil || *got != d {
		t.Fatalf("diagnostic = %#v", got)
	}
}
