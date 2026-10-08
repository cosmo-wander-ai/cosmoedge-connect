package onboarding

import (
	"bytes"
	"encoding"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"testing"

	"github.com/cosmo-wander-ai/cosmoedge-connect/internal/operator/credential"
)

func TestProtectedOnboardingInputsFailClosedAcrossCommonProjections(t *testing.T) {
	access := Access{TenantID: "tenant-sensitive", SiteID: "site-sensitive", PrincipalSHA256: strings.Repeat("a", 64)}
	cases := []struct {
		name      string
		value     any
		sensitive []string
	}{
		{name: "access", value: access, sensitive: []string{"tenant-sensitive", "site-sensitive"}},
		{name: "create", value: CreateRequest{Access: access, Endpoint: "https://10.20.30.40:443", Username: "private-user", Secret: []byte("create-private-secret")}, sensitive: []string{"10.20.30.40", "private-user", "create-private-secret", "tenant-sensitive"}},
		{name: "update", value: UpdateEndpointRequest{Access: access, Endpoint: "https://10.20.30.41:443", Username: "updated-private-user"}, sensitive: []string{"10.20.30.41", "updated-private-user", "tenant-sensitive"}},
		{name: "rotate", value: RotateCredentialRequest{Access: access, Secret: []byte("rotated-private-secret")}, sensitive: []string{"rotated-private-secret", "tenant-sensitive"}},
		{name: "forget", value: ForgetRequest{Access: access, ProfileID: "dpf_private"}, sensitive: []string{"dpf_private", "tenant-sensitive"}},
		{name: "resume", value: ResumeRequest{Access: access, Secret: []byte("resume-private-secret")}, sensitive: []string{"resume-private-secret", "tenant-sensitive"}},
	}
	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			if _, err := json.Marshal(testCase.value); !errors.Is(err, credential.ErrProtectedProjection) {
				t.Fatalf("json projection error=%v", err)
			}
			textMarshaler, ok := testCase.value.(encoding.TextMarshaler)
			if !ok {
				t.Fatal("protected input does not implement encoding.TextMarshaler")
			}
			if _, err := textMarshaler.MarshalText(); !errors.Is(err, credential.ErrProtectedProjection) {
				t.Fatalf("text projection error=%v", err)
			}
			projected := fmt.Sprintf("%+v %#v", testCase.value, testCase.value)
			var logOutput bytes.Buffer
			logger := slog.New(slog.NewJSONHandler(&logOutput, nil))
			logger.Info("protected", slog.Any("request", testCase.value))
			projected += logOutput.String()
			for _, sensitive := range testCase.sensitive {
				if strings.Contains(projected, sensitive) {
					t.Fatalf("projection leaked %q: %s", sensitive, projected)
				}
			}
		})
	}
	if _, err := json.Marshal(Result{OperationID: operationID("1"), Status: StatusCompleted, Phase: PhaseCompleted}); err != nil {
		t.Fatalf("business result must remain serializable: %v", err)
	}
}

func TestOperationErrorDoesNotProjectProtectedCause(t *testing.T) {
	ref, err := credential.ParseRef("cred_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")
	if err != nil {
		t.Fatal(err)
	}
	value := &OperationError{
		OperationID: operationID("9"), Operation: OperationRotateCredential,
		Status: StatusOutcomeUnknown, Phase: PhaseOutcomeUnknown,
		cause: &credential.OutcomeUnknownError{Operation: "rotate", OldRef: ref, NewRef: ref},
	}
	if _, err := json.Marshal(value); !errors.Is(err, credential.ErrProtectedProjection) {
		t.Fatalf("operation error JSON projection error=%v", err)
	}
	if _, err := value.MarshalText(); !errors.Is(err, credential.ErrProtectedProjection) {
		t.Fatalf("operation error text projection error=%v", err)
	}
	projected := fmt.Sprintf("%v %+v %#v", value, value, value)
	var logOutput bytes.Buffer
	slog.New(slog.NewJSONHandler(&logOutput, nil)).Info("operation", slog.Any("error", value))
	projected += logOutput.String()
	for _, sensitive := range []string{ref.ProtectedValue(), value.OperationID} {
		if strings.Contains(projected, sensitive) {
			t.Fatalf("operation error projection leaked %q: %s", sensitive, projected)
		}
	}
	if !errors.Is(value, credential.ErrOutcomeUnknown) {
		t.Fatal("operation error no longer unwraps its protected cause")
	}
}
