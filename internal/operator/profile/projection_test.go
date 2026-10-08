package profile

import (
	"bytes"
	"encoding/json"
	"fmt"
	"log/slog"
	"strings"
	"testing"
)

func TestBusinessSummaryDoesNotProjectConnectionOrIdentitySecrets(t *testing.T) {
	item := DeviceProfile{
		ProfileID: "dpf_00112233445566778899aabbccddeeff",
		TenantID:  "tenant-private", SiteID: "site-private", Alias: "一号店边缘设备",
		Endpoint: "http://10.20.30.40:8000", Username: "private-user",
		CredentialRef: "cred_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
		PinnedSerial:  "private-serial", PinnedType: "edge-box",
		TransportFingerprint: "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
		Generation:           7, State: StateActive, CredentialState: CredentialReady,
	}
	raw, err := json.Marshal(item.BusinessSummary())
	if err != nil {
		t.Fatal(err)
	}
	text := string(raw)
	for _, forbidden := range []string{
		"10.20.30.40", "private-user", "private-serial", "tenant-private", "site-private",
		"cred_", "sha256:", "endpoint", "username", "credentialRef", "pinnedSerial", "transportFingerprint",
	} {
		if strings.Contains(text, forbidden) {
			t.Fatalf("business summary exposed %q: %s", forbidden, text)
		}
	}
	if !strings.Contains(text, "一号店边缘设备") || !strings.Contains(text, "edge-box") {
		t.Fatalf("business summary lost safe labels: %s", text)
	}
}

func TestBusinessSummaryRequiresCredentialAttention(t *testing.T) {
	item := DeviceProfile{
		ProfileID: "dpf_00112233445566778899aabbccddeeff", Alias: "设备",
		PinnedType: "edge-box", Generation: 3, State: StateActive, CredentialState: CredentialInvalid,
	}
	summary := item.BusinessSummary()
	if summary.State != "credential_attention" || !summary.NeedsCredential {
		t.Fatalf("unexpected summary: %#v", summary)
	}
}

func TestProtectedProfileAndCredentialRefRejectGenericJSONProjection(t *testing.T) {
	item := DeviceProfile{
		ProfileID:     "dpf_00112233445566778899aabbccddeeff",
		CredentialRef: "cred_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
	}
	if raw, err := json.Marshal(item); err == nil || len(raw) != 0 {
		t.Fatalf("protected profile serialized: %s, %v", raw, err)
	}
	if raw, err := json.Marshal(item.CredentialRef); err == nil || len(raw) != 0 {
		t.Fatalf("credential capability serialized: %s, %v", raw, err)
	}
	for _, formatted := range []string{fmt.Sprintf("%v", item), fmt.Sprintf("%+v", item), fmt.Sprintf("%#v", item)} {
		if strings.Contains(formatted, "cred_") || strings.Contains(formatted, "dpf_") {
			t.Fatalf("protected profile formatting leaked material: %s", formatted)
		}
	}
	var log bytes.Buffer
	slog.New(slog.NewTextHandler(&log, nil)).Info("profile", "value", item)
	if strings.Contains(log.String(), "cred_") || strings.Contains(log.String(), "dpf_") {
		t.Fatalf("structured log leaked protected profile: %s", log.String())
	}
}

func TestProtectedProfileInputsAndEventsRejectGenericProjection(t *testing.T) {
	protected := []any{
		NewDeviceProfile{
			ProfileID: "dpf_00112233445566778899aabbccddeeff",
			TenantID:  "tenant-private", SiteID: "site-private", Endpoint: "http://10.20.30.40:8000",
			Username: "private-user", CredentialRef: "cred_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
		},
		UpdateDeviceProfile{
			ProfileID: "dpf_00112233445566778899aabbccddeeff",
			TenantID:  "tenant-private", SiteID: "site-private", Endpoint: "http://10.20.30.40:8000",
			Username: "private-user", CredentialRef: "cred_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
		},
		Event{
			ProfileID: "dpf_00112233445566778899aabbccddeeff",
			TenantID:  "tenant-private", SiteID: "site-private",
		},
	}
	for _, value := range protected {
		if raw, err := json.Marshal(value); err == nil || len(raw) != 0 {
			t.Fatalf("protected value serialized: %s, %v", raw, err)
		}
		for _, formatted := range []string{fmt.Sprintf("%v", value), fmt.Sprintf("%+v", value), fmt.Sprintf("%#v", value)} {
			for _, forbidden := range []string{"dpf_", "cred_", "tenant-private", "site-private", "10.20.30.40", "private-user"} {
				if strings.Contains(formatted, forbidden) {
					t.Fatalf("protected formatting leaked %q: %s", forbidden, formatted)
				}
			}
		}
		var log bytes.Buffer
		slog.New(slog.NewTextHandler(&log, nil)).Info("protected", "value", value)
		for _, forbidden := range []string{"dpf_", "cred_", "tenant-private", "site-private", "10.20.30.40", "private-user"} {
			if strings.Contains(log.String(), forbidden) {
				t.Fatalf("protected structured log leaked %q: %s", forbidden, log.String())
			}
		}
	}
}
