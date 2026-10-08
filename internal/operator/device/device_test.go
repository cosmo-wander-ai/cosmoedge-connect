package device

import "testing"

func TestNewV1ClientBindsCapturesToDeviceWebOrigin(t *testing.T) {
	tests := map[string]struct {
		endpoint string
		want     string
	}{
		"http management port":  {endpoint: "http://192.0.2.10:8000", want: "http://192.0.2.10"},
		"https management port": {endpoint: "https://192.0.2.10:8443", want: "https://192.0.2.10"},
		"ipv6 management port":  {endpoint: "http://[2001:db8::10]:8000", want: "http://[2001:db8::10]"},
	}
	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			client, ok := NewV1Client(test.endpoint, "operator", "private").(*v1Client)
			if !ok || client.client.ImageBaseURL() != test.want {
				t.Fatalf("capture origin = %q, want %q", client.client.ImageBaseURL(), test.want)
			}
		})
	}
}

func TestCosmoEdgeMediaOriginRejectsInvalidEndpoint(t *testing.T) {
	for _, endpoint := range []string{
		"", "ftp://192.0.2.10:8000", "http://user@192.0.2.10:8000",
		"http://192.0.2.10:8000/private", "http://192.0.2.10:8000?private=value",
	} {
		if got := cosmoEdgeMediaOrigin(endpoint); got != "" {
			t.Fatalf("cosmoEdgeMediaOrigin(%q) = %q, want empty", endpoint, got)
		}
	}
}

func TestCanonicalTaskIDUsesDeviceIDOrCompatibleDerivedID(t *testing.T) {
	tests := map[string]struct {
		channelID   string
		algorithmID string
		explicitID  string
		want        string
	}{
		"explicit":   {"channel-1", "algorithm-1", "task-1", "task-1"},
		"derived":    {"channel-1", "algorithm-1", "", "channel-1_algorithm-1"},
		"incomplete": {"channel-1", "", "", ""},
	}
	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			if got := canonicalTaskID(test.channelID, test.algorithmID, test.explicitID); got != test.want {
				t.Fatalf("canonicalTaskID() = %q, want %q", got, test.want)
			}
		})
	}
}
