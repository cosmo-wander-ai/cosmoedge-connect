package session

import "testing"

func TestNormalizeDeviceAddress(t *testing.T) {
	t.Parallel()
	tests := map[string]string{
		"10.20.30.40":             "http://10.20.30.40:8000",
		" 192.168.1.8 ":           "http://192.168.1.8:8000",
		"http://172.16.2.3:18000": "http://172.16.2.3:18000",
		"https://[fd00::22]:8443": "https://[fd00::22]:8443",
	}
	for input, want := range tests {
		input, want := input, want
		t.Run(input, func(t *testing.T) {
			t.Parallel()
			got, err := NormalizeDeviceAddress(input)
			if err != nil || got.URL != want {
				t.Fatalf("NormalizeDeviceAddress(%q)=%q, %v; want %q", input, got.URL, err, want)
			}
		})
	}
}

func TestNormalizeDeviceAddressRejectsUnsafeTargets(t *testing.T) {
	t.Parallel()
	for _, input := range []string{
		"", "device.internal", "https://example.com", "http://8.8.8.8:8000",
		"http://127.0.0.1:8000", "http://169.254.169.254:8000", "http://224.0.0.1:8000",
		"http://user:password@10.0.0.1:8000", "http://10.0.0.1:8000/path",
		"http://10.0.0.1:8000?token=secret", "http://10.0.0.1:8000#fragment",
	} {
		if _, err := NormalizeDeviceAddress(input); err == nil {
			t.Fatalf("unsafe target %q accepted", input)
		}
	}
}
