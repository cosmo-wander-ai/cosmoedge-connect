//go:build windows

package devauthority

import (
	"bytes"
	"testing"
)

func TestWindowsDPAPIRoundTrip(t *testing.T) {
	secret := []byte("dpapi-development-secret-private")
	protected, err := protectSecret(secret)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(protected, secret) {
		t.Fatal("DPAPI envelope contains the clear-text secret")
	}
	opened, err := unprotectSecret(protected)
	if err != nil {
		t.Fatal(err)
	}
	defer clear(opened)
	if !bytes.Equal(opened, secret) {
		t.Fatal("DPAPI round trip changed the secret")
	}
}
