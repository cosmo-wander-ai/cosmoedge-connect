//go:build !darwin && !windows

package credential

// OpenSystemStore has no plaintext fallback. Platforms without a native
// implementation fail before accepting any secret.
func OpenSystemStore(string) (SecretStore, error) {
	return nil, ErrUnsupported
}
