package dataset

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"strings"
	"sync"
)

const (
	minimumPseudonymKeyBytes = 32
	maximumPseudonymKeyBytes = 128
)

// HMACPseudonymizer provides stable, non-reversible strata identifiers. Its
// key belongs in protected local state and is copied on construction.
type HMACPseudonymizer struct {
	mu  sync.RWMutex
	key []byte
}

func NewHMACPseudonymizer(key []byte) (*HMACPseudonymizer, error) {
	if len(key) < minimumPseudonymKeyBytes || len(key) > maximumPseudonymKeyBytes {
		return nil, errors.New("dataset pseudonym key length is invalid")
	}
	return &HMACPseudonymizer{key: append([]byte(nil), key...)}, nil
}

func (p *HMACPseudonymizer) Pseudonym(domain string, values ...string) (string, error) {
	if p == nil || !validOpaqueRef(domain) || len(values) == 0 || len(values) > 8 {
		return "", errors.New("dataset pseudonym request is invalid")
	}
	p.mu.RLock()
	defer p.mu.RUnlock()
	if len(p.key) == 0 {
		return "", errors.New("dataset pseudonym request is invalid")
	}
	mac := hmac.New(sha256.New, p.key)
	_, _ = mac.Write([]byte("cosmoedge.dataset.pseudonym.v3\x00"))
	_, _ = mac.Write([]byte(domain))
	for _, value := range values {
		if !validOpaqueRef(value) {
			return "", errors.New("dataset pseudonym input is invalid")
		}
		_, _ = mac.Write([]byte{0})
		_, _ = mac.Write([]byte(value))
	}
	return strings.ReplaceAll(domain, ":", "_") + "_" + hex.EncodeToString(mac.Sum(nil)[:16]), nil
}

// Close clears the in-memory key copy. Calls after Close fail closed.
func (p *HMACPseudonymizer) Close() {
	if p == nil {
		return
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	clear(p.key)
	p.key = nil
}
