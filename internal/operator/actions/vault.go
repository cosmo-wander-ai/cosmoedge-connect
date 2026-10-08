package actions

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"sync"
	"time"

	"github.com/cosmo-wander-ai/cosmoedge-connect/internal/operator/device"
)

var (
	ErrActionUnavailable = errors.New("foreground action authority is unavailable")
	ErrActionConflict    = errors.New("action authority is invalid or already consumed")
)

type material struct {
	id                  string
	kind                string
	sessionBinding      string
	resourceKey         string
	serial              string
	endpointFingerprint string
	expiresAt           time.Time
	task                device.Task
	originalSwitch      int
	targetSwitch        int
	beforeParameters    []device.ParameterField
	targetParameters    []device.ParameterField
	sourceName          string
	sourceURL           []byte
	sourceFingerprint   string
	catalogFingerprint  string
	catalogCountBefore  int
	token               string
	timer               *time.Timer
}

type memoryVault struct {
	mu        sync.Mutex
	now       func() time.Time
	materials map[string]*material
	tokens    map[string]string
}

func newMemoryVault(now func() time.Time) *memoryVault {
	return &memoryVault{now: now, materials: map[string]*material{}, tokens: map[string]string{}}
}

func (v *memoryVault) put(item *material) (string, error) {
	if item == nil || item.id == "" || item.sessionBinding == "" || !item.expiresAt.After(v.now()) {
		return "", ErrActionUnavailable
	}
	token, err := randomToken()
	if err != nil {
		return "", err
	}
	v.mu.Lock()
	defer v.mu.Unlock()
	v.sweepLocked()
	if _, exists := v.materials[item.id]; exists {
		return "", ErrActionConflict
	}
	item.token = token
	item.timer = time.AfterFunc(item.expiresAt.Sub(v.now()), func() { v.delete(item.id) })
	v.materials[item.id] = item
	v.tokens[token] = item.id
	return token, nil
}

func (v *memoryVault) get(id string) (*material, error) {
	v.mu.Lock()
	defer v.mu.Unlock()
	v.sweepLocked()
	item := v.materials[id]
	if item == nil {
		return nil, ErrActionUnavailable
	}
	return cloneMaterial(item), nil
}

func (v *memoryVault) consume(token, sessionBinding, expectedID, serial, endpointFingerprint string) (string, error) {
	v.mu.Lock()
	defer v.mu.Unlock()
	v.sweepLocked()
	id := v.tokens[token]
	item := v.materials[id]
	if item == nil || item.sessionBinding != sessionBinding || item.token != token || expectedID != "" && item.id != expectedID {
		return "", ErrActionConflict
	}
	// The connection fingerprint includes the selected connection epoch. An
	// A -> B -> A replacement cannot revive A's earlier proposal authority.
	if item.serial != serial || item.endpointFingerprint != endpointFingerprint {
		return "", ErrActionConflict
	}
	delete(v.tokens, token)
	item.token = ""
	if item.timer != nil {
		item.timer.Stop()
	}
	item.expiresAt = v.now().Add(proposalTTL)
	item.timer = time.AfterFunc(proposalTTL, func() { v.delete(item.id) })
	return id, nil
}

func (v *memoryVault) owns(id, sessionBinding string) bool {
	v.mu.Lock()
	defer v.mu.Unlock()
	v.sweepLocked()
	item := v.materials[id]
	return item != nil && item.sessionBinding == sessionBinding
}

func (v *memoryVault) delete(id string) {
	v.mu.Lock()
	defer v.mu.Unlock()
	v.deleteLocked(id)
}

func (v *memoryVault) sweepLocked() {
	now := v.now()
	for id, item := range v.materials {
		if !now.Before(item.expiresAt) {
			v.deleteLocked(id)
		}
	}
}

func (v *memoryVault) deleteLocked(id string) {
	item := v.materials[id]
	if item == nil {
		return
	}
	if item.timer != nil {
		item.timer.Stop()
	}
	delete(v.tokens, item.token)
	clear(item.sourceURL)
	for index := range item.beforeParameters {
		item.beforeParameters[index].Value = ""
	}
	for index := range item.targetParameters {
		item.targetParameters[index].Value = ""
	}
	delete(v.materials, id)
}

func randomToken() (string, error) {
	buffer := make([]byte, 32)
	if _, err := rand.Read(buffer); err != nil {
		return "", err
	}
	return hex.EncodeToString(buffer), nil
}

func cloneMaterial(item *material) *material {
	clone := *item
	clone.sourceURL = append([]byte(nil), item.sourceURL...)
	clone.beforeParameters = cloneFields(item.beforeParameters)
	clone.targetParameters = cloneFields(item.targetParameters)
	clone.timer = nil
	return &clone
}
