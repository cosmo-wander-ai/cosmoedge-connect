//go:build windows

package credential

import (
	"crypto/sha256"
	"errors"
	"runtime"
	"strings"
	"unsafe"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"
)

type windowsProtector struct {
	entropy []byte
}

func OpenSystemStore(stateRoot string) (SecretStore, error) {
	root, err := prepareSystemRoot(stateRoot)
	if err != nil {
		return nil, err
	}
	namespace, err := namespaceForRoot(root)
	if err != nil {
		return nil, err
	}
	protector, err := newWindowsProtector(namespace)
	if err != nil {
		return nil, err
	}
	return newProtectedFileStore(root, protector)
}

func newWindowsProtector(namespace string) (*windowsProtector, error) {
	key, err := registry.OpenKey(registry.LOCAL_MACHINE, `SOFTWARE\Microsoft\Cryptography`, registry.QUERY_VALUE)
	if err != nil {
		return nil, errors.New("Windows machine identity is unavailable")
	}
	defer key.Close()
	machineID, _, err := key.GetStringValue("MachineGuid")
	if err != nil || strings.TrimSpace(machineID) == "" {
		return nil, errors.New("Windows machine identity is unavailable")
	}
	sum := sha256.Sum256([]byte("CosmoEdge/ordinary-device-credential/v2\x00" + machineID + "\x00" + namespace))
	return &windowsProtector{entropy: append([]byte(nil), sum[:]...)}, nil
}

func (p *windowsProtector) Protect(secret []byte) ([]byte, error) {
	if len(secret) == 0 || len(p.entropy) == 0 {
		return nil, errors.New("Windows credential protection input is invalid")
	}
	in := windows.DataBlob{Size: uint32(len(secret)), Data: &secret[0]}
	entropy := windows.DataBlob{Size: uint32(len(p.entropy)), Data: &p.entropy[0]}
	var out windows.DataBlob
	if err := windows.CryptProtectData(&in, nil, &entropy, 0, nil, windows.CRYPTPROTECT_UI_FORBIDDEN, &out); err != nil {
		return nil, err
	}
	return copyAndClearLocalBlob(&out)
}

func (p *windowsProtector) Unprotect(protected []byte) ([]byte, error) {
	if len(protected) == 0 || len(p.entropy) == 0 {
		return nil, errors.New("Windows credential envelope is invalid")
	}
	in := windows.DataBlob{Size: uint32(len(protected)), Data: &protected[0]}
	entropy := windows.DataBlob{Size: uint32(len(p.entropy)), Data: &p.entropy[0]}
	var out windows.DataBlob
	if err := windows.CryptUnprotectData(&in, nil, &entropy, 0, nil, windows.CRYPTPROTECT_UI_FORBIDDEN, &out); err != nil {
		return nil, err
	}
	return copyAndClearLocalBlob(&out)
}

func copyAndClearLocalBlob(blob *windows.DataBlob) ([]byte, error) {
	if blob == nil || blob.Size == 0 || blob.Data == nil {
		if blob != nil && blob.Data != nil {
			_, _ = windows.LocalFree(windows.Handle(uintptr(unsafe.Pointer(blob.Data))))
		}
		return nil, errors.New("Windows credential result is invalid")
	}
	native := unsafe.Slice(blob.Data, int(blob.Size))
	result := append([]byte(nil), native...)
	clear(native)
	runtime.KeepAlive(native)
	_, freeErr := windows.LocalFree(windows.Handle(uintptr(unsafe.Pointer(blob.Data))))
	blob.Data = nil
	blob.Size = 0
	if freeErr != nil {
		clear(result)
		return nil, errors.New("Windows credential memory release failed")
	}
	return result, nil
}

var _ secretProtector = (*windowsProtector)(nil)
