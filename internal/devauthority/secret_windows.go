//go:build windows

package devauthority

import (
	"crypto/sha256"
	"errors"
	"unsafe"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"
)

func protectSecret(secret []byte) ([]byte, error) {
	if len(secret) == 0 {
		return nil, errors.New("development credential is empty")
	}
	entropy, err := machineEntropy()
	if err != nil {
		return nil, err
	}
	in := windows.DataBlob{Size: uint32(len(secret)), Data: &secret[0]}
	entropyBlob := windows.DataBlob{Size: uint32(len(entropy)), Data: &entropy[0]}
	var out windows.DataBlob
	if err := windows.CryptProtectData(&in, nil, &entropyBlob, 0, nil, windows.CRYPTPROTECT_UI_FORBIDDEN, &out); err != nil {
		return nil, err
	}
	defer windows.LocalFree(windows.Handle(uintptr(unsafe.Pointer(out.Data))))
	protected := make([]byte, int(out.Size))
	copy(protected, unsafe.Slice(out.Data, int(out.Size)))
	return protected, nil
}

func unprotectSecret(protected []byte) ([]byte, error) {
	if len(protected) == 0 {
		return nil, errors.New("encrypted development credential is empty")
	}
	entropy, err := machineEntropy()
	if err != nil {
		return nil, err
	}
	in := windows.DataBlob{Size: uint32(len(protected)), Data: &protected[0]}
	entropyBlob := windows.DataBlob{Size: uint32(len(entropy)), Data: &entropy[0]}
	var out windows.DataBlob
	if err := windows.CryptUnprotectData(&in, nil, &entropyBlob, 0, nil, windows.CRYPTPROTECT_UI_FORBIDDEN, &out); err != nil {
		return nil, err
	}
	defer windows.LocalFree(windows.Handle(uintptr(unsafe.Pointer(out.Data))))
	secret := make([]byte, int(out.Size))
	copy(secret, unsafe.Slice(out.Data, int(out.Size)))
	return secret, nil
}

func machineEntropy() ([]byte, error) {
	key, err := registry.OpenKey(registry.LOCAL_MACHINE, `SOFTWARE\Microsoft\Cryptography`, registry.QUERY_VALUE)
	if err != nil {
		return nil, err
	}
	defer key.Close()
	machineID, _, err := key.GetStringValue("MachineGuid")
	if err != nil || machineID == "" {
		return nil, errors.New("Windows machine identity is unavailable")
	}
	sum := sha256.Sum256([]byte("CosmoEdge/development-device-authority/v1\x00" + machineID))
	return sum[:], nil
}
