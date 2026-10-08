//go:build windows

package credential

import (
	"errors"
	"os"

	"github.com/cosmo-wander-ai/cosmoedge-connect/internal/localstate"
	"golang.org/x/sys/windows"
)

type encryptedFileLock struct {
	file       *os.File
	overlapped windows.Overlapped
}

func acquireEncryptedFileLock(statePath string) (*encryptedFileLock, error) {
	path := statePath + ".lock"
	file, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_RDWR, 0o600)
	if errors.Is(err, os.ErrExist) {
		if err := localstate.ValidateFile(path); err != nil {
			return nil, err
		}
		file, err = os.OpenFile(path, os.O_RDWR, 0)
	}
	if err != nil {
		return nil, err
	}
	if err := localstate.ProtectFile(path); err != nil {
		_ = file.Close()
		return nil, err
	}
	lock := &encryptedFileLock{file: file}
	if err := windows.LockFileEx(windows.Handle(file.Fd()), windows.LOCKFILE_EXCLUSIVE_LOCK, 0, 1, 0, &lock.overlapped); err != nil {
		_ = file.Close()
		return nil, err
	}
	return lock, nil
}

func (lock *encryptedFileLock) Close() error {
	if lock == nil || lock.file == nil {
		return nil
	}
	unlockErr := windows.UnlockFileEx(windows.Handle(lock.file.Fd()), 0, 1, 0, &lock.overlapped)
	closeErr := lock.file.Close()
	lock.file = nil
	return errors.Join(unlockErr, closeErr)
}
