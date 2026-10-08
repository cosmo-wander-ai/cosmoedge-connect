//go:build !windows

package credential

import (
	"errors"
	"os"
	"syscall"

	"github.com/cosmo-wander-ai/cosmoedge-connect/internal/localstate"
)

type encryptedFileLock struct{ file *os.File }

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
	if err := syscall.Flock(int(file.Fd()), syscall.LOCK_EX); err != nil {
		_ = file.Close()
		return nil, err
	}
	return &encryptedFileLock{file: file}, nil
}

func (lock *encryptedFileLock) Close() error {
	if lock == nil || lock.file == nil {
		return nil
	}
	unlockErr := syscall.Flock(int(lock.file.Fd()), syscall.LOCK_UN)
	closeErr := lock.file.Close()
	lock.file = nil
	return errors.Join(unlockErr, closeErr)
}
