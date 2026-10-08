//go:build !windows

package inspectionauthority

import (
	"errors"
	"os"
	"path/filepath"
	"syscall"

	"github.com/cosmo-wander-ai/cosmoedge-connect/internal/localstate"
)

type sagaLock struct{ file *os.File }

func acquireSagaLock(databasePath string) (*sagaLock, error) {
	absolute, err := filepath.Abs(databasePath)
	if err != nil {
		return nil, err
	}
	if err := localstate.PrepareStateRoot(filepath.Dir(absolute)); err != nil {
		return nil, err
	}
	path := absolute + ".authority-saga.lock"
	file, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR, 0o600)
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
	return &sagaLock{file: file}, nil
}

func (lock *sagaLock) Close() error {
	if lock == nil || lock.file == nil {
		return nil
	}
	unlockErr := syscall.Flock(int(lock.file.Fd()), syscall.LOCK_UN)
	closeErr := lock.file.Close()
	lock.file = nil
	return errors.Join(unlockErr, closeErr)
}
