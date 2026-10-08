//go:build windows

package inspectionauthority

import (
	"errors"
	"os"
	"path/filepath"

	"github.com/cosmo-wander-ai/cosmoedge-connect/internal/localstate"
	"golang.org/x/sys/windows"
)

type sagaLock struct {
	file       *os.File
	overlapped windows.Overlapped
}

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
	lock := &sagaLock{file: file}
	if err := windows.LockFileEx(windows.Handle(file.Fd()), windows.LOCKFILE_EXCLUSIVE_LOCK, 0, 1, 0, &lock.overlapped); err != nil {
		_ = file.Close()
		return nil, err
	}
	return lock, nil
}

func (lock *sagaLock) Close() error {
	if lock == nil || lock.file == nil {
		return nil
	}
	unlockErr := windows.UnlockFileEx(windows.Handle(lock.file.Fd()), 0, 1, 0, &lock.overlapped)
	closeErr := lock.file.Close()
	lock.file = nil
	return errors.Join(unlockErr, closeErr)
}
