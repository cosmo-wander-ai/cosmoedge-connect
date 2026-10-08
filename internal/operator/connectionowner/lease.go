package connectionowner

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync"

	"github.com/cosmo-wander-ai/cosmoedge-connect/internal/localstate"
)

var ErrAlreadyOwned = errors.New("CosmoEdge Connect state already has an active owner")

var processLeases = struct {
	sync.Mutex
	roots map[string]bool
}{roots: make(map[string]bool)}

// Lease excludes another new or compatibility service from the same state root.
// It is held for the entire generation, unlike per-write credential file locks.
// The lock file remains after release; deleting it would permit inode races.
type Lease struct {
	mu   sync.Mutex
	root string
	file *os.File
}

func AcquireLease(root string) (*Lease, error) {
	if strings.TrimSpace(root) == "" || strings.ContainsAny(root, "\x00?#") {
		return nil, errors.New("dedicated CosmoEdge Connect state root is required")
	}
	absolute, err := filepath.Abs(root)
	if err != nil || absolute == filepath.Dir(absolute) {
		return nil, errors.New("dedicated CosmoEdge Connect state root is required")
	}
	if err := localstate.PrepareStateRoot(absolute); err != nil {
		return nil, err
	}
	canonical, err := filepath.EvalSymlinks(absolute)
	if err != nil {
		return nil, err
	}
	processLeases.Lock()
	defer processLeases.Unlock()
	if processLeases.roots[canonical] {
		return nil, ErrAlreadyOwned
	}
	path := filepath.Join(canonical, "cosmoedge-connect-owner.lock")
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
	fail := func(err error) (*Lease, error) { _ = file.Close(); return nil, err }
	info, err := file.Stat()
	if err != nil {
		return fail(err)
	}
	if !info.Mode().IsRegular() {
		return fail(errors.New("CosmoEdge Connect owner lease is not a regular file"))
	}
	if err := localstate.ProtectFile(path); err != nil {
		return fail(err)
	}
	if err := lockFile(file); err != nil {
		return fail(err)
	}
	processLeases.roots[canonical] = true
	return &Lease{root: canonical, file: file}, nil
}

func (l *Lease) Close() error {
	if l == nil {
		return nil
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.file == nil {
		return nil
	}
	processLeases.Lock()
	defer processLeases.Unlock()
	err := errors.Join(unlockFile(l.file), l.file.Close())
	delete(processLeases.roots, l.root)
	l.file = nil
	return err
}
