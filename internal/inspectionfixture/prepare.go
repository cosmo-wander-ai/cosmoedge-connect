package inspectionfixture

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"io"
	"os"
	"path/filepath"

	"github.com/cosmo-wander-ai/cosmoedge-connect/internal/localstate"
)

// PrepareAssetRoot copies the repository fixture assets into a new owner-only
// runtime directory. Runtime loading remains strict; repository file modes are
// never treated as runtime authorization.
func PrepareAssetRoot(sourceRoot, runtimeRoot string) error {
	source, err := filepath.Abs(sourceRoot)
	if err != nil {
		return err
	}
	destination, err := filepath.Abs(runtimeRoot)
	if err != nil || destination == string(os.PathSeparator) || source == destination {
		return errors.New("fixture asset preparation paths are invalid")
	}
	if info, err := os.Lstat(source); err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return errors.New("fixture repository asset source must be a real directory")
	}
	var installed assets
	destinationExists := false
	if _, err := os.Lstat(destination); err == nil {
		installed, err = loadAssets(destination)
		if err != nil {
			return err
		}
		destinationExists = true
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	parent := filepath.Dir(destination)
	if err := localstate.PrepareStateRoot(parent); err != nil {
		return err
	}
	temporary, err := newProtectedTemporaryAssetRoot(parent)
	if err != nil {
		return err
	}
	committed := false
	defer func() {
		if !committed {
			_ = os.RemoveAll(temporary)
		}
	}()
	for _, name := range []string{snapshotAssetName, clipAssetName, clipFrameAssetName, eventAssetName, manifestAssetName} {
		inputPath := filepath.Join(source, name)
		info, err := os.Lstat(inputPath)
		if err != nil || !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 || info.Size() < 1 || info.Size() > maxFixtureAsset {
			return errors.New("fixture repository asset is missing or unsafe")
		}
		input, err := os.Open(inputPath)
		if err != nil {
			return err
		}
		output, err := os.OpenFile(filepath.Join(temporary, name), os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
		if err != nil {
			_ = input.Close()
			return err
		}
		_, copyErr := io.Copy(output, io.LimitReader(input, maxFixtureAsset+1))
		syncErr := output.Sync()
		closeOutputErr := output.Close()
		closeInputErr := input.Close()
		if err := errors.Join(copyErr, syncErr, closeOutputErr, closeInputErr); err != nil {
			return err
		}
		if err := localstate.ProtectFile(filepath.Join(temporary, name)); err != nil {
			return err
		}
	}
	prepared, err := loadAssets(temporary)
	if err != nil {
		return err
	}
	if destinationExists && sameAssets(installed, prepared) {
		return nil
	}
	if destinationExists {
		backup := temporary + ".previous"
		if err := os.Rename(destination, backup); err != nil {
			return err
		}
		if err := os.Rename(temporary, destination); err != nil {
			rollbackErr := os.Rename(backup, destination)
			return errors.Join(err, rollbackErr)
		}
		committed = true
		if err := os.RemoveAll(backup); err != nil {
			return err
		}
	} else {
		if err := os.Rename(temporary, destination); err != nil {
			return err
		}
		committed = true
	}
	loaded, err := loadAssets(destination)
	if err != nil {
		return err
	}
	return loaded.validate()
}

func newProtectedTemporaryAssetRoot(parent string) (string, error) {
	for attempt := 0; attempt < 8; attempt++ {
		random := make([]byte, 16)
		if _, err := rand.Read(random); err != nil {
			return "", err
		}
		candidate := filepath.Join(parent, ".inspection-fixture-assets-"+hex.EncodeToString(random))
		clear(random)
		if _, err := os.Lstat(candidate); err == nil {
			continue
		} else if !errors.Is(err, os.ErrNotExist) {
			return "", err
		}
		if err := localstate.PrepareStateRoot(candidate); err != nil {
			return "", err
		}
		return candidate, nil
	}
	return "", errors.New("could not allocate a unique fixture asset directory")
}

func sameAssets(left, right assets) bool {
	return left.snapshotWidth == right.snapshotWidth && left.snapshotHeight == right.snapshotHeight &&
		left.clipWidth == right.clipWidth && left.clipHeight == right.clipHeight && left.clipFrameRate == right.clipFrameRate &&
		left.clipDuration == right.clipDuration && left.clipFrameOffset == right.clipFrameOffset &&
		bytes.Equal(left.snapshot, right.snapshot) && bytes.Equal(left.clip, right.clip) &&
		bytes.Equal(left.clipFrame, right.clipFrame) && bytes.Equal(left.event, right.event) && bytes.Equal(left.manifest, right.manifest)
}
