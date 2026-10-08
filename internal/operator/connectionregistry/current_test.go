package connectionregistry

import (
	"context"
	"errors"
	"path/filepath"
	"strings"
	"testing"
)

func TestCurrentSelectionOnlySwitchesAfterDurableExactCAS(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "state", "current.db")
	initial := Selection{ProfileID: "dpf_" + strings.Repeat("a", 32), Revision: 1}
	operationID, newID, target := "onb_"+strings.Repeat("b", 32), "dpf_"+strings.Repeat("c", 32), strings.Repeat("d", 64)
	store, err := OpenCurrentStore(path, initial.ProfileID)
	if err != nil {
		t.Fatal(err)
	}
	if err := store.prepare(ctx, initial, operationID, newID, target); err != nil {
		t.Fatal(err)
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
	store, err = OpenCurrentStore(path, initial.ProfileID)
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	if current, err := store.Current(ctx); err != nil || current != initial {
		t.Fatal("interrupted preparation activated the new profile")
	}
	wrong := initial
	wrong.Revision++
	if err := store.switchCurrent(ctx, wrong, operationID, newID, target); !errors.Is(err, ErrBindingConflict) {
		t.Fatalf("stale CAS: %v", err)
	}
	var state string
	if err := store.db.QueryRow("SELECT state FROM replacements WHERE operation_id=?", operationID).Scan(&state); err != nil || state != "prepared" {
		t.Fatal("failed switch lost recovery evidence")
	}
	if err := store.switchCurrent(ctx, initial, operationID, newID, target); err != nil {
		t.Fatal(err)
	}
	if current, err := store.Current(ctx); err != nil || current.ProfileID != newID || current.Revision != 2 {
		t.Fatal("exact switch not durable")
	}
	if err := store.switchCurrent(ctx, initial, operationID, newID, target); !errors.Is(err, ErrBindingConflict) {
		t.Fatal("old replacement confirmation replayed")
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
	store, err = OpenCurrentStore(path, initial.ProfileID)
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	if current, err := store.Current(ctx); err != nil || current.ProfileID != newID || current.Revision != 2 {
		t.Fatal("restart reverted current selection")
	}
	if err := store.db.QueryRow("SELECT state FROM replacements WHERE operation_id=?", operationID).Scan(&state); err != nil || state != "switched" {
		t.Fatal("switch evidence absent")
	}
}
