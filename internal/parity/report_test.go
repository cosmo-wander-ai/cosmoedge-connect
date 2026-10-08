package parity

import (
	"path/filepath"
	"reflect"
	"testing"
)

func TestNormalizedFileRoundTripIsSorted(t *testing.T) {
	path := filepath.Join(t.TempDir(), "normalized.json")
	input := []NormalizedResult{{Scenario: "z", Class: "unknown"}, {Scenario: "a", Class: "completed"}}
	if err := WriteNormalizedFile(path, input); err != nil {
		t.Fatal(err)
	}
	got, err := ReadNormalizedFile(path)
	if err != nil {
		t.Fatal(err)
	}
	want := []NormalizedResult{{Scenario: "a", Class: "completed"}, {Scenario: "z", Class: "unknown"}}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("normalized results=%#v want=%#v", got, want)
	}
}
