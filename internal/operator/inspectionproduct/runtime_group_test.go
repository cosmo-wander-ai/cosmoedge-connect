package inspectionproduct

import (
	"context"
	"errors"
	"slices"
	"sync"
	"testing"
)

func TestRuntimeGroupStartsInOrderAndStopsInReverseOnce(t *testing.T) {
	var mu sync.Mutex
	var events []string
	record := func(event string) {
		mu.Lock()
		events = append(events, event)
		mu.Unlock()
	}
	group, err := NewRuntimeGroup(
		&orderedRuntime{name: "standard", record: record},
		&orderedRuntime{name: "secondary", record: record},
	)
	if err != nil {
		t.Fatal(err)
	}
	if err := group.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	group.Stop()
	group.Stop()
	if err := group.Start(context.Background()); err == nil {
		t.Fatal("consumed runtime group restarted")
	}
	want := []string{"start:standard", "start:secondary", "stop:secondary", "stop:standard"}
	if !slices.Equal(events, want) {
		t.Fatalf("runtime group events=%v, want %v", events, want)
	}
}

func TestRuntimeGroupRollsBackPartiallyFailedStart(t *testing.T) {
	var events []string
	record := func(event string) { events = append(events, event) }
	group, err := NewRuntimeGroup(
		&orderedRuntime{name: "standard", record: record},
		&orderedRuntime{name: "secondary", record: record, startErr: errors.New("unavailable")},
		&orderedRuntime{name: "never", record: record},
	)
	if err != nil {
		t.Fatal(err)
	}
	if err := group.Start(context.Background()); err == nil {
		t.Fatal("runtime group accepted failed child")
	}
	group.Stop()
	want := []string{"start:standard", "start:secondary", "stop:secondary", "stop:standard"}
	if !slices.Equal(events, want) {
		t.Fatalf("runtime rollback events=%v, want %v", events, want)
	}
}

func TestRuntimeGroupRejectsTypedNilAndCanceledStart(t *testing.T) {
	var typedNil *orderedRuntime
	if group, err := NewRuntimeGroup(typedNil, &orderedRuntime{}); err == nil || group != nil {
		t.Fatalf("typed nil runtime accepted: group=%v err=%v", group, err)
	}
	group, err := NewRuntimeGroup(&orderedRuntime{}, &orderedRuntime{})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := group.Start(ctx); !errors.Is(err, context.Canceled) {
		t.Fatalf("canceled runtime group start error=%v", err)
	}
}

type orderedRuntime struct {
	name     string
	record   func(string)
	startErr error
}

func (r *orderedRuntime) Start(context.Context) error {
	if r.record != nil {
		r.record("start:" + r.name)
	}
	return r.startErr
}

func (r *orderedRuntime) Stop() {
	if r.record != nil {
		r.record("stop:" + r.name)
	}
}
