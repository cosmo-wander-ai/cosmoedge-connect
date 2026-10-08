package inspectiontest

import (
	"errors"
	"fmt"
	"regexp"
	"sort"
	"sync"
	"time"
)

var idPrefixPattern = regexp.MustCompile(`^[A-Za-z][A-Za-z0-9_-]{0,31}$`)

// MonotonicClock advances by Step on every call to Now. Advance permits tests
// to move it further forward but never backwards.
type MonotonicClock struct {
	mu   sync.Mutex
	next time.Time
	step time.Duration
	last time.Time
}

func NewMonotonicClock(start time.Time, step time.Duration) (*MonotonicClock, error) {
	if start.IsZero() || step <= 0 {
		return nil, errors.New("fixture clock requires a start time and positive step")
	}
	return &MonotonicClock{next: start.UTC(), step: step}, nil
}

func (clock *MonotonicClock) Now() time.Time {
	clock.mu.Lock()
	defer clock.mu.Unlock()
	value := clock.next
	clock.last = value
	clock.next = clock.next.Add(clock.step)
	return value
}

func (clock *MonotonicClock) Peek() time.Time {
	clock.mu.Lock()
	defer clock.mu.Unlock()
	return clock.next
}

func (clock *MonotonicClock) Advance(duration time.Duration) error {
	if duration < 0 {
		return errors.New("fixture clock cannot move backwards")
	}
	clock.mu.Lock()
	clock.next = clock.next.Add(duration)
	clock.mu.Unlock()
	return nil
}

type ClockState struct {
	Next time.Time
	Last time.Time
	Step time.Duration
}

func (clock *MonotonicClock) Snapshot() ClockState {
	clock.mu.Lock()
	defer clock.mu.Unlock()
	return ClockState{Next: clock.next, Last: clock.last, Step: clock.step}
}

func RestoreMonotonicClock(state ClockState) (*MonotonicClock, error) {
	if state.Next.IsZero() || state.Step <= 0 || (!state.Last.IsZero() && state.Next.Before(state.Last)) {
		return nil, errors.New("fixture clock state is invalid")
	}
	return &MonotonicClock{next: state.Next.UTC(), last: state.Last.UTC(), step: state.Step}, nil
}

// DeterministicIDs provides prefix-local counters for fixture-owned identities.
type DeterministicIDs struct {
	mu       sync.Mutex
	counters map[string]uint64
}

func NewDeterministicIDs() *DeterministicIDs {
	return &DeterministicIDs{counters: map[string]uint64{}}
}

func (ids *DeterministicIDs) Next(prefix string) (string, error) {
	if ids == nil || !idPrefixPattern.MatchString(prefix) {
		return "", errors.New("fixture id prefix is invalid")
	}
	ids.mu.Lock()
	defer ids.mu.Unlock()
	if ids.counters == nil {
		ids.counters = map[string]uint64{}
	}
	ids.counters[prefix]++
	return fmt.Sprintf("%s-%06d", prefix, ids.counters[prefix]), nil
}

type IDState struct {
	Counters map[string]uint64
}

func (ids *DeterministicIDs) Snapshot() IDState {
	ids.mu.Lock()
	defer ids.mu.Unlock()
	state := IDState{Counters: make(map[string]uint64, len(ids.counters))}
	for prefix, value := range ids.counters {
		state.Counters[prefix] = value
	}
	return state
}

func RestoreDeterministicIDs(state IDState) (*DeterministicIDs, error) {
	ids := NewDeterministicIDs()
	keys := make([]string, 0, len(state.Counters))
	for prefix := range state.Counters {
		keys = append(keys, prefix)
	}
	sort.Strings(keys)
	for _, prefix := range keys {
		if !idPrefixPattern.MatchString(prefix) {
			return nil, errors.New("fixture id state contains an invalid prefix")
		}
		ids.counters[prefix] = state.Counters[prefix]
	}
	return ids, nil
}
