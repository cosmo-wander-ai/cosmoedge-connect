package changeflow

import (
	"context"
	"sync"
)

// MemoryStore is a deterministic device-free workflow store used by fixtures.
// Product composition must supply its persistent implementation.
type MemoryStore struct {
	mu      sync.Mutex
	records map[string]Record
}

func NewMemoryStore() *MemoryStore { return &MemoryStore{records: make(map[string]Record)} }

func (s *MemoryStore) Create(_ context.Context, record Record) (Record, error) {
	if s == nil || record.validate() != nil {
		return Record{}, ErrInvalid
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if existing, ok := s.records[record.WorkflowID]; ok {
		if sameRecord(existing, record) {
			return existing, nil
		}
		return Record{}, ErrConflict
	}
	s.records[record.WorkflowID] = record
	return record, nil
}

func (s *MemoryStore) Get(_ context.Context, workflowID string) (Record, error) {
	if s == nil || !validRef(workflowID) {
		return Record{}, ErrNotFound
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	record, ok := s.records[workflowID]
	if !ok {
		return Record{}, ErrNotFound
	}
	if record.validate() != nil {
		return Record{}, ErrInvalid
	}
	return record, nil
}

func (s *MemoryStore) CompareAndSwap(_ context.Context, next Record, expectedRevision uint64) (Record, error) {
	if s == nil || next.validate() != nil || expectedRevision == 0 {
		return Record{}, ErrInvalid
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	current, ok := s.records[next.WorkflowID]
	if !ok {
		return Record{}, ErrNotFound
	}
	if current.Revision != expectedRevision {
		return Record{}, ErrConflict
	}
	next.Revision = expectedRevision + 1
	if next.validate() != nil {
		return Record{}, ErrInvalid
	}
	s.records[next.WorkflowID] = next
	return next, nil
}

func sameRecord(first, second Record) bool {
	return first.Schema == second.Schema && first.WorkflowID == second.WorkflowID && first.Revision == second.Revision &&
		first.Request == second.Request && first.GrantID == second.GrantID && first.GrantScopeSHA256 == second.GrantScopeSHA256 &&
		first.ActionID == second.ActionID && first.LocalHandoffRef == second.LocalHandoffRef && first.State == second.State &&
		first.Reason == second.Reason && first.CreatedAt.Equal(second.CreatedAt) && first.UpdatedAt.Equal(second.UpdatedAt)
}
