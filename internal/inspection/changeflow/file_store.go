package changeflow

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/cosmo-wander-ai/cosmoedge-connect/internal/localstate"
	"github.com/cosmo-wander-ai/cosmoedge-connect/internal/strictjson"
)

const (
	fileStoreSchema = "cosmoedge.inspection.changeflow.store.v2"
	maxStoreBytes   = 8 << 20
	maxStoreRecords = 10_000
)

var ErrPersistenceOutcomeUnknown = errors.New("persistent change workflow durability outcome is unknown")

type storedRequest struct {
	RequestID        string    `json:"requestId"`
	TenantID         string    `json:"tenantId"`
	SiteID           string    `json:"siteId"`
	DeviceProfileID  string    `json:"deviceProfileId"`
	PrincipalSHA256  string    `json:"principalSha256"`
	OperationKind    string    `json:"operationKind"`
	RequestedAt      time.Time `json:"requestedAt"`
	RequestExpiresAt time.Time `json:"requestExpiresAt"`
}

type storedRecord struct {
	Schema             string        `json:"schema"`
	WorkflowID         string        `json:"workflowId"`
	Revision           uint64        `json:"revision"`
	Request            storedRequest `json:"request"`
	GrantID            string        `json:"grantId"`
	GrantScopeSHA256   string        `json:"grantScopeSha256"`
	ActionID           string        `json:"actionId"`
	LocalHandoffRef    string        `json:"localHandoffRef"`
	ActionEvidenceRef  string        `json:"actionEvidenceRef,omitempty"`
	ReadbackSHA256     string        `json:"readbackSha256,omitempty"`
	CatalogFingerprint string        `json:"catalogFingerprint,omitempty"`
	AssignmentRef      string        `json:"assignmentRef,omitempty"`
	State              State         `json:"state"`
	Reason             string        `json:"reason"`
	CreatedAt          time.Time     `json:"createdAt"`
	UpdatedAt          time.Time     `json:"updatedAt"`
}

type storedEnvelope struct {
	Schema   string         `json:"schema"`
	Revision uint64         `json:"revision"`
	Records  []storedRecord `json:"records"`
	SHA256   string         `json:"sha256"`
}

type FileStore struct {
	mu       sync.Mutex
	path     string
	revision uint64
	records  map[string]Record
}

func OpenFileStore(path string) (*FileStore, error) {
	if strings.TrimSpace(path) == "" || strings.ContainsAny(path, "\x00?#") {
		return nil, errors.New("persistent change workflow store path is invalid")
	}
	absolute, err := filepath.Abs(path)
	if err != nil {
		return nil, err
	}
	root := filepath.Dir(absolute)
	if err := localstate.PrepareStateRoot(root); err != nil {
		return nil, err
	}
	store := &FileStore{path: absolute, revision: 1, records: make(map[string]Record)}
	if _, err := os.Lstat(absolute); errors.Is(err, os.ErrNotExist) {
		_, err := store.persistLocked()
		if err != nil {
			return nil, err
		}
		return store, nil
	} else if err != nil {
		return nil, err
	}
	if err := localstate.ValidateFile(absolute); err != nil {
		return nil, fmt.Errorf("reject existing persistent change workflow store: %w", err)
	}
	envelope, err := readStoredEnvelope(absolute)
	if err != nil {
		return nil, err
	}
	store.revision = envelope.Revision
	for _, item := range envelope.Records {
		record := item.record()
		store.records[record.WorkflowID] = record
	}
	return store, nil
}

func (s *FileStore) Create(_ context.Context, record Record) (Record, error) {
	if s == nil || record.validate() != nil {
		return Record{}, ErrInvalid
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if current, ok := s.records[record.WorkflowID]; ok {
		if sameRecord(current, record) {
			return current, nil
		}
		return Record{}, ErrConflict
	}
	if len(s.records) >= maxStoreRecords {
		return Record{}, errors.New("persistent change workflow store capacity is exhausted")
	}
	s.records[record.WorkflowID] = record
	s.revision++
	committed, err := s.persistLocked()
	if err != nil {
		if !committed {
			delete(s.records, record.WorkflowID)
			s.revision--
		}
		return Record{}, err
	}
	return record, nil
}

func (s *FileStore) Get(_ context.Context, workflowID string) (Record, error) {
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

func (s *FileStore) CompareAndSwap(_ context.Context, next Record, expectedRevision uint64) (Record, error) {
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
	previous := current
	next.Revision = expectedRevision + 1
	if next.validate() != nil {
		return Record{}, ErrInvalid
	}
	s.records[next.WorkflowID] = next
	s.revision++
	committed, err := s.persistLocked()
	if err != nil {
		if !committed {
			s.records[next.WorkflowID] = previous
			s.revision--
		}
		return Record{}, err
	}
	return next, nil
}

func (s *FileStore) persistLocked() (bool, error) {
	envelope, err := buildStoredEnvelope(s.revision, s.records)
	if err != nil {
		return false, err
	}
	raw, err := json.Marshal(envelope)
	if err != nil || len(raw) > maxStoreBytes {
		return false, errors.New("persistent change workflow store exceeds its bound")
	}
	root := filepath.Dir(s.path)
	temporary, err := os.CreateTemp(root, ".changeflow-v2-")
	if err != nil {
		return false, err
	}
	temporaryPath := temporary.Name()
	committed := false
	defer func() {
		_ = temporary.Close()
		if !committed {
			_ = os.Remove(temporaryPath)
		}
	}()
	if err := temporary.Chmod(0o600); err != nil {
		return false, err
	}
	if _, err := temporary.Write(raw); err != nil {
		return false, err
	}
	if err := temporary.Sync(); err != nil {
		return false, err
	}
	if err := temporary.Close(); err != nil {
		return false, err
	}
	if err := localstate.ProtectFile(temporaryPath); err != nil {
		return false, err
	}
	if err := replaceStoreFile(temporaryPath, s.path); err != nil {
		return false, err
	}
	committed = true
	if err := localstate.ValidateFile(s.path); err != nil {
		return true, ErrPersistenceOutcomeUnknown
	}
	if err := syncStoreDirectory(root); err != nil {
		return true, ErrPersistenceOutcomeUnknown
	}
	return true, nil
}

func buildStoredEnvelope(revision uint64, records map[string]Record) (storedEnvelope, error) {
	if revision == 0 || len(records) > maxStoreRecords {
		return storedEnvelope{}, ErrInvalid
	}
	items := make([]storedRecord, 0, len(records))
	for _, record := range records {
		if record.validate() != nil {
			return storedEnvelope{}, ErrInvalid
		}
		items = append(items, persistRecord(record))
	}
	sort.Slice(items, func(i, j int) bool { return items[i].WorkflowID < items[j].WorkflowID })
	unsigned := struct {
		Schema   string         `json:"schema"`
		Revision uint64         `json:"revision"`
		Records  []storedRecord `json:"records"`
	}{fileStoreSchema, revision, items}
	raw, err := json.Marshal(unsigned)
	if err != nil {
		return storedEnvelope{}, err
	}
	digest := sha256.Sum256(raw)
	return storedEnvelope{Schema: fileStoreSchema, Revision: revision, Records: items, SHA256: hex.EncodeToString(digest[:])}, nil
}

func readStoredEnvelope(path string) (storedEnvelope, error) {
	file, err := os.Open(path)
	if err != nil {
		return storedEnvelope{}, err
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil || info.Size() <= 0 || info.Size() > maxStoreBytes {
		return storedEnvelope{}, errors.New("persistent change workflow store size is invalid")
	}
	raw := make([]byte, info.Size())
	if _, err := io.ReadFull(file, raw); err != nil {
		return storedEnvelope{}, err
	}
	var envelope storedEnvelope
	if err := strictjson.ValidateExactFields(raw, &envelope, 12); err != nil {
		return storedEnvelope{}, err
	}
	if err := json.Unmarshal(raw, &envelope); err != nil {
		return storedEnvelope{}, err
	}
	if envelope.Schema != fileStoreSchema || envelope.Revision == 0 || len(envelope.Records) > maxStoreRecords {
		return storedEnvelope{}, errors.New("persistent change workflow store schema is unsupported; explicitly reset this development store")
	}
	records := make(map[string]Record, len(envelope.Records))
	for index, item := range envelope.Records {
		record := item.record()
		if record.validate() != nil || index > 0 && envelope.Records[index-1].WorkflowID >= item.WorkflowID {
			return storedEnvelope{}, errors.New("persistent change workflow store record is invalid")
		}
		records[record.WorkflowID] = record
	}
	expected, err := buildStoredEnvelope(envelope.Revision, records)
	if err != nil || expected.SHA256 != envelope.SHA256 {
		return storedEnvelope{}, errors.New("persistent change workflow store digest is invalid")
	}
	return envelope, nil
}

func persistRecord(record Record) storedRecord {
	return storedRecord{
		Schema: record.Schema, WorkflowID: record.WorkflowID, Revision: record.Revision,
		Request: storedRequest{
			RequestID: record.Request.RequestID, TenantID: record.Request.TenantID, SiteID: record.Request.SiteID,
			DeviceProfileID: record.Request.DeviceProfileID, PrincipalSHA256: record.Request.PrincipalSHA256,
			OperationKind: record.Request.OperationKind, RequestedAt: record.Request.RequestedAt,
			RequestExpiresAt: record.Request.RequestExpiresAt,
		},
		GrantID: record.GrantID, GrantScopeSHA256: record.GrantScopeSHA256, ActionID: record.ActionID,
		LocalHandoffRef: record.LocalHandoffRef, ActionEvidenceRef: record.ActionEvidenceRef,
		ReadbackSHA256: record.ReadbackSHA256, CatalogFingerprint: record.CatalogFingerprint,
		AssignmentRef: record.AssignmentRef, State: record.State, Reason: record.Reason,
		CreatedAt: record.CreatedAt, UpdatedAt: record.UpdatedAt,
	}
}

func (stored storedRecord) record() Record {
	return Record{
		Schema: stored.Schema, WorkflowID: stored.WorkflowID, Revision: stored.Revision,
		Request: Request{
			RequestID: stored.Request.RequestID, TenantID: stored.Request.TenantID, SiteID: stored.Request.SiteID,
			DeviceProfileID: stored.Request.DeviceProfileID, PrincipalSHA256: stored.Request.PrincipalSHA256,
			OperationKind: stored.Request.OperationKind, RequestedAt: stored.Request.RequestedAt,
			RequestExpiresAt: stored.Request.RequestExpiresAt,
		},
		GrantID: stored.GrantID, GrantScopeSHA256: stored.GrantScopeSHA256, ActionID: stored.ActionID,
		LocalHandoffRef: stored.LocalHandoffRef, ActionEvidenceRef: stored.ActionEvidenceRef,
		ReadbackSHA256: stored.ReadbackSHA256, CatalogFingerprint: stored.CatalogFingerprint,
		AssignmentRef: stored.AssignmentRef, State: stored.State, Reason: stored.Reason,
		CreatedAt: stored.CreatedAt, UpdatedAt: stored.UpdatedAt,
	}
}

var _ Store = (*FileStore)(nil)
