package media

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/cosmo-wander-ai/cosmoedge-connect/internal/strictjson"
)

const idempotencySchema = "cosmoedge.inspection.media-idempotency.v3"

type idempotencyState string

const (
	idempotencyReserved  idempotencyState = "reserved"
	idempotencyPublished idempotencyState = "published"
)

var idempotencyKeyPattern = regexp.MustCompile(`^media_put_[a-f0-9]{64}$`)

type idempotencyRecord struct {
	Schema           string           `json:"schema"`
	IdempotencyKey   string           `json:"idempotencyKey"`
	RequestSHA256    string           `json:"requestSha256"`
	Request          PutRequest       `json:"request"`
	MediaRef         string           `json:"mediaRef"`
	State            idempotencyState `json:"state"`
	CreatedAt        time.Time        `json:"createdAt"`
	DescriptorSHA256 string           `json:"descriptorSha256,omitempty"`
	RecordSHA256     string           `json:"recordSha256"`
}

// PutIdempotent publishes one exact content object under a media identity that
// is reserved durably before the content copy begins. Replaying the same key
// and request returns the original descriptor. Reusing the key for any other
// request fails closed. ExpectedSHA256 is mandatory because the operation key
// must bind content even across a crash before descriptor publication.
func (s *Store) PutIdempotent(ctx context.Context, request IdempotentPutRequest, source io.Reader) (Descriptor, bool, error) {
	if s == nil || source == nil {
		return Descriptor{}, false, errors.New("media store and source are required")
	}
	if !idempotencyKeyPattern.MatchString(request.IdempotencyKey) {
		return Descriptor{}, false, ErrInvalidIdempotencyKey
	}
	if request.Media.Kind == KindFrameSet || !validKind(request.Media.Kind) {
		return Descriptor{}, false, ErrUnsupportedKind
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.ensureLayout(); err != nil {
		return Descriptor{}, false, err
	}

	record, exists, err := s.readOptionalIdempotencyRecordLocked(request.IdempotencyKey)
	if err != nil {
		return Descriptor{}, false, err
	}
	createdAt := s.now().UTC()
	if exists {
		createdAt = record.CreatedAt
	}
	canonical, err := s.canonicalIdempotentRequest(request.Media, createdAt)
	if err != nil {
		return Descriptor{}, false, err
	}
	requestDigest, err := idempotentRequestDigest(canonical)
	if err != nil {
		return Descriptor{}, false, err
	}
	if exists && (record.RequestSHA256 != requestDigest || !samePutRequest(record.Request, canonical)) {
		return Descriptor{}, false, ErrIdempotencyConflict
	}
	if err := s.validateParentLocked(canonical.Binding, canonical.Lineage, canonical.Governance.ExpiresAt); err != nil {
		return Descriptor{}, false, err
	}
	if !exists {
		mediaRef, err := s.unusedMediaRefLocked()
		if err != nil {
			return Descriptor{}, false, err
		}
		record = idempotencyRecord{
			Schema: idempotencySchema, IdempotencyKey: request.IdempotencyKey,
			RequestSHA256: requestDigest, Request: canonical, MediaRef: mediaRef,
			State: idempotencyReserved, CreatedAt: createdAt,
		}
		if err := s.writeIdempotencyRecordLocked(record); err != nil {
			return Descriptor{}, false, err
		}
	}

	if tombstone, found, err := s.readOptionalDescriptor(s.tombstonePath(record.MediaRef)); err != nil {
		return Descriptor{}, false, err
	} else if found {
		if !descriptorMatchesIdempotentRequest(tombstone, record) {
			return Descriptor{}, false, ErrCorruptIdempotency
		}
		digest, digestErr := descriptorDigest(tombstone)
		if digestErr != nil {
			return Descriptor{}, false, digestErr
		}
		if record.State == idempotencyPublished && record.DescriptorSHA256 != digest {
			return Descriptor{}, false, ErrCorruptIdempotency
		}
		if record.State == idempotencyReserved {
			record.State = idempotencyPublished
			record.DescriptorSHA256 = digest
			if err := s.writeIdempotencyRecordLocked(record); err != nil {
				return Descriptor{}, false, err
			}
		}
		return Descriptor{}, false, ErrDeleted
	}
	if descriptor, found, err := s.readOptionalDescriptor(s.descriptorPath(record.MediaRef)); err != nil {
		return Descriptor{}, false, err
	} else if found {
		if !descriptorMatchesIdempotentRequest(descriptor, record) {
			return Descriptor{}, false, ErrCorruptIdempotency
		}
		if err := s.verifyObject(descriptor); err != nil {
			return Descriptor{}, false, err
		}
		if record.State == idempotencyReserved {
			record.State = idempotencyPublished
			record.DescriptorSHA256, err = descriptorDigest(descriptor)
			if err != nil {
				return Descriptor{}, false, err
			}
			if err := s.writeIdempotencyRecordLocked(record); err != nil {
				return Descriptor{}, false, err
			}
		} else if !descriptorDigestMatches(descriptor, record.DescriptorSHA256) {
			return Descriptor{}, false, ErrCorruptIdempotency
		}
		return cloneDescriptor(descriptor), false, nil
	}
	if record.State == idempotencyPublished {
		return Descriptor{}, false, ErrCorruptIdempotency
	}
	if err := removeRegularIfExists(s.objectPath(record.MediaRef)); err != nil {
		return Descriptor{}, false, err
	}

	descriptor, err := s.putLocked(ctx, canonical, source, record.CreatedAt, record.MediaRef)
	if err != nil {
		return Descriptor{}, false, err
	}
	record.State = idempotencyPublished
	record.DescriptorSHA256, err = descriptorDigest(descriptor)
	if err != nil {
		return Descriptor{}, false, err
	}
	if err := s.writeIdempotencyRecordLocked(record); err != nil {
		return Descriptor{}, false, err
	}
	return descriptor, true, nil
}

func (s *Store) canonicalIdempotentRequest(request PutRequest, createdAt time.Time) (PutRequest, error) {
	request = normalizePutRequest(request, createdAt, s.defaultTTL)
	if request.ExpectedSHA256 == "" {
		return PutRequest{}, ErrHashMismatch
	}
	mimeType, err := normalizedMIME(request.Encoding.MIMEType)
	if err != nil {
		return PutRequest{}, err
	}
	request.Encoding.MIMEType = mimeType
	if err := validatePutRequest(request, createdAt, s.maximumTTL); err != nil {
		return PutRequest{}, err
	}
	return request, nil
}

func idempotentRequestDigest(request PutRequest) (string, error) {
	raw, err := json.Marshal(request)
	if err != nil {
		return "", err
	}
	digest := sha256.Sum256(raw)
	return hex.EncodeToString(digest[:]), nil
}

func samePutRequest(left, right PutRequest) bool {
	leftRaw, leftErr := json.Marshal(left)
	rightRaw, rightErr := json.Marshal(right)
	return leftErr == nil && rightErr == nil && bytes.Equal(leftRaw, rightRaw)
}

func descriptorMatchesIdempotentRequest(descriptor Descriptor, record idempotencyRecord) bool {
	request := record.Request
	if descriptor.MediaRef != record.MediaRef || descriptor.Kind != request.Kind || descriptor.Binding != request.Binding ||
		descriptor.Lineage != request.Lineage || !descriptor.CreatedAt.Equal(record.CreatedAt) ||
		!equalTemporal(descriptor.Temporal, request.Temporal) ||
		!sameGovernance(descriptor.Governance, request.Governance) || descriptor.Integrity.SHA256 != request.ExpectedSHA256 ||
		!encodingSatisfiesRequest(descriptor.Encoding, request.Encoding) {
		return false
	}
	return descriptor.RuntimeLease == (RuntimeLease{}) && len(descriptor.FrameMembers) == 0
}

func encodingSatisfiesRequest(actual, requested Encoding) bool {
	return actual.MIMEType == requested.MIMEType &&
		(requested.Container == "" || actual.Container == requested.Container) &&
		(requested.Codec == "" || actual.Codec == requested.Codec) &&
		(requested.WidthPixels == 0 || actual.WidthPixels == requested.WidthPixels) &&
		(requested.HeightPixels == 0 || actual.HeightPixels == requested.HeightPixels) &&
		(requested.FrameRate == 0 || actual.FrameRate == requested.FrameRate)
}

func sameGovernance(left, right Governance) bool {
	if left.PrivacyClass != right.PrivacyClass || left.RedactionPolicyRef != right.RedactionPolicyRef ||
		left.RetentionPolicyRef != right.RetentionPolicyRef || !left.ExpiresAt.Equal(right.ExpiresAt) ||
		len(left.Audience) != len(right.Audience) {
		return false
	}
	for index := range left.Audience {
		if left.Audience[index] != right.Audience[index] {
			return false
		}
	}
	return true
}

func descriptorDigest(descriptor Descriptor) (string, error) {
	// Deletion is a lifecycle transition over the same immutable publication.
	// Bind the idempotency record to publication fields rather than tombstone
	// metadata so a legitimate delete cannot make the store fail on restart.
	descriptor.Availability = AvailabilityAvailable
	descriptor.DeletedAt = nil
	descriptor.DeletionReason = ""
	raw, err := json.Marshal(descriptor)
	if err != nil {
		return "", err
	}
	digest := sha256.Sum256(raw)
	return hex.EncodeToString(digest[:]), nil
}

func descriptorDigestMatches(descriptor Descriptor, expected string) bool {
	actual, err := descriptorDigest(descriptor)
	return err == nil && expected != "" && actual == expected
}

func (s *Store) readOptionalIdempotencyRecordLocked(key string) (idempotencyRecord, bool, error) {
	record, err := s.readIdempotencyRecordLocked(s.idempotencyPath(key))
	if errors.Is(err, ErrNotFound) {
		return idempotencyRecord{}, false, nil
	}
	return record, err == nil, err
}

func (s *Store) readIdempotencyRecordLocked(path string) (idempotencyRecord, error) {
	info, err := regularFileInfo(path)
	if err != nil {
		return idempotencyRecord{}, err
	}
	if info.Size() <= 0 || info.Size() > idempotencyMaxBytes {
		return idempotencyRecord{}, ErrCorruptIdempotency
	}
	file, err := os.Open(path)
	if err != nil {
		return idempotencyRecord{}, ErrCorruptIdempotency
	}
	defer file.Close()
	after, err := file.Stat()
	if err != nil || !os.SameFile(info, after) || !after.Mode().IsRegular() {
		return idempotencyRecord{}, ErrCorruptIdempotency
	}
	raw, err := io.ReadAll(io.LimitReader(file, idempotencyMaxBytes+1))
	if err != nil || len(raw) > idempotencyMaxBytes {
		return idempotencyRecord{}, ErrCorruptIdempotency
	}
	var record idempotencyRecord
	if strictjson.ValidateExactFields(raw, &record, 8) != nil {
		return idempotencyRecord{}, ErrCorruptIdempotency
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&record) != nil || !validIdempotencyRecord(record) {
		return idempotencyRecord{}, ErrCorruptIdempotency
	}
	canonical, err := s.canonicalIdempotentRequest(record.Request, record.CreatedAt)
	if err != nil || !samePutRequest(canonical, record.Request) {
		return idempotencyRecord{}, ErrCorruptIdempotency
	}
	if filepath.Base(path) != record.IdempotencyKey+".json" {
		return idempotencyRecord{}, ErrCorruptIdempotency
	}
	expected, err := idempotencyRecordDigest(record)
	if err != nil || expected != record.RecordSHA256 {
		return idempotencyRecord{}, ErrCorruptIdempotency
	}
	return record, nil
}

func validIdempotencyRecord(record idempotencyRecord) bool {
	if record.Schema != idempotencySchema || !idempotencyKeyPattern.MatchString(record.IdempotencyKey) ||
		!validDigest(record.RequestSHA256) || validateMediaRef(record.MediaRef) != nil || record.CreatedAt.IsZero() ||
		!record.CreatedAt.Equal(record.CreatedAt.UTC()) || !validDigest(record.RecordSHA256) {
		return false
	}
	requestDigest, err := idempotentRequestDigest(record.Request)
	if err != nil || requestDigest != record.RequestSHA256 || record.Request.ExpectedSHA256 == "" {
		return false
	}
	switch record.State {
	case idempotencyReserved:
		return record.DescriptorSHA256 == ""
	case idempotencyPublished:
		return validDigest(record.DescriptorSHA256)
	default:
		return false
	}
}

func idempotencyRecordDigest(record idempotencyRecord) (string, error) {
	record.RecordSHA256 = ""
	raw, err := json.Marshal(record)
	if err != nil {
		return "", err
	}
	digest := sha256.Sum256(append([]byte("cosmoedge.inspection.media-idempotency.v3\x00"), raw...))
	return hex.EncodeToString(digest[:]), nil
}

func (s *Store) writeIdempotencyRecordLocked(record idempotencyRecord) error {
	record.Schema = idempotencySchema
	digest, err := idempotencyRecordDigest(record)
	if err != nil {
		return err
	}
	record.RecordSHA256 = digest
	if !validIdempotencyRecord(record) {
		return ErrCorruptIdempotency
	}
	raw, err := json.Marshal(record)
	if err != nil || len(raw) > idempotencyMaxBytes {
		return ErrCorruptIdempotency
	}
	temporary, err := os.CreateTemp(s.tempDir, "idempotency-*.json")
	if err != nil {
		return err
	}
	name := temporary.Name()
	defer func() {
		_ = temporary.Close()
		_ = os.Remove(name)
	}()
	if err := temporary.Chmod(0o600); err != nil {
		return err
	}
	if _, err := temporary.Write(raw); err != nil {
		return err
	}
	if err := temporary.Sync(); err != nil {
		return err
	}
	if err := temporary.Close(); err != nil {
		return err
	}
	if err := os.Rename(name, s.idempotencyPath(record.IdempotencyKey)); err != nil {
		return err
	}
	target := s.idempotencyPath(record.IdempotencyKey)
	if err := os.Chmod(target, 0o600); err != nil {
		return err
	}
	return syncMediaDirectory(target)
}

func (s *Store) reconcileIdempotencyLocked() error {
	entries, err := os.ReadDir(s.idempotencyDir)
	if err != nil {
		return err
	}
	seenMedia := make(map[string]string, len(entries))
	sort.Slice(entries, func(i, j int) bool { return entries[i].Name() < entries[j].Name() })
	for _, entry := range entries {
		if entry.IsDir() || entry.Type()&os.ModeSymlink != 0 || !strings.HasSuffix(entry.Name(), ".json") {
			return ErrUnsafePath
		}
		key := strings.TrimSuffix(entry.Name(), ".json")
		if !idempotencyKeyPattern.MatchString(key) {
			return ErrUnsafePath
		}
		record, err := s.readIdempotencyRecordLocked(filepath.Join(s.idempotencyDir, entry.Name()))
		if err != nil {
			return err
		}
		if prior, duplicate := seenMedia[record.MediaRef]; duplicate && prior != key {
			return ErrCorruptIdempotency
		}
		seenMedia[record.MediaRef] = key

		descriptor, available, err := s.readOptionalDescriptor(s.descriptorPath(record.MediaRef))
		if err != nil {
			return err
		}
		if !available {
			descriptor, available, err = s.readOptionalDescriptor(s.tombstonePath(record.MediaRef))
			if err != nil {
				return err
			}
		}
		if !available {
			if record.State == idempotencyPublished {
				return ErrCorruptIdempotency
			}
			if err := removeRegularIfExists(s.objectPath(record.MediaRef)); err != nil {
				return err
			}
			continue
		}
		if !descriptorMatchesIdempotentRequest(descriptor, record) {
			return ErrCorruptIdempotency
		}
		digest, err := descriptorDigest(descriptor)
		if err != nil {
			return err
		}
		if record.State == idempotencyPublished {
			if record.DescriptorSHA256 != digest {
				return ErrCorruptIdempotency
			}
			continue
		}
		record.State = idempotencyPublished
		record.DescriptorSHA256 = digest
		if err := s.writeIdempotencyRecordLocked(record); err != nil {
			return err
		}
	}
	return nil
}

func (s *Store) idempotencyPath(key string) string {
	return filepath.Join(s.idempotencyDir, key+".json")
}
