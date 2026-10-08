// Package media owns the Inspection v2 bounded media contract and local
// content store. Content crosses the package boundary only as an io.Reader or
// io.ReadCloser; descriptors contain no storage or transport location.
package media

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"image"
	_ "image/jpeg"
	_ "image/png"
	"io"
	"math"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/cosmo-wander-ai/cosmoedge-connect/internal/strictjson"
)

const (
	rootMarkerName      = ".cosmoedge-inspection-media-root"
	rootMarkerBody      = Schema + "\n"
	descriptorMaxBytes  = 256 << 10
	idempotencyMaxBytes = 64 << 10
	maxFrameMembers     = 1024
	defaultObjectBytes  = int64(64 << 20)
	defaultTotalBytes   = int64(512 << 20)
	defaultDescriptors  = 10_000
	defaultTTL          = 24 * time.Hour
	defaultMaximumTTL   = 30 * 24 * time.Hour
	absoluteMaximumTTL  = 365 * 24 * time.Hour
)

type Config struct {
	Root           string
	MaxObjectBytes int64
	MaxTotalBytes  int64
	MaxDescriptors int
	DefaultTTL     time.Duration
	MaximumTTL     time.Duration
	Now            func() time.Time
}

type Store struct {
	root           string
	objectsDir     string
	descriptorsDir string
	tombstonesDir  string
	idempotencyDir string
	tempDir        string
	maxObjectBytes int64
	maxTotalBytes  int64
	maxDescriptors int
	defaultTTL     time.Duration
	maximumTTL     time.Duration
	now            func() time.Time
	mu             sync.RWMutex
}

func New(config Config) (*Store, error) {
	if strings.TrimSpace(config.Root) == "" {
		return nil, errors.New("media store root is required")
	}
	if err := normalizeConfig(&config); err != nil {
		return nil, err
	}
	root, err := canonicalStoreRoot(config.Root)
	if err != nil {
		return nil, err
	}
	if err := claimStoreRoot(root); err != nil {
		return nil, err
	}
	if config.Now == nil {
		config.Now = time.Now
	}
	store := &Store{
		root: root, objectsDir: filepath.Join(root, "objects"),
		descriptorsDir: filepath.Join(root, "descriptors"),
		tombstonesDir:  filepath.Join(root, "tombstones"),
		idempotencyDir: filepath.Join(root, "idempotency"), tempDir: filepath.Join(root, "tmp"),
		maxObjectBytes: config.MaxObjectBytes, maxTotalBytes: config.MaxTotalBytes,
		maxDescriptors: config.MaxDescriptors, defaultTTL: config.DefaultTTL,
		maximumTTL: config.MaximumTTL, now: config.Now,
	}
	if err := store.ensureLayout(); err != nil {
		return nil, err
	}
	if err := store.reconcile(); err != nil {
		return nil, fmt.Errorf("reconcile media v2 store: %w", err)
	}
	return store, nil
}

func normalizeConfig(config *Config) error {
	if config.MaxObjectBytes == 0 {
		config.MaxObjectBytes = defaultObjectBytes
	}
	if config.MaxObjectBytes < 1 || config.MaxObjectBytes == math.MaxInt64 {
		return errors.New("bounded positive per-object media limit is required")
	}
	if config.MaxTotalBytes == 0 {
		config.MaxTotalBytes = defaultTotalBytes
		if config.MaxObjectBytes > config.MaxTotalBytes {
			config.MaxTotalBytes = config.MaxObjectBytes
		}
	}
	if config.MaxDescriptors == 0 {
		config.MaxDescriptors = defaultDescriptors
	}
	if config.DefaultTTL == 0 {
		config.DefaultTTL = defaultTTL
	}
	if config.MaximumTTL == 0 {
		config.MaximumTTL = defaultMaximumTTL
	}
	if config.MaxTotalBytes < config.MaxObjectBytes || config.MaxTotalBytes == math.MaxInt64 || config.MaxDescriptors < 1 {
		return errors.New("bounded media store quotas are required")
	}
	if config.DefaultTTL <= 0 || config.MaximumTTL <= 0 || config.DefaultTTL > config.MaximumTTL || config.MaximumTTL > absoluteMaximumTTL {
		return ErrInvalidRetention
	}
	return nil
}

// Root is for local lifecycle wiring only. It must never be projected through
// the business or Skill surface.
func (s *Store) Root() string {
	if s == nil {
		return ""
	}
	return s.root
}

// Put streams one bounded content object into the v2 store.
func (s *Store) Put(ctx context.Context, request PutRequest, source io.Reader) (Descriptor, error) {
	if s == nil || source == nil {
		return Descriptor{}, errors.New("media store and source are required")
	}
	if request.Kind == KindFrameSet || !validKind(request.Kind) {
		return Descriptor{}, ErrUnsupportedKind
	}
	createdAt := s.now().UTC()
	request = normalizePutRequest(request, createdAt, s.defaultTTL)
	if err := validatePutRequest(request, createdAt, s.maximumTTL); err != nil {
		return Descriptor{}, err
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.ensureLayout(); err != nil {
		return Descriptor{}, err
	}
	if err := s.validateParentLocked(request.Binding, request.Lineage, request.Governance.ExpiresAt); err != nil {
		return Descriptor{}, err
	}
	mediaRef, err := s.unusedMediaRefLocked()
	if err != nil {
		return Descriptor{}, err
	}
	return s.putLocked(ctx, request, source, createdAt, mediaRef)
}

// putLocked publishes one already-normalized request to an already-reserved
// media identity. The caller must hold s.mu and must have validated lineage.
func (s *Store) putLocked(ctx context.Context, request PutRequest, source io.Reader, createdAt time.Time, mediaRef string) (Descriptor, error) {
	temporary, err := os.CreateTemp(s.tempDir, "put-*.media")
	if err != nil {
		return Descriptor{}, err
	}
	temporaryPath := temporary.Name()
	defer func() {
		_ = temporary.Close()
		_ = os.Remove(temporaryPath)
	}()
	if err := temporary.Chmod(0o600); err != nil {
		return Descriptor{}, err
	}
	hash := sha256.New()
	prefix := &prefixWriter{maximum: 512}
	limited := &io.LimitedReader{R: contextReader{ctx: ctx, source: source}, N: s.maxObjectBytes + 1}
	size, err := io.Copy(io.MultiWriter(temporary, hash, prefix), limited)
	if err != nil {
		return Descriptor{}, err
	}
	if size > s.maxObjectBytes {
		return Descriptor{}, ErrTooLarge
	}
	if size == 0 {
		return Descriptor{}, errors.New("empty media content is not allowed")
	}
	digest := hex.EncodeToString(hash.Sum(nil))
	if request.ExpectedSHA256 != "" && request.ExpectedSHA256 != digest {
		return Descriptor{}, ErrHashMismatch
	}
	if err := temporary.Sync(); err != nil {
		return Descriptor{}, err
	}
	if err := temporary.Close(); err != nil {
		return Descriptor{}, err
	}
	if err := requireRegularFile(temporaryPath); err != nil {
		return Descriptor{}, err
	}
	encoding, err := normalizeAndVerifyEncoding(request.Kind, request.Encoding, temporaryPath, prefix.bytes)
	if err != nil {
		return Descriptor{}, err
	}
	if err := s.reserveAllowedLocked(size, 1); err != nil {
		return Descriptor{}, err
	}
	objectPath := s.objectPath(mediaRef)
	if err := os.Rename(temporaryPath, objectPath); err != nil {
		return Descriptor{}, err
	}
	temporaryPath = ""
	if err := os.Chmod(objectPath, 0o600); err != nil {
		_ = os.Remove(objectPath)
		return Descriptor{}, err
	}
	if err := syncMediaDirectory(objectPath); err != nil {
		_ = os.Remove(objectPath)
		return Descriptor{}, err
	}
	descriptor := Descriptor{
		Schema: Schema, MediaRef: mediaRef, Kind: request.Kind, Binding: request.Binding,
		Encoding: encoding, Temporal: normalizeTemporal(request.Temporal),
		Integrity: Integrity{SHA256: digest, SizeBytes: size}, Lineage: request.Lineage,
		Governance: normalizeGovernance(request.Governance), FrameMembers: []FrameMember{},
		Availability: AvailabilityAvailable, CreatedAt: createdAt,
	}
	if err := s.writeDescriptorAtomic(s.descriptorPath(mediaRef), descriptor); err != nil {
		_ = os.Remove(objectPath)
		return Descriptor{}, err
	}
	return cloneDescriptor(descriptor), nil
}

// RegisterFrameSet creates an ordered manifest over existing image media. The
// set becomes the lifecycle parent and registration atomically binds each
// member's lineage in normal operation. Reconciliation fails closed if a crash
// interrupts this multi-file publication.
func (s *Store) RegisterFrameSet(ctx context.Context, request FrameSetRequest) (Descriptor, error) {
	if s == nil {
		return Descriptor{}, ErrNotFound
	}
	select {
	case <-ctx.Done():
		return Descriptor{}, ctx.Err()
	default:
	}
	createdAt := s.now().UTC()
	request.Governance = normalizeInputGovernance(request.Governance, createdAt, s.defaultTTL)
	request.Temporal = normalizeTemporal(request.Temporal)
	if err := validateBinding(request.Binding); err != nil {
		return Descriptor{}, err
	}
	if err := validateTemporal(request.Temporal); err != nil {
		return Descriptor{}, err
	}
	if err := validateLineage(request.Lineage); err != nil {
		return Descriptor{}, err
	}
	if err := validateGovernance(request.Governance, createdAt); err != nil || request.Governance.ExpiresAt.After(createdAt.Add(s.maximumTTL)) {
		return Descriptor{}, ErrInvalidRetention
	}
	if len(request.Members) < 1 || len(request.Members) > maxFrameMembers {
		return Descriptor{}, errors.New("frame set member count is outside the bounded range")
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.ensureLayout(); err != nil {
		return Descriptor{}, err
	}
	if err := s.reserveAllowedLocked(0, 1); err != nil {
		return Descriptor{}, err
	}
	if err := s.validateParentLocked(request.Binding, request.Lineage, request.Governance.ExpiresAt); err != nil {
		return Descriptor{}, err
	}
	mediaRef, err := s.unusedMediaRefLocked()
	if err != nil {
		return Descriptor{}, err
	}
	members := make([]FrameMember, len(request.Members))
	originals := make([]Descriptor, len(request.Members))
	seen := make(map[string]struct{}, len(request.Members))
	var previousOffset int64
	for index, input := range request.Members {
		if input.Ordinal != index || input.OffsetMillis < 0 || index > 0 && input.OffsetMillis < previousOffset ||
			validateMediaRef(input.MediaRef) != nil || !validOpaqueRef(input.TransformPolicyRef) {
			return Descriptor{}, errors.New("frame set members are not strictly ordered")
		}
		if input.MediaRef == request.Lineage.ParentMediaRef {
			return Descriptor{}, ErrLineageConflict
		}
		if _, duplicate := seen[input.MediaRef]; duplicate {
			return Descriptor{}, ErrLineageConflict
		}
		seen[input.MediaRef] = struct{}{}
		child, err := s.readAvailableLocked(input.MediaRef)
		if err != nil {
			return Descriptor{}, err
		}
		if child.Kind != KindImage || child.Lineage.ParentMediaRef != "" ||
			child.Binding.TenantID != request.Binding.TenantID || child.Binding.SiteID != request.Binding.SiteID ||
			child.Binding.RunID != request.Binding.RunID || child.Governance.ExpiresAt.Before(request.Governance.ExpiresAt) {
			return Descriptor{}, ErrLineageConflict
		}
		originals[index] = child
		members[index] = FrameMember{
			MediaRef: child.MediaRef, SHA256: child.Integrity.SHA256, Ordinal: index,
			OffsetMillis: input.OffsetMillis, TransformPolicyRef: input.TransformPolicyRef,
		}
		previousOffset = input.OffsetMillis
	}
	manifest, err := json.Marshal(members)
	if err != nil {
		return Descriptor{}, err
	}
	descriptor := Descriptor{
		Schema: Schema, MediaRef: mediaRef, Kind: KindFrameSet, Binding: request.Binding,
		Encoding: Encoding{}, Temporal: request.Temporal,
		Integrity: Integrity{SHA256: digestBytes(manifest), SizeBytes: 0}, Lineage: request.Lineage,
		Governance: normalizeGovernance(request.Governance), FrameMembers: members,
		Availability: AvailabilityAvailable, CreatedAt: createdAt,
	}
	if err := validateDescriptor(descriptor); err != nil {
		return Descriptor{}, err
	}
	if err := s.writeDescriptorAtomic(s.descriptorPath(mediaRef), descriptor); err != nil {
		return Descriptor{}, err
	}
	updated := 0
	rollback := func() {
		for index := 0; index < updated; index++ {
			_ = s.writeDescriptorAtomic(s.descriptorPath(originals[index].MediaRef), originals[index])
		}
		_ = os.Remove(s.descriptorPath(mediaRef))
	}
	for index, original := range originals {
		child := original
		child.Lineage = Lineage{
			ParentMediaRef: mediaRef, TransformPolicyRef: members[index].TransformPolicyRef,
			Ordinal: index, OffsetMillis: members[index].OffsetMillis,
		}
		if err := s.writeDescriptorAtomic(s.descriptorPath(child.MediaRef), child); err != nil {
			rollback()
			return Descriptor{}, err
		}
		updated++
	}
	return cloneDescriptor(descriptor), nil
}

// LeaseForRun creates a bounded run-owned reference to immutable media that
// was ingested before the execution existed. The source descriptor is never
// rewritten and its content is copied under a new opaque media reference so a
// later transform has an ordinary same-run parent. Lease expiry can only
// shorten, never extend, the source media lifetime.
func (s *Store) LeaseForRun(ctx context.Context, request RunLeaseRequest) (Descriptor, error) {
	if s == nil {
		return Descriptor{}, ErrNotFound
	}
	select {
	case <-ctx.Done():
		return Descriptor{}, ctx.Err()
	default:
	}
	createdAt := s.now().UTC()
	request.Governance = normalizeInputGovernance(request.Governance, createdAt, s.defaultTTL)
	request.PolicyRef = strings.TrimSpace(request.PolicyRef)
	if validateMediaRef(request.SourceMediaRef) != nil || validateBinding(request.Binding) != nil ||
		!validOpaqueRef(request.PolicyRef) || validateGovernance(request.Governance, createdAt) != nil ||
		request.Governance.ExpiresAt.After(createdAt.Add(s.maximumTTL)) {
		return Descriptor{}, ErrLineageConflict
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.ensureLayout(); err != nil {
		return Descriptor{}, err
	}
	source, err := s.readAvailableLocked(request.SourceMediaRef)
	if err != nil {
		return Descriptor{}, err
	}
	if source.Kind == KindFrameSet || source.RuntimeLease.SourceMediaRef != "" || source.Lineage.ParentMediaRef != "" ||
		source.Binding.TenantID != request.Binding.TenantID || source.Binding.SiteID != request.Binding.SiteID ||
		source.Binding.SourceRef != request.Binding.SourceRef || source.Binding.RunID == request.Binding.RunID ||
		!runtimeLeaseGovernanceAllowed(source.Governance, request.Governance) {
		return Descriptor{}, ErrLineageConflict
	}
	if err := s.verifyObject(source); err != nil {
		return Descriptor{}, err
	}
	if err := s.reserveAllowedLocked(source.Integrity.SizeBytes, 1); err != nil {
		return Descriptor{}, err
	}
	mediaRef, err := s.unusedMediaRefLocked()
	if err != nil {
		return Descriptor{}, err
	}

	input, err := os.Open(s.objectPath(source.MediaRef))
	if err != nil {
		return Descriptor{}, err
	}
	defer input.Close()
	temporary, err := os.CreateTemp(s.tempDir, "put-*.media")
	if err != nil {
		return Descriptor{}, err
	}
	temporaryPath := temporary.Name()
	defer func() {
		_ = temporary.Close()
		_ = os.Remove(temporaryPath)
	}()
	if err := temporary.Chmod(0o600); err != nil {
		return Descriptor{}, err
	}
	hash := sha256.New()
	limited := &io.LimitedReader{R: contextReader{ctx: ctx, source: input}, N: s.maxObjectBytes + 1}
	size, err := io.Copy(io.MultiWriter(temporary, hash), limited)
	if err != nil {
		return Descriptor{}, err
	}
	if size != source.Integrity.SizeBytes || size > s.maxObjectBytes || hex.EncodeToString(hash.Sum(nil)) != source.Integrity.SHA256 {
		return Descriptor{}, ErrIntegrityMismatch
	}
	if err := temporary.Sync(); err != nil {
		return Descriptor{}, err
	}
	if err := temporary.Close(); err != nil {
		return Descriptor{}, err
	}
	objectPath := s.objectPath(mediaRef)
	if err := os.Rename(temporaryPath, objectPath); err != nil {
		return Descriptor{}, err
	}
	temporaryPath = ""
	if err := os.Chmod(objectPath, 0o600); err != nil {
		_ = os.Remove(objectPath)
		return Descriptor{}, err
	}
	descriptor := Descriptor{
		Schema: Schema, MediaRef: mediaRef, Kind: source.Kind, Binding: request.Binding,
		Encoding: source.Encoding, Temporal: cloneDescriptor(source).Temporal, Integrity: source.Integrity,
		Lineage: Lineage{}, RuntimeLease: RuntimeLease{
			SourceMediaRef: source.MediaRef, SourceSHA256: source.Integrity.SHA256, PolicyRef: request.PolicyRef,
		},
		Governance: normalizeGovernance(request.Governance), FrameMembers: []FrameMember{},
		Availability: AvailabilityAvailable, CreatedAt: createdAt,
	}
	if err := s.writeDescriptorAtomic(s.descriptorPath(mediaRef), descriptor); err != nil {
		_ = os.Remove(objectPath)
		return Descriptor{}, err
	}
	return cloneDescriptor(descriptor), nil
}

func (s *Store) Describe(mediaRef string) (Descriptor, error) {
	if s == nil {
		return Descriptor{}, ErrNotFound
	}
	if err := validateMediaRef(mediaRef); err != nil {
		return Descriptor{}, err
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	if tombstone, ok, err := s.readOptionalDescriptor(s.tombstonePath(mediaRef)); err != nil {
		return Descriptor{}, err
	} else if ok {
		return cloneDescriptor(tombstone), ErrDeleted
	}
	descriptor, err := s.readDescriptor(s.descriptorPath(mediaRef))
	if err != nil {
		return Descriptor{}, err
	}
	if expired(descriptor, s.now().UTC()) {
		return cloneDescriptor(descriptor), ErrExpired
	}
	return cloneDescriptor(descriptor), nil
}

// Open verifies the complete object before seeking back to the beginning. The
// returned reader holds a store read lease until Close, so in-process deletion
// cannot race the stream.
func (s *Store) Open(ctx context.Context, mediaRef string) (Descriptor, io.ReadCloser, error) {
	if s == nil {
		return Descriptor{}, nil, ErrNotFound
	}
	if err := validateMediaRef(mediaRef); err != nil {
		return Descriptor{}, nil, err
	}
	s.mu.RLock()
	release := true
	defer func() {
		if release {
			s.mu.RUnlock()
		}
	}()
	if _, ok, err := s.readOptionalDescriptor(s.tombstonePath(mediaRef)); err != nil {
		return Descriptor{}, nil, err
	} else if ok {
		return Descriptor{}, nil, ErrDeleted
	}
	descriptor, err := s.readDescriptor(s.descriptorPath(mediaRef))
	if err != nil {
		return Descriptor{}, nil, err
	}
	if expired(descriptor, s.now().UTC()) {
		return cloneDescriptor(descriptor), nil, ErrExpired
	}
	if descriptor.Kind == KindFrameSet {
		return cloneDescriptor(descriptor), nil, ErrNoContent
	}
	file, err := s.openAndVerify(ctx, descriptor)
	if err != nil {
		return cloneDescriptor(descriptor), nil, err
	}
	release = false
	return cloneDescriptor(descriptor), &leasedReader{file: file, release: s.mu.RUnlock}, nil
}

func (s *Store) Delete(ctx context.Context, mediaRef string) (Descriptor, error) {
	if s == nil {
		return Descriptor{}, ErrNotFound
	}
	if err := validateMediaRef(mediaRef); err != nil {
		return Descriptor{}, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.deleteCascadeLocked(ctx, mediaRef, "deleted")
}

// GC deletes every expired root and all of its descendants. Descendants never
// outlive a deleted or expired parent.
func (s *Store) GC(ctx context.Context) (int, error) {
	if s == nil {
		return 0, ErrNotFound
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	descriptors, err := s.loadActiveLocked()
	if err != nil {
		return 0, err
	}
	now := s.now().UTC()
	refs := make([]string, 0)
	for ref, descriptor := range descriptors {
		if expired(descriptor, now) {
			refs = append(refs, ref)
		}
	}
	sort.Strings(refs)
	deleted := 0
	for _, ref := range refs {
		select {
		case <-ctx.Done():
			return deleted, ctx.Err()
		default:
		}
		if _, err := regularFileInfo(s.descriptorPath(ref)); errors.Is(err, ErrNotFound) {
			continue
		} else if err != nil {
			return deleted, err
		}
		if _, err := s.deleteCascadeLocked(ctx, ref, "expired"); err != nil {
			return deleted, err
		}
		deleted++
	}
	return deleted, nil
}

func normalizePutRequest(request PutRequest, createdAt time.Time, ttl time.Duration) PutRequest {
	request.Governance = normalizeInputGovernance(request.Governance, createdAt, ttl)
	request.Temporal = normalizeTemporal(request.Temporal)
	request.ExpectedSHA256 = strings.ToLower(strings.TrimSpace(request.ExpectedSHA256))
	return request
}

func normalizeInputGovernance(value Governance, createdAt time.Time, ttl time.Duration) Governance {
	result := value
	result.Audience = append([]string(nil), value.Audience...)
	sort.Strings(result.Audience)
	if result.ExpiresAt.IsZero() {
		result.ExpiresAt = createdAt.Add(ttl)
	} else {
		result.ExpiresAt = result.ExpiresAt.UTC()
	}
	return result
}

func normalizeGovernance(value Governance) Governance {
	value.Audience = append([]string(nil), value.Audience...)
	value.ExpiresAt = value.ExpiresAt.UTC()
	return value
}

func normalizeTemporal(value Temporal) Temporal {
	if value.WindowStart != nil {
		start := value.WindowStart.UTC()
		value.WindowStart = &start
	}
	if value.WindowEnd != nil {
		end := value.WindowEnd.UTC()
		value.WindowEnd = &end
	}
	return value
}

func validatePutRequest(request PutRequest, createdAt time.Time, maximumTTL time.Duration) error {
	if err := validateBinding(request.Binding); err != nil {
		return err
	}
	if !validKind(request.Kind) || request.Kind == KindFrameSet {
		return ErrUnsupportedKind
	}
	if err := validateTemporal(request.Temporal); err != nil {
		return err
	}
	if request.Kind == KindVideoClip && request.Temporal.DurationMillis <= 0 {
		return errors.New("video duration is required")
	}
	if err := validateLineage(request.Lineage); err != nil {
		return err
	}
	if err := validateGovernance(request.Governance, createdAt); err != nil || request.Governance.ExpiresAt.After(createdAt.Add(maximumTTL)) {
		return ErrInvalidRetention
	}
	if request.ExpectedSHA256 != "" && !validDigest(request.ExpectedSHA256) {
		return ErrHashMismatch
	}
	return nil
}

func normalizeAndVerifyEncoding(kind Kind, declared Encoding, path string, prefix []byte) (Encoding, error) {
	declaredMIME, err := normalizedMIME(declared.MIMEType)
	if err != nil {
		return Encoding{}, err
	}
	declared.MIMEType = declaredMIME
	sniffed := strings.ToLower(strings.TrimSpace(strings.Split(http.DetectContentType(prefix), ";")[0]))
	switch kind {
	case KindImage:
		if declaredMIME != "image/jpeg" && declaredMIME != "image/png" || sniffed != declaredMIME {
			return Encoding{}, ErrMIMEMismatch
		}
		file, err := os.Open(path)
		if err != nil {
			return Encoding{}, err
		}
		config, format, err := image.DecodeConfig(file)
		_ = file.Close()
		if err != nil || config.Width < 1 || config.Height < 1 {
			return Encoding{}, ErrMIMEMismatch
		}
		if format == "jpeg" && declaredMIME != "image/jpeg" || format == "png" && declaredMIME != "image/png" {
			return Encoding{}, ErrMIMEMismatch
		}
		if declared.WidthPixels != 0 && declared.WidthPixels != config.Width || declared.HeightPixels != 0 && declared.HeightPixels != config.Height {
			return Encoding{}, ErrMIMEMismatch
		}
		declared.WidthPixels, declared.HeightPixels = config.Width, config.Height
		if declared.Container == "" {
			declared.Container = format
		}
		if declared.Codec == "" {
			declared.Codec = format
		}
	case KindVideoClip:
		if declaredMIME != "video/mp4" || !looksLikeMP4(prefix) {
			return Encoding{}, ErrMIMEMismatch
		}
		if declared.Container == "" {
			declared.Container = "mp4"
		}
	case KindMetric, KindDetection, KindEvent:
		if declaredMIME != "application/json" || !looksLikeJSON(prefix) {
			return Encoding{}, ErrMIMEMismatch
		}
		if declared.Container == "" {
			declared.Container = "json"
		}
		if declared.Codec == "" {
			declared.Codec = "json"
		}
	default:
		return Encoding{}, ErrUnsupportedKind
	}
	if err := validateEncoding(kind, declared); err != nil {
		return Encoding{}, err
	}
	return declared, nil
}

func looksLikeMP4(prefix []byte) bool {
	return len(prefix) >= 12 && string(prefix[4:8]) == "ftyp"
}

func looksLikeJSON(prefix []byte) bool {
	trimmed := bytes.TrimSpace(prefix)
	return len(trimmed) > 0 && (trimmed[0] == '{' || trimmed[0] == '[')
}

func (s *Store) validateParentLocked(binding Binding, lineage Lineage, expiresAt time.Time) error {
	if lineage.ParentMediaRef == "" {
		return nil
	}
	parent, err := s.readAvailableLocked(lineage.ParentMediaRef)
	if err != nil {
		return err
	}
	if parent.Binding.TenantID != binding.TenantID || parent.Binding.SiteID != binding.SiteID || parent.Binding.RunID != binding.RunID ||
		expiresAt.After(parent.Governance.ExpiresAt) {
		return ErrLineageConflict
	}
	return nil
}

func (s *Store) readAvailableLocked(mediaRef string) (Descriptor, error) {
	if tombstone, ok, err := s.readOptionalDescriptor(s.tombstonePath(mediaRef)); err != nil {
		return Descriptor{}, err
	} else if ok {
		_ = tombstone
		return Descriptor{}, ErrDeleted
	}
	descriptor, err := s.readDescriptor(s.descriptorPath(mediaRef))
	if err != nil {
		return Descriptor{}, err
	}
	if expired(descriptor, s.now().UTC()) {
		return Descriptor{}, ErrExpired
	}
	return descriptor, nil
}

func (s *Store) reserveAllowedLocked(addBytes int64, addDescriptors int) error {
	descriptors, err := s.loadActiveLocked()
	if err != nil {
		return err
	}
	var usedBytes int64
	for _, descriptor := range descriptors {
		if usedBytes > s.maxTotalBytes-descriptor.Integrity.SizeBytes {
			return ErrQuotaExceeded
		}
		usedBytes += descriptor.Integrity.SizeBytes
	}
	if len(descriptors)+addDescriptors > s.maxDescriptors || addBytes > s.maxTotalBytes-usedBytes {
		return fmt.Errorf("%w: descriptors=%d+%d/%d bytes=%d+%d/%d", ErrQuotaExceeded,
			len(descriptors), addDescriptors, s.maxDescriptors, usedBytes, addBytes, s.maxTotalBytes)
	}
	return nil
}

func (s *Store) deleteCascadeLocked(ctx context.Context, mediaRef, reason string) (Descriptor, error) {
	if tombstone, ok, err := s.readOptionalDescriptor(s.tombstonePath(mediaRef)); err != nil {
		return Descriptor{}, err
	} else if ok {
		return cloneDescriptor(tombstone), nil
	}
	descriptors, err := s.loadActiveLocked()
	if err != nil {
		return Descriptor{}, err
	}
	root, exists := descriptors[mediaRef]
	if !exists {
		return Descriptor{}, ErrNotFound
	}
	children := make(map[string][]string)
	for ref, descriptor := range descriptors {
		if descriptor.RuntimeLease.SourceMediaRef != "" {
			children[descriptor.RuntimeLease.SourceMediaRef] = append(children[descriptor.RuntimeLease.SourceMediaRef], ref)
		}
		if descriptor.Lineage.ParentMediaRef != "" {
			children[descriptor.Lineage.ParentMediaRef] = append(children[descriptor.Lineage.ParentMediaRef], ref)
		}
		if descriptor.Kind == KindFrameSet {
			for _, member := range descriptor.FrameMembers {
				children[ref] = append(children[ref], member.MediaRef)
			}
		}
	}
	for parent := range children {
		sort.Strings(children[parent])
		children[parent] = uniqueStrings(children[parent])
	}
	queue := []string{mediaRef}
	seen := make(map[string]struct{})
	ordered := make([]string, 0)
	for len(queue) > 0 {
		ref := queue[0]
		queue = queue[1:]
		if _, duplicate := seen[ref]; duplicate {
			continue
		}
		seen[ref] = struct{}{}
		ordered = append(ordered, ref)
		queue = append(queue, children[ref]...)
	}
	deletedAt := s.now().UTC()
	for index, ref := range ordered {
		select {
		case <-ctx.Done():
			return Descriptor{}, ctx.Err()
		default:
		}
		descriptor, exists := descriptors[ref]
		if !exists {
			continue
		}
		descriptor.Availability = AvailabilityDeleted
		when := deletedAt
		if when.Before(descriptor.CreatedAt) {
			when = descriptor.CreatedAt
		}
		descriptor.DeletedAt = &when
		if index == 0 {
			descriptor.DeletionReason = reason
		} else if reason == "expired" || reason == "recovery_expired" {
			descriptor.DeletionReason = "parent_expired"
		} else {
			descriptor.DeletionReason = "parent_deleted"
		}
		if err := s.writeDescriptorAtomic(s.tombstonePath(ref), descriptor); err != nil {
			return Descriptor{}, err
		}
		if err := removeRegularIfExists(s.descriptorPath(ref)); err != nil {
			return Descriptor{}, err
		}
		if descriptor.Kind != KindFrameSet {
			if err := removeRegularIfExists(s.objectPath(ref)); err != nil {
				return Descriptor{}, err
			}
		}
		if ref == mediaRef {
			root = descriptor
		}
	}
	return cloneDescriptor(root), nil
}

func (s *Store) openAndVerify(ctx context.Context, descriptor Descriptor) (*os.File, error) {
	path := s.objectPath(descriptor.MediaRef)
	before, err := regularFileInfo(path)
	if err != nil {
		return nil, err
	}
	if before.Size() != descriptor.Integrity.SizeBytes || before.Size() > s.maxObjectBytes {
		return nil, ErrIntegrityMismatch
	}
	file, err := os.Open(path)
	if os.IsNotExist(err) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	fail := func(err error) (*os.File, error) {
		_ = file.Close()
		return nil, err
	}
	after, err := file.Stat()
	if err != nil || !os.SameFile(before, after) || !after.Mode().IsRegular() {
		if err != nil {
			return fail(err)
		}
		return fail(ErrIntegrityMismatch)
	}
	hash := sha256.New()
	read, err := io.Copy(hash, io.LimitReader(contextReader{ctx: ctx, source: file}, descriptor.Integrity.SizeBytes+1))
	if err != nil {
		return fail(err)
	}
	if read != descriptor.Integrity.SizeBytes || hex.EncodeToString(hash.Sum(nil)) != descriptor.Integrity.SHA256 {
		return fail(ErrIntegrityMismatch)
	}
	if _, err := file.Seek(0, io.SeekStart); err != nil {
		return fail(err)
	}
	return file, nil
}

func (s *Store) reconcile() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.ensureLayout(); err != nil {
		return err
	}
	if err := s.removeTemporaryResidues(); err != nil {
		return err
	}
	tombstones, err := s.loadDirectoryLocked(s.tombstonesDir, AvailabilityDeleted)
	if err != nil {
		return err
	}
	for ref := range tombstones {
		if err := removeRegularIfExists(s.descriptorPath(ref)); err != nil {
			return err
		}
		if err := removeRegularIfExists(s.objectPath(ref)); err != nil {
			return err
		}
	}
	descriptors, err := s.loadActiveLocked()
	if err != nil {
		return err
	}
	invalid := make(map[string]string)
	now := s.now().UTC()
	for ref, descriptor := range descriptors {
		if expired(descriptor, now) {
			invalid[ref] = "recovery_expired"
			continue
		}
		if descriptor.RuntimeLease.SourceMediaRef != "" {
			source, exists := descriptors[descriptor.RuntimeLease.SourceMediaRef]
			if !exists || !validRuntimeLeaseGraph(source, descriptor) {
				invalid[ref] = "recovery_runtime_lease_invalid"
				continue
			}
		}
		if descriptor.Lineage.ParentMediaRef != "" {
			parent, exists := descriptors[descriptor.Lineage.ParentMediaRef]
			if !exists || parent.Binding.TenantID != descriptor.Binding.TenantID || parent.Binding.SiteID != descriptor.Binding.SiteID ||
				parent.Binding.RunID != descriptor.Binding.RunID || !validChildExpiry(parent, descriptor) {
				invalid[ref] = "recovery_lineage_invalid"
				continue
			}
		}
		if descriptor.Kind == KindFrameSet {
			if !validFrameSetGraph(descriptor, descriptors) {
				invalid[ref] = "recovery_frame_set_invalid"
			}
			continue
		}
		if err := s.verifyObject(descriptor); err != nil {
			switch {
			case errors.Is(err, ErrNotFound):
				invalid[ref] = "recovery_content_missing"
			case errors.Is(err, ErrIntegrityMismatch):
				invalid[ref] = "recovery_hash_mismatch"
			default:
				return err
			}
		}
	}
	refs := make([]string, 0, len(invalid))
	for ref := range invalid {
		refs = append(refs, ref)
	}
	sort.Strings(refs)
	for _, ref := range refs {
		if _, err := regularFileInfo(s.descriptorPath(ref)); errors.Is(err, ErrNotFound) {
			continue
		} else if err != nil {
			return err
		}
		if _, err := s.deleteCascadeLocked(context.Background(), ref, invalid[ref]); err != nil {
			return err
		}
	}
	if err := s.reconcileIdempotencyLocked(); err != nil {
		return err
	}
	return s.removeOrphanObjectsLocked()
}

func validFrameSetGraph(parent Descriptor, descriptors map[string]Descriptor) bool {
	manifest, err := json.Marshal(parent.FrameMembers)
	if err != nil || digestBytes(manifest) != parent.Integrity.SHA256 {
		return false
	}
	for _, member := range parent.FrameMembers {
		child, exists := descriptors[member.MediaRef]
		if !exists || child.Kind != KindImage || child.Integrity.SHA256 != member.SHA256 ||
			child.Lineage.ParentMediaRef != parent.MediaRef || child.Lineage.Ordinal != member.Ordinal ||
			child.Lineage.OffsetMillis != member.OffsetMillis || child.Lineage.TransformPolicyRef != member.TransformPolicyRef ||
			child.Governance.ExpiresAt.Before(parent.Governance.ExpiresAt) {
			return false
		}
	}
	return true
}

func validRuntimeLeaseGraph(source, lease Descriptor) bool {
	if source.Kind == KindFrameSet || source.RuntimeLease.SourceMediaRef != "" || source.Lineage.ParentMediaRef != "" ||
		lease.RuntimeLease.SourceMediaRef != source.MediaRef || lease.RuntimeLease.SourceSHA256 != source.Integrity.SHA256 ||
		lease.Binding.TenantID != source.Binding.TenantID || lease.Binding.SiteID != source.Binding.SiteID ||
		lease.Binding.SourceRef != source.Binding.SourceRef || lease.Binding.RunID == source.Binding.RunID ||
		lease.Kind != source.Kind || lease.Encoding != source.Encoding || lease.Integrity != source.Integrity ||
		lease.CreatedAt.Before(source.CreatedAt) || !runtimeLeaseGovernanceAllowed(source.Governance, lease.Governance) {
		return false
	}
	return equalTemporal(source.Temporal, lease.Temporal)
}

func runtimeLeaseGovernanceAllowed(source, lease Governance) bool {
	if lease.PrivacyClass != source.PrivacyClass || lease.RedactionPolicyRef != source.RedactionPolicyRef ||
		lease.ExpiresAt.After(source.ExpiresAt) {
		return false
	}
	allowed := make(map[string]struct{}, len(source.Audience))
	for _, audience := range source.Audience {
		allowed[audience] = struct{}{}
	}
	for _, audience := range lease.Audience {
		if _, ok := allowed[audience]; !ok {
			return false
		}
	}
	return true
}

func equalTemporal(left, right Temporal) bool {
	if left.DurationMillis != right.DurationMillis || left.SampleOrdinal != right.SampleOrdinal ||
		(left.WindowStart == nil) != (right.WindowStart == nil) || (left.WindowEnd == nil) != (right.WindowEnd == nil) {
		return false
	}
	if left.WindowStart != nil && !left.WindowStart.Equal(*right.WindowStart) {
		return false
	}
	return left.WindowEnd == nil || left.WindowEnd.Equal(*right.WindowEnd)
}

func validChildExpiry(parent, child Descriptor) bool {
	if parent.Kind == KindFrameSet {
		return !child.Governance.ExpiresAt.Before(parent.Governance.ExpiresAt)
	}
	return !child.Governance.ExpiresAt.After(parent.Governance.ExpiresAt)
}

func (s *Store) verifyObject(descriptor Descriptor) error {
	file, err := s.openAndVerify(context.Background(), descriptor)
	if err != nil {
		return err
	}
	return file.Close()
}

func (s *Store) loadActiveLocked() (map[string]Descriptor, error) {
	return s.loadDirectoryLocked(s.descriptorsDir, AvailabilityAvailable)
}

func (s *Store) loadDirectoryLocked(directory string, availability Availability) (map[string]Descriptor, error) {
	entries, err := os.ReadDir(directory)
	if err != nil {
		return nil, err
	}
	result := make(map[string]Descriptor, len(entries))
	for _, entry := range entries {
		ref, err := mediaRefFromEntry(entry, ".json")
		if err != nil {
			return nil, err
		}
		descriptor, err := s.readDescriptor(filepath.Join(directory, entry.Name()))
		if err != nil {
			return nil, err
		}
		if descriptor.Availability != availability {
			return nil, ErrCorruptDescriptor
		}
		result[ref] = descriptor
	}
	return result, nil
}

func (s *Store) removeOrphanObjectsLocked() error {
	entries, err := os.ReadDir(s.objectsDir)
	if err != nil {
		return err
	}
	for _, entry := range entries {
		ref, err := mediaRefFromEntry(entry, ".media")
		if err != nil {
			return err
		}
		if _, err := regularFileInfo(s.descriptorPath(ref)); err == nil {
			continue
		} else if !errors.Is(err, ErrNotFound) {
			return err
		}
		if err := removeRegularIfExists(s.objectPath(ref)); err != nil {
			return err
		}
	}
	return nil
}

func (s *Store) removeTemporaryResidues() error {
	entries, err := os.ReadDir(s.tempDir)
	if err != nil {
		return err
	}
	for _, entry := range entries {
		name := entry.Name()
		recognized := strings.HasPrefix(name, "put-") && strings.HasSuffix(name, ".media") ||
			strings.HasPrefix(name, "descriptor-") && strings.HasSuffix(name, ".json") ||
			strings.HasPrefix(name, "idempotency-") && strings.HasSuffix(name, ".json")
		if !recognized || entry.IsDir() || entry.Type()&os.ModeSymlink != 0 {
			return ErrUnsafePath
		}
		if err := removeRegularIfExists(filepath.Join(s.tempDir, name)); err != nil {
			return err
		}
	}
	return nil
}

func (s *Store) writeDescriptorAtomic(target string, descriptor Descriptor) error {
	if err := validateDescriptor(descriptor); err != nil {
		return err
	}
	encoded, err := json.Marshal(descriptor)
	if err != nil || len(encoded) > descriptorMaxBytes {
		return ErrCorruptDescriptor
	}
	temporary, err := os.CreateTemp(s.tempDir, "descriptor-*.json")
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
	if _, err := temporary.Write(encoded); err != nil {
		return err
	}
	if err := temporary.Sync(); err != nil {
		return err
	}
	if err := temporary.Close(); err != nil {
		return err
	}
	if err := os.Rename(name, target); err != nil {
		return err
	}
	if err := os.Chmod(target, 0o600); err != nil {
		return err
	}
	return syncMediaDirectory(target)
}

func (s *Store) readOptionalDescriptor(path string) (Descriptor, bool, error) {
	descriptor, err := s.readDescriptor(path)
	if errors.Is(err, ErrNotFound) {
		return Descriptor{}, false, nil
	}
	return descriptor, err == nil, err
}

func (s *Store) readDescriptor(path string) (Descriptor, error) {
	info, err := regularFileInfo(path)
	if err != nil {
		return Descriptor{}, err
	}
	if info.Size() > descriptorMaxBytes {
		return Descriptor{}, ErrCorruptDescriptor
	}
	file, err := os.Open(path)
	if os.IsNotExist(err) {
		return Descriptor{}, ErrNotFound
	}
	if err != nil {
		return Descriptor{}, err
	}
	defer file.Close()
	after, err := file.Stat()
	if err != nil || !os.SameFile(info, after) {
		if err != nil {
			return Descriptor{}, err
		}
		return Descriptor{}, ErrUnsafePath
	}
	raw, err := io.ReadAll(io.LimitReader(file, descriptorMaxBytes+1))
	if err != nil || len(raw) > descriptorMaxBytes {
		return Descriptor{}, ErrCorruptDescriptor
	}
	var descriptor Descriptor
	if err := strictjson.ValidateExactFields(raw, &descriptor, 8); err != nil {
		return Descriptor{}, ErrCorruptDescriptor
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&descriptor); err != nil {
		return Descriptor{}, ErrCorruptDescriptor
	}
	if err := validateDescriptor(descriptor); err != nil {
		return Descriptor{}, err
	}
	expectedRef := strings.TrimSuffix(filepath.Base(path), filepath.Ext(path))
	if descriptor.MediaRef != expectedRef {
		return Descriptor{}, ErrCorruptDescriptor
	}
	return descriptor, nil
}

func (s *Store) ensureLayout() error {
	if err := ensurePrivateDirectory(s.root); err != nil {
		return err
	}
	if err := verifyStoreRootMarker(s.root); err != nil {
		return err
	}
	for _, directory := range []string{s.objectsDir, s.descriptorsDir, s.tombstonesDir, s.idempotencyDir, s.tempDir} {
		if err := ensurePrivateDirectory(directory); err != nil {
			return err
		}
	}
	return nil
}

func canonicalStoreRoot(raw string) (string, error) {
	absolute, err := filepath.Abs(filepath.Clean(raw))
	if err != nil {
		return "", err
	}
	cursor := absolute
	missing := []string{}
	for {
		info, statErr := os.Lstat(cursor)
		if statErr == nil {
			if info.Mode()&os.ModeSymlink != 0 || !info.IsDir() {
				return "", ErrUnsafePath
			}
			resolved, resolveErr := filepath.EvalSymlinks(cursor)
			if resolveErr != nil {
				return "", resolveErr
			}
			for index := len(missing) - 1; index >= 0; index-- {
				resolved = filepath.Join(resolved, missing[index])
			}
			if err := os.MkdirAll(resolved, 0o700); err != nil {
				return "", err
			}
			return resolved, nil
		}
		if !os.IsNotExist(statErr) {
			return "", statErr
		}
		parent := filepath.Dir(cursor)
		if parent == cursor {
			return "", ErrUnsafePath
		}
		missing = append(missing, filepath.Base(cursor))
		cursor = parent
	}
}

func claimStoreRoot(root string) error {
	if filepath.Dir(root) == root {
		return ErrUnsafePath
	}
	marker := filepath.Join(root, rootMarkerName)
	if _, err := os.Lstat(marker); err == nil {
		return verifyStoreRootMarker(root)
	} else if !os.IsNotExist(err) {
		return err
	}
	entries, err := os.ReadDir(root)
	if err != nil {
		return err
	}
	if len(entries) != 0 {
		return ErrIncompatibleStore
	}
	file, err := os.OpenFile(marker, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return err
	}
	remove := true
	defer func() {
		_ = file.Close()
		if remove {
			_ = os.Remove(marker)
		}
	}()
	if _, err := io.WriteString(file, rootMarkerBody); err != nil {
		return err
	}
	if err := file.Sync(); err != nil {
		return err
	}
	if err := file.Close(); err != nil {
		return err
	}
	if err := os.Chmod(marker, 0o600); err != nil {
		return err
	}
	if err := syncMediaDirectory(marker); err != nil {
		return err
	}
	remove = false
	return nil
}

func verifyStoreRootMarker(root string) error {
	marker := filepath.Join(root, rootMarkerName)
	info, err := regularFileInfo(marker)
	if err != nil || info.Size() != int64(len(rootMarkerBody)) {
		return ErrIncompatibleStore
	}
	content, err := os.ReadFile(marker)
	if err != nil || string(content) != rootMarkerBody {
		return ErrIncompatibleStore
	}
	return os.Chmod(marker, 0o600)
}

func ensurePrivateDirectory(path string) error {
	info, err := os.Lstat(path)
	if os.IsNotExist(err) {
		if err := os.Mkdir(path, 0o700); err != nil && !os.IsExist(err) {
			return err
		}
		info, err = os.Lstat(path)
	}
	if err != nil {
		return err
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.IsDir() {
		return ErrUnsafePath
	}
	return os.Chmod(path, 0o700)
}

func (s *Store) unusedMediaRefLocked() (string, error) {
	for range 8 {
		buffer := make([]byte, 16)
		if _, err := io.ReadFull(rand.Reader, buffer); err != nil {
			return "", err
		}
		ref := "media_" + hex.EncodeToString(buffer)
		available := true
		for _, path := range []string{s.objectPath(ref), s.descriptorPath(ref), s.tombstonePath(ref)} {
			if _, err := os.Lstat(path); err == nil {
				available = false
				break
			} else if !os.IsNotExist(err) {
				return "", err
			}
		}
		if available {
			return ref, nil
		}
	}
	return "", errors.New("could not allocate opaque media reference")
}

func mediaRefFromEntry(entry os.DirEntry, suffix string) (string, error) {
	if entry.IsDir() || entry.Type()&os.ModeSymlink != 0 || !strings.HasSuffix(entry.Name(), suffix) {
		return "", ErrUnsafePath
	}
	ref := strings.TrimSuffix(entry.Name(), suffix)
	if validateMediaRef(ref) != nil {
		return "", ErrUnsafePath
	}
	return ref, nil
}

func regularFileInfo(path string) (os.FileInfo, error) {
	info, err := os.Lstat(path)
	if os.IsNotExist(err) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() {
		return nil, ErrUnsafePath
	}
	return info, nil
}

func requireRegularFile(path string) error {
	_, err := regularFileInfo(path)
	return err
}

func removeRegularIfExists(path string) error {
	if _, err := regularFileInfo(path); errors.Is(err, ErrNotFound) {
		return nil
	} else if err != nil {
		return err
	}
	return os.Remove(path)
}

func expired(descriptor Descriptor, now time.Time) bool {
	return !now.Before(descriptor.Governance.ExpiresAt.UTC())
}

func cloneDescriptor(value Descriptor) Descriptor {
	value.Governance.Audience = append([]string(nil), value.Governance.Audience...)
	members := value.FrameMembers
	value.FrameMembers = make([]FrameMember, len(value.FrameMembers))
	copy(value.FrameMembers, members)
	if value.Temporal.WindowStart != nil {
		copy := *value.Temporal.WindowStart
		value.Temporal.WindowStart = &copy
	}
	if value.Temporal.WindowEnd != nil {
		copy := *value.Temporal.WindowEnd
		value.Temporal.WindowEnd = &copy
	}
	if value.DeletedAt != nil {
		copy := *value.DeletedAt
		value.DeletedAt = &copy
	}
	return value
}

func uniqueStrings(values []string) []string {
	if len(values) < 2 {
		return values
	}
	result := values[:1]
	for _, value := range values[1:] {
		if value != result[len(result)-1] {
			result = append(result, value)
		}
	}
	return result
}

func (s *Store) objectPath(mediaRef string) string {
	return filepath.Join(s.objectsDir, mediaRef+".media")
}

func (s *Store) descriptorPath(mediaRef string) string {
	return filepath.Join(s.descriptorsDir, mediaRef+".json")
}

func (s *Store) tombstonePath(mediaRef string) string {
	return filepath.Join(s.tombstonesDir, mediaRef+".json")
}

type leasedReader struct {
	file    *os.File
	release func()
	once    sync.Once
}

func (r *leasedReader) Read(buffer []byte) (int, error) {
	return r.file.Read(buffer)
}

func (r *leasedReader) Close() error {
	var err error
	r.once.Do(func() {
		err = r.file.Close()
		r.release()
	})
	return err
}

type prefixWriter struct {
	bytes   []byte
	maximum int
}

func (w *prefixWriter) Write(value []byte) (int, error) {
	remaining := w.maximum - len(w.bytes)
	if remaining > 0 {
		if len(value) < remaining {
			remaining = len(value)
		}
		w.bytes = append(w.bytes, value[:remaining]...)
	}
	return len(value), nil
}

type contextReader struct {
	ctx    context.Context
	source io.Reader
}

func (r contextReader) Read(value []byte) (int, error) {
	select {
	case <-r.ctx.Done():
		return 0, r.ctx.Err()
	default:
		return r.source.Read(value)
	}
}
