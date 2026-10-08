package inspectioninteraction

import (
	"bytes"
	"context"
	"errors"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/cosmo-wander-ai/cosmoedge-connect/internal/inspection/planning"
	"github.com/cosmo-wander-ai/cosmoedge-connect/internal/operator/authority"
	"github.com/cosmo-wander-ai/cosmoedge-connect/internal/operator/credential"
	"github.com/cosmo-wander-ai/cosmoedge-connect/internal/operator/onboarding"
	"github.com/cosmo-wander-ai/cosmoedge-connect/internal/operator/profile"
)

func TestRegistrarRoutesConnectionToOnboardingAndChangeToPendingStore(t *testing.T) {
	now := time.Date(2026, 7, 20, 0, 0, 0, 0, time.UTC)
	root := filepath.Join(t.TempDir(), "protected")
	profiles, err := profile.Open(filepath.Join(root, "profiles.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer profiles.Close()
	credentials := credential.NewMemoryStore()
	defer credentials.Purge()
	journal, err := onboarding.OpenJournal(filepath.Join(root, "onboarding.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer journal.Close()
	signer, err := authority.NewSigner("interaction-test-issuer", bytes.Repeat([]byte{0x6b}, 32))
	if err != nil {
		t.Fatal(err)
	}
	defer signer.Close()
	core, err := onboarding.NewService(profiles, credentials, journal, signer, onboarding.WithClock(func() time.Time { return now }))
	if err != nil {
		t.Fatal(err)
	}
	onboardingStore, err := onboarding.OpenHandoffStore(onboarding.HandoffStoreConfig{
		Path: filepath.Join(root, "onboarding-handoffs.db"), Now: func() time.Time { return now },
	})
	if err != nil {
		t.Fatal(err)
	}
	defer onboardingStore.Close()
	entry, err := onboarding.NewEntryService(onboarding.EntryServiceConfig{Core: core, Handoffs: onboardingStore})
	if err != nil {
		t.Fatal(err)
	}
	changeStore := openTestStore(t, filepath.Join(root, "pending-changes.db"), func() time.Time { return now })
	defer changeStore.Close()
	registrar, err := NewRegistrar(RegistrarConfig{Onboarding: entry, Changes: changeStore, Now: func() time.Time { return now }})
	if err != nil {
		t.Fatal(err)
	}

	connection := planning.LocalInteractionRegistration{
		Type: planning.LocalInteractionConnection, TenantID: "tenant-a", SiteID: "site-a",
		PrincipalSHA256: strings.Repeat("a", 64), HandoffRef: "handoff_connection", ExpiresAt: now.Add(10 * time.Minute),
	}
	for attempt := 0; attempt < 2; attempt++ {
		receipt, err := registrar.Register(context.Background(), connection)
		if err != nil || receipt.Type != connection.Type || receipt.HandoffRef != connection.HandoffRef || !receipt.ExpiresAt.Equal(connection.ExpiresAt) {
			t.Fatalf("Register(connection %d)=(%+v, %v)", attempt, receipt, err)
		}
	}
	onboardingRecord, err := onboardingStore.Resolve(context.Background(), onboarding.HandoffBinding{
		TenantID: connection.TenantID, SiteID: connection.SiteID, PrincipalSHA256: connection.PrincipalSHA256,
	}, connection.HandoffRef)
	if err != nil || onboardingRecord.State != onboarding.HandoffPending || onboardingRecord.ExpiresAt != connection.ExpiresAt {
		t.Fatalf("onboarding handoff=%+v err=%v", onboardingRecord, err)
	}
	items, err := profiles.ListSite(context.Background(), connection.TenantID, connection.SiteID)
	if err != nil || len(items) != 0 {
		t.Fatalf("registration unexpectedly created device profiles=%d err=%v", len(items), err)
	}

	change := planning.PendingChangeIntent{
		Operation: planning.PendingTaskDisable, SourceRef: "source-opaque", ExpectedSourceRevision: 4,
		TaskRef: "task-opaque", ExpectedTaskRevision: 7,
	}
	persistent := planning.LocalInteractionRegistration{
		Type: planning.LocalInteractionPersistentChange, TenantID: "tenant-a", SiteID: "site-a",
		PrincipalSHA256: strings.Repeat("a", 64), HandoffRef: "handoff_persistent", ExpiresAt: now.Add(10 * time.Minute),
		Change: &change,
	}
	for attempt := 0; attempt < 2; attempt++ {
		receipt, err := registrar.Register(context.Background(), persistent)
		if err != nil || receipt.Type != persistent.Type || receipt.HandoffRef != persistent.HandoffRef || !receipt.ExpiresAt.Equal(persistent.ExpiresAt) {
			t.Fatalf("Register(persistent %d)=(%+v, %v)", attempt, receipt, err)
		}
	}
	pending, err := changeStore.Resolve(context.Background(), Binding{
		TenantID: persistent.TenantID, SiteID: persistent.SiteID, PrincipalSHA256: persistent.PrincipalSHA256,
	}, persistent.HandoffRef)
	if err != nil || pending.Operation != planning.PendingTaskDisable || pending.SourceRef != "source-opaque" ||
		pending.TaskRef != "task-opaque" || pending.ExpectedSourceRevision != 4 || pending.ExpectedTaskRevision != 7 {
		t.Fatalf("pending local change=%+v err=%v", pending, err)
	}
	if _, err := onboardingStore.Resolve(context.Background(), onboarding.HandoffBinding{
		TenantID: persistent.TenantID, SiteID: persistent.SiteID, PrincipalSHA256: persistent.PrincipalSHA256,
	}, persistent.HandoffRef); !errors.Is(err, onboarding.ErrHandoffNotFound) {
		t.Fatalf("persistent change leaked into onboarding handoffs: %v", err)
	}
}

func TestRegistrarFailsClosedOnOnboardingMismatchExpiryAndPersistentConflict(t *testing.T) {
	now := time.Date(2026, 7, 20, 1, 0, 0, 0, time.UTC)
	store := openTestStore(t, filepath.Join(t.TempDir(), "protected", "pending.db"), func() time.Time { return now })
	defer store.Close()
	base := planning.LocalInteractionRegistration{
		Type: planning.LocalInteractionConnection, TenantID: "tenant-a", SiteID: "site-a",
		PrincipalSHA256: strings.Repeat("a", 64), HandoffRef: "handoff_exact", ExpiresAt: now.Add(time.Minute),
	}
	injected := errors.New("injected onboarding failure")
	for _, test := range []struct {
		name  string
		entry *onboardingEntryFixture
		want  error
	}{
		{name: "error", entry: &onboardingEntryFixture{err: injected}, want: injected},
		{name: "ref", entry: &onboardingEntryFixture{ticket: onboarding.SkillHandoff{HandoffRef: "handoff_wrong", ExpiresAt: base.ExpiresAt}}, want: ErrOnboardingMismatch},
		{name: "expiry", entry: &onboardingEntryFixture{ticket: onboarding.SkillHandoff{HandoffRef: base.HandoffRef, ExpiresAt: base.ExpiresAt.Add(time.Second)}}, want: ErrOnboardingMismatch},
		{name: "noncanonical expiry", entry: &onboardingEntryFixture{ticket: onboarding.SkillHandoff{HandoffRef: base.HandoffRef, ExpiresAt: base.ExpiresAt.In(time.FixedZone("other", 3600))}}, want: ErrOnboardingMismatch},
	} {
		t.Run(test.name, func(t *testing.T) {
			registrar, err := NewRegistrar(RegistrarConfig{Onboarding: test.entry, Changes: store, Now: func() time.Time { return now }})
			if err != nil {
				t.Fatal(err)
			}
			_, err = registrar.Register(context.Background(), base)
			if !errors.Is(err, test.want) {
				t.Fatalf("Register(mismatch) error=%v", err)
			}
		})
	}

	exactEntry := &onboardingEntryFixture{}
	exactEntry.ticket = onboarding.SkillHandoff{HandoffRef: base.HandoffRef, ExpiresAt: base.ExpiresAt}
	registrar, err := NewRegistrar(RegistrarConfig{Onboarding: exactEntry, Changes: store, Now: func() time.Time { return now }})
	if err != nil {
		t.Fatal(err)
	}
	expired := base
	expired.ExpiresAt = now
	if _, err := registrar.Register(context.Background(), expired); !errors.Is(err, ErrInvalidRegistration) {
		t.Fatalf("Register(expired) error=%v", err)
	}

	change := planning.PendingChangeIntent{Operation: planning.PendingSourceUpdate, SourceRef: "source-a", ExpectedSourceRevision: 1}
	persistent := planning.LocalInteractionRegistration{
		Type: planning.LocalInteractionPersistentChange, TenantID: base.TenantID, SiteID: base.SiteID,
		PrincipalSHA256: base.PrincipalSHA256, HandoffRef: "handoff_conflict", ExpiresAt: base.ExpiresAt, Change: &change,
	}
	if _, err := registrar.Register(context.Background(), persistent); err != nil {
		t.Fatal(err)
	}
	changed := change
	changed.ExpectedSourceRevision = 2
	persistent.Change = &changed
	if _, err := registrar.Register(context.Background(), persistent); !errors.Is(err, ErrConflict) {
		t.Fatalf("Register(persistent conflict) error=%v", err)
	}
}

type onboardingEntryFixture struct {
	ticket onboarding.SkillHandoff
	err    error
	last   onboarding.SkillHandoffRequest
}

func (f *onboardingEntryFixture) BeginSkill(_ context.Context, request onboarding.SkillHandoffRequest) (onboarding.SkillHandoff, error) {
	f.last = request
	if f.err != nil {
		return onboarding.SkillHandoff{}, f.err
	}
	return f.ticket, nil
}
