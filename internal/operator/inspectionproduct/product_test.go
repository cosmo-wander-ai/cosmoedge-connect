package inspectionproduct

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/cosmo-wander-ai/cosmoedge-connect/internal/inspection"
	inspectionapplication "github.com/cosmo-wander-ai/cosmoedge-connect/internal/inspection/application"
	inspectionauthority "github.com/cosmo-wander-ai/cosmoedge-connect/internal/inspection/authority"
	inspectioncatalog "github.com/cosmo-wander-ai/cosmoedge-connect/internal/inspection/catalog"
	inspectionchangeflow "github.com/cosmo-wander-ai/cosmoedge-connect/internal/inspection/changeflow"
	inspectionchannelauth "github.com/cosmo-wander-ai/cosmoedge-connect/internal/inspection/channelauth"
	inspectiondelivery "github.com/cosmo-wander-ai/cosmoedge-connect/internal/inspection/delivery"
	inspectiondeliverybinding "github.com/cosmo-wander-ai/cosmoedge-connect/internal/inspection/deliverybinding"
	inspectionhttpapi "github.com/cosmo-wander-ai/cosmoedge-connect/internal/inspection/httpapi"
	inspectionmedia "github.com/cosmo-wander-ai/cosmoedge-connect/internal/inspection/media"
	inspectionmediaprep "github.com/cosmo-wander-ai/cosmoedge-connect/internal/inspection/mediaprep"
	inspectionplanning "github.com/cosmo-wander-ai/cosmoedge-connect/internal/inspection/planning"
	inspectionruntime "github.com/cosmo-wander-ai/cosmoedge-connect/internal/inspection/runtime"
	inspectionschedule "github.com/cosmo-wander-ai/cosmoedge-connect/internal/inspection/schedule"
	inspectionstore "github.com/cosmo-wander-ai/cosmoedge-connect/internal/inspection/store"
	inspectiontemporary "github.com/cosmo-wander-ai/cosmoedge-connect/internal/inspection/temporary"
	"github.com/cosmo-wander-ai/cosmoedge-connect/internal/inspectiontest"
	operatorauthority "github.com/cosmo-wander-ai/cosmoedge-connect/internal/operator/authority"
	"github.com/cosmo-wander-ai/cosmoedge-connect/internal/operator/credential"
	"github.com/cosmo-wander-ai/cosmoedge-connect/internal/operator/inspectioninteraction"
	"github.com/cosmo-wander-ai/cosmoedge-connect/internal/operator/onboarding"
	"github.com/cosmo-wander-ai/cosmoedge-connect/internal/operator/profile"
)

func TestDisabledProductHasZeroEffects(t *testing.T) {
	root := filepath.Join(t.TempDir(), "must-not-exist")
	product, err := New(Config{Enabled: false, StateRoot: root}, Factories{})
	if err != nil {
		t.Fatal(err)
	}
	if err := product.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	if err := product.Stop(); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Lstat(root); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("disabled product touched state root: %v", err)
	}
	if readiness := product.Readiness(); readiness.Enabled || readiness.Ready || readiness.State != StateDisabled || readiness.Generation != 0 || readiness.Failure != "" {
		t.Fatalf("unexpected disabled readiness: %+v", readiness)
	}
	if metrics := product.Metrics(); metrics != (Metrics{}) {
		t.Fatalf("disabled product emitted lifecycle metrics: %+v", metrics)
	}
	if handler, err := product.Handler(); !errors.Is(err, ErrHTTPSurfaceUnavailable) || handler != nil {
		t.Fatalf("disabled product exposed HTTP surface: handler=%v err=%v", handler, err)
	}
}

func TestProductOwnsGenerationBoundExactScopeDeliveryBindingManagement(t *testing.T) {
	factories := persistentTestFactories(validTestBuilders())
	credentials := credential.NewMemoryStore()
	t.Cleanup(credentials.Purge)
	factories.OpenCredentials = func(context.Context, string) (Opened[credential.SecretStore], error) {
		return Opened[credential.SecretStore]{Value: credentials, Close: noClose}, nil
	}
	product, err := New(Config{
		Enabled: true, StateRoot: filepath.Join(t.TempDir(), "state"), TemporaryWorkerOwner: "binding-management-test",
	}, factories)
	if err != nil {
		t.Fatal(err)
	}
	session := inspectionhttpapi.SessionBinding{
		TenantID: "tenant-binding", SiteID: "site-binding", Channel: "wechat",
		ConversationRef: "conversation-binding", RecipientRef: "recipient-binding", PrincipalSHA256: strings.Repeat("a", 64),
	}
	credentialSHA256 := productDigest("binding-management-credential")
	authorizationRequest := inspectionhttpapi.AuthorizationRequest{
		Scope: inspectionhttpapi.ScopeRequestCreate, CredentialSHA256: credentialSHA256,
	}
	if manager, err := product.DeliveryBindings(context.Background(), authorizationRequest); !errors.Is(err, ErrDeliveryBindingUnavailable) || manager != nil {
		t.Fatalf("stopped DeliveryBindings()=%v err=%v", manager, err)
	}
	if err := product.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	if _, created, err := product.opened.channelAuth.Value.Bind(context.Background(), inspectionchannelauth.Binding{
		CredentialSHA256: credentialSHA256, Session: session, Scopes: []inspectionhttpapi.Scope{inspectionhttpapi.ScopeRequestCreate},
		CreatedAt: now, ExpiresAt: now.Add(time.Hour),
	}); err != nil || !created {
		t.Fatalf("Bind() created=%v err=%v", created, err)
	}
	manager, err := product.DeliveryBindings(context.Background(), authorizationRequest)
	if err != nil {
		t.Fatal(err)
	}
	binding := inspectiondeliverybinding.Binding{
		TenantID: session.TenantID, SiteID: session.SiteID, BindingRef: "binding-managed", Revision: 1,
		Audience: inspectiondelivery.Audience{
			TenantID: session.TenantID, SiteID: session.SiteID, Channel: session.Channel,
			ConversationRef: session.ConversationRef, RecipientRef: session.RecipientRef,
		},
		PrincipalSHA256: session.PrincipalSHA256, CreatedAt: now, ValidFrom: now, ValidUntil: now.Add(time.Hour),
	}
	substituted := binding
	substituted.Audience.RecipientRef = "recipient-other"
	if _, _, err := manager.Register(context.Background(), substituted); !errors.Is(err, ErrDeliveryBindingScope) {
		t.Fatalf("cross-scope Register() err=%v", err)
	}
	stored, created, err := manager.Register(context.Background(), binding)
	if err != nil || !created {
		t.Fatalf("Register() created=%v err=%v", created, err)
	}
	if _, err := product.opened.deliveryBindings.Value.Resolve(context.Background(), inspectiondeliverybinding.ResolveRequest{
		TenantID: stored.TenantID, SiteID: stored.SiteID, BindingRef: stored.BindingRef, Revision: stored.Revision,
		AudienceSHA256: stored.AudienceSHA256, PrincipalSHA256: stored.PrincipalSHA256, At: now,
	}); err != nil {
		t.Fatalf("newly registered binding was not admission-ready: %v", err)
	}
	revoked, changed, err := manager.Revoke(context.Background(), stored.BindingRef, stored.Revision, now.Add(time.Minute))
	if err != nil || !changed || revoked.RevokedAt.IsZero() {
		t.Fatalf("Revoke() changed=%v value=%+v err=%v", changed, revoked, err)
	}
	if _, err := product.opened.deliveryBindings.Value.Resolve(context.Background(), inspectiondeliverybinding.ResolveRequest{
		TenantID: stored.TenantID, SiteID: stored.SiteID, BindingRef: stored.BindingRef, Revision: stored.Revision,
		AudienceSHA256: stored.AudienceSHA256, PrincipalSHA256: stored.PrincipalSHA256, At: now.Add(2 * time.Minute),
	}); !errors.Is(err, inspectiondeliverybinding.ErrInactive) {
		t.Fatalf("revoked binding remained admission-ready: %v", err)
	}
	if err := product.opened.channelAuth.Value.Revoke(context.Background(), credentialSHA256, now.Add(3*time.Minute)); err != nil {
		t.Fatal(err)
	}
	if _, _, err := manager.Register(context.Background(), binding); !errors.Is(err, ErrDeliveryBindingUnavailable) {
		t.Fatalf("revoked caller credential manager Register() err=%v", err)
	}
	if err := product.Stop(); err != nil {
		t.Fatal(err)
	}
	if _, _, err := manager.Register(context.Background(), binding); !errors.Is(err, ErrDeliveryBindingUnavailable) {
		t.Fatalf("stale generation manager Register() err=%v", err)
	}
}

func TestScheduledApplicationRetentionWaitsForAllTerminalProofsAcrossRestart(t *testing.T) {
	ctx := context.Background()
	now := time.Now().UTC().Truncate(time.Second)
	createdAt := now.Add(-31 * 24 * time.Hour)
	root := filepath.Join(t.TempDir(), "cross-store-state")
	applicationPath := filepath.Join(root, "application.db")
	runPath := filepath.Join(root, "runs.db")
	deliveryPath := filepath.Join(root, "delivery.db")
	applicationState, err := inspectionapplication.OpenState(inspectionapplication.StateConfig{
		Path: applicationPath, RequestRetention: 30 * 24 * time.Hour, FeedbackRetention: 90 * 24 * time.Hour,
		Now: func() time.Time { return now },
	})
	if err != nil {
		t.Fatal(err)
	}
	runs, err := inspectionstore.Open(runPath)
	if err != nil {
		t.Fatal(err)
	}
	deliveries, err := inspectiondelivery.OpenSQLite(deliveryPath)
	if err != nil {
		t.Fatal(err)
	}
	closeStores := func() {
		for _, closeStore := range []func() error{deliveries.Close, runs.Close, applicationState.Close} {
			if err := closeStore(); err != nil {
				t.Fatal(err)
			}
		}
	}

	template := inspectiontest.PublishedSceneTemplate()
	assignment := inspectiontest.PublishedSceneAssignment()
	request := inspectiontest.SceneRunRequest()
	request.Origin = inspection.OriginSchedule
	request.RequestID = "request-retention-product"
	request.RequestedAt = createdAt
	request.Deadline = createdAt.Add(5 * time.Minute)
	plan, err := inspection.CompilePlan(template, assignment, request)
	if err != nil {
		t.Fatal(err)
	}
	runID, err := inspectionruntime.RunIDForPlan(plan)
	if err != nil {
		t.Fatal(err)
	}
	requestJSON, err := json.Marshal(request)
	if err != nil {
		t.Fatal(err)
	}
	session := inspectionhttpapi.SessionBinding{
		TenantID: request.TenantID, SiteID: request.SiteID, Channel: "wechat",
		ConversationRef: "conversation-retention", RecipientRef: "recipient-retention", PrincipalSHA256: strings.Repeat("b", 64),
	}
	audience := inspectiondelivery.Audience{
		TenantID: session.TenantID, SiteID: session.SiteID, Channel: session.Channel,
		ConversationRef: session.ConversationRef, RecipientRef: session.RecipientRef,
	}
	audienceSHA, err := audience.SHA256()
	if err != nil {
		t.Fatal(err)
	}
	publicRunRef := "scheduled-retention-product"
	decision, created, err := applicationState.FreezeScheduledDecision(ctx, inspectionapplication.ScheduledDecisionRecord{
		Session: session, PublicRunRef: publicRunRef, InternalRunID: runID,
		OccurrenceID: "occurrence-retention-product", SubmissionRef: "submission-retention-product",
		BindingRef: "binding-retention-product", BindingRevision: 1, AudienceSHA256: audienceSHA,
		DeliverySHA256: productDigest("delivery-retention"), ServicePrincipalSHA256: productDigest("service-retention"),
		OccurrenceSHA256: productDigest("occurrence-retention"), RequestSHA256: productDigest(string(requestJSON)),
		PlanSHA256: plan.PlanSHA256, Template: template, Assignment: assignment, RunRequest: request, CreatedAt: createdAt,
	})
	if err != nil || !created {
		t.Fatalf("FreezeScheduledDecision() created=%v err=%v", created, err)
	}
	if _, created, err := runs.CreateQueuedRun(ctx, plan, runID, createdAt); err != nil || !created {
		t.Fatalf("CreateQueuedRun() created=%v err=%v", created, err)
	}
	resultRef, err := inspectiondelivery.ResultRefForRun(publicRunRef)
	if err != nil {
		t.Fatal(err)
	}
	message, err := inspectiondelivery.NewMessage(publicRunRef, resultRef, audience,
		inspectiondelivery.Presentation{Title: "巡检结果", Summary: "定时巡检已完成"}, nil, createdAt.Add(2*time.Second))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := deliveries.Enqueue(ctx, message); err != nil {
		t.Fatal(err)
	}
	if purged, err := purgeScheduledApplicationState(ctx, applicationState, runs, occurrenceReleaseProof(true), deliveries, now); err != nil || purged != 0 {
		t.Fatalf("nonterminal run purge=%d err=%v", purged, err)
	}
	if err := runs.Cancel(ctx, runID, createdAt.Add(time.Second), "retention_test_cancelled"); err != nil {
		t.Fatal(err)
	}
	if purged, err := purgeScheduledApplicationState(ctx, applicationState, runs, occurrenceReleaseProof(true), deliveries, now); err != nil || purged != 0 {
		t.Fatalf("pending delivery purge=%d err=%v", purged, err)
	}
	_, attempt, claimed, err := deliveries.Claim(ctx, "retention-delivery", createdAt.Add(3*time.Second), time.Minute)
	if err != nil || !claimed {
		t.Fatalf("Claim() claimed=%v err=%v", claimed, err)
	}
	if err := deliveries.MarkDelivered(ctx, attempt, "receipt-retention", createdAt.Add(4*time.Second)); err != nil {
		t.Fatal(err)
	}
	closeStores()

	applicationState, err = inspectionapplication.OpenState(inspectionapplication.StateConfig{
		Path: applicationPath, RequestRetention: 30 * 24 * time.Hour, FeedbackRetention: 90 * 24 * time.Hour,
		Now: func() time.Time { return now },
	})
	if err != nil {
		t.Fatal(err)
	}
	runs, err = inspectionstore.Open(runPath)
	if err != nil {
		t.Fatal(err)
	}
	deliveries, err = inspectiondelivery.OpenSQLite(deliveryPath)
	if err != nil {
		t.Fatal(err)
	}
	defer closeStores()
	if purged, err := purgeScheduledApplicationState(ctx, applicationState, runs, occurrenceReleaseProof(false), deliveries, now); err != nil || purged != 0 {
		t.Fatalf("held reservation purge=%d err=%v", purged, err)
	}
	if _, err := applicationState.GetScheduledDecisionByRunID(ctx, decision.InternalRunID); err != nil {
		t.Fatalf("restart lost submitted binding before reservation release: %v", err)
	}
	if purged, err := purgeScheduledApplicationState(ctx, applicationState, runs, occurrenceReleaseProof(true), deliveries, now); err != nil || purged != 1 {
		t.Fatalf("terminal proof purge=%d err=%v", purged, err)
	}
	if _, err := applicationState.GetScheduledDecisionByRunID(ctx, decision.InternalRunID); !errors.Is(err, inspectionapplication.ErrStateNotFound) {
		t.Fatalf("terminal cross-store binding remained: %v", err)
	}
}

type occurrenceReleaseProof bool

func (proof occurrenceReleaseProof) IsOccurrenceReleasedTerminal(context.Context, string, string) (bool, error) {
	return bool(proof), nil
}

func productDigest(value string) string {
	digest := sha256.Sum256([]byte(value))
	return hex.EncodeToString(digest[:])
}

func TestResourcesExposeOnlyInspectionDomainState(t *testing.T) {
	resourceType := reflect.TypeOf(Resources{})
	gotFields := make([]string, 0, resourceType.NumField())
	for index := 0; index < resourceType.NumField(); index++ {
		field := resourceType.Field(index)
		if field.PkgPath != "" {
			t.Fatalf("Resources contains an unexported ambiguity field %q", field.Name)
		}
		gotFields = append(gotFields, field.Name)
	}
	wantFields := []string{
		"Catalog", "Application", "ChannelAuth", "Runs", "Temporary", "Schedules", "Media", "Delivery",
	}
	if !slices.Equal(gotFields, wantFields) {
		t.Fatalf("ordinary builder resources=%v, want exact least-privilege set %v", gotFields, wantFields)
	}

	servicesType := reflect.TypeOf(OperatorServices{})
	if servicesType.NumField() != 2 {
		t.Fatalf("OperatorServices fields=%d, want 2 Product-private identities", servicesType.NumField())
	}
	for index := 0; index < servicesType.NumField(); index++ {
		field := servicesType.Field(index)
		if field.PkgPath == "" {
			t.Fatalf("OperatorServices exposed field %q", field.Name)
		}
	}
	if servicesType.NumMethod() != 1 || servicesType.Method(0).Name != "InteractionRegistrar" {
		t.Fatalf("OperatorServices exported methods=%v, want registration-only access", exportedMethodNames(servicesType))
	}
	registrarType := reflect.TypeOf((*inspectionplanning.LocalInteractionRegistrar)(nil)).Elem()
	if registrarType.NumMethod() != 1 || registrarType.Method(0).Name != "Register" {
		t.Fatalf("application registrar methods=%v, want Register only", exportedMethodNames(registrarType))
	}
	executionType := reflect.TypeOf(ExecutionBinding{})
	if executionType.NumField() != 2 || executionType.Field(0).PkgPath == "" || executionType.Field(1).PkgPath == "" ||
		executionType.NumMethod() != 2 {
		t.Fatalf("execution binding exposed replaceable state: fields=%d methods=%v", executionType.NumField(), exportedMethodNames(executionType))
	}
	registrar := MediaPreparationRegistrar(mediaPreparationRegistrar{prepare: func(context.Context, inspectionmediaprep.FrozenRequest) (inspectionmediaprep.Status, bool, error) {
		return inspectionmediaprep.Status{}, false, nil
	}})
	reader := MediaPreparationReader(mediaPreparationReader{get: func(context.Context, string) (inspectionmediaprep.Status, error) {
		return inspectionmediaprep.Status{}, nil
	}})
	type processNexter interface {
		ProcessNext(context.Context) (inspectionmediaprep.Status, bool, error)
	}
	type recoverer interface {
		Recover(context.Context) (inspectionmediaprep.Recovery, error)
	}
	type closer interface{ Close() error }
	for name, port := range map[string]any{"registrar": registrar, "reader": reader} {
		if _, ok := port.(processNexter); ok {
			t.Fatalf("%s implements ProcessNext", name)
		}
		if _, ok := port.(recoverer); ok {
			t.Fatalf("%s implements Recover", name)
		}
		if _, ok := port.(closer); ok {
			t.Fatalf("%s implements Close", name)
		}
	}
	if _, ok := registrar.(MediaPreparationReader); ok {
		t.Fatal("application registrar implements media preparation lookup")
	}
	if _, ok := reader.(MediaPreparationRegistrar); ok {
		t.Fatal("temporary reader implements media preparation registration")
	}
}

func TestHandoffRecoveryIntervalDefaultsIndependentlyAndRejectsInvalidBounds(t *testing.T) {
	base := Config{
		Enabled: true, StateRoot: filepath.Join(t.TempDir(), "state"),
		WorkerInterval: 17 * time.Second, TemporaryWorkerOwner: "recovery-config-test",
	}
	normalized, paths, err := normalizeEnabledConfig(base)
	if err != nil {
		t.Fatal(err)
	}
	if normalized.HandoffRecoveryInterval != defaultHandoffRecoveryInterval {
		t.Fatalf("default handoff recovery interval=%s, want %s", normalized.HandoffRecoveryInterval, defaultHandoffRecoveryInterval)
	}
	if normalized.HandoffRecoveryInterval == normalized.WorkerInterval {
		t.Fatal("handoff recovery cadence inherited the ordinary worker interval")
	}
	if normalized.ExecutionAuthorityIssuerID != defaultExecutionAuthorityIssuer ||
		normalized.ExecutionRuntimeID != defaultExecutionRuntimeID {
		t.Fatalf("default execution identities=%q/%q", normalized.ExecutionAuthorityIssuerID, normalized.ExecutionRuntimeID)
	}
	if normalized.MediaPreparationWorkerInterval != base.WorkerInterval ||
		normalized.MediaPreparationWorkerOwner != defaultMediaPreparationOwner {
		t.Fatalf("default media preparation worker=%s/%q", normalized.MediaPreparationWorkerInterval, normalized.MediaPreparationWorkerOwner)
	}
	if filepath.Base(paths.MediaPreparationDatabase) != "media-preparations.db" ||
		paths.MediaPreparationDatabase == paths.TemporaryDatabase ||
		paths.MediaPreparationDatabase == paths.DeliveryDatabase {
		t.Fatalf("media preparation state path is not independent: %+v", paths)
	}

	base.HandoffRecoveryInterval = 37 * time.Minute
	base.ExecutionAuthorityIssuerID = "installation-authority-v2"
	base.ExecutionRuntimeID = "installation-runtime-v2"
	normalized, _, err = normalizeEnabledConfig(base)
	if err != nil {
		t.Fatal(err)
	}
	if normalized.HandoffRecoveryInterval != 37*time.Minute {
		t.Fatalf("explicit handoff recovery interval=%s", normalized.HandoffRecoveryInterval)
	}
	if normalized.ExecutionAuthorityIssuerID != base.ExecutionAuthorityIssuerID ||
		normalized.ExecutionRuntimeID != base.ExecutionRuntimeID {
		t.Fatalf("explicit execution identities changed=%q/%q", normalized.ExecutionAuthorityIssuerID, normalized.ExecutionRuntimeID)
	}
	for _, invalid := range []time.Duration{-time.Nanosecond, 24*time.Hour + time.Nanosecond} {
		config := base
		config.HandoffRecoveryInterval = invalid
		if _, _, err := normalizeEnabledConfig(config); err == nil {
			t.Fatalf("invalid handoff recovery interval %s was accepted", invalid)
		}
	}
	for _, mutate := range []func(*Config){
		func(value *Config) { value.MediaPreparationWorkerInterval = -time.Nanosecond },
		func(value *Config) { value.MediaPreparationWorkerInterval = 24*time.Hour + time.Nanosecond },
		func(value *Config) { value.MediaPreparationWorkerOwner = "invalid owner" },
		func(value *Config) { value.MediaPreparationWorkerOwner = strings.Repeat("m", 65) },
	} {
		invalid := base
		mutate(&invalid)
		if _, _, err := normalizeEnabledConfig(invalid); err == nil {
			t.Fatal("invalid media preparation worker configuration was accepted")
		}
	}
	for _, mutate := range []func(*Config){
		func(value *Config) { value.ExecutionAuthorityIssuerID = "invalid issuer" },
		func(value *Config) { value.ExecutionRuntimeID = strings.Repeat("r", 65) },
	} {
		invalid := base
		mutate(&invalid)
		if _, _, err := normalizeEnabledConfig(invalid); err == nil {
			t.Fatal("invalid execution identity was accepted")
		}
	}
}

func TestTypedNilAuthorityVerifierIsRejectedBeforeStateCreation(t *testing.T) {
	root := filepath.Join(t.TempDir(), "must-not-exist")
	var verifier *recordingAuthorityVerifier
	product, err := New(Config{
		Enabled: true, StateRoot: root, TemporaryWorkerOwner: "typed-nil-verifier",
	}, PersistentFactories(verifier, idleMediaPreparationAcquirer{}, validTestBuilders()))
	if err == nil || product != nil {
		t.Fatalf("typed nil authority verifier accepted: product=%v err=%v", product, err)
	}
	if _, statErr := os.Lstat(root); !errors.Is(statErr, os.ErrNotExist) {
		t.Fatalf("invalid factories touched state root: %v", statErr)
	}
}

func TestMediaPreparationFactoriesAreCompleteBeforeStateCreation(t *testing.T) {
	for _, testCase := range []struct {
		name   string
		mutate func(*Factories)
	}{
		{name: "typed nil acquirer", mutate: func(factories *Factories) {
			var acquirer *typedNilMediaPreparationAcquirer
			factories.MediaPreparationAcquirer = acquirer
		}},
		{name: "missing state opener", mutate: func(factories *Factories) {
			factories.OpenMediaPreparations = nil
		}},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			root := filepath.Join(t.TempDir(), "must-not-exist")
			factories := persistentTestFactories(validTestBuilders())
			testCase.mutate(&factories)
			product, err := New(Config{
				Enabled: true, StateRoot: root, TemporaryWorkerOwner: "factory-completeness",
			}, factories)
			if err == nil || product != nil {
				t.Fatalf("incomplete media preparation factory accepted: product=%v err=%v", product, err)
			}
			if _, statErr := os.Lstat(root); !errors.Is(statErr, os.ErrNotExist) {
				t.Fatalf("invalid factories touched state root: %v", statErr)
			}
		})
	}
}

func TestEnabledPersistentProductStartsStopsAndRestarts(t *testing.T) {
	root := filepath.Join(t.TempDir(), "operator-state")
	var runtimeInstancesMu sync.Mutex
	var runtimeInstances []*recordingRuntime
	var temporaryInstancesMu sync.Mutex
	var temporaryInstances []*recordingTemporaryProcessor
	var generationResources []Resources
	var generationServices []OperatorServices
	var generationAuthorities []inspectionauthority.Broker
	builders := Builders{
		StandardRuntime: func(_ context.Context, resources Resources, execution ExecutionBinding) (StandardRuntime, error) {
			if resources.Temporary == nil || resources.Schedules == nil || resources.Runs == nil || resources.Application == nil ||
				!execution.valid() || execution.RuntimeID() != defaultExecutionRuntimeID {
				t.Fatal("product did not compose all inspection v2 state owners")
			}
			generationAuthorities = append(generationAuthorities, execution.Authority())
			runtimeWorker := &recordingRuntime{}
			runtimeInstancesMu.Lock()
			runtimeInstances = append(runtimeInstances, runtimeWorker)
			runtimeInstancesMu.Unlock()
			return runtimeWorker, nil
		},
		TemporaryRuntime: func(context.Context, Resources, MediaPreparationReader) (TemporaryRuntime, error) {
			processor := &recordingTemporaryProcessor{}
			temporaryInstancesMu.Lock()
			temporaryInstances = append(temporaryInstances, processor)
			temporaryInstancesMu.Unlock()
			return processor, nil
		},
		OutboxMaterializer: func(context.Context, Resources, inspectiondelivery.TerminalMessageBuilder) (OutboxMaterializer, error) {
			return &oneItemMaterializer{}, nil
		},
		DeliveryDispatcher: func(context.Context, Resources) (DeliveryDispatcher, error) {
			return &oneItemDispatcher{}, nil
		},
		ScheduleCoordinator: func(context.Context, *inspectionschedule.Store, ScheduleBridge) (ScheduleCoordinator, error) {
			return &oneItemScheduler{}, nil
		},
		ApplicationBackend: func(ctx context.Context, resources Resources, services OperatorServices, standard StandardRuntime, temporary TemporaryRuntime, registrar MediaPreparationRegistrar) (ApplicationBackend, error) {
			if _, forbidden := registrar.(mediaPreparationProcessor); forbidden {
				t.Fatal("application registrar acquired media preparation worker authority")
			}
			generationResources = append(generationResources, resources)
			generationServices = append(generationServices, services)
			return buildReadyApplicationBackend(ctx, resources, services, standard, temporary, registrar)
		},
	}
	factories := persistentTestFactories(builders)
	credentials := credential.NewMemoryStore()
	t.Cleanup(credentials.Purge)
	factories.OpenCredentials = func(context.Context, string) (Opened[credential.SecretStore], error) {
		return Opened[credential.SecretStore]{Value: credentials, Close: noClose}, nil
	}
	product, err := New(Config{
		Enabled: true, StateRoot: root,
		WorkerInterval: 5 * time.Millisecond, MediaGCInterval: 5 * time.Millisecond,
		TemporaryWorkerOwner: "inspection-product-test",
	}, factories)
	if err != nil {
		t.Fatal(err)
	}
	if handler, err := product.Handler(); !errors.Is(err, ErrHTTPSurfaceUnavailable) || handler != nil {
		t.Fatalf("stopped product exposed HTTP surface: handler=%v err=%v", handler, err)
	}
	executionIdentity, err := inspectionauthority.NewExecutionIdentity(
		inspectionauthority.IdentityActor,
		strings.Repeat("e", 64),
	)
	if err != nil {
		t.Fatal(err)
	}
	authorityDeadline := time.Now().UTC().Add(time.Hour)
	authorityDemand := inspectionauthority.IssueDemand{
		Identity: executionIdentity, TenantID: "tenant-product", SiteID: "site-product",
		RunID: "run-product-authority", PlanSHA256: strings.Repeat("f", 64),
		AssignmentID: "assignment-product", AssignmentRevision: 1,
		RequestKey: "req_" + strings.Repeat("1", 32), RuntimeID: defaultExecutionRuntimeID,
		Steps:    []inspectionauthority.StepScope{{StepID: "step-product", Authority: inspectionauthority.StepAuthorityDeviceRead}},
		Deadline: authorityDeadline,
	}
	var firstAuthorization inspectionauthority.Authorization

	var previousHandler http.Handler
	expiresAt := time.Now().UTC().Add(time.Hour)
	binding := inspectioninteraction.Binding{
		TenantID: "tenant-product", SiteID: "site-product", PrincipalSHA256: strings.Repeat("a", 64),
	}
	connection := inspectionplanning.LocalInteractionRegistration{
		Type:     inspectionplanning.LocalInteractionConnection,
		TenantID: binding.TenantID, SiteID: binding.SiteID, PrincipalSHA256: binding.PrincipalSHA256,
		HandoffRef: "handoff_product_connection", ExpiresAt: expiresAt,
	}
	change := inspectionplanning.PendingChangeIntent{
		Operation: inspectionplanning.PendingTaskDisable,
		SourceRef: "source-product", ExpectedSourceRevision: 3,
		TaskRef: "task-product", ExpectedTaskRevision: 4,
	}
	persistent := inspectionplanning.LocalInteractionRegistration{
		Type:     inspectionplanning.LocalInteractionPersistentChange,
		TenantID: binding.TenantID, SiteID: binding.SiteID, PrincipalSHA256: binding.PrincipalSHA256,
		HandoffRef: "handoff_product_persistent", ExpiresAt: expiresAt, Change: &change,
	}
	for generation := uint64(1); generation <= 2; generation++ {
		if err := product.Start(context.Background()); err != nil {
			t.Fatalf("start generation %d: %v", generation, err)
		}
		waitFor(t, func() bool {
			metrics := product.Metrics()
			return metrics.OutboxMessages >= generation && metrics.Deliveries >= generation &&
				metrics.ScheduleOccurrences >= generation && metrics.TemporaryPasses >= generation &&
				metrics.MediaPreparationPasses >= generation && metrics.MediaPreparationRecoveryPasses >= 2*generation &&
				metrics.MediaGCPasses >= generation && metrics.HandoffRecoverySweeps >= generation
		})
		readiness := product.Readiness()
		if !readiness.Enabled || !readiness.Ready || readiness.State != StateReady || readiness.Generation != generation || readiness.Failure != "" {
			t.Fatalf("generation %d readiness: %+v", generation, readiness)
		}
		handler, err := product.Handler()
		if err != nil {
			t.Fatalf("generation %d handler: %v", generation, err)
		}
		if status := serveStatus(handler); status != http.StatusOK {
			t.Fatalf("generation %d HTTP status=%d", generation, status)
		}
		if previousHandler != nil {
			if status := serveStatus(previousHandler); status != http.StatusServiceUnavailable {
				t.Fatalf("stale generation HTTP status=%d", status)
			}
		}
		if len(generationResources) != int(generation) || len(generationServices) != int(generation) ||
			len(generationAuthorities) != int(generation) {
			t.Fatalf("generation %d composition resources=%d services=%d authorities=%d", generation,
				len(generationResources), len(generationServices), len(generationAuthorities))
		}
		currentAuthority := generationAuthorities[generation-1]
		if generation == 1 {
			var created bool
			firstAuthorization, created, err = currentAuthority.Issue(context.Background(), authorityDemand)
			if err != nil || !created {
				t.Fatalf("generation 1 persistent authority issue created=%v err=%v", created, err)
			}
		} else {
			reopened, lookupErr := currentAuthority.Lookup(context.Background(), authorityDemand.RunID)
			if lookupErr != nil || reopened.AuthorizationID != firstAuthorization.AuthorizationID ||
				reopened.RuntimeID != defaultExecutionRuntimeID {
				t.Fatalf("generation 2 authority did not survive restart: authorization=%+v err=%v", reopened, lookupErr)
			}
			if _, lookupErr := generationAuthorities[0].Lookup(context.Background(), authorityDemand.RunID); !errors.Is(lookupErr, inspectionauthority.ErrClosed) {
				t.Fatalf("stale authority generation remained usable: %v", lookupErr)
			}
		}
		services := generationServices[generation-1]
		if !services.valid() || services.InteractionRegistrar() != services.InteractionRegistrar() ||
			product.services.interactionRegistrar != services.InteractionRegistrar() {
			t.Fatalf("generation %d did not preserve one Product-owned service identity", generation)
		}
		if generation == 1 {
			if _, err := services.InteractionRegistrar().Register(context.Background(), connection); err != nil {
				t.Fatalf("register connection handoff: %v", err)
			}
			if _, err := services.InteractionRegistrar().Register(context.Background(), persistent); err != nil {
				t.Fatalf("register persistent handoff: %v", err)
			}
		} else if services.InteractionRegistrar() == generationServices[0].InteractionRegistrar() {
			t.Fatal("restart reused the prior generation registrar")
		}
		assertProductInteractionRouting(
			t,
			product.opened.onboardingHandoffs.Value,
			product.opened.pendingInteractions.Value,
			binding,
			connection.HandoffRef,
			persistent.HandoffRef,
		)
		if err := product.Stop(); err != nil {
			t.Fatalf("stop generation %d: %v", generation, err)
		}
		if readiness := product.Readiness(); readiness.Ready || readiness.State != StateStopped || readiness.Generation != generation {
			t.Fatalf("generation %d stopped readiness: %+v", generation, readiness)
		}
		if status := serveStatus(handler); status != http.StatusServiceUnavailable {
			t.Fatalf("stopped generation %d HTTP status=%d", generation, status)
		}
		if current, err := product.Handler(); !errors.Is(err, ErrHTTPSurfaceUnavailable) || current != nil {
			t.Fatalf("stopped generation %d exposed HTTP surface: handler=%v err=%v", generation, current, err)
		}
		previousHandler = handler
	}

	for _, relative := range []string{
		"execution-authority.db", "device-profiles.db", "onboarding-journal.db", "onboarding-handoffs.db", "pending-interactions.db",
		"source-catalog.db", "application.db", "channel-bindings.db", "changeflow.json",
		"runs.db", "temporary-runs.db", "schedules.db", "media-preparations.db", "delivery.db",
		filepath.Join("media", ".cosmoedge-inspection-media-root"),
	} {
		if _, err := os.Stat(filepath.Join(root, "inspection-v2", relative)); err != nil {
			t.Fatalf("persistent v2 state %s is unavailable: %v", relative, err)
		}
	}
	if _, err := os.Lstat(filepath.Join(root, "inspection-v2", "onboarding-sagas.db")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("retired onboarding database compatibility path exists: %v", err)
	}
	runtimeInstancesMu.Lock()
	defer runtimeInstancesMu.Unlock()
	if len(runtimeInstances) != 2 {
		t.Fatalf("runtime generations=%d, want 2", len(runtimeInstances))
	}
	for index, runtimeWorker := range runtimeInstances {
		if runtimeWorker.starts.Load() != 1 || runtimeWorker.stops.Load() != 1 {
			t.Fatalf("runtime %d lifecycle starts=%d stops=%d", index, runtimeWorker.starts.Load(), runtimeWorker.stops.Load())
		}
	}
	temporaryInstancesMu.Lock()
	defer temporaryInstancesMu.Unlock()
	if len(temporaryInstances) != 2 {
		t.Fatalf("temporary processor generations=%d, want 2", len(temporaryInstances))
	}
	for index, processor := range temporaryInstances {
		owner, lease, calls := processor.snapshot()
		if calls == 0 || owner != "inspection-product-test" || lease != defaultTemporaryLease {
			t.Fatalf("temporary processor %d calls=%d owner=%q lease=%s", index, calls, owner, lease)
		}
	}
	metrics := product.Metrics()
	if metrics.Starts != 2 || metrics.Stops != 2 || metrics.StartupFailures != 0 || metrics.WorkerFailures != 0 ||
		metrics.HandoffRecoveryPasses < 2 || metrics.HandoffRecoverySweeps < 2 ||
		metrics.MediaPreparationRecoveryPasses < 4 || metrics.MediaPreparationPasses < 2 {
		t.Fatalf("unexpected restart metrics: %+v", metrics)
	}
}

func TestStartupReconcilesCompletedHandoffGapThroughEmptyKeysetPageBeforeRuntime(t *testing.T) {
	root := filepath.Join(t.TempDir(), "operator-state")
	config := Config{
		Enabled: true, StateRoot: root, TemporaryWorkerOwner: "startup-recovery-test",
		WorkerInterval: time.Hour, MediaGCInterval: time.Hour, HandoffRecoveryInterval: time.Hour,
	}
	_, paths, err := normalizeEnabledConfig(config)
	if err != nil {
		t.Fatal(err)
	}
	credentials := credential.NewMemoryStore()
	defer credentials.Purge()
	verifier := &recordingAuthorityVerifier{}
	seedCompletedHandoffGap(t, paths, credentials, verifier, onboarding.MaximumHandoffRecoveryBatch+1)
	verificationCalls := verifier.calls.Load()

	var product *Product
	var handoffsAtRuntimeStart *onboarding.HandoffStore
	var metricsAtRuntimeStart Metrics
	pendingAtRuntimeStart := -1
	runtimeWorker := &recordingRuntime{}
	runtimeWorker.onStart = func() {
		metricsAtRuntimeStart = product.Metrics()
		pendingAtRuntimeStart = countPendingHandoffs(t, handoffsAtRuntimeStart)
	}
	builders := validTestBuilders()
	builders.StandardRuntime = func(context.Context, Resources, ExecutionBinding) (StandardRuntime, error) {
		return runtimeWorker, nil
	}
	factories := PersistentFactories(verifier, idleMediaPreparationAcquirer{}, builders)
	factories.OpenCredentials = func(context.Context, string) (Opened[credential.SecretStore], error) {
		return Opened[credential.SecretStore]{Value: credentials, Close: noClose}, nil
	}
	openHandoffs := factories.OpenOnboardingHandoffs
	factories.OpenOnboardingHandoffs = func(ctx context.Context, path string) (Opened[*onboarding.HandoffStore], error) {
		opened, err := openHandoffs(ctx, path)
		if err == nil {
			handoffsAtRuntimeStart = opened.Value
		}
		return opened, err
	}
	product, err = New(config, factories)
	if err != nil {
		t.Fatal(err)
	}
	if err := product.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = product.Stop() })
	if pendingAtRuntimeStart != onboarding.MaximumHandoffRecoveryBatch {
		t.Fatalf("runtime started before completed gap converged: pending=%d", pendingAtRuntimeStart)
	}
	if metricsAtRuntimeStart.HandoffRecoveryPasses != 3 || metricsAtRuntimeStart.HandoffsExamined != 101 ||
		metricsAtRuntimeStart.HandoffsCompleted != 1 || metricsAtRuntimeStart.HandoffRecoverySweeps != 1 {
		t.Fatalf("startup recovery metrics at runtime start=%+v", metricsAtRuntimeStart)
	}
	if verifier.calls.Load() != verificationCalls {
		t.Fatalf("handoff recovery invoked authority verifier: before=%d after=%d", verificationCalls, verifier.calls.Load())
	}
	if readiness := product.Readiness(); !readiness.Ready || readiness.State != StateReady || readiness.Generation != 1 {
		t.Fatalf("recovered product readiness=%+v", readiness)
	}
}

func seedCompletedHandoffGap(
	t *testing.T,
	paths StatePaths,
	credentials credential.SecretStore,
	verifier onboarding.AuthorityVerifier,
	records int,
) {
	t.Helper()
	seedNow := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	profiles, err := profile.Open(paths.ProfileDatabase)
	if err != nil {
		t.Fatal(err)
	}
	journal, err := onboarding.OpenJournal(paths.OnboardingJournalDatabase)
	if err != nil {
		_ = profiles.Close()
		t.Fatal(err)
	}
	handoffs, err := onboarding.OpenHandoffStore(onboarding.HandoffStoreConfig{
		Path: paths.OnboardingHandoffDatabase, Now: func() time.Time { return seedNow },
	})
	if err != nil {
		_ = journal.Close()
		_ = profiles.Close()
		t.Fatal(err)
	}
	closeSeed := func() {
		for _, closeStore := range []func() error{handoffs.Close, journal.Close, profiles.Close} {
			if err := closeStore(); err != nil {
				t.Error(err)
			}
		}
	}
	core, err := onboarding.NewService(
		profiles, credentials, journal, verifier, onboarding.WithClock(func() time.Time { return seedNow }),
	)
	if err != nil {
		closeSeed()
		t.Fatal(err)
	}
	entry, err := onboarding.NewEntryService(onboarding.EntryServiceConfig{Core: core, Handoffs: handoffs})
	if err != nil {
		closeSeed()
		t.Fatal(err)
	}
	binding := onboarding.HandoffBinding{
		TenantID: "tenant-recovery", SiteID: "site-recovery", PrincipalSHA256: strings.Repeat("b", 64),
	}
	expiresAt := seedNow.Add(time.Hour)
	completedRef := ""
	for index := 0; index < records; index++ {
		ref := fmt.Sprintf("handoff_recovery_%03d", index)
		if _, err := entry.BeginSkill(context.Background(), onboarding.SkillHandoffRequest{
			TenantID: binding.TenantID, SiteID: binding.SiteID, PrincipalSHA256: binding.PrincipalSHA256,
			HandoffRef: ref, ExpiresAt: expiresAt,
		}); err != nil {
			closeSeed()
			t.Fatal(err)
		}
		if index == records-1 {
			completedRef = ref
		}
	}
	failingEntry, err := onboarding.NewEntryService(onboarding.EntryServiceConfig{
		Core: core, Handoffs: failMarkHandoffRepository{delegate: handoffs},
	})
	if err != nil {
		closeSeed()
		t.Fatal(err)
	}
	secret := []byte("startup-recovery-private-secret")
	result, err := failingEntry.CompleteSkill(context.Background(), onboarding.CompleteSkillRequest{
		TenantID: binding.TenantID, SiteID: binding.SiteID, PrincipalSHA256: binding.PrincipalSHA256,
		HandoffRef: completedRef,
		Connection: onboarding.LocalConnectionInput{
			Alias: "恢复测试设备", IP: "10.20.30.40", Port: 8000, Username: "operator", Password: secret,
			PinnedSerial: "recovery-serial", PinnedType: "edge-box",
		},
	})
	if !errors.Is(err, onboarding.ErrHandoffCommit) || result.Status != onboarding.StatusCompleted {
		closeSeed()
		t.Fatalf("seed completed handoff gap result=%+v err=%v", result, err)
	}
	closeSeed()
}

func countPendingHandoffs(t *testing.T, store *onboarding.HandoffStore) int {
	t.Helper()
	afterRef := ""
	total := 0
	for {
		records, err := store.PendingForRecovery(context.Background(), afterRef, onboarding.MaximumHandoffRecoveryBatch)
		if err != nil {
			t.Fatal(err)
		}
		if len(records) == 0 {
			return total
		}
		total += len(records)
		afterRef = records[len(records)-1].HandoffRef
	}
}

type failMarkHandoffRepository struct {
	delegate onboarding.HandoffRepository
}

func (r failMarkHandoffRepository) Begin(ctx context.Context, record onboarding.HandoffRecord) (onboarding.HandoffRecord, error) {
	return r.delegate.Begin(ctx, record)
}

func (r failMarkHandoffRepository) Resolve(ctx context.Context, binding onboarding.HandoffBinding, ref string) (onboarding.HandoffRecord, error) {
	return r.delegate.Resolve(ctx, binding, ref)
}

func (r failMarkHandoffRepository) PendingForRecovery(ctx context.Context, afterRef string, limit int) ([]onboarding.HandoffRecord, error) {
	return r.delegate.PendingForRecovery(ctx, afterRef, limit)
}

func (failMarkHandoffRepository) MarkCompleted(context.Context, onboarding.HandoffRecord) (onboarding.HandoffRecord, error) {
	return onboarding.HandoffRecord{}, errors.New("injected handoff mark failure")
}

func TestHandoffRecoveryRequiresEmptyPageAndValidMonotonicProgress(t *testing.T) {
	if handoffRecoveryCursorPattern == temporaryWorkerOwnerPattern {
		t.Fatal("handoff recovery cursor validation reused the temporary worker owner expression")
	}
	shortPage := onboarding.HandoffReconcileResult{Examined: 1, NextAfterRef: "handoff_002"}
	complete, err := validateHandoffReconcileResult("handoff_001", shortPage)
	if err != nil || complete {
		t.Fatalf("short recovery page complete=%v err=%v", complete, err)
	}
	complete, err = validateHandoffReconcileResult("handoff_002", onboarding.HandoffReconcileResult{})
	if err != nil || !complete {
		t.Fatalf("empty recovery page complete=%v err=%v", complete, err)
	}

	for _, testCase := range []struct {
		name     string
		afterRef string
		result   onboarding.HandoffReconcileResult
	}{
		{name: "negative examined", result: onboarding.HandoffReconcileResult{Examined: -1}},
		{name: "oversized examined", result: onboarding.HandoffReconcileResult{Examined: onboarding.MaximumHandoffRecoveryBatch + 1, NextAfterRef: "handoff_999"}},
		{name: "negative completed", result: onboarding.HandoffReconcileResult{Examined: 1, ConfirmedCompleted: -1, NextAfterRef: "handoff_001"}},
		{name: "completed exceeds examined", result: onboarding.HandoffReconcileResult{Examined: 1, ConfirmedCompleted: 2, NextAfterRef: "handoff_001"}},
		{name: "empty page with cursor", result: onboarding.HandoffReconcileResult{NextAfterRef: "handoff_001"}},
		{name: "nonempty page without cursor", result: onboarding.HandoffReconcileResult{Examined: 1}},
		{name: "whitespace cursor", result: onboarding.HandoffReconcileResult{Examined: 1, NextAfterRef: " handoff_001"}},
		{name: "malformed cursor", result: onboarding.HandoffReconcileResult{Examined: 1, NextAfterRef: "handoff 001"}},
		{name: "equal cursor", afterRef: "handoff_001", result: onboarding.HandoffReconcileResult{Examined: 1, NextAfterRef: "handoff_001"}},
		{name: "backward cursor", afterRef: "handoff_002", result: onboarding.HandoffReconcileResult{Examined: 1, NextAfterRef: "handoff_001"}},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			if _, err := validateHandoffReconcileResult(testCase.afterRef, testCase.result); err == nil {
				t.Fatalf("invalid recovery result was accepted: %+v", testCase.result)
			}
		})
	}
}

func TestHandoffRecoveryRecordsOnlyTrustworthyPartialProgress(t *testing.T) {
	injected := errors.New("injected recovery read failure")
	validPartial := onboarding.HandoffReconcileResult{
		Examined: 2, ConfirmedCompleted: 1, NextAfterRef: "handoff_002",
	}
	product := &Product{}
	_, complete, err := product.reconcileHandoffPage(context.Background(), &scriptedHandoffReconciler{
		steps: []handoffReconcileStep{{result: validPartial, err: injected}},
	}, "handoff_001")
	if !errors.Is(err, injected) || complete {
		t.Fatalf("valid partial failure complete=%v err=%v", complete, err)
	}
	if metrics := product.Metrics(); metrics.HandoffRecoveryPasses != 1 || metrics.HandoffsExamined != 2 ||
		metrics.HandoffsCompleted != 1 || metrics.HandoffRecoverySweeps != 0 {
		t.Fatalf("valid partial failure metrics=%+v", metrics)
	}

	product = &Product{}
	invalidPartial := onboarding.HandoffReconcileResult{
		Examined: 1, ConfirmedCompleted: 1, NextAfterRef: "invalid cursor",
	}
	_, complete, err = product.reconcileHandoffPage(context.Background(), &scriptedHandoffReconciler{
		steps: []handoffReconcileStep{{result: invalidPartial, err: injected}},
	}, "")
	if !errors.Is(err, injected) || complete {
		t.Fatalf("invalid partial failure complete=%v err=%v", complete, err)
	}
	if metrics := product.Metrics(); metrics.HandoffRecoveryPasses != 1 || metrics.HandoffsExamined != 0 ||
		metrics.HandoffsCompleted != 0 || metrics.HandoffRecoverySweeps != 0 {
		t.Fatalf("invalid partial failure invented metrics=%+v", metrics)
	}
}

func TestRuntimeHandoffRecoveryDrainsEveryPageBeforeWaitingAgain(t *testing.T) {
	reconciler := &scriptedHandoffReconciler{
		steps: []handoffReconcileStep{
			{result: onboarding.HandoffReconcileResult{Examined: 100, ConfirmedCompleted: 2, NextAfterRef: "handoff_100"}},
			{result: onboarding.HandoffReconcileResult{Examined: 1, ConfirmedCompleted: 1, NextAfterRef: "handoff_101"}},
			{result: onboarding.HandoffReconcileResult{}},
		},
		called: make(chan onboarding.HandoffReconcileRequest, 4),
	}
	product := &Product{}
	ctx, cancel := context.WithCancel(context.Background())
	product.workers.Add(1)
	go product.runHandoffRecovery(ctx, 40*time.Millisecond, reconciler)

	requests := make([]onboarding.HandoffReconcileRequest, 0, 3)
	for len(requests) < 3 {
		select {
		case request := <-reconciler.called:
			requests = append(requests, request)
		case <-time.After(time.Second):
			cancel()
			product.workers.Wait()
			t.Fatal("runtime recovery did not complete one full sweep")
		}
	}
	wantAfterRefs := []string{"", "handoff_100", "handoff_101"}
	for index, request := range requests {
		if request.AfterRef != wantAfterRefs[index] || request.Limit != onboarding.MaximumHandoffRecoveryBatch {
			t.Fatalf("runtime recovery request %d=%+v", index, request)
		}
	}
	select {
	case request := <-reconciler.called:
		cancel()
		product.workers.Wait()
		t.Fatalf("runtime recovery started a new sweep without waiting: %+v", request)
	case <-time.After(10 * time.Millisecond):
	}
	cancel()
	product.workers.Wait()
	if metrics := product.Metrics(); metrics.HandoffRecoveryPasses != 3 || metrics.HandoffsExamined != 101 ||
		metrics.HandoffsCompleted != 3 || metrics.HandoffRecoverySweeps != 1 || metrics.WorkerFailures != 0 {
		t.Fatalf("runtime recovery metrics=%+v", metrics)
	}
}

func TestStartupHandoffRecoveryFailureRollsBackBeforeReadiness(t *testing.T) {
	runtimeWorker := &recordingRuntime{}
	var handoffs *onboarding.HandoffStore
	builders := validTestBuilders()
	builders.StandardRuntime = func(context.Context, Resources, ExecutionBinding) (StandardRuntime, error) {
		return runtimeWorker, nil
	}
	buildApplication := builders.ApplicationBackend
	builders.ApplicationBackend = func(
		ctx context.Context,
		resources Resources,
		services OperatorServices,
		standard StandardRuntime,
		temporary TemporaryRuntime,
		registrar MediaPreparationRegistrar,
	) (ApplicationBackend, error) {
		backend, err := buildApplication(ctx, resources, services, standard, temporary, registrar)
		if err != nil {
			return nil, err
		}
		if handoffs == nil {
			return nil, errors.New("handoff store was not captured")
		}
		if err := handoffs.Close(); err != nil {
			return nil, err
		}
		return backend, nil
	}
	factories := persistentTestFactories(builders)
	factories.OpenCredentials = memoryCredentialFactory()
	openHandoffs := factories.OpenOnboardingHandoffs
	factories.OpenOnboardingHandoffs = func(ctx context.Context, path string) (Opened[*onboarding.HandoffStore], error) {
		opened, err := openHandoffs(ctx, path)
		if err == nil {
			handoffs = opened.Value
		}
		return opened, err
	}
	product, err := New(Config{
		Enabled: true, StateRoot: filepath.Join(t.TempDir(), "state"), TemporaryWorkerOwner: "startup-recovery-failure",
	}, factories)
	if err != nil {
		t.Fatal(err)
	}
	if err := product.Start(context.Background()); err == nil {
		t.Fatal("startup accepted an unreadable handoff recovery store")
	}
	if readiness := product.Readiness(); readiness.Ready || readiness.State != StateFailed ||
		readiness.Generation != 0 || readiness.Failure != "startup_failed" {
		t.Fatalf("startup recovery failure readiness=%+v", readiness)
	}
	if runtimeWorker.starts.Load() != 0 || runtimeWorker.stops.Load() != 1 {
		t.Fatalf("startup recovery runtime starts=%d stops=%d", runtimeWorker.starts.Load(), runtimeWorker.stops.Load())
	}
	if metrics := product.Metrics(); metrics.StartupFailures != 1 || metrics.Starts != 0 ||
		metrics.HandoffRecoveryPasses != 1 || metrics.HandoffRecoverySweeps != 0 {
		t.Fatalf("startup recovery failure metrics=%+v", metrics)
	}
	if handler, err := product.Handler(); !errors.Is(err, ErrHTTPSurfaceUnavailable) || handler != nil {
		t.Fatalf("startup recovery failure exposed handler=%v err=%v", handler, err)
	}
}

func TestProtectedOperatorStateOpenAndSchemaFailuresBlockReadiness(t *testing.T) {
	for _, testCase := range []struct {
		name    string
		prepare func(*testing.T, StatePaths, *Factories)
	}{
		{
			name: "open failure",
			prepare: func(_ *testing.T, _ StatePaths, factories *Factories) {
				factories.OpenOnboardingJournal = func(context.Context, string) (Opened[*onboarding.Journal], error) {
					return Opened[*onboarding.Journal]{}, errors.New("journal unavailable")
				}
			},
		},
		{
			name: "altered handoff schema",
			prepare: func(t *testing.T, paths StatePaths, _ *Factories) {
				store, err := onboarding.OpenHandoffStore(onboarding.HandoffStoreConfig{Path: paths.OnboardingHandoffDatabase})
				if err != nil {
					t.Fatal(err)
				}
				if err := store.Close(); err != nil {
					t.Fatal(err)
				}
				execProtectedSQLite(t, paths.OnboardingHandoffDatabase, `ALTER TABLE onboarding_handoffs ADD COLUMN compatibility_value TEXT`)
			},
		},
		{
			name: "old pending interaction schema",
			prepare: func(t *testing.T, paths StatePaths, _ *Factories) {
				store, err := inspectioninteraction.OpenStore(inspectioninteraction.StoreConfig{Path: paths.PendingInteractionDatabase})
				if err != nil {
					t.Fatal(err)
				}
				if err := store.Close(); err != nil {
					t.Fatal(err)
				}
				execProtectedSQLite(t, paths.PendingInteractionDatabase, `PRAGMA user_version=2`)
			},
		},
		{
			name: "old media preparation schema",
			prepare: func(t *testing.T, paths StatePaths, factories *Factories) {
				publisher, err := inspectionmedia.New(inspectionmedia.Config{Root: filepath.Join(t.TempDir(), "schema-media")})
				if err != nil {
					t.Fatal(err)
				}
				manager, err := inspectionmediaprep.Open(inspectionmediaprep.Config{
					Path: paths.MediaPreparationDatabase, Owner: defaultMediaPreparationOwner,
					Acquirer: factories.MediaPreparationAcquirer, Publisher: publisher,
				})
				if err != nil {
					t.Fatal(err)
				}
				if err := manager.Close(); err != nil {
					t.Fatal(err)
				}
				execProtectedSQLite(t, paths.MediaPreparationDatabase, `PRAGMA user_version=1`)
			},
		},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			root := filepath.Join(t.TempDir(), "state")
			config := Config{Enabled: true, StateRoot: root, TemporaryWorkerOwner: "schema-failure"}
			_, paths, err := normalizeEnabledConfig(config)
			if err != nil {
				t.Fatal(err)
			}
			runtimeWorker := &recordingRuntime{}
			builders := validTestBuilders()
			builders.StandardRuntime = func(context.Context, Resources, ExecutionBinding) (StandardRuntime, error) {
				return runtimeWorker, nil
			}
			factories := persistentTestFactories(builders)
			factories.OpenCredentials = memoryCredentialFactory()
			testCase.prepare(t, paths, &factories)
			product, err := New(config, factories)
			if err != nil {
				t.Fatal(err)
			}
			if err := product.Start(context.Background()); err == nil {
				t.Fatal("invalid protected state was accepted")
			}
			if readiness := product.Readiness(); readiness.Ready || readiness.State != StateFailed ||
				readiness.Generation != 0 || readiness.Failure != "startup_failed" {
				t.Fatalf("protected state failure readiness=%+v", readiness)
			}
			if runtimeWorker.starts.Load() != 0 {
				t.Fatalf("runtime started %d times with invalid protected state", runtimeWorker.starts.Load())
			}
			if metrics := product.Metrics(); metrics.StartupFailures != 1 || metrics.Starts != 0 {
				t.Fatalf("protected state failure metrics=%+v", metrics)
			}
			if handler, err := product.Handler(); !errors.Is(err, ErrHTTPSurfaceUnavailable) || handler != nil {
				t.Fatalf("protected state failure exposed handler=%v err=%v", handler, err)
			}
		})
	}
}

func TestRuntimeHandoffRecoveryFailureFailsClosedAndInvalidatesCachedHandler(t *testing.T) {
	runtimeWorker := &recordingRuntime{}
	builders := validTestBuilders()
	builders.StandardRuntime = func(context.Context, Resources, ExecutionBinding) (StandardRuntime, error) {
		return runtimeWorker, nil
	}
	factories := persistentTestFactories(builders)
	factories.OpenCredentials = memoryCredentialFactory()
	var handoffs *onboarding.HandoffStore
	openHandoffs := factories.OpenOnboardingHandoffs
	factories.OpenOnboardingHandoffs = func(ctx context.Context, path string) (Opened[*onboarding.HandoffStore], error) {
		opened, err := openHandoffs(ctx, path)
		if err == nil {
			handoffs = opened.Value
		}
		return opened, err
	}
	product, err := New(Config{
		Enabled: true, StateRoot: filepath.Join(t.TempDir(), "state"), TemporaryWorkerOwner: "runtime-recovery-failure",
		WorkerInterval: time.Hour, MediaGCInterval: time.Hour, HandoffRecoveryInterval: 5 * time.Millisecond,
	}, factories)
	if err != nil {
		t.Fatal(err)
	}
	if err := product.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	handler := mustProductHandler(t, product)
	if handoffs == nil {
		t.Fatal("handoff store was not captured")
	}
	if err := handoffs.Close(); err != nil {
		t.Fatal(err)
	}
	waitFor(t, func() bool { return product.Readiness().State == StateFailed })
	if readiness := product.Readiness(); readiness.Ready || readiness.Failure != "onboarding_recovery_worker_failed" || readiness.Generation != 1 {
		t.Fatalf("runtime recovery failure readiness=%+v", readiness)
	}
	if metrics := product.Metrics(); metrics.WorkerFailures != 1 || metrics.HandoffRecoveryPasses < 2 ||
		metrics.HandoffRecoverySweeps != 1 {
		t.Fatalf("runtime recovery failure metrics=%+v", metrics)
	}
	if status := serveStatus(handler); status != http.StatusServiceUnavailable {
		t.Fatalf("cached handler after recovery failure status=%d", status)
	}
	if current, err := product.Handler(); !errors.Is(err, ErrHTTPSurfaceUnavailable) || current != nil {
		t.Fatalf("recovery failure exposed current handler=%v err=%v", current, err)
	}
	if err := product.Stop(); err != nil {
		t.Fatal(err)
	}
	if runtimeWorker.stops.Load() != 1 {
		t.Fatalf("runtime recovery cleanup stop count=%d", runtimeWorker.stops.Load())
	}
}

func TestStopWaitsForInFlightHandoffRecoveryBeforeClosingState(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	reconciler := &blockingHandoffReconciler{
		started: make(chan struct{}), release: make(chan struct{}),
	}
	closedAfterRecovery := atomic.Bool{}
	runtimeWorker := &recordingRuntime{}
	product := &Product{
		config: Config{Enabled: true}, state: StateReady, generation: 1, active: true,
		cancel: cancel, standard: runtimeWorker,
		opened: openedResources{
			onboardingHandoffs: Opened[*onboarding.HandoffStore]{Close: func() error {
				closedAfterRecovery.Store(reconciler.finished.Load())
				return nil
			}},
		},
	}
	product.workers.Add(1)
	go product.runHandoffRecovery(ctx, time.Millisecond, reconciler)
	select {
	case <-reconciler.started:
	case <-time.After(time.Second):
		cancel()
		close(reconciler.release)
		product.workers.Wait()
		t.Fatal("recovery did not enter the in-flight call")
	}
	stopDone := make(chan error, 1)
	go func() { stopDone <- product.Stop() }()
	select {
	case err := <-stopDone:
		close(reconciler.release)
		t.Fatalf("Stop returned before in-flight recovery drained: %v", err)
	case <-time.After(20 * time.Millisecond):
	}
	close(reconciler.release)
	select {
	case err := <-stopDone:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("Stop did not return after in-flight recovery completed")
	}
	if !reconciler.finished.Load() || !closedAfterRecovery.Load() {
		t.Fatalf("recovery finished=%v state closed after recovery=%v", reconciler.finished.Load(), closedAfterRecovery.Load())
	}
	if runtimeWorker.stops.Load() != 1 {
		t.Fatalf("runtime stop count=%d", runtimeWorker.stops.Load())
	}
}

func TestStopWaitsForInFlightMediaPreparationBeforeClosingManagerAndMedia(t *testing.T) {
	acquirer := &blockingMediaPreparationAcquirer{started: make(chan struct{})}
	builders := validTestBuilders()
	buildApplication := builders.ApplicationBackend
	builders.ApplicationBackend = func(
		ctx context.Context,
		resources Resources,
		services OperatorServices,
		standard StandardRuntime,
		temporary TemporaryRuntime,
		registrar MediaPreparationRegistrar,
	) (ApplicationBackend, error) {
		if _, _, err := registrar.Prepare(ctx, testMediaPreparationRequest(time.Now().UTC(), "request-stop-drain")); err != nil {
			return nil, err
		}
		return buildApplication(ctx, resources, services, standard, temporary, registrar)
	}
	factories := PersistentFactories(&recordingAuthorityVerifier{}, acquirer, builders)
	factories.OpenCredentials = memoryCredentialFactory()
	var preparationClosed atomic.Bool
	var preparationClosedAfterAcquire atomic.Bool
	var mediaClosedAfterPreparation atomic.Bool
	openPreparations := factories.OpenMediaPreparations
	factories.OpenMediaPreparations = func(ctx context.Context, config inspectionmediaprep.Config) (Opened[*inspectionmediaprep.Manager], error) {
		opened, err := openPreparations(ctx, config)
		if err != nil {
			return opened, err
		}
		closeManager := opened.Close
		opened.Close = func() error {
			preparationClosedAfterAcquire.Store(acquirer.finished.Load())
			preparationClosed.Store(true)
			return closeManager()
		}
		return opened, nil
	}
	openMedia := factories.OpenMedia
	factories.OpenMedia = func(ctx context.Context, config inspectionmedia.Config) (Opened[*inspectionmedia.Store], error) {
		opened, err := openMedia(ctx, config)
		if err != nil {
			return opened, err
		}
		opened.Close = func() error {
			mediaClosedAfterPreparation.Store(preparationClosed.Load())
			return nil
		}
		return opened, nil
	}
	product, err := New(Config{
		Enabled: true, StateRoot: filepath.Join(t.TempDir(), "state"),
		TemporaryWorkerOwner: "stop-media-drain", WorkerInterval: time.Hour,
		MediaPreparationWorkerInterval: time.Hour, MediaGCInterval: time.Hour,
	}, factories)
	if err != nil {
		t.Fatal(err)
	}
	if err := product.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	select {
	case <-acquirer.started:
	case <-time.After(time.Second):
		t.Fatal("media acquisition did not start")
	}
	if err := product.Stop(); err != nil {
		t.Fatal(err)
	}
	if !acquirer.finished.Load() || !preparationClosedAfterAcquire.Load() || !mediaClosedAfterPreparation.Load() {
		t.Fatalf("stop ordering acquire=%v preparation-after=%v media-after=%v",
			acquirer.finished.Load(), preparationClosedAfterAcquire.Load(), mediaClosedAfterPreparation.Load())
	}
	if readiness := product.Readiness(); readiness.State != StateStopped || readiness.Ready {
		t.Fatalf("stop readiness=%+v", readiness)
	}
}

func TestStopDrainsAdmittedHTTPRequestBeforeClosingResources(t *testing.T) {
	surface := newBlockingHTTPSurface()
	factories := persistentTestFactories(Builders{
		StandardRuntime: func(context.Context, Resources, ExecutionBinding) (StandardRuntime, error) {
			return &recordingRuntime{}, nil
		},
		TemporaryRuntime: buildIdleTemporaryRuntime,
		OutboxMaterializer: func(context.Context, Resources, inspectiondelivery.TerminalMessageBuilder) (OutboxMaterializer, error) {
			return &oneItemMaterializer{}, nil
		},
		DeliveryDispatcher: func(context.Context, Resources) (DeliveryDispatcher, error) {
			return &oneItemDispatcher{}, nil
		},
		ScheduleCoordinator: func(context.Context, *inspectionschedule.Store, ScheduleBridge) (ScheduleCoordinator, error) {
			return &oneItemScheduler{}, nil
		},
		ApplicationBackend: func(ctx context.Context, resources Resources, _ OperatorServices, _ StandardRuntime, _ TemporaryRuntime, _ MediaPreparationRegistrar) (ApplicationBackend, error) {
			if err := bindTestChannel(ctx, resources); err != nil {
				return nil, err
			}
			return surface, nil
		},
	})
	factories.OpenCredentials = func(context.Context, string) (Opened[credential.SecretStore], error) {
		return Opened[credential.SecretStore]{Value: credential.NewMemoryStore(), Close: noClose}, nil
	}
	product, err := New(Config{
		Enabled: true, StateRoot: filepath.Join(t.TempDir(), "state"), TemporaryWorkerOwner: "test-owner",
		WorkerInterval: 5 * time.Millisecond, MediaGCInterval: 5 * time.Millisecond,
	}, factories)
	if err != nil {
		t.Fatal(err)
	}
	if err := product.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	handler, err := product.Handler()
	if err != nil {
		t.Fatal(err)
	}
	requestDone := make(chan int, 1)
	go func() { requestDone <- serveStatus(handler) }()
	<-surface.started
	stopDone := make(chan error, 1)
	go func() { stopDone <- product.Stop() }()
	waitFor(t, func() bool { return product.Readiness().State == StateStopping })
	select {
	case err := <-stopDone:
		t.Fatalf("stop returned before admitted request drained: %v", err)
	case <-time.After(20 * time.Millisecond):
	}
	close(surface.release)
	if status := <-requestDone; status != http.StatusOK {
		t.Fatalf("admitted HTTP status=%d", status)
	}
	if err := <-stopDone; err != nil {
		t.Fatal(err)
	}
	if status := serveStatus(handler); status != http.StatusServiceUnavailable {
		t.Fatalf("drained stale HTTP status=%d", status)
	}
}

func assertProductInteractionRouting(
	t *testing.T,
	handoffs *onboarding.HandoffStore,
	interactions *inspectioninteraction.Store,
	binding inspectioninteraction.Binding,
	connectionRef string,
	persistentRef string,
) {
	t.Helper()
	handoff, err := handoffs.Resolve(context.Background(), onboarding.HandoffBinding{
		TenantID: binding.TenantID, SiteID: binding.SiteID, PrincipalSHA256: binding.PrincipalSHA256,
	}, connectionRef)
	if err != nil || handoff.State != onboarding.HandoffPending {
		t.Fatalf("connection handoff state=%q err=%v", handoff.State, err)
	}
	if _, err := interactions.Resolve(context.Background(), binding, connectionRef); !errors.Is(err, inspectioninteraction.ErrNotFound) {
		t.Fatalf("connection leaked into pending interactions: %v", err)
	}
	pending, err := interactions.Resolve(context.Background(), binding, persistentRef)
	if err != nil || pending.State != inspectioninteraction.StatePending || pending.Operation != inspectionplanning.PendingTaskDisable {
		t.Fatalf("persistent interaction state=%q operation=%q err=%v", pending.State, pending.Operation, err)
	}
	if _, err := handoffs.Resolve(context.Background(), onboarding.HandoffBinding{
		TenantID: binding.TenantID, SiteID: binding.SiteID, PrincipalSHA256: binding.PrincipalSHA256,
	}, persistentRef); !errors.Is(err, onboarding.ErrHandoffNotFound) {
		t.Fatalf("persistent interaction leaked into onboarding handoffs: %v", err)
	}
}

func TestEnabledStartupFailureClosesEveryOpenedResourceInReverseOrder(t *testing.T) {
	var eventsMu sync.Mutex
	var events []string
	record := func(event string) {
		eventsMu.Lock()
		events = append(events, event)
		eventsMu.Unlock()
	}
	opened := func(name string, close func() error) func() error {
		record("open:" + name)
		return func() error {
			record("close:" + name)
			if close != nil {
				return close()
			}
			return nil
		}
	}
	factories := Factories{
		AuthorityVerifier:        &recordingAuthorityVerifier{},
		MediaPreparationAcquirer: idleMediaPreparationAcquirer{},
		OpenCredentials: func(context.Context, string) (Opened[credential.SecretStore], error) {
			return Opened[credential.SecretStore]{Value: credential.NewMemoryStore(), Close: opened("credentials", nil)}, nil
		},
		OpenExecutionAuthority: func(context.Context, string, string, credential.SecretStore) (Opened[inspectionauthority.Broker], error) {
			broker, err := inspectionauthority.NewEphemeralBroker(
				"test-product-authority", []byte(strings.Repeat("k", 32)), time.Hour, time.Now,
			)
			if err != nil {
				return Opened[inspectionauthority.Broker]{}, err
			}
			return Opened[inspectionauthority.Broker]{Value: broker, Close: opened("execution-authority", nil)}, nil
		},
		OpenProfiles: func(context.Context, string) (Opened[*profile.Store], error) {
			return Opened[*profile.Store]{Value: &profile.Store{}, Close: opened("profiles", nil)}, nil
		},
		OpenOnboardingJournal: func(_ context.Context, path string) (Opened[*onboarding.Journal], error) {
			journal, err := onboarding.OpenJournal(path)
			if err != nil {
				return Opened[*onboarding.Journal]{}, err
			}
			return Opened[*onboarding.Journal]{Value: journal, Close: opened("onboarding-journal", journal.Close)}, nil
		},
		OpenOnboardingHandoffs: func(_ context.Context, path string) (Opened[*onboarding.HandoffStore], error) {
			store, err := onboarding.OpenHandoffStore(onboarding.HandoffStoreConfig{Path: path})
			if err != nil {
				return Opened[*onboarding.HandoffStore]{}, err
			}
			return Opened[*onboarding.HandoffStore]{Value: store, Close: opened("onboarding-handoffs", store.Close)}, nil
		},
		OpenPendingInteractions: func(_ context.Context, path string) (Opened[*inspectioninteraction.Store], error) {
			store, err := inspectioninteraction.OpenStore(inspectioninteraction.StoreConfig{Path: path})
			if err != nil {
				return Opened[*inspectioninteraction.Store]{}, err
			}
			return Opened[*inspectioninteraction.Store]{Value: store, Close: opened("pending-interactions", store.Close)}, nil
		},
		OpenCatalog: func(context.Context, string) (Opened[*inspectioncatalog.Store], error) {
			return Opened[*inspectioncatalog.Store]{Value: &inspectioncatalog.Store{}, Close: opened("catalog", nil)}, nil
		},
		OpenApplication: func(context.Context, string) (Opened[*inspectionapplication.StateStore], error) {
			return Opened[*inspectionapplication.StateStore]{Value: &inspectionapplication.StateStore{}, Close: opened("application", nil)}, nil
		},
		OpenChannelAuth: func(context.Context, string) (Opened[*inspectionchannelauth.Store], error) {
			return Opened[*inspectionchannelauth.Store]{Value: &inspectionchannelauth.Store{}, Close: opened("channel-auth", nil)}, nil
		},
		OpenChangeflow: func(context.Context, string) (Opened[inspectionchangeflow.Store], error) {
			return Opened[inspectionchangeflow.Store]{Value: inspectionchangeflow.NewMemoryStore(), Close: opened("changeflow", nil)}, nil
		},
		OpenRuns: func(context.Context, string) (Opened[*inspectionstore.Store], error) {
			return Opened[*inspectionstore.Store]{Value: &inspectionstore.Store{}, Close: opened("runs", nil)}, nil
		},
		OpenTemporary: func(context.Context, string) (Opened[*inspectiontemporary.SQLiteStore], error) {
			return Opened[*inspectiontemporary.SQLiteStore]{Value: &inspectiontemporary.SQLiteStore{}, Close: opened("temporary", nil)}, nil
		},
		OpenSchedules: func(context.Context, string) (Opened[*inspectionschedule.Store], error) {
			return Opened[*inspectionschedule.Store]{Value: &inspectionschedule.Store{}, Close: opened("schedules", nil)}, nil
		},
		OpenMedia: func(context.Context, inspectionmedia.Config) (Opened[*inspectionmedia.Store], error) {
			return Opened[*inspectionmedia.Store]{Value: &inspectionmedia.Store{}, Close: opened("media", nil)}, nil
		},
		OpenMediaPreparations: func(_ context.Context, config inspectionmediaprep.Config) (Opened[*inspectionmediaprep.Manager], error) {
			manager, err := inspectionmediaprep.Open(config)
			if err != nil {
				return Opened[*inspectionmediaprep.Manager]{}, err
			}
			return Opened[*inspectionmediaprep.Manager]{Value: manager, Close: opened("media-preparations", manager.Close)}, nil
		},
		OpenDelivery: func(context.Context, string) (Opened[*inspectiondelivery.SQLiteStore], error) {
			return Opened[*inspectiondelivery.SQLiteStore]{Value: &inspectiondelivery.SQLiteStore{}, Close: opened("delivery", nil)}, nil
		},
		OpenDeliveryBindings: func(context.Context, string) (Opened[*inspectiondeliverybinding.Store], error) {
			return Opened[*inspectiondeliverybinding.Store]{Value: &inspectiondeliverybinding.Store{}, Close: opened("delivery-bindings", nil)}, nil
		},
		BuildStandardRuntime: func(context.Context, Resources, ExecutionBinding) (StandardRuntime, error) {
			record("build:runtime")
			return &recordingRuntime{onStop: func() { record("stop:runtime") }}, nil
		},
		BuildTemporaryRuntime: func(context.Context, Resources, MediaPreparationReader) (TemporaryRuntime, error) {
			record("build:temporary")
			return idleTemporaryProcessor{}, nil
		},
		BuildApplicationBackend: func(context.Context, Resources, OperatorServices, StandardRuntime, TemporaryRuntime, MediaPreparationRegistrar) (ApplicationBackend, error) {
			record("build:application")
			return &applicationBackendStub{}, nil
		},
		BuildOutboxMaterializer: func(context.Context, Resources, inspectiondelivery.TerminalMessageBuilder) (OutboxMaterializer, error) {
			record("build:outbox")
			return &oneItemMaterializer{}, nil
		},
		BuildDeliveryDispatcher: func(context.Context, Resources) (DeliveryDispatcher, error) {
			record("build:delivery")
			return nil, errors.New("dispatcher unavailable")
		},
		BuildScheduleCoordinator: func(context.Context, *inspectionschedule.Store, ScheduleBridge) (ScheduleCoordinator, error) {
			record("build:schedule")
			return &oneItemScheduler{}, nil
		},
	}
	product, err := New(Config{
		Enabled: true, StateRoot: filepath.Join(t.TempDir(), "state"), TemporaryWorkerOwner: "inspection-product-test",
	}, factories)
	if err != nil {
		t.Fatal(err)
	}
	if err := product.Start(context.Background()); err == nil {
		t.Fatal("startup accepted a missing dispatcher")
	}
	expected := []string{
		"open:credentials", "open:execution-authority", "open:profiles", "open:onboarding-journal", "open:onboarding-handoffs", "open:pending-interactions", "open:catalog", "open:application", "open:channel-auth", "open:changeflow", "open:runs", "open:temporary", "open:schedules", "open:media", "open:media-preparations", "open:delivery", "open:delivery-bindings",
		"build:runtime", "build:temporary", "build:application", "build:outbox", "build:delivery", "stop:runtime",
		"close:delivery-bindings", "close:delivery", "close:media-preparations", "close:media", "close:schedules", "close:temporary", "close:runs", "close:changeflow", "close:channel-auth", "close:application", "close:catalog", "close:pending-interactions", "close:onboarding-handoffs", "close:onboarding-journal", "close:profiles", "close:execution-authority", "close:credentials",
	}
	if !slices.Equal(events, expected) {
		t.Fatalf("startup cleanup order:\n got %v\nwant %v", events, expected)
	}
	if readiness := product.Readiness(); readiness.State != StateFailed || readiness.Ready || readiness.Failure != "startup_failed" {
		t.Fatalf("unexpected failed readiness: %+v", readiness)
	}
	if metrics := product.Metrics(); metrics.StartupFailures != 1 || metrics.Starts != 0 || metrics.Stops != 0 {
		t.Fatalf("unexpected failed startup metrics: %+v", metrics)
	}
	if err := product.Stop(); err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(events, expected) {
		t.Fatal("stop repeated cleanup after failed startup")
	}
}

func TestApplicationBackendBuildFailureNeverPublishesReadiness(t *testing.T) {
	for _, testCase := range []struct {
		name  string
		build func(context.Context, Resources, OperatorServices, StandardRuntime, TemporaryRuntime, MediaPreparationRegistrar) (ApplicationBackend, error)
	}{
		{name: "builder error", build: func(context.Context, Resources, OperatorServices, StandardRuntime, TemporaryRuntime, MediaPreparationRegistrar) (ApplicationBackend, error) {
			return nil, errors.New("HTTP surface unavailable")
		}},
		{name: "typed nil", build: func(context.Context, Resources, OperatorServices, StandardRuntime, TemporaryRuntime, MediaPreparationRegistrar) (ApplicationBackend, error) {
			var backend *applicationBackendStub
			return backend, nil
		}},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			runtimeWorker := &recordingRuntime{}
			factories := persistentTestFactories(Builders{
				StandardRuntime:  func(context.Context, Resources, ExecutionBinding) (StandardRuntime, error) { return runtimeWorker, nil },
				TemporaryRuntime: buildIdleTemporaryRuntime,
				OutboxMaterializer: func(context.Context, Resources, inspectiondelivery.TerminalMessageBuilder) (OutboxMaterializer, error) {
					return &oneItemMaterializer{}, nil
				},
				DeliveryDispatcher: func(context.Context, Resources) (DeliveryDispatcher, error) {
					return &oneItemDispatcher{}, nil
				},
				ScheduleCoordinator: func(context.Context, *inspectionschedule.Store, ScheduleBridge) (ScheduleCoordinator, error) {
					return &oneItemScheduler{}, nil
				},
				ApplicationBackend: testCase.build,
			})
			factories.OpenCredentials = func(context.Context, string) (Opened[credential.SecretStore], error) {
				return Opened[credential.SecretStore]{Value: credential.NewMemoryStore(), Close: noClose}, nil
			}
			product, err := New(Config{
				Enabled: true, StateRoot: filepath.Join(t.TempDir(), "state"), TemporaryWorkerOwner: "test-owner",
			}, factories)
			if err != nil {
				t.Fatal(err)
			}
			if err := product.Start(context.Background()); err == nil {
				t.Fatal("product accepted unavailable HTTP surface")
			}
			if readiness := product.Readiness(); readiness.Ready || readiness.State != StateFailed || readiness.Failure != "startup_failed" {
				t.Fatalf("HTTP startup failure readiness=%+v", readiness)
			}
			if handler, err := product.Handler(); !errors.Is(err, ErrHTTPSurfaceUnavailable) || handler != nil {
				t.Fatalf("HTTP startup failure exposed handler=%v err=%v", handler, err)
			}
			if runtimeWorker.starts.Load() != 0 || runtimeWorker.stops.Load() != 1 {
				t.Fatalf("passive build cleanup starts=%d stops=%d", runtimeWorker.starts.Load(), runtimeWorker.stops.Load())
			}
		})
	}
}

func TestGenerationUsesExactSameRuntimeAndApplicationInstances(t *testing.T) {
	standard := &recordingRuntime{}
	temporaryRuntime := &recordingTemporaryProcessor{}
	backend := &applicationBackendStub{}
	var applicationStandard StandardRuntime
	var applicationTemporary TemporaryRuntime
	var materializerBuilder inspectiondelivery.TerminalMessageBuilder
	var schedulePort ScheduleBridge
	factories := persistentTestFactories(Builders{
		StandardRuntime: func(context.Context, Resources, ExecutionBinding) (StandardRuntime, error) { return standard, nil },
		TemporaryRuntime: func(context.Context, Resources, MediaPreparationReader) (TemporaryRuntime, error) {
			return temporaryRuntime, nil
		},
		ApplicationBackend: func(ctx context.Context, resources Resources, _ OperatorServices, gotStandard StandardRuntime, gotTemporary TemporaryRuntime, _ MediaPreparationRegistrar) (ApplicationBackend, error) {
			applicationStandard, applicationTemporary = gotStandard, gotTemporary
			if err := bindTestChannel(ctx, resources); err != nil {
				return nil, err
			}
			return backend, nil
		},
		OutboxMaterializer: func(_ context.Context, _ Resources, builder inspectiondelivery.TerminalMessageBuilder) (OutboxMaterializer, error) {
			materializerBuilder = builder
			return &oneItemMaterializer{}, nil
		},
		DeliveryDispatcher: func(context.Context, Resources) (DeliveryDispatcher, error) {
			return &oneItemDispatcher{}, nil
		},
		ScheduleCoordinator: func(_ context.Context, _ *inspectionschedule.Store, bridge ScheduleBridge) (ScheduleCoordinator, error) {
			schedulePort = bridge
			return &oneItemScheduler{}, nil
		},
	})
	factories.OpenCredentials = func(context.Context, string) (Opened[credential.SecretStore], error) {
		return Opened[credential.SecretStore]{Value: credential.NewMemoryStore(), Close: noClose}, nil
	}
	product, err := New(Config{
		Enabled: true, StateRoot: filepath.Join(t.TempDir(), "state"), TemporaryWorkerOwner: "identity-test",
		WorkerInterval: time.Hour, MediaGCInterval: time.Hour,
	}, factories)
	if err != nil {
		t.Fatal(err)
	}
	if err := product.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = product.Stop() })
	if applicationStandard != standard || schedulePort == nil || any(schedulePort) == any(standard) || applicationTemporary != temporaryRuntime {
		t.Fatalf("runtime identities changed: applicationStandard=%T schedule=%T temporary=%T", applicationStandard, schedulePort, applicationTemporary)
	}
	if _, rawRuntime := any(schedulePort).(inspectionapplication.Runner); rawRuntime {
		t.Fatal("schedule coordinator received the raw application runtime submission port")
	}
	surface, ok := materializerBuilder.(*applicationSurface)
	if !ok || surface != product.application || surface.backend != backend {
		t.Fatalf("application identity changed: materializer=%T product=%p backend=%T", materializerBuilder, product.application, surface)
	}
	if status := serveStatus(mustProductHandler(t, product)); status != http.StatusOK {
		t.Fatalf("canonical application HTTP status=%d", status)
	}
}

func TestTypedNilGenerationComponentsFailBeforeReadiness(t *testing.T) {
	for _, testCase := range []struct {
		name   string
		mutate func(*Builders)
	}{
		{name: "standard runtime", mutate: func(builders *Builders) {
			builders.StandardRuntime = func(context.Context, Resources, ExecutionBinding) (StandardRuntime, error) {
				var runtimeWorker *recordingRuntime
				return runtimeWorker, nil
			}
		}},
		{name: "temporary runtime", mutate: func(builders *Builders) {
			builders.TemporaryRuntime = func(context.Context, Resources, MediaPreparationReader) (TemporaryRuntime, error) {
				var runtimeWorker *recordingTemporaryProcessor
				return runtimeWorker, nil
			}
		}},
		{name: "application backend", mutate: func(builders *Builders) {
			builders.ApplicationBackend = func(context.Context, Resources, OperatorServices, StandardRuntime, TemporaryRuntime, MediaPreparationRegistrar) (ApplicationBackend, error) {
				var backend *applicationBackendStub
				return backend, nil
			}
		}},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			builders := validTestBuilders()
			testCase.mutate(&builders)
			factories := persistentTestFactories(builders)
			factories.OpenCredentials = func(context.Context, string) (Opened[credential.SecretStore], error) {
				return Opened[credential.SecretStore]{Value: credential.NewMemoryStore(), Close: noClose}, nil
			}
			product, err := New(Config{
				Enabled: true, StateRoot: filepath.Join(t.TempDir(), "state"), TemporaryWorkerOwner: "typed-nil-test",
			}, factories)
			if err != nil {
				t.Fatal(err)
			}
			if err := product.Start(context.Background()); err == nil {
				t.Fatal("typed nil component was accepted")
			}
			if readiness := product.Readiness(); readiness.Ready || readiness.State != StateFailed {
				t.Fatalf("typed nil readiness=%+v", readiness)
			}
			if handler, err := product.Handler(); !errors.Is(err, ErrHTTPSurfaceUnavailable) || handler != nil {
				t.Fatalf("typed nil exposed handler=%v err=%v", handler, err)
			}
		})
	}
}

func TestWorkerFailureCancelsProductAndRequiresExplicitCleanup(t *testing.T) {
	root := filepath.Join(t.TempDir(), "operator-state")
	runtimeWorker := &recordingRuntime{}
	factories := persistentTestFactories(Builders{
		StandardRuntime:  func(context.Context, Resources, ExecutionBinding) (StandardRuntime, error) { return runtimeWorker, nil },
		TemporaryRuntime: buildIdleTemporaryRuntime,
		OutboxMaterializer: func(context.Context, Resources, inspectiondelivery.TerminalMessageBuilder) (OutboxMaterializer, error) {
			return errorMaterializer{}, nil
		},
		DeliveryDispatcher: func(context.Context, Resources) (DeliveryDispatcher, error) {
			return &oneItemDispatcher{}, nil
		},
		ScheduleCoordinator: func(context.Context, *inspectionschedule.Store, ScheduleBridge) (ScheduleCoordinator, error) {
			return &oneItemScheduler{}, nil
		},
		ApplicationBackend: buildReadyApplicationBackend,
	})
	factories.OpenCredentials = func(context.Context, string) (Opened[credential.SecretStore], error) {
		return Opened[credential.SecretStore]{Value: credential.NewMemoryStore(), Close: noClose}, nil
	}
	product, err := New(Config{
		Enabled: true, StateRoot: root,
		WorkerInterval: 5 * time.Millisecond, MediaGCInterval: 5 * time.Millisecond,
		TemporaryWorkerOwner: "inspection-product-test",
	}, factories)
	if err != nil {
		t.Fatal(err)
	}
	if err := product.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	handler, err := product.Handler()
	if err != nil {
		t.Fatal(err)
	}
	waitFor(t, func() bool { return product.Readiness().State == StateFailed })
	readiness := product.Readiness()
	if readiness.Ready || readiness.Failure != "outbox_worker_failed" {
		t.Fatalf("worker failure did not fail closed: %+v", readiness)
	}
	if metrics := product.Metrics(); metrics.WorkerFailures != 1 {
		t.Fatalf("worker failure metric=%+v", metrics)
	}
	if status := serveStatus(handler); status != http.StatusServiceUnavailable {
		t.Fatalf("failed product cached HTTP status=%d", status)
	}
	if current, err := product.Handler(); !errors.Is(err, ErrHTTPSurfaceUnavailable) || current != nil {
		t.Fatalf("failed product exposed HTTP surface: handler=%v err=%v", current, err)
	}
	if err := product.Stop(); err != nil {
		t.Fatal(err)
	}
	if runtimeWorker.stops.Load() != 1 {
		t.Fatalf("runtime stop count=%d", runtimeWorker.stops.Load())
	}
}

func TestTemporaryProcessorFailureFailsClosed(t *testing.T) {
	processor := &recordingTemporaryProcessor{err: errors.New("temporary analysis unavailable")}
	factories := persistentTestFactories(Builders{
		StandardRuntime: func(context.Context, Resources, ExecutionBinding) (StandardRuntime, error) {
			return &recordingRuntime{}, nil
		},
		TemporaryRuntime: func(context.Context, Resources, MediaPreparationReader) (TemporaryRuntime, error) {
			return processor, nil
		},
		OutboxMaterializer: func(context.Context, Resources, inspectiondelivery.TerminalMessageBuilder) (OutboxMaterializer, error) {
			return &oneItemMaterializer{}, nil
		},
		DeliveryDispatcher: func(context.Context, Resources) (DeliveryDispatcher, error) {
			return &oneItemDispatcher{}, nil
		},
		ScheduleCoordinator: func(context.Context, *inspectionschedule.Store, ScheduleBridge) (ScheduleCoordinator, error) {
			return &oneItemScheduler{}, nil
		},
		ApplicationBackend: buildReadyApplicationBackend,
	})
	factories.OpenCredentials = func(context.Context, string) (Opened[credential.SecretStore], error) {
		return Opened[credential.SecretStore]{Value: credential.NewMemoryStore(), Close: noClose}, nil
	}
	product, err := New(Config{
		Enabled: true, StateRoot: filepath.Join(t.TempDir(), "state"),
		WorkerInterval: 5 * time.Millisecond, MediaGCInterval: 5 * time.Millisecond,
		TemporaryWorkerOwner: "temporary-owner", TemporaryLeaseTTL: 2 * time.Minute,
	}, factories)
	if err != nil {
		t.Fatal(err)
	}
	if err := product.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	waitFor(t, func() bool { return product.Readiness().State == StateFailed })
	readiness := product.Readiness()
	if readiness.Ready || readiness.Failure != "temporary_worker_failed" {
		t.Fatalf("temporary worker failure did not fail closed: %+v", readiness)
	}
	metrics := product.Metrics()
	if metrics.TemporaryPasses != 1 || metrics.TemporaryClaims != 0 || metrics.WorkerFailures != 1 {
		t.Fatalf("temporary worker failure metrics=%+v", metrics)
	}
	owner, lease, calls := processor.snapshot()
	if owner != "temporary-owner" || lease != 2*time.Minute || calls != 1 {
		t.Fatalf("temporary worker owner=%q lease=%s calls=%d", owner, lease, calls)
	}
	if err := product.Stop(); err != nil {
		t.Fatal(err)
	}
}

func TestMediaPreparationDurableOutcomesDoNotFailProduct(t *testing.T) {
	processor := &scriptedMediaPreparationProcessor{steps: []mediaPreparationStep{
		{processed: true, err: inspectionmediaprep.ErrOutcomeUnknown},
		{processed: true, err: inspectionmediaprep.ErrPublicationUnknown},
		{processed: true, err: inspectionmediaprep.ErrPublicationRejected},
		{processed: true, err: inspectionmediaprep.ErrAcquirerContract},
		{processed: true, err: inspectionmediaprep.ErrLeaseLost},
		{processed: false},
	}}
	ctx, cancel := context.WithCancel(context.Background())
	product := &Product{state: StateReady, active: true, cancel: cancel}
	product.workers.Add(1)
	go product.runMediaPreparations(ctx, time.Hour, processor)
	waitFor(t, func() bool { return processor.processCalls.Load() == 6 })
	cancel()
	product.workers.Wait()
	if readiness := product.Readiness(); readiness.State != StateReady || !readiness.Ready || readiness.Failure != "" {
		t.Fatalf("durable media outcomes failed readiness=%+v", readiness)
	}
	metrics := product.Metrics()
	if metrics.MediaPreparationRecoveryPasses != 1 || metrics.MediaPreparationPasses != 6 ||
		metrics.MediaPreparationsProcessed != 5 || metrics.MediaPreparationPersistedOutcomes != 4 ||
		metrics.MediaPreparationLeaseConflicts != 1 ||
		metrics.WorkerFailures != 0 {
		t.Fatalf("durable media outcome metrics=%+v", metrics)
	}
}

func TestMediaPreparationCorruptionAndRecoveryIOFailClosed(t *testing.T) {
	for _, testCase := range []struct {
		name        string
		processor   *scriptedMediaPreparationProcessor
		wantFailure string
	}{
		{
			name:        "process corruption",
			processor:   &scriptedMediaPreparationProcessor{steps: []mediaPreparationStep{{err: inspectionmediaprep.ErrCorruptStore}}},
			wantFailure: "media_preparation_worker_failed",
		},
		{
			name:        "recovery IO",
			processor:   &scriptedMediaPreparationProcessor{recoverErr: errors.New("preparation database unavailable")},
			wantFailure: "media_preparation_recovery_worker_failed",
		},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			ctx, cancel := context.WithCancel(context.Background())
			product := &Product{state: StateReady, active: true, cancel: cancel}
			product.workers.Add(1)
			go product.runMediaPreparations(ctx, time.Hour, testCase.processor)
			waitFor(t, func() bool { return product.Readiness().State == StateFailed })
			product.workers.Wait()
			if readiness := product.Readiness(); readiness.Ready || readiness.Failure != testCase.wantFailure {
				t.Fatalf("fail-closed readiness=%+v", readiness)
			}
			if metrics := product.Metrics(); metrics.WorkerFailures != 1 {
				t.Fatalf("fail-closed metrics=%+v", metrics)
			}
		})
	}
}

func TestDeliveryOutcomeUnknownDoesNotFailOrStarveTheProduct(t *testing.T) {
	root := filepath.Join(t.TempDir(), "operator-state")
	unknown := &unknownOnceDispatcher{}
	factories := persistentTestFactories(Builders{
		StandardRuntime: func(context.Context, Resources, ExecutionBinding) (StandardRuntime, error) {
			return &recordingRuntime{}, nil
		},
		TemporaryRuntime: buildIdleTemporaryRuntime,
		OutboxMaterializer: func(context.Context, Resources, inspectiondelivery.TerminalMessageBuilder) (OutboxMaterializer, error) {
			return &oneItemMaterializer{}, nil
		},
		DeliveryDispatcher: func(context.Context, Resources) (DeliveryDispatcher, error) {
			return unknown, nil
		},
		ScheduleCoordinator: func(context.Context, *inspectionschedule.Store, ScheduleBridge) (ScheduleCoordinator, error) {
			return &oneItemScheduler{}, nil
		},
		ApplicationBackend: buildReadyApplicationBackend,
	})
	factories.OpenCredentials = func(context.Context, string) (Opened[credential.SecretStore], error) {
		return Opened[credential.SecretStore]{Value: credential.NewMemoryStore(), Close: noClose}, nil
	}
	product, err := New(Config{
		Enabled: true, StateRoot: root,
		WorkerInterval: 5 * time.Millisecond, MediaGCInterval: 5 * time.Millisecond,
		TemporaryWorkerOwner: "inspection-product-test",
	}, factories)
	if err != nil {
		t.Fatal(err)
	}
	if err := product.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = product.Stop() })
	waitFor(t, func() bool {
		metrics := product.Metrics()
		return metrics.DeliveryUnknownOutcomes == 1 && unknown.calls.Load() >= 2
	})
	readiness := product.Readiness()
	if !readiness.Ready || readiness.State != StateReady || readiness.Failure != "" {
		t.Fatalf("durable unknown delivery failed product readiness: %+v", readiness)
	}
	metrics := product.Metrics()
	if metrics.WorkerFailures != 0 || metrics.Deliveries != 1 || metrics.DeliveryUnknownOutcomes != 1 {
		t.Fatalf("unexpected outcome-unknown metrics: %+v", metrics)
	}
}

func TestDeliveryRecoveryCompletesBeforeRuntimeStart(t *testing.T) {
	root := filepath.Join(t.TempDir(), "operator-state")
	runtime := &recordingRuntime{}
	dispatcher := &failingRecoveryDispatcher{err: errors.New("delivery recovery failed")}
	builders := validTestBuilders()
	builders.StandardRuntime = func(context.Context, Resources, ExecutionBinding) (StandardRuntime, error) { return runtime, nil }
	builders.DeliveryDispatcher = func(context.Context, Resources) (DeliveryDispatcher, error) { return dispatcher, nil }
	factories := persistentTestFactories(builders)
	factories.OpenCredentials = func(context.Context, string) (Opened[credential.SecretStore], error) {
		return Opened[credential.SecretStore]{Value: credential.NewMemoryStore(), Close: noClose}, nil
	}
	product, err := New(Config{
		Enabled: true, StateRoot: root, TemporaryWorkerOwner: "inspection-product-test",
	}, factories)
	if err != nil {
		t.Fatal(err)
	}
	if err := product.Start(context.Background()); err == nil || !strings.Contains(err.Error(), "recover inspection deliveries before startup") {
		t.Fatalf("startup recovery error=%v", err)
	}
	if runtime.starts.Load() != 0 || dispatcher.recoverCalls.Load() != 1 {
		t.Fatalf("runtime starts=%d recovery calls=%d", runtime.starts.Load(), dispatcher.recoverCalls.Load())
	}
	readiness := product.Readiness()
	if readiness.State != StateFailed || readiness.Ready || readiness.Failure != "startup_failed" {
		t.Fatalf("readiness=%+v", readiness)
	}
}

func TestMediaPreparationRecoveryCompletesBeforeRuntimeStart(t *testing.T) {
	runtimeWorker := &recordingRuntime{}
	builders := validTestBuilders()
	builders.StandardRuntime = func(context.Context, Resources, ExecutionBinding) (StandardRuntime, error) {
		return runtimeWorker, nil
	}
	factories := persistentTestFactories(builders)
	factories.OpenCredentials = memoryCredentialFactory()
	openPreparations := factories.OpenMediaPreparations
	factories.OpenMediaPreparations = func(ctx context.Context, config inspectionmediaprep.Config) (Opened[*inspectionmediaprep.Manager], error) {
		opened, err := openPreparations(ctx, config)
		if err != nil {
			return Opened[*inspectionmediaprep.Manager]{}, err
		}
		if err := opened.Value.Close(); err != nil {
			return Opened[*inspectionmediaprep.Manager]{}, err
		}
		return Opened[*inspectionmediaprep.Manager]{Value: opened.Value, Close: noClose}, nil
	}
	product, err := New(Config{
		Enabled: true, StateRoot: filepath.Join(t.TempDir(), "state"), TemporaryWorkerOwner: "media-recovery-gate",
	}, factories)
	if err != nil {
		t.Fatal(err)
	}
	startErr := product.Start(context.Background())
	if startErr == nil || !strings.Contains(startErr.Error(), "recover temporary media preparations before startup") ||
		!errors.Is(startErr, inspectionmediaprep.ErrClosed) {
		t.Fatalf("startup recovery error=%v", startErr)
	}
	if runtimeWorker.starts.Load() != 0 || runtimeWorker.stops.Load() != 1 {
		t.Fatalf("runtime starts=%d stops=%d", runtimeWorker.starts.Load(), runtimeWorker.stops.Load())
	}
	if readiness := product.Readiness(); readiness.Ready || readiness.State != StateFailed ||
		readiness.Generation != 0 || readiness.Failure != "startup_failed" {
		t.Fatalf("media recovery gate readiness=%+v", readiness)
	}
	if metrics := product.Metrics(); metrics.MediaPreparationRecoveryPasses != 0 ||
		metrics.Starts != 0 || metrics.StartupFailures != 1 {
		t.Fatalf("media recovery gate metrics=%+v", metrics)
	}
}

func TestDeliveryWorkerRecoversThenReconcilesBeforeNewSend(t *testing.T) {
	root := filepath.Join(t.TempDir(), "operator-state")
	dispatcher := &orderedDeliveryDispatcher{}
	builders := validTestBuilders()
	builders.DeliveryDispatcher = func(context.Context, Resources) (DeliveryDispatcher, error) { return dispatcher, nil }
	factories := persistentTestFactories(builders)
	factories.OpenCredentials = func(context.Context, string) (Opened[credential.SecretStore], error) {
		return Opened[credential.SecretStore]{Value: credential.NewMemoryStore(), Close: noClose}, nil
	}
	product, err := New(Config{
		Enabled: true, StateRoot: root, WorkerInterval: 5 * time.Millisecond,
		MediaGCInterval: 5 * time.Millisecond, TemporaryWorkerOwner: "inspection-product-test",
	}, factories)
	if err != nil {
		t.Fatal(err)
	}
	if err := product.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = product.Stop() })
	waitFor(t, func() bool {
		metrics := product.Metrics()
		return metrics.DeliveryRecoveryPasses >= 2 && metrics.DeliveriesReconciled == 1 && metrics.Deliveries == 1
	})
	if sequence := dispatcher.sequenceSnapshot(); len(sequence) < 4 || !reflect.DeepEqual(sequence[:4], []string{"recover", "recover", "reconcile", "deliver"}) {
		t.Fatalf("delivery sequence=%v", sequence)
	}
	readiness := product.Readiness()
	if !readiness.Ready || readiness.Failure != "" {
		t.Fatalf("readiness=%+v", readiness)
	}
}

func TestScheduleFailureFailsProductWithoutInventingSubmission(t *testing.T) {
	root := filepath.Join(t.TempDir(), "operator-state")
	factories := persistentTestFactories(Builders{
		StandardRuntime: func(context.Context, Resources, ExecutionBinding) (StandardRuntime, error) {
			return &recordingRuntime{}, nil
		},
		TemporaryRuntime: buildIdleTemporaryRuntime,
		OutboxMaterializer: func(context.Context, Resources, inspectiondelivery.TerminalMessageBuilder) (OutboxMaterializer, error) {
			return &oneItemMaterializer{}, nil
		},
		DeliveryDispatcher: func(context.Context, Resources) (DeliveryDispatcher, error) {
			return &oneItemDispatcher{}, nil
		},
		ScheduleCoordinator: func(context.Context, *inspectionschedule.Store, ScheduleBridge) (ScheduleCoordinator, error) {
			return errorScheduler{}, nil
		},
		ApplicationBackend: buildReadyApplicationBackend,
	})
	factories.OpenCredentials = func(context.Context, string) (Opened[credential.SecretStore], error) {
		return Opened[credential.SecretStore]{Value: credential.NewMemoryStore(), Close: noClose}, nil
	}
	product, err := New(Config{
		Enabled: true, StateRoot: root,
		WorkerInterval: 5 * time.Millisecond, MediaGCInterval: 5 * time.Millisecond,
		TemporaryWorkerOwner: "inspection-product-test",
	}, factories)
	if err != nil {
		t.Fatal(err)
	}
	if err := product.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	waitFor(t, func() bool { return product.Readiness().State == StateFailed })
	if readiness := product.Readiness(); readiness.Failure != "schedule_worker_failed" || readiness.Ready {
		t.Fatalf("schedule failure readiness=%+v", readiness)
	}
	if metrics := product.Metrics(); metrics.SchedulePasses != 1 || metrics.ScheduleSubmissions != 0 || metrics.WorkerFailures != 1 {
		t.Fatalf("schedule failure metrics=%+v", metrics)
	}
	if err := product.Stop(); err != nil {
		t.Fatal(err)
	}
}

func TestParentCancellationRemovesReadinessUntilCleanup(t *testing.T) {
	root := filepath.Join(t.TempDir(), "operator-state")
	factories := persistentTestFactories(Builders{
		StandardRuntime: func(context.Context, Resources, ExecutionBinding) (StandardRuntime, error) {
			return &recordingRuntime{}, nil
		},
		TemporaryRuntime: buildIdleTemporaryRuntime,
		OutboxMaterializer: func(context.Context, Resources, inspectiondelivery.TerminalMessageBuilder) (OutboxMaterializer, error) {
			return &oneItemMaterializer{}, nil
		},
		DeliveryDispatcher: func(context.Context, Resources) (DeliveryDispatcher, error) {
			return &oneItemDispatcher{}, nil
		},
		ScheduleCoordinator: func(context.Context, *inspectionschedule.Store, ScheduleBridge) (ScheduleCoordinator, error) {
			return &oneItemScheduler{}, nil
		},
		ApplicationBackend: buildReadyApplicationBackend,
	})
	factories.OpenCredentials = func(context.Context, string) (Opened[credential.SecretStore], error) {
		return Opened[credential.SecretStore]{Value: credential.NewMemoryStore(), Close: noClose}, nil
	}
	product, err := New(Config{
		Enabled: true, StateRoot: root,
		WorkerInterval: 5 * time.Millisecond, MediaGCInterval: 5 * time.Millisecond,
		TemporaryWorkerOwner: "inspection-product-test",
	}, factories)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	if err := product.Start(ctx); err != nil {
		t.Fatal(err)
	}
	cancel()
	waitFor(t, func() bool { return product.Readiness().State == StateFailed })
	readiness := product.Readiness()
	if readiness.Ready || readiness.Failure != "lifecycle_context_closed" {
		t.Fatalf("cancelled parent left product ready: %+v", readiness)
	}
	if metrics := product.Metrics(); metrics.LifecycleInterruptions != 1 || metrics.WorkerFailures != 0 {
		t.Fatalf("unexpected lifecycle interruption metrics: %+v", metrics)
	}
	if err := product.Stop(); err != nil {
		t.Fatal(err)
	}
}

func TestCancellationBeforeWorkerReleaseRollsBackWithoutReadiness(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	standard := &recordingRuntime{onStart: cancel}
	builders := validTestBuilders()
	builders.StandardRuntime = func(context.Context, Resources, ExecutionBinding) (StandardRuntime, error) { return standard, nil }
	factories := persistentTestFactories(builders)
	factories.OpenCredentials = func(context.Context, string) (Opened[credential.SecretStore], error) {
		return Opened[credential.SecretStore]{Value: credential.NewMemoryStore(), Close: noClose}, nil
	}
	product, err := New(Config{
		Enabled: true, StateRoot: filepath.Join(t.TempDir(), "state"), TemporaryWorkerOwner: "startup-gate-test",
	}, factories)
	if err != nil {
		t.Fatal(err)
	}
	if err := product.Start(ctx); !errors.Is(err, context.Canceled) {
		t.Fatalf("startup cancellation error=%v", err)
	}
	if readiness := product.Readiness(); readiness.Ready || readiness.State != StateFailed || readiness.Generation != 0 {
		t.Fatalf("startup cancellation readiness=%+v", readiness)
	}
	if standard.starts.Load() != 1 || standard.stops.Load() != 1 {
		t.Fatalf("startup cancellation lifecycle starts=%d stops=%d", standard.starts.Load(), standard.stops.Load())
	}
	if metrics := product.Metrics(); metrics.Starts != 0 || metrics.Stops != 0 || metrics.StartupFailures != 1 {
		t.Fatalf("startup cancellation metrics=%+v", metrics)
	}
	if handler, err := product.Handler(); !errors.Is(err, ErrHTTPSurfaceUnavailable) || handler != nil {
		t.Fatalf("startup cancellation exposed handler=%v err=%v", handler, err)
	}
}

type handoffReconcileStep struct {
	result onboarding.HandoffReconcileResult
	err    error
}

type scriptedHandoffReconciler struct {
	mu     sync.Mutex
	steps  []handoffReconcileStep
	called chan onboarding.HandoffReconcileRequest
}

func (r *scriptedHandoffReconciler) ReconcileCompletedHandoffs(
	_ context.Context,
	request onboarding.HandoffReconcileRequest,
) (onboarding.HandoffReconcileResult, error) {
	r.mu.Lock()
	if len(r.steps) == 0 {
		r.mu.Unlock()
		return onboarding.HandoffReconcileResult{}, errors.New("unexpected handoff recovery call")
	}
	step := r.steps[0]
	r.steps = r.steps[1:]
	called := r.called
	r.mu.Unlock()
	if called != nil {
		called <- request
	}
	return step.result, step.err
}

type blockingHandoffReconciler struct {
	started  chan struct{}
	release  chan struct{}
	once     sync.Once
	finished atomic.Bool
}

func (r *blockingHandoffReconciler) ReconcileCompletedHandoffs(
	ctx context.Context,
	_ onboarding.HandoffReconcileRequest,
) (onboarding.HandoffReconcileResult, error) {
	r.once.Do(func() { close(r.started) })
	<-r.release
	r.finished.Store(true)
	return onboarding.HandoffReconcileResult{}, ctx.Err()
}

func memoryCredentialFactory() func(context.Context, string) (Opened[credential.SecretStore], error) {
	return func(context.Context, string) (Opened[credential.SecretStore], error) {
		return Opened[credential.SecretStore]{Value: credential.NewMemoryStore(), Close: noClose}, nil
	}
}

func execProtectedSQLite(t *testing.T, path, statement string) {
	t.Helper()
	database, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := database.Exec(statement); err != nil {
		_ = database.Close()
		t.Fatal(err)
	}
	if err := database.Close(); err != nil {
		t.Fatal(err)
	}
}

func exportedMethodNames(valueType reflect.Type) []string {
	names := make([]string, 0, valueType.NumMethod())
	for index := 0; index < valueType.NumMethod(); index++ {
		names = append(names, valueType.Method(index).Name)
	}
	return names
}

type recordingRuntime struct {
	starts  atomic.Uint64
	stops   atomic.Uint64
	onStart func()
	onStop  func()
}

func (r *recordingRuntime) Start(context.Context) error {
	r.starts.Add(1)
	if r.onStart != nil {
		r.onStart()
	}
	return nil
}

func (r *recordingRuntime) Stop() {
	r.stops.Add(1)
	if r.onStop != nil {
		r.onStop()
	}
}

func (r *recordingRuntime) Submit(
	context.Context,
	inspection.InspectionTemplate,
	inspection.Assignment,
	inspectionauthority.Submission,
) (inspection.Run, bool, error) {
	return inspection.Run{}, false, nil
}

type oneItemMaterializer struct{ returned atomic.Bool }

func (m *oneItemMaterializer) MaterializeNext(context.Context) (bool, error) {
	return !m.returned.Swap(true), nil
}

type oneItemDispatcher struct{ returned atomic.Bool }

func (*oneItemDispatcher) Recover(context.Context) (inspectiondelivery.Recovery, error) {
	return inspectiondelivery.Recovery{}, nil
}

func (d *oneItemDispatcher) DeliverNext(context.Context) (bool, error) {
	return !d.returned.Swap(true), nil
}

func (*oneItemDispatcher) ReconcileNext(context.Context) (bool, error) { return false, nil }

type failingRecoveryDispatcher struct {
	err          error
	recoverCalls atomic.Uint64
}

func (d *failingRecoveryDispatcher) Recover(context.Context) (inspectiondelivery.Recovery, error) {
	d.recoverCalls.Add(1)
	return inspectiondelivery.Recovery{}, d.err
}

func (*failingRecoveryDispatcher) DeliverNext(context.Context) (bool, error) { return false, nil }
func (*failingRecoveryDispatcher) ReconcileNext(context.Context) (bool, error) {
	return false, nil
}

type orderedDeliveryDispatcher struct {
	mu         sync.Mutex
	sequence   []string
	reconciled bool
	delivered  bool
}

func (d *orderedDeliveryDispatcher) Recover(context.Context) (inspectiondelivery.Recovery, error) {
	d.record("recover")
	return inspectiondelivery.Recovery{}, nil
}

func (d *orderedDeliveryDispatcher) ReconcileNext(context.Context) (bool, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.reconciled {
		return false, nil
	}
	d.reconciled = true
	d.sequence = append(d.sequence, "reconcile")
	return true, nil
}

func (d *orderedDeliveryDispatcher) DeliverNext(context.Context) (bool, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.delivered {
		return false, nil
	}
	d.delivered = true
	d.sequence = append(d.sequence, "deliver")
	return true, nil
}

func (d *orderedDeliveryDispatcher) record(value string) {
	d.mu.Lock()
	d.sequence = append(d.sequence, value)
	d.mu.Unlock()
}

func (d *orderedDeliveryDispatcher) sequenceSnapshot() []string {
	d.mu.Lock()
	defer d.mu.Unlock()
	return append([]string(nil), d.sequence...)
}

type oneItemScheduler struct{ returned atomic.Bool }

func (s *oneItemScheduler) Tick(context.Context) (inspectionschedule.TickReport, error) {
	if s.returned.Swap(true) {
		return inspectionschedule.TickReport{}, nil
	}
	return inspectionschedule.TickReport{OccurrencesCreated: 1, Submitted: 1}, nil
}

type errorMaterializer struct{}

func (errorMaterializer) MaterializeNext(context.Context) (bool, error) {
	return false, errors.New("outbox projection failed")
}

type errorScheduler struct{}

func (errorScheduler) Tick(context.Context) (inspectionschedule.TickReport, error) {
	return inspectionschedule.TickReport{}, errors.New("schedule coordination failed")
}

type unknownOnceDispatcher struct{ calls atomic.Uint64 }

func (*unknownOnceDispatcher) Recover(context.Context) (inspectiondelivery.Recovery, error) {
	return inspectiondelivery.Recovery{}, nil
}

func (d *unknownOnceDispatcher) DeliverNext(context.Context) (bool, error) {
	if d.calls.Add(1) == 1 {
		return true, inspectiondelivery.ErrOutcomeUnknown
	}
	return false, nil
}

func (*unknownOnceDispatcher) ReconcileNext(context.Context) (bool, error) { return false, nil }

type idleTemporaryProcessor struct{}

func (idleTemporaryProcessor) RunOnce(context.Context, string, time.Duration) (inspectiontemporary.Record, bool, error) {
	return inspectiontemporary.Record{}, false, nil
}

func (idleTemporaryProcessor) Submit(context.Context, inspectiontemporary.Submission) (inspectiontemporary.Record, bool, error) {
	return inspectiontemporary.Record{}, false, nil
}

func (idleTemporaryProcessor) Get(context.Context, string) (inspectiontemporary.Record, error) {
	return inspectiontemporary.Record{}, errors.New("temporary record unavailable")
}

type recordingTemporaryProcessor struct {
	mu    sync.Mutex
	owner string
	lease time.Duration
	calls uint64
	err   error
}

func (p *recordingTemporaryProcessor) RunOnce(_ context.Context, owner string, lease time.Duration) (inspectiontemporary.Record, bool, error) {
	p.mu.Lock()
	p.owner = owner
	p.lease = lease
	p.calls++
	err := p.err
	p.mu.Unlock()
	return inspectiontemporary.Record{}, false, err
}

func (p *recordingTemporaryProcessor) Submit(context.Context, inspectiontemporary.Submission) (inspectiontemporary.Record, bool, error) {
	return inspectiontemporary.Record{}, false, nil
}

func (p *recordingTemporaryProcessor) Get(context.Context, string) (inspectiontemporary.Record, error) {
	return inspectiontemporary.Record{}, errors.New("temporary record unavailable")
}

func (p *recordingTemporaryProcessor) snapshot() (string, time.Duration, uint64) {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.owner, p.lease, p.calls
}

type blockingHTTPSurface struct {
	applicationBackendStub
	started chan struct{}
	release chan struct{}
	once    sync.Once
}

func newBlockingHTTPSurface() *blockingHTTPSurface {
	return &blockingHTTPSurface{started: make(chan struct{}), release: make(chan struct{})}
}

func (s *blockingHTTPSurface) QueryCapabilities(context.Context, inspectionhttpapi.SessionBinding) (inspectionhttpapi.CapabilitySet, error) {
	s.once.Do(func() { close(s.started) })
	<-s.release
	return testCapabilities(), nil
}

func buildIdleTemporaryRuntime(_ context.Context, _ Resources, reader MediaPreparationReader) (TemporaryRuntime, error) {
	if _, forbidden := reader.(mediaPreparationProcessor); forbidden {
		return nil, errors.New("temporary reader acquired media preparation worker authority")
	}
	return idleTemporaryProcessor{}, nil
}

func buildReadyApplicationBackend(ctx context.Context, resources Resources, _ OperatorServices, _ StandardRuntime, _ TemporaryRuntime, registrar MediaPreparationRegistrar) (ApplicationBackend, error) {
	if _, forbidden := registrar.(mediaPreparationProcessor); forbidden {
		return nil, errors.New("application registrar acquired media preparation worker authority")
	}
	if err := bindTestChannel(ctx, resources); err != nil {
		return nil, err
	}
	return &applicationBackendStub{}, nil
}

func validTestBuilders() Builders {
	return Builders{
		StandardRuntime: func(context.Context, Resources, ExecutionBinding) (StandardRuntime, error) {
			return &recordingRuntime{}, nil
		},
		TemporaryRuntime:   buildIdleTemporaryRuntime,
		ApplicationBackend: buildReadyApplicationBackend,
		OutboxMaterializer: func(context.Context, Resources, inspectiondelivery.TerminalMessageBuilder) (OutboxMaterializer, error) {
			return &oneItemMaterializer{}, nil
		},
		DeliveryDispatcher: func(context.Context, Resources) (DeliveryDispatcher, error) {
			return &oneItemDispatcher{}, nil
		},
		ScheduleCoordinator: func(context.Context, *inspectionschedule.Store, ScheduleBridge) (ScheduleCoordinator, error) {
			return &oneItemScheduler{}, nil
		},
	}
}

func persistentTestFactories(builders Builders) Factories {
	return PersistentFactories(&recordingAuthorityVerifier{}, idleMediaPreparationAcquirer{}, builders)
}

type idleMediaPreparationAcquirer struct{}

func (idleMediaPreparationAcquirer) Acquire(context.Context, inspectionmediaprep.AcquisitionRequest) (inspectionmediaprep.AcquisitionResult, error) {
	return inspectionmediaprep.AcquisitionResult{Outcome: inspectionmediaprep.AcquisitionPending}, nil
}

func (idleMediaPreparationAcquirer) Reconcile(context.Context, inspectionmediaprep.ReconciliationRequest) (inspectionmediaprep.AcquisitionResult, error) {
	return inspectionmediaprep.AcquisitionResult{Outcome: inspectionmediaprep.AcquisitionPending}, nil
}

func testMediaPreparationRequest(now time.Time, requestID string) inspectionmediaprep.FrozenRequest {
	point := now.Add(-time.Minute).UTC()
	return inspectionmediaprep.FrozenRequest{
		Schema:   inspectionmediaprep.RequestSchema,
		TenantID: "tenant-product", SiteID: "site-product", RequestID: requestID,
		SourceRef: "source-product", CapabilityRef: "capability-snapshot",
		TimeScope:          inspectionmediaprep.TimeScope{WindowStart: point, WindowEnd: point},
		AudienceBindingRef: "audience-product", AudienceSHA256: strings.Repeat("a", 64),
		EvidenceExpiresAt: now.Add(time.Hour).UTC(),
		Media: inspectionmediaprep.MediaSpec{
			Kind: inspectionmedia.KindImage, RunID: "run-product", StepID: "step-product", Attempt: 1,
			PrivacyClass: "sensitive", RetentionPolicyRef: "retention-product",
		},
	}
}

type blockingMediaPreparationAcquirer struct {
	started   chan struct{}
	startOnce sync.Once
	finished  atomic.Bool
}

func (a *blockingMediaPreparationAcquirer) Acquire(ctx context.Context, _ inspectionmediaprep.AcquisitionRequest) (inspectionmediaprep.AcquisitionResult, error) {
	a.startOnce.Do(func() { close(a.started) })
	<-ctx.Done()
	a.finished.Store(true)
	return inspectionmediaprep.AcquisitionResult{}, ctx.Err()
}

func (a *blockingMediaPreparationAcquirer) Reconcile(ctx context.Context, _ inspectionmediaprep.ReconciliationRequest) (inspectionmediaprep.AcquisitionResult, error) {
	<-ctx.Done()
	a.finished.Store(true)
	return inspectionmediaprep.AcquisitionResult{}, ctx.Err()
}

type mediaPreparationStep struct {
	status    inspectionmediaprep.Status
	processed bool
	err       error
}

type scriptedMediaPreparationProcessor struct {
	mu           sync.Mutex
	steps        []mediaPreparationStep
	recovery     inspectionmediaprep.Recovery
	recoverErr   error
	recoverCalls atomic.Uint64
	processCalls atomic.Uint64
}

func (p *scriptedMediaPreparationProcessor) Recover(context.Context) (inspectionmediaprep.Recovery, error) {
	p.recoverCalls.Add(1)
	return p.recovery, p.recoverErr
}

func (p *scriptedMediaPreparationProcessor) ProcessNext(context.Context) (inspectionmediaprep.Status, bool, error) {
	p.processCalls.Add(1)
	p.mu.Lock()
	defer p.mu.Unlock()
	if len(p.steps) == 0 {
		return inspectionmediaprep.Status{}, false, nil
	}
	step := p.steps[0]
	p.steps = p.steps[1:]
	return step.status, step.processed, step.err
}

type typedNilMediaPreparationAcquirer struct{}

func (*typedNilMediaPreparationAcquirer) Acquire(context.Context, inspectionmediaprep.AcquisitionRequest) (inspectionmediaprep.AcquisitionResult, error) {
	return inspectionmediaprep.AcquisitionResult{}, nil
}

func (*typedNilMediaPreparationAcquirer) Reconcile(context.Context, inspectionmediaprep.ReconciliationRequest) (inspectionmediaprep.AcquisitionResult, error) {
	return inspectionmediaprep.AcquisitionResult{}, nil
}

type recordingAuthorityVerifier struct {
	calls atomic.Uint64
	err   error
}

func (v *recordingAuthorityVerifier) Verify(operatorauthority.Grant, operatorauthority.Demand, time.Time) error {
	v.calls.Add(1)
	return v.err
}

func mustProductHandler(t *testing.T, product *Product) http.Handler {
	t.Helper()
	handler, err := product.Handler()
	if err != nil {
		t.Fatal(err)
	}
	return handler
}

func serveStatus(handler http.Handler) int {
	recorder := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodGet, "/api/inspection/capabilities", nil)
	request.Header.Set("Authorization", "Bearer "+testBearerToken)
	handler.ServeHTTP(recorder, request)
	return recorder.Code
}

const testBearerToken = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"

func bindTestChannel(ctx context.Context, resources Resources) error {
	digest := sha256.Sum256([]byte(testBearerToken))
	_, _, err := resources.ChannelAuth.Bind(ctx, inspectionchannelauth.Binding{
		CredentialSHA256: hex.EncodeToString(digest[:]),
		Session: inspectionhttpapi.SessionBinding{
			TenantID: "tenant-test", SiteID: "site-test", Channel: "workbuddy",
			ConversationRef: "conversation-test", RecipientRef: "recipient-test",
			PrincipalSHA256: strings.Repeat("b", 64),
		},
		Scopes:    []inspectionhttpapi.Scope{inspectionhttpapi.ScopeCapabilitiesRead},
		CreatedAt: time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC),
		ExpiresAt: time.Date(2026, 12, 31, 0, 0, 0, 0, time.UTC),
	})
	return err
}

type applicationBackendStub struct{}

func (*applicationBackendStub) QueryCapabilities(context.Context, inspectionhttpapi.SessionBinding) (inspectionhttpapi.CapabilitySet, error) {
	return testCapabilities(), nil
}

func (*applicationBackendStub) ResolveContinuation(context.Context, inspectionhttpapi.SessionBinding) (inspectionhttpapi.ContinuationResolution, error) {
	return inspectionhttpapi.ContinuationResolution{Status: inspectionhttpapi.ContinuationNone}, nil
}

func testCapabilities() inspectionhttpapi.CapabilitySet {
	return inspectionhttpapi.CapabilitySet{
		ContextLabel: "测试范围",
		Capabilities: []inspectionhttpapi.CapabilityView{{
			CapabilityRef: "inspection.scene", Title: "现场巡检", Description: "根据问题查看现场情况",
		}},
	}
}

func (*applicationBackendStub) RequestInspection(context.Context, inspectionhttpapi.SessionBinding, inspectionhttpapi.InspectionRequest, string) (inspectionhttpapi.RunView, bool, error) {
	return inspectionhttpapi.RunView{}, false, inspectionhttpapi.ErrNotFound
}

func (*applicationBackendStub) GetRun(context.Context, inspectionhttpapi.SessionBinding, string) (inspectionhttpapi.RunView, error) {
	return inspectionhttpapi.RunView{}, inspectionhttpapi.ErrNotFound
}

func (*applicationBackendStub) GetResult(context.Context, inspectionhttpapi.SessionBinding, string) (inspectionhttpapi.ResultView, error) {
	return inspectionhttpapi.ResultView{}, inspectionhttpapi.ErrNotFound
}

func (*applicationBackendStub) GetMedia(context.Context, inspectionhttpapi.SessionBinding, string) (inspectionhttpapi.MediaPayload, error) {
	return inspectionhttpapi.MediaPayload{}, inspectionhttpapi.ErrNotFound
}

func (*applicationBackendStub) SubmitFeedback(context.Context, inspectionhttpapi.SessionBinding, string, inspectionhttpapi.FeedbackRequest, string) (inspectionhttpapi.FeedbackReceipt, bool, error) {
	return inspectionhttpapi.FeedbackReceipt{}, false, inspectionhttpapi.ErrNotFound
}

func (*applicationBackendStub) BuildDeliveryMessage(context.Context, string) (inspectiondelivery.Message, error) {
	return inspectiondelivery.Message{}, inspectionhttpapi.ErrNotFound
}

var (
	_ StandardRuntime    = (*recordingRuntime)(nil)
	_ TemporaryRuntime   = (*recordingTemporaryProcessor)(nil)
	_ TemporaryRuntime   = idleTemporaryProcessor{}
	_ ApplicationBackend = (*applicationBackendStub)(nil)
)

func waitFor(t *testing.T, condition func() bool) {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if condition() {
			return
		}
		time.Sleep(time.Millisecond)
	}
	t.Fatal("condition was not reached before timeout")
}
