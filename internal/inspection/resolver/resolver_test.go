package resolver

import (
	"errors"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/cosmo-wander-ai/cosmoedge-connect/internal/inspection"
	"github.com/cosmo-wander-ai/cosmoedge-connect/internal/inspection/catalog"
	"github.com/cosmo-wander-ai/cosmoedge-connect/internal/inspection/temporary"
)

var testNow = time.Date(2026, 7, 19, 10, 30, 0, 0, time.UTC)

func TestResolveSelectsEveryClosedRoute(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name       string
		request    func() Request
		wantRoute  Route
		wantReason ReasonCode
		check      func(*testing.T, Resolution)
	}{
		{
			name: "existing installed task",
			request: func() Request {
				request := standardRequest()
				request.Intent.Inspection.Preference = PreferenceExistingTask
				return request
			},
			wantRoute: RouteExistingTaskRead, wantReason: ReasonExistingTaskMatched,
		},
		{
			name: "snapshot analysis",
			request: func() Request {
				request := standardRequest()
				request.Intent.Inspection.Preference = PreferenceSnapshot
				return request
			},
			wantRoute: RouteSnapshotAnalysis, wantReason: ReasonSnapshotCapabilityMatched,
		},
		{
			name: "clip analysis",
			request: func() Request {
				request := standardRequest()
				request.Intent.Inspection.Preference = PreferenceClip
				return request
			},
			wantRoute: RouteClipAnalysis, wantReason: ReasonClipCapabilityMatched,
		},
		{
			name: "hybrid analysis",
			request: func() Request {
				request := standardRequest()
				request.Intent.Inspection.Preference = PreferenceHybrid
				return request
			},
			wantRoute: RouteHybridAnalysis, wantReason: ReasonHybridCapabilitiesMatched,
		},
		{
			name: "unsupported without authority",
			request: func() Request {
				request := standardRequest()
				request.Intent.Inspection.Preference = PreferenceSnapshot
				request.Authorities = authorities(AuthorityDeviceRead)
				return request
			},
			wantRoute: RouteUnsupported, wantReason: ReasonAuthorityUnavailable,
			check: func(t *testing.T, resolution Resolution) {
				t.Helper()
				if !reflect.DeepEqual(resolution.MissingAuthorities, []AuthorityClass{AuthorityInspectionExecution}) {
					t.Fatalf("missing authorities = %v", resolution.MissingAuthorities)
				}
			},
		},
		{
			name: "clarification for ambiguous source",
			request: func() Request {
				request := standardRequest()
				request.Intent.Inspection.Source = SourceSelector{Alias: "就餐区"}
				first := sourceFact()
				first.Summary.Alias = "就餐区"
				second := sourceFact()
				second.Summary.SourceHandle = "source-west"
				second.Summary.Alias = "就餐区"
				second.Summary.ZoneID = "zone-west"
				request.Sources = []SourceFact{first, second}
				return request
			},
			wantRoute: RouteClarificationRequired, wantReason: ReasonSourceAmbiguous,
		},
		{
			name: "connection workflow without catalog",
			request: func() Request {
				request := standardRequest()
				request.Sources = nil
				request.Tasks = nil
				return request
			},
			wantRoute: RouteConnectionWorkflow, wantReason: ReasonSourceCatalogEmpty,
			check: func(t *testing.T, resolution Resolution) {
				t.Helper()
				if resolution.ConnectionWorkflow == nil || !resolution.ConnectionWorkflow.RequiresSecureLocalInput {
					t.Fatal("connection workflow did not require secure local input")
				}
			},
		},
		{
			name:      "persistent change proposal",
			request:   persistentRequest,
			wantRoute: RoutePersistentChangeProposal, wantReason: ReasonPersistentChangeNeedsProposal,
			check: func(t *testing.T, resolution Resolution) {
				t.Helper()
				proposal := resolution.PersistentChangeProposal
				if proposal == nil || !proposal.HandoffOnly || !proposal.RequiresConfirmation {
					t.Fatal("persistent change was not reduced to a confirmed handoff proposal")
				}
			},
		},
	}

	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			resolver := fixedResolver(t)
			resolution, err := resolver.Resolve(test.request())
			if err != nil {
				t.Fatal(err)
			}
			if resolution.Route != test.wantRoute || resolution.Reason != test.wantReason {
				t.Fatalf("route/reason = %s/%s, want %s/%s", resolution.Route, resolution.Reason, test.wantRoute, test.wantReason)
			}
			if err := resolution.Validate(); err != nil {
				t.Fatalf("resolution does not validate: %v", err)
			}
			if test.check != nil {
				test.check(t, resolution)
			}
		})
	}
}

func TestTemporaryVisualIntentIsNormalizedBeforeRouting(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name       string
		timeScope  temporary.TimeScope
		preference RoutePreference
		taskHandle string
		wantRoute  Route
	}{
		{name: "current snapshot", timeScope: temporary.TimeScope{Kind: temporary.TimeScopeCurrent}, preference: PreferenceAuto, wantRoute: RouteSnapshotAnalysis},
		{name: "recent clip", timeScope: temporary.TimeScope{Kind: temporary.TimeScopeRecentWindow, WindowSeconds: 120}, preference: PreferenceAuto, wantRoute: RouteClipAnalysis},
		{name: "current hybrid", timeScope: temporary.TimeScope{Kind: temporary.TimeScopeCurrent}, preference: PreferenceHybrid, taskHandle: "task-hygiene", wantRoute: RouteHybridAnalysis},
	}
	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			request := temporaryRequest(test.timeScope)
			request.Intent.Inspection.Preference = test.preference
			request.Intent.Inspection.TaskHandle = test.taskHandle
			resolution, err := fixedResolver(t).Resolve(request)
			if err != nil {
				t.Fatal(err)
			}
			if resolution.Route != test.wantRoute {
				t.Fatalf("route = %s, want %s", resolution.Route, test.wantRoute)
			}
			if resolution.TemporaryObservationSpec == nil {
				t.Fatal("successful temporary route has no normalized observation spec")
			}
			if err := resolution.TemporaryObservationSpec.Validate(); err != nil {
				t.Fatalf("temporary spec is invalid: %v", err)
			}
			if resolution.TemporaryObservationSpec.Observable != "桌面是否有明显餐后残留" {
				t.Fatalf("normalized observable = %q", resolution.TemporaryObservationSpec.Observable)
			}
		})
	}
}

func TestExplicitConnectionAlwaysReturnsSecureLocalWorkflow(t *testing.T) {
	t.Parallel()
	request := standardRequest()
	request.Intent = BusinessIntent{
		Goal:       GoalConnect,
		Connection: &ConnectionIntent{Purpose: ConnectionPurposeRefresh},
	}
	resolution, err := fixedResolver(t).Resolve(request)
	if err != nil {
		t.Fatal(err)
	}
	if resolution.Route != RouteConnectionWorkflow || resolution.Reason != ReasonExplicitConnectionRequested ||
		resolution.ConnectionWorkflow == nil || resolution.ConnectionWorkflow.Purpose != ConnectionPurposeRefresh {
		t.Fatalf("unexpected explicit connection resolution: %+v", resolution)
	}
}

func TestEveryPersistentChangeKindStopsAtProposalHandoff(t *testing.T) {
	t.Parallel()
	tests := []PersistentChangeIntent{
		{Kind: ChangeSourceCreate},
		{Kind: ChangeSourceUpdate, SourceHandle: "source-east", ExpectedSourceRevision: 7},
		{Kind: ChangeSourceDelete, SourceHandle: "source-east", ExpectedSourceRevision: 7},
		{Kind: ChangeTaskDeploy, SourceHandle: "source-east", ExpectedSourceRevision: 7, ObservableCode: "hygiene"},
		{Kind: ChangeTaskUpdate, SourceHandle: "source-east", TaskHandle: "task-hygiene", ObservableCode: "hygiene", ExpectedSourceRevision: 7, ExpectedTaskRevision: 3},
		{Kind: ChangeTaskEnable, SourceHandle: "source-east", TaskHandle: "task-hygiene", ExpectedSourceRevision: 7, ExpectedTaskRevision: 3},
		{Kind: ChangeTaskDisable, SourceHandle: "source-east", TaskHandle: "task-hygiene", ExpectedSourceRevision: 7, ExpectedTaskRevision: 3},
		{Kind: ChangeDeviceScheduleUpdate, SourceHandle: "source-east", TaskHandle: "task-hygiene", ExpectedSourceRevision: 7, ExpectedTaskRevision: 3},
	}
	for _, intent := range tests {
		intent := intent
		t.Run(string(intent.Kind), func(t *testing.T) {
			t.Parallel()
			request := standardRequest()
			request.Intent = BusinessIntent{Goal: GoalPersistentChange, PersistentChange: &intent}
			resolution, err := fixedResolver(t).Resolve(request)
			if err != nil {
				t.Fatal(err)
			}
			proposal := resolution.PersistentChangeProposal
			if resolution.Route != RoutePersistentChangeProposal || proposal == nil || proposal.Kind != intent.Kind ||
				!proposal.HandoffOnly || !proposal.RequiresConfirmation {
				t.Fatalf("persistent change escaped proposal handoff: %+v", resolution)
			}
		})
	}
}

func TestResolveFailsClosedAcrossAuthenticatedScope(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name   string
		mutate func(*Request)
	}{
		{name: "source tenant", mutate: func(request *Request) { request.Sources[0].TenantID = "tenant-other" }},
		{name: "source site", mutate: func(request *Request) { request.Sources[0].SiteID = "site-other" }},
		{name: "task tenant", mutate: func(request *Request) { request.Tasks[0].TenantID = "tenant-other" }},
		{name: "task site", mutate: func(request *Request) { request.Tasks[0].SiteID = "site-other" }},
		{name: "authority tenant", mutate: func(request *Request) { request.Authorities[0].TenantID = "tenant-other" }},
		{name: "authority site", mutate: func(request *Request) { request.Authorities[0].SiteID = "site-other" }},
		{name: "authority principal", mutate: func(request *Request) { request.Authorities[0].PrincipalSHA256 = strings.Repeat("b", 64) }},
	}
	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			request := standardRequest()
			test.mutate(&request)
			_, err := fixedResolver(t).Resolve(request)
			if !errors.Is(err, ErrScopeMismatch) {
				t.Fatalf("error = %v, want scope mismatch", err)
			}
		})
	}
}

func TestAuthoritySelectionIsExactScopedAndFresh(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name        string
		authorities func() []AuthorityAvailability
		wantRoute   Route
		wantMissing []AuthorityClass
	}{
		{
			name:        "site wide inspection authority",
			authorities: func() []AuthorityAvailability { return authorities(AuthorityInspectionExecution) },
			wantRoute:   RouteSnapshotAnalysis,
		},
		{
			name: "source scoped inspection authority",
			authorities: func() []AuthorityAvailability {
				values := authorities(AuthorityInspectionExecution)
				values[0].SourceHandles = []string{"source-east"}
				return values
			},
			wantRoute: RouteSnapshotAnalysis,
		},
		{
			name: "wrong source scope",
			authorities: func() []AuthorityAvailability {
				values := authorities(AuthorityInspectionExecution)
				values[0].SourceHandles = []string{"source-west"}
				return values
			},
			wantRoute: RouteUnsupported, wantMissing: []AuthorityClass{AuthorityInspectionExecution},
		},
		{
			name: "expired authority",
			authorities: func() []AuthorityAvailability {
				values := authorities(AuthorityInspectionExecution)
				values[0].ExpiresAt = testNow
				return values
			},
			wantRoute: RouteUnsupported, wantMissing: []AuthorityClass{AuthorityInspectionExecution},
		},
		{
			name:        "service authority cannot substitute",
			authorities: func() []AuthorityAvailability { return authorities(AuthorityServiceExecution) },
			wantRoute:   RouteUnsupported, wantMissing: []AuthorityClass{AuthorityInspectionExecution},
		},
	}

	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			request := standardRequest()
			request.Intent.Inspection.Preference = PreferenceSnapshot
			request.Authorities = test.authorities()
			resolution, err := fixedResolver(t).Resolve(request)
			if err != nil {
				t.Fatal(err)
			}
			if resolution.Route != test.wantRoute || !equalAuthorities(resolution.MissingAuthorities, test.wantMissing) {
				t.Fatalf("route/missing = %s/%v, want %s/%v", resolution.Route, resolution.MissingAuthorities, test.wantRoute, test.wantMissing)
			}
		})
	}
}

func TestAmbiguousStaleAndDriftFactsRequireClarification(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name       string
		mutate     func(*Request)
		wantReason ReasonCode
	}{
		{
			name: "ambiguous task",
			mutate: func(request *Request) {
				other := taskFact()
				other.TaskHandle = "task-hygiene-2"
				request.Tasks = append(request.Tasks, other)
			},
			wantReason: ReasonTaskAmbiguous,
		},
		{name: "stale source", mutate: func(request *Request) { request.Sources[0].ExpiresAt = testNow }, wantReason: ReasonSourceStale},
		{name: "changed source revision", mutate: func(request *Request) { request.Intent.Inspection.Source.ExpectedRevision = 99 }, wantReason: ReasonSourceRevisionChanged},
		{name: "source identity drift", mutate: func(request *Request) { request.Sources[0].Summary.State = catalog.StateIdentityDrift }, wantReason: ReasonSourceIdentityDrift},
		{name: "disabled source", mutate: func(request *Request) { request.Sources[0].Summary.State = catalog.StateDisabled }, wantReason: ReasonSourceDisabled},
		{name: "stale task", mutate: func(request *Request) { request.Tasks[0].ExpiresAt = testNow }, wantReason: ReasonTaskStale},
		{name: "task source revision drift", mutate: func(request *Request) { request.Tasks[0].SourceRevision = 99 }, wantReason: ReasonTaskSourceDrift},
		{name: "task result schema drift", mutate: func(request *Request) { request.Tasks[0].ResultSchema = "inspection.other.v2" }, wantReason: ReasonTaskSourceDrift},
		{name: "task identity drift", mutate: func(request *Request) { request.Tasks[0].State = catalog.StateIdentityDrift }, wantReason: ReasonTaskIdentityDrift},
		{name: "disabled task", mutate: func(request *Request) { request.Tasks[0].State = catalog.StateDisabled }, wantReason: ReasonTaskDisabled},
	}

	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			request := standardRequest()
			test.mutate(&request)
			resolution, err := fixedResolver(t).Resolve(request)
			if err != nil {
				t.Fatal(err)
			}
			if resolution.Route != RouteClarificationRequired || resolution.Reason != test.wantReason {
				t.Fatalf("route/reason = %s/%s, want clarification/%s", resolution.Route, resolution.Reason, test.wantReason)
			}
		})
	}
}

func TestMissingCapabilityIsUnsupported(t *testing.T) {
	t.Parallel()
	request := standardRequest()
	request.Intent.Inspection.Preference = PreferenceSnapshot
	request.Sources[0].Summary.Capabilities = []catalog.CapabilitySummary{
		request.Sources[0].Summary.Capabilities[0],
		request.Sources[0].Summary.Capabilities[2],
	}
	resolution, err := fixedResolver(t).Resolve(request)
	if err != nil {
		t.Fatal(err)
	}
	if resolution.Route != RouteUnsupported || resolution.Reason != ReasonCapabilityUnavailable {
		t.Fatalf("route/reason = %s/%s", resolution.Route, resolution.Reason)
	}
}

func TestResolverIsSafeForConcurrentUse(t *testing.T) {
	resolver := fixedResolver(t)
	const workers = 24
	const iterations = 50
	var wait sync.WaitGroup
	errorsFound := make(chan error, workers)
	for worker := 0; worker < workers; worker++ {
		wait.Add(1)
		go func() {
			defer wait.Done()
			for iteration := 0; iteration < iterations; iteration++ {
				resolution, err := resolver.Resolve(standardRequest())
				if err != nil {
					errorsFound <- err
					return
				}
				if resolution.Route != RouteExistingTaskRead {
					errorsFound <- errors.New("concurrent resolver selected an unexpected route")
					return
				}
			}
		}()
	}
	wait.Wait()
	close(errorsFound)
	for err := range errorsFound {
		t.Fatal(err)
	}
}

func fixedResolver(t *testing.T) *Resolver {
	t.Helper()
	resolver, err := NewWithClock(func() time.Time { return testNow })
	if err != nil {
		t.Fatal(err)
	}
	return resolver
}

func standardRequest() Request {
	timeScope := temporary.TimeScope{Kind: temporary.TimeScopeCurrent}
	return Request{
		Schema: RequestSchemaVersion,
		Scope: AuthenticatedScope{
			TenantID: "tenant-a", SiteID: "site-a", Channel: ChannelWorkBuddyWeChat,
			PrincipalSHA256: strings.Repeat("a", 64),
		},
		Intent: BusinessIntent{
			Goal: GoalInspect,
			Inspection: &InspectionIntent{
				Mode:           InspectionModeStandard,
				Source:         SourceSelector{SourceHandle: "source-east", ExpectedRevision: 7},
				ObservableCode: "hygiene", StandardTimeScope: &timeScope, Preference: PreferenceAuto,
			},
		},
		Sources:     []SourceFact{sourceFact()},
		Tasks:       []InstalledTaskFact{taskFact()},
		Authorities: authorities(AuthorityConnectionProfileWrite, AuthorityDeviceRead, AuthorityInspectionExecution, AuthorityPersistentDeviceWrite),
	}
}

func temporaryRequest(timeScope temporary.TimeScope) Request {
	request := standardRequest()
	request.Intent.Inspection = &InspectionIntent{
		Mode:       InspectionModeTemporaryVisual,
		Source:     SourceSelector{SourceHandle: "source-east", ExpectedRevision: 7},
		Preference: PreferenceAuto,
		TemporaryIntent: &temporary.Intent{
			Subject: "就餐区", Region: "东侧", Observable: "  桌面是否有明显餐后残留  ", Locale: "zh-CN",
			TimeScope: timeScope, EvidenceTTLSeconds: 600,
		},
	}
	return request
}

func persistentRequest() Request {
	request := standardRequest()
	request.Intent = BusinessIntent{
		Goal: GoalPersistentChange,
		PersistentChange: &PersistentChangeIntent{
			Kind: ChangeTaskEnable, SourceHandle: "source-east", TaskHandle: "task-hygiene",
			ExpectedSourceRevision: 7, ExpectedTaskRevision: 3,
		},
	}
	return request
}

func sourceFact() SourceFact {
	return SourceFact{
		TenantID: "tenant-a", SiteID: "site-a", ObservedAt: testNow.Add(-time.Minute), ExpiresAt: testNow.Add(5 * time.Minute),
		Summary: catalog.BusinessSummary{
			SourceHandle: "source-east", Kind: inspection.SourceCamera, Alias: "东侧就餐区", ZoneID: "zone-east",
			State: catalog.StateActive, Revision: 7,
			Capabilities: []catalog.CapabilitySummary{
				{Ref: "cap.clip", Kind: catalog.CapabilityClip, MediaKinds: []inspection.MediaKind{inspection.MediaVideoClip}},
				{Ref: "cap.snapshot", Kind: catalog.CapabilitySnapshot, MediaKinds: []inspection.MediaKind{inspection.MediaImage}},
				{Ref: "cap.task", Kind: catalog.CapabilityTaskEvidence, MediaKinds: []inspection.MediaKind{inspection.MediaDetection, inspection.MediaEvent}, ResultSchema: "inspection.hygiene.v2"},
			},
		},
	}
}

func taskFact() InstalledTaskFact {
	return InstalledTaskFact{
		TenantID: "tenant-a", SiteID: "site-a", TaskHandle: "task-hygiene", SourceHandle: "source-east",
		SourceRevision: 7, CapabilityRef: "cap.task", Revision: 3, State: catalog.StateActive,
		ObservableCodes: []string{"hygiene", "occupancy"}, ResultSchema: "inspection.hygiene.v2",
		ObservedAt: testNow.Add(-time.Minute), ExpiresAt: testNow.Add(5 * time.Minute),
	}
}

func authorities(classes ...AuthorityClass) []AuthorityAvailability {
	result := make([]AuthorityAvailability, 0, len(classes))
	for _, class := range classes {
		result = append(result, AuthorityAvailability{
			Class: class, TenantID: "tenant-a", SiteID: "site-a", PrincipalSHA256: strings.Repeat("a", 64),
			VerifiedAt: testNow.Add(-time.Minute), ExpiresAt: testNow.Add(5 * time.Minute),
		})
	}
	return result
}
