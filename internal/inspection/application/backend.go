// Package application owns the trusted boundary between a channel session and
// the protected Inspection v2 runtime. It deliberately exposes only the
// business-facing httpapi.Backend contract.
package application

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"regexp"
	"sort"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/cosmo-wander-ai/cosmoedge-connect/internal/inspection"
	inspectionauthority "github.com/cosmo-wander-ai/cosmoedge-connect/internal/inspection/authority"
	"github.com/cosmo-wander-ai/cosmoedge-connect/internal/inspection/delivery"
	"github.com/cosmo-wander-ai/cosmoedge-connect/internal/inspection/httpapi"
	"github.com/cosmo-wander-ai/cosmoedge-connect/internal/inspection/inputguard"
	"github.com/cosmo-wander-ai/cosmoedge-connect/internal/inspection/media"
	"github.com/cosmo-wander-ai/cosmoedge-connect/internal/inspection/mediaprep"
	inspectionstore "github.com/cosmo-wander-ai/cosmoedge-connect/internal/inspection/store"
	"github.com/cosmo-wander-ai/cosmoedge-connect/internal/inspection/temporary"
)

const (
	defaultMediaCapabilityTTL = 15 * time.Minute
	maximumMediaCapabilityTTL = 24 * time.Hour
	maximumProjectionItems    = 10_000
)

var (
	publicRefPattern        = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$`)
	audienceRefPattern      = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$`)
	protectedText           = regexp.MustCompile(`(?i)(?:https?|rtsps?|file|data):|(?:password|credential|secret|token|authorization|cookie|endpoint|device[_ -]?id|camera[_ -]?id|source[_ -]?handle|prompt|model[_ -]?output)`)
	temporaryPrepRefPattern = regexp.MustCompile(`^media_prep_[0-9a-f]{32}$`)
)

// CapabilityQuery returns only channel-safe business descriptions. Device,
// source, task, prompt and model details do not cross this interface.
type CapabilityQuery interface {
	QueryCapabilities(context.Context, httpapi.SessionBinding) (httpapi.CapabilitySet, error)
}

// TemporaryPreParsedIntent carries structured semantic fields for a temporary
// visual observation that has already been parsed by an external agent (e.g.,
// WorkBuddy). Carried through PlanningRequest without importing the planning
// package to avoid a circular dependency.
type TemporaryPreParsedIntent struct {
	Subject    string
	Region     string
	Observable string
}

// PlanningRequest gives a trusted planner an authenticated scope, the user's
// open-ended request and a stable application-owned request identity. A
// planner must use RequestedAt and RequestID in the frozen submission so a
// crash replay has exactly the same runtime idempotency identity.
type PlanningRequest struct {
	Session            httpapi.SessionBinding
	Request            httpapi.InspectionRequest
	RequestID          string
	RequestedAt        time.Time
	PreParsedTemporary *TemporaryPreParsedIntent
}

// PlanningDecision is a closed union: local interaction, a complete
// temporary decision, or all three standard execution values.
type PlanningDecision struct {
	Template    inspection.InspectionTemplate
	Assignment  inspection.Assignment
	Submission  inspectionauthority.Submission
	Temporary   *TemporaryDecision
	Interaction *httpapi.InteractionRequired
}

type RequestPlanner interface {
	Plan(context.Context, PlanningRequest) (PlanningDecision, error)
}

type Runner interface {
	Submit(context.Context, inspection.InspectionTemplate, inspection.Assignment, inspectionauthority.Submission) (inspection.Run, bool, error)
}

type TemporaryRunner interface {
	Submit(context.Context, temporary.Submission) (temporary.Record, bool, error)
}

// TemporaryMediaRegistrar can only durably register an already-frozen
// preparation. Planning has no access to this port.
type TemporaryMediaRegistrar interface {
	Prepare(context.Context, mediaprep.FrozenRequest) (mediaprep.Status, bool, error)
}

type TemporaryRepository interface {
	Get(context.Context, string) (temporary.Record, error)
}

type Repository interface {
	GetRun(context.Context, string) (inspection.Run, error)
	GetPlan(context.Context, string) (inspection.ExecutionPlan, error)
	GetOutcome(context.Context, string) (inspection.Outcome, bool, error)
	ListObservations(context.Context, string) ([]inspection.Observation, error)
}

type InstalledTaskValidator interface {
	ValidateInstalledTask(context.Context, string, string, inspection.InstalledTaskBinding) error
}

// MediaReader is intentionally the narrow read-only shape implemented by the
// Inspection v2 media store. No storage root or native locator is available.
type MediaReader interface {
	Describe(string) (media.Descriptor, error)
	Open(context.Context, string) (media.Descriptor, io.ReadCloser, error)
}

// ProjectionInput contains only trusted business names and typed results. It
// excludes prompts, sources, endpoints, credentials, adapter/model metadata,
// integrity metadata and raw model output.
type ProjectionInput struct {
	OverallAssessment inspection.Assessment
	Coverage          inspection.Coverage
	CompletedAt       time.Time
	Findings          []ProjectionFindingInput
}

type ProjectionFindingInput struct {
	TargetTitle    string
	CriterionTitle string
	Assessment     inspection.Assessment
	Values         []ProjectionValue
	Evidence       []ProjectionEvidence
}

// ProjectionValue is the display-safe subset of the typed result union. In
// particular it has no evidence reference, scene timestamp, analyzer output,
// model identity or source binding.
type ProjectionValue struct {
	Kind        inspection.ResultKind
	Label       string
	Number      float64
	Integer     int64
	Boolean     *bool
	Unit        string
	Fields      []ProjectionField
	ObjectCount int
	EventState  inspection.EventState
}

type ProjectionField struct {
	Name    string
	Kind    inspection.StructuredScalarKind
	Text    string
	Number  float64
	Integer int64
	Boolean *bool
}

type ProjectionEvidence struct {
	InternalMediaRef string
	ExpectedSHA256   string
	Title            string
}

type Projection struct {
	Summary     string
	Sections    []ProjectedSection
	Limitations []string
}

type ProjectedSection struct {
	Title      string
	Conclusion string
	Details    []string
	Evidence   []ProjectionEvidence
}

// ResultProjector converts a deliberately sanitized typed view into business
// language. Backend validates the returned text again before publication.
type ResultProjector interface {
	Project(context.Context, ProjectionInput) (Projection, error)
}

type IDSource func(prefix string) (string, error)

type Config struct {
	Capabilities        CapabilityQuery
	Planner             RequestPlanner
	Runner              Runner
	Repository          Repository
	TemporaryRunner     TemporaryRunner
	TemporaryRepository TemporaryRepository
	TemporaryMedia      TemporaryMediaRegistrar
	InstalledTasks      InstalledTaskValidator
	Projector           ResultProjector
	Media               MediaReader
	State               *StateStore
	Now                 func() time.Time
	NewID               IDSource
	MediaCapabilityTTL  time.Duration
	MediaAudience       string
}

type Backend struct {
	capabilities        CapabilityQuery
	planner             RequestPlanner
	runner              Runner
	repository          Repository
	temporaryRunner     TemporaryRunner
	temporaryRepository TemporaryRepository
	temporaryMedia      TemporaryMediaRegistrar
	tasks               InstalledTaskValidator
	projector           ResultProjector
	media               MediaReader
	state               *StateStore
	now                 func() time.Time
	newID               IDSource
	mediaTTL            time.Duration
	mediaAudience       string
}

func New(config Config) (*Backend, error) {
	if config.Capabilities == nil || config.Planner == nil || config.Runner == nil || config.Repository == nil ||
		config.TemporaryRunner == nil || config.TemporaryRepository == nil || config.TemporaryMedia == nil ||
		config.InstalledTasks == nil || config.Projector == nil || config.Media == nil || config.State == nil {
		return nil, errors.New("complete inspection application dependencies are required")
	}
	if config.Now == nil {
		config.Now = time.Now
	}
	if config.NewID == nil {
		config.NewID = randomID
	}
	if config.MediaCapabilityTTL == 0 {
		config.MediaCapabilityTTL = defaultMediaCapabilityTTL
	}
	if config.MediaCapabilityTTL <= 0 || config.MediaCapabilityTTL > maximumMediaCapabilityTTL {
		return nil, errors.New("inspection media capability lifetime is invalid")
	}
	if !validRef(config.MediaAudience) {
		return nil, errors.New("inspection media delivery audience is required")
	}
	return &Backend{
		capabilities: config.Capabilities, planner: config.Planner, runner: config.Runner,
		repository: config.Repository, tasks: config.InstalledTasks, projector: config.Projector,
		temporaryRunner: config.TemporaryRunner, temporaryRepository: config.TemporaryRepository, temporaryMedia: config.TemporaryMedia,
		media: config.Media, state: config.State, now: config.Now, newID: config.NewID,
		mediaTTL: config.MediaCapabilityTTL, mediaAudience: config.MediaAudience,
	}, nil
}

func (b *Backend) QueryCapabilities(ctx context.Context, session httpapi.SessionBinding) (httpapi.CapabilitySet, error) {
	if err := validateSession(session); err != nil {
		return httpapi.CapabilitySet{}, httpapi.ErrForbidden
	}
	result, err := b.capabilities.QueryCapabilities(ctx, session)
	if err != nil {
		return httpapi.CapabilitySet{}, err
	}
	if err := validateCapabilitySet(result); err != nil {
		return httpapi.CapabilitySet{}, fmt.Errorf("unsafe inspection capability projection: %w", err)
	}
	return cloneCapabilitySet(result), nil
}

func (b *Backend) ResolveContinuation(ctx context.Context, session httpapi.SessionBinding) (httpapi.ContinuationResolution, error) {
	if err := validateSession(session); err != nil {
		return httpapi.ContinuationResolution{}, httpapi.ErrForbidden
	}
	type eligible struct {
		record ContinuationRecord
		run    httpapi.RunView
	}
	values := make([]eligible, 0, 5)
	var after *ContinuationRecord
	for len(values) < 5 {
		records, err := b.state.ListContinuationCandidates(ctx, session, after, 5)
		if err != nil {
			return httpapi.ContinuationResolution{}, err
		}
		for _, record := range records {
			run, err := b.GetRun(ctx, session, record.PublicRunRef)
			if errors.Is(err, httpapi.ErrNotFound) {
				continue
			}
			if err != nil {
				return httpapi.ContinuationResolution{}, err
			}
			if run.Status == httpapi.RunAccepted || run.Status == httpapi.RunWorking || run.Status == httpapi.RunReady {
				values = append(values, eligible{record: record, run: run})
				if len(values) == 5 {
					break
				}
			}
		}
		if len(records) < 5 {
			break
		}
		after = &records[len(records)-1]
	}
	if len(values) == 0 {
		return httpapi.ContinuationResolution{Status: httpapi.ContinuationNone}, nil
	}
	if len(values) == 1 {
		run := values[0].run
		return httpapi.ContinuationResolution{Status: httpapi.ContinuationResolved, Run: &run}, nil
	}
	count := len(values)
	if count > 4 {
		count = 4
	}
	candidates := make([]httpapi.ContinuationCandidate, count)
	for index := 0; index < count; index++ {
		candidates[index] = httpapi.ContinuationCandidate{
			RunRef:    values[index].record.PublicRunRef,
			Area:      continuationDescription(continuationArea(values[index].record.Request.Context), 256),
			Goal:      continuationDescription(values[index].record.Request.Instruction, 512),
			StartedAt: values[index].record.CreatedAt,
		}
	}
	return httpapi.ContinuationResolution{Status: httpapi.ContinuationAmbiguous, Candidates: candidates}, nil
}

func continuationDescription(value string, maximum int) string {
	value = strings.ReplaceAll(value, "\t", " ")
	if len(value) <= maximum {
		return value
	}
	end := maximum - len("…")
	for !utf8.RuneStart(value[end]) {
		end--
	}
	return strings.TrimSpace(value[:end]) + "…"
}

func continuationArea(context []httpapi.BusinessContext) string {
	for _, item := range context {
		name := strings.ToLower(item.Name)
		if strings.Contains(name, "区域") || strings.Contains(name, "位置") || name == "area" || name == "region" {
			return item.Value
		}
	}
	return "当前站点"
}

// BuildDeliveryMessage is the non-HTTP terminal-outbox bridge. The worker
// supplies only an internal run identity; this method resolves the one bound
// audience, reuses the safe public result projection and emits only public
// run/result/media references.
func (b *Backend) BuildDeliveryMessage(ctx context.Context, internalRunID string) (delivery.Message, error) {
	if !validRef(internalRunID) {
		return delivery.Message{}, httpapi.ErrNotFound
	}
	now := b.now().UTC()
	if _, err := b.state.PurgeExpired(ctx, now); err != nil {
		return delivery.Message{}, err
	}
	runAudience, err := b.state.ResolveRunAudience(ctx, internalRunID)
	if err != nil {
		return delivery.Message{}, mapStateNotFound(err)
	}
	session := httpapi.SessionBinding{
		TenantID: runAudience.Audience.TenantID, SiteID: runAudience.Audience.SiteID,
		Channel: runAudience.Audience.Channel, ConversationRef: runAudience.Audience.ConversationRef,
		RecipientRef: runAudience.Audience.RecipientRef, PrincipalSHA256: runAudience.PrincipalSHA256,
	}
	result, err := b.GetResult(ctx, session, runAudience.PublicRunRef)
	if err != nil {
		return delivery.Message{}, err
	}
	attachments := make([]delivery.Attachment, 0)
	for _, section := range result.Sections {
		for _, evidence := range section.Evidence {
			if len(attachments) >= 16 {
				return delivery.Message{}, errors.New("inspection result exceeds the bounded delivery attachment count")
			}
			capability, err := b.state.GetMediaCapability(ctx, session, evidence.MediaRef, now)
			if err != nil {
				return delivery.Message{}, mapStateNotFound(err)
			}
			if capability.InternalRunID != internalRunID || capability.PublicRunRef != runAudience.PublicRunRef || capability.ContentType != evidence.MediaType {
				return delivery.Message{}, errors.New("inspection delivery attachment failed its run and media binding")
			}
			attachments = append(attachments, delivery.Attachment{
				MediaRef: capability.PublicMediaRef, SHA256: capability.SHA256,
				Kind: "image", ExpiresAt: capability.ExpiresAt,
			})
		}
	}
	resultRef, err := delivery.ResultRefForRun(runAudience.PublicRunRef)
	if err != nil {
		return delivery.Message{}, err
	}
	message, err := delivery.NewMessage(
		runAudience.PublicRunRef, resultRef, runAudience.Audience,
		delivery.Presentation{Title: "巡检结果", Summary: result.Summary}, attachments, result.CompletedAt,
	)
	if err != nil {
		return delivery.Message{}, err
	}
	return message, nil
}

func (b *Backend) RequestInspection(ctx context.Context, session httpapi.SessionBinding, request httpapi.InspectionRequest, idempotencyKey string) (httpapi.RunView, bool, error) {
	if validateSession(session) != nil {
		return httpapi.RunView{}, false, httpapi.ErrForbidden
	}
	requestJSON, requestSHA, err := canonicalRequest(request)
	if err != nil || !validRef(idempotencyKey) {
		return httpapi.RunView{}, false, httpapi.ErrInvalid
	}
	now := b.now().UTC()
	if now.IsZero() {
		return httpapi.RunView{}, false, errors.New("inspection application clock returned zero")
	}
	if _, err := b.state.PurgeExpired(ctx, now); err != nil {
		return httpapi.RunView{}, false, err
	}
	record, err := b.state.MatchRequest(ctx, session, idempotencyKey, requestJSON, requestSHA)
	if errors.Is(err, ErrStateNotFound) {
		publicRunRef, idErr := b.newID("run")
		if idErr != nil || !validRef(publicRunRef) {
			return httpapi.RunView{}, false, errors.New("generate inspection public run reference")
		}
		runtimeRequestID, idErr := b.newID("request")
		if idErr != nil || !validRef(runtimeRequestID) {
			return httpapi.RunView{}, false, errors.New("generate inspection runtime request identity")
		}
		record, _, err = b.state.ReserveRequest(ctx, RequestReservation{
			Session: session, IdempotencyKey: idempotencyKey, RequestJSON: requestJSON,
			RequestSHA256: requestSHA, PublicRunRef: publicRunRef, RuntimeRequestID: runtimeRequestID,
			CreatedAt: now,
		})
	}
	if err != nil {
		return httpapi.RunView{}, false, mapStateError(err)
	}
	if record.Resolution == requestInteraction {
		interaction, err := decodeInteraction(record.InteractionJSON)
		if err != nil {
			return httpapi.RunView{}, false, err
		}
		return httpapi.RunView{}, false, &httpapi.InteractionRequiredError{Interaction: interaction}
	}
	if record.Resolution == requestTemporaryPending {
		stored, err := b.state.GetTemporaryDecision(ctx, session, record.PublicRunRef)
		if err != nil {
			return httpapi.RunView{}, false, mapStateError(err)
		}
		return b.submitTemporary(ctx, record, stored.Decision)
	}
	if record.Resolution == requestStandardBound || record.Resolution == requestTemporaryBound {
		view, err := b.GetRun(ctx, session, record.PublicRunRef)
		if err != nil {
			return httpapi.RunView{}, false, err
		}
		return view, false, nil
	}

	var decision PlanningDecision
	var frozenPlan inspection.ExecutionPlan
	storedDecision, storedErr := b.state.GetStandardDecision(ctx, session, record.PublicRunRef)
	if storedErr == nil {
		identity, identityErr := inspectionauthority.ExecutionIdentityForOrigin(storedDecision.RunRequest.Origin, storedDecision.Session.PrincipalSHA256)
		if identityErr != nil {
			return httpapi.RunView{}, false, errors.New("stored inspection execution identity is invalid")
		}
		submission, err := inspectionauthority.NewSubmission(storedDecision.RunRequest, identity)
		if err != nil {
			return httpapi.RunView{}, false, errors.New("stored inspection submission is invalid")
		}
		decision = PlanningDecision{Template: storedDecision.Template, Assignment: storedDecision.Assignment, Submission: submission}
		frozenPlan, err = inspection.CompilePlan(storedDecision.Template, storedDecision.Assignment, storedDecision.RunRequest)
		if err != nil || frozenPlan.PlanSHA256 != storedDecision.PlanSHA256 {
			return httpapi.RunView{}, false, errors.New("stored inspection decision failed its frozen plan binding")
		}
	} else if !errors.Is(storedErr, ErrStateNotFound) {
		return httpapi.RunView{}, false, storedErr
	} else {
		var preParsed *TemporaryPreParsedIntent
		if request.TemporaryIntent != nil {
			preParsed = &TemporaryPreParsedIntent{
				Subject:    request.TemporaryIntent.Subject,
				Region:     request.TemporaryIntent.Region,
				Observable: request.TemporaryIntent.Observable,
			}
		}
		decision, err = b.planner.Plan(ctx, PlanningRequest{
			Session:            session,
			Request:            cloneRequest(request),
			RequestID:          record.RuntimeRequestID,
			RequestedAt:        record.CreatedAt,
			PreParsedTemporary: preParsed,
		})
		if err != nil {
			return httpapi.RunView{}, false, err
		}
		if decision.Interaction != nil {
			if decision.Temporary != nil {
				return httpapi.RunView{}, false, fmt.Errorf("%w: planner returned multiple decision kinds", httpapi.ErrConflict)
			}
			if _, submissionErr := decision.Submission.PlanRequest(); submissionErr == nil {
				return httpapi.RunView{}, false, fmt.Errorf("%w: onboarding decision carried an execution submission", httpapi.ErrConflict)
			}
			if err := validateInteraction(*decision.Interaction); err != nil {
				return httpapi.RunView{}, false, fmt.Errorf("unsafe inspection onboarding handoff: %w", err)
			}
			stored, _, err := b.state.MarkInteraction(ctx, session, record.PublicRunRef, *decision.Interaction, now)
			if err != nil {
				return httpapi.RunView{}, false, mapStateError(err)
			}
			interaction, err := decodeInteraction(stored.InteractionJSON)
			if err != nil {
				return httpapi.RunView{}, false, err
			}
			return httpapi.RunView{}, false, &httpapi.InteractionRequiredError{Interaction: interaction}
		}
		if decision.Temporary != nil {
			if err := validateTemporaryDecision(*decision.Temporary, record.CreatedAt); err != nil {
				return httpapi.RunView{}, false, fmt.Errorf("%w: temporary observation decision is invalid", httpapi.ErrConflict)
			}
			if _, submissionErr := decision.Submission.PlanRequest(); submissionErr == nil {
				return httpapi.RunView{}, false, fmt.Errorf("%w: temporary observation carried a standard execution submission", httpapi.ErrConflict)
			}
			if decision.Template.Schema != "" || decision.Assignment.Schema != "" {
				return httpapi.RunView{}, false, fmt.Errorf("%w: temporary observation carried a standard catalog binding", httpapi.ErrConflict)
			}
			stored, _, err := b.state.FreezeTemporaryDecision(ctx, TemporaryDecisionRecord{
				Session: session, PublicRunRef: record.PublicRunRef, RuntimeRequestID: record.RuntimeRequestID,
				Decision: *decision.Temporary, CreatedAt: record.CreatedAt,
			})
			if err != nil {
				return httpapi.RunView{}, false, mapStateError(err)
			}
			return b.submitTemporary(ctx, record, stored.Decision)
		}
		requestForPlan, err := validateTechnicalDecision(ctx, b.tasks, session, record, decision)
		if err != nil {
			return httpapi.RunView{}, false, err
		}
		plan, err := inspection.CompilePlan(decision.Template, decision.Assignment, requestForPlan)
		if err != nil {
			return httpapi.RunView{}, false, fmt.Errorf("%w: frozen inspection decision is inconsistent", httpapi.ErrConflict)
		}
		if _, _, err := b.state.FreezeStandardDecision(ctx, StandardDecisionRecord{
			Session: session, PublicRunRef: record.PublicRunRef, PlanSHA256: plan.PlanSHA256,
			Template: decision.Template, Assignment: decision.Assignment, RunRequest: requestForPlan, CreatedAt: record.CreatedAt,
		}); err != nil {
			return httpapi.RunView{}, false, mapStateError(err)
		}
		frozenPlan = plan
	}
	run, _, err := b.runner.Submit(ctx, decision.Template, decision.Assignment, decision.Submission)
	if err != nil {
		if errors.Is(err, inspectionstore.ErrConflict) {
			return httpapi.RunView{}, false, httpapi.ErrConflict
		}
		return httpapi.RunView{}, false, err
	}
	if err := validateRunPlanBinding(run, frozenPlan); err != nil {
		return httpapi.RunView{}, false, fmt.Errorf("inspection runtime returned an unbound run: %w", err)
	}
	run, err = b.authoritativeBoundRun(ctx, run.RunID, frozenPlan)
	if err != nil {
		return httpapi.RunView{}, false, err
	}
	bound, changed, err := b.state.BindRun(ctx, session, record.PublicRunRef, run.RunID, b.now().UTC())
	if err != nil {
		return httpapi.RunView{}, false, mapStateError(err)
	}
	if bound.InternalRunID != run.RunID {
		return httpapi.RunView{}, false, errors.New("inspection channel mapping rejected runtime identity")
	}
	return projectRun(bound.PublicRunRef, run), changed, nil
}

func (b *Backend) submitTemporary(ctx context.Context, request RequestRecord, decision TemporaryDecision) (httpapi.RunView, bool, error) {
	submission, err := buildTemporarySubmission(request, decision)
	if err != nil {
		return httpapi.RunView{}, false, fmt.Errorf("%w: frozen temporary decision is invalid", httpapi.ErrConflict)
	}
	preparationRequest, err := decision.PreparationRequest()
	if err != nil {
		return httpapi.RunView{}, false, fmt.Errorf("%w: frozen temporary preparation is invalid", httpapi.ErrConflict)
	}
	status, _, err := b.temporaryMedia.Prepare(ctx, preparationRequest)
	if err != nil {
		return httpapi.RunView{}, false, fmt.Errorf("register frozen temporary media preparation: %w", err)
	}
	if err := validatePreparationRegistration(status, submission.PreparationRef); err != nil {
		return httpapi.RunView{}, false, fmt.Errorf("temporary media registration returned an invalid receipt: %w", err)
	}
	run, _, err := b.temporaryRunner.Submit(ctx, submission)
	if err != nil {
		return httpapi.RunView{}, false, mapTemporaryRuntimeError(err)
	}
	if err := validateTemporaryRunBinding(run, submission); err != nil {
		return httpapi.RunView{}, false, fmt.Errorf("temporary runtime returned an unbound run: %w", err)
	}
	run, err = b.temporaryRepository.Get(ctx, run.RunID)
	if err != nil {
		return httpapi.RunView{}, false, mapTemporaryRuntimeError(err)
	}
	if err := validateTemporaryRunBinding(run, submission); err != nil {
		return httpapi.RunView{}, false, fmt.Errorf("temporary repository returned an unbound run: %w", err)
	}
	bound, changed, err := b.state.BindTemporaryRun(ctx, request.Session, request.PublicRunRef, run.RunID, b.now().UTC())
	if err != nil {
		return httpapi.RunView{}, false, mapStateError(err)
	}
	if bound.InternalRunID != run.RunID {
		return httpapi.RunView{}, false, errors.New("temporary channel mapping rejected runtime identity")
	}
	return projectTemporaryRun(bound.PublicRunRef, run, b.now().UTC()), changed, nil
}

func (b *Backend) GetRun(ctx context.Context, session httpapi.SessionBinding, publicRunRef string) (httpapi.RunView, error) {
	if _, err := b.state.PurgeExpired(ctx, b.now().UTC()); err != nil {
		return httpapi.RunView{}, err
	}
	audienceRun, err := b.state.GetAudienceRun(ctx, session, publicRunRef)
	if err != nil {
		return httpapi.RunView{}, mapStateNotFound(err)
	}
	if audienceRun.RunKind == "temporary" {
		if audienceRun.Origin != string(audienceRunChannel) {
			return httpapi.RunView{}, httpapi.ErrNotFound
		}
		_, run, err := b.getScopedTemporaryRun(ctx, session, publicRunRef)
		if err != nil {
			return httpapi.RunView{}, err
		}
		return projectTemporaryRun(audienceRun.PublicRunRef, run, b.now().UTC()), nil
	}
	_, run, err := b.getScopedStandardRun(ctx, session, publicRunRef)
	if err != nil {
		return httpapi.RunView{}, err
	}
	return projectRun(audienceRun.PublicRunRef, run), nil
}

func (b *Backend) GetResult(ctx context.Context, session httpapi.SessionBinding, publicRunRef string) (httpapi.ResultView, error) {
	if _, err := b.state.PurgeExpired(ctx, b.now().UTC()); err != nil {
		return httpapi.ResultView{}, err
	}
	audienceRun, err := b.state.GetAudienceRun(ctx, session, publicRunRef)
	if err != nil {
		return httpapi.ResultView{}, mapStateNotFound(err)
	}
	if audienceRun.RunKind == "temporary" {
		if audienceRun.Origin != string(audienceRunChannel) {
			return httpapi.ResultView{}, httpapi.ErrNotFound
		}
		record, err := b.state.GetRunMapping(ctx, session, publicRunRef)
		if err != nil {
			return httpapi.ResultView{}, mapStateNotFound(err)
		}
		_, run, err := b.getScopedTemporaryRun(ctx, session, publicRunRef)
		if err != nil {
			return httpapi.ResultView{}, err
		}
		return b.projectTemporaryResult(ctx, session, record, run)
	}
	_, run, err := b.getScopedStandardRun(ctx, session, publicRunRef)
	if err != nil {
		return httpapi.ResultView{}, err
	}
	if !inspection.Terminal(run.State) {
		return httpapi.ResultView{}, httpapi.ErrResultNotReady
	}
	if run.PersistentConfigWrites != 0 {
		return httpapi.ResultView{}, errors.New("inspection run violated its persistent-write invariant")
	}
	plan, err := b.repository.GetPlan(ctx, run.RunID)
	if err != nil {
		return httpapi.ResultView{}, mapRepositoryError(err)
	}
	if plan.TenantID != session.TenantID || plan.SiteID != session.SiteID || plan.PlanSHA256 != run.PlanSHA256 {
		return httpapi.ResultView{}, errors.New("inspection plan failed its scoped run binding")
	}
	outcome, present, err := b.repository.GetOutcome(ctx, run.RunID)
	if err != nil {
		return httpapi.ResultView{}, mapRepositoryError(err)
	}
	if !present || outcome.State != run.State {
		return httpapi.ResultView{}, errors.New("terminal inspection outcome is missing or mismatched")
	}
	observations, err := b.repository.ListObservations(ctx, run.RunID)
	if err != nil {
		return httpapi.ResultView{}, mapRepositoryError(err)
	}
	input, err := sanitizedProjectionInput(run, plan, outcome, observations)
	if err != nil {
		return httpapi.ResultView{}, err
	}
	projection, err := b.projector.Project(ctx, input)
	if err != nil {
		return httpapi.ResultView{}, err
	}
	if err := validateProjection(projection, input); err != nil {
		return httpapi.ResultView{}, fmt.Errorf("unsafe inspection result projection: %w", err)
	}
	view := httpapi.ResultView{
		RunRef: audienceRun.PublicRunRef, Summary: projection.Summary,
		Limitations: append([]string(nil), projection.Limitations...), CompletedAt: run.UpdatedAt.UTC(),
		Sections: make([]httpapi.ResultSection, 0, len(projection.Sections)),
	}
	seenMedia := make(map[string]struct{})
	for _, section := range projection.Sections {
		publicSection := httpapi.ResultSection{
			Title: section.Title, Conclusion: section.Conclusion,
			Details:  append([]string(nil), section.Details...),
			Evidence: make([]httpapi.MediaCapability, 0),
		}
		for _, evidence := range section.Evidence {
			if _, duplicate := seenMedia[evidence.InternalMediaRef]; duplicate {
				continue
			}
			capability, include, err := b.issueMediaCapability(ctx, session, audienceRun.PublicRunRef, run, evidence)
			if err != nil {
				return httpapi.ResultView{}, err
			}
			if include {
				seenMedia[evidence.InternalMediaRef] = struct{}{}
				publicSection.Evidence = append(publicSection.Evidence, capability)
			}
		}
		view.Sections = append(view.Sections, publicSection)
	}
	return view, nil
}

func (b *Backend) GetMedia(ctx context.Context, session httpapi.SessionBinding, publicMediaRef string) (httpapi.MediaPayload, error) {
	if validateSession(session) != nil || !validRef(publicMediaRef) {
		return httpapi.MediaPayload{}, httpapi.ErrNotFound
	}
	now := b.now().UTC()
	if _, err := b.state.PurgeExpired(ctx, now); err != nil {
		return httpapi.MediaPayload{}, err
	}
	capability, err := b.state.GetMediaCapability(ctx, session, publicMediaRef, now)
	if err != nil {
		return httpapi.MediaPayload{}, mapStateNotFound(err)
	}
	readerDescriptor, reader, err := b.media.Open(ctx, capability.InternalMediaRef)
	if err != nil {
		return httpapi.MediaPayload{}, httpapi.ErrNotFound
	}
	defer reader.Close()
	temporaryAudience, audienceErr := temporary.FreezeAudience(temporary.ChannelSession{
		TenantID: session.TenantID, SiteID: session.SiteID, Channel: session.Channel,
		ConversationRef: session.ConversationRef, RecipientRef: session.RecipientRef,
		PrincipalSHA256: session.PrincipalSHA256,
	})
	if capability.Audience != b.mediaAudience && (audienceErr != nil || capability.Audience != temporaryAudience.Ref) {
		return httpapi.MediaPayload{}, errors.New("inspection media capability audience is invalid")
	}
	if err := validateMediaDescriptor(readerDescriptor, capability, session); err != nil {
		return httpapi.MediaPayload{}, errors.New("inspection media failed its capability binding")
	}
	limited := &io.LimitedReader{R: reader, N: httpapi.MaxMediaBytes + 1}
	raw, err := io.ReadAll(limited)
	if err != nil {
		return httpapi.MediaPayload{}, err
	}
	if len(raw) == 0 || len(raw) > httpapi.MaxMediaBytes || int64(len(raw)) != capability.SizeBytes || !validImageMagic(capability.ContentType, raw) {
		return httpapi.MediaPayload{}, errors.New("inspection media content failed its bounded type and size binding")
	}
	digest := sha256.Sum256(raw)
	actual := hex.EncodeToString(digest[:])
	if actual != capability.SHA256 {
		return httpapi.MediaPayload{}, errors.New("inspection media content failed its integrity binding")
	}
	return httpapi.MediaPayload{ContentType: capability.ContentType, SHA256: actual, Bytes: raw}, nil
}

func (b *Backend) SubmitFeedback(ctx context.Context, session httpapi.SessionBinding, publicRunRef string, request httpapi.FeedbackRequest, idempotencyKey string) (httpapi.FeedbackReceipt, bool, error) {
	if validateSession(session) != nil {
		return httpapi.FeedbackReceipt{}, false, httpapi.ErrForbidden
	}
	if !validRef(publicRunRef) || !validRef(idempotencyKey) || request.Helpful == nil || !validInputText(request.Comment, 0, 1000) || inputguard.ValidateText(request.Comment) != nil {
		return httpapi.FeedbackReceipt{}, false, httpapi.ErrInvalid
	}
	if _, err := b.state.PurgeExpired(ctx, b.now().UTC()); err != nil {
		return httpapi.FeedbackReceipt{}, false, err
	}
	if _, err := b.GetRun(ctx, session, publicRunRef); err != nil {
		return httpapi.FeedbackReceipt{}, false, err
	}
	raw, err := json.Marshal(request)
	if err != nil {
		return httpapi.FeedbackReceipt{}, false, err
	}
	digest := sha256.Sum256(raw)
	created, err := b.state.RecordFeedback(ctx, FeedbackRecord{
		Session: session, PublicRunRef: publicRunRef, IdempotencyKey: idempotencyKey,
		FeedbackJSON: raw, FeedbackSHA256: hex.EncodeToString(digest[:]), CreatedAt: b.now().UTC(),
	})
	if err != nil {
		return httpapi.FeedbackReceipt{}, false, mapStateError(err)
	}
	return httpapi.FeedbackReceipt{Accepted: true}, created, nil
}

func (b *Backend) getScopedStandardRun(ctx context.Context, session httpapi.SessionBinding, publicRunRef string) (AudienceRunRecord, inspection.Run, error) {
	if validateSession(session) != nil || !validRef(publicRunRef) {
		return AudienceRunRecord{}, inspection.Run{}, httpapi.ErrNotFound
	}
	audienceRun, err := b.state.GetAudienceRun(ctx, session, publicRunRef)
	if err != nil {
		return AudienceRunRecord{}, inspection.Run{}, mapStateNotFound(err)
	}
	if audienceRun.RunKind != "standard" || audienceRun.BindingState != "bound" {
		return AudienceRunRecord{}, inspection.Run{}, httpapi.ErrNotFound
	}
	var template inspection.InspectionTemplate
	var assignment inspection.Assignment
	var request inspection.CreateRunRequest
	var planSHA256 string
	if audienceRun.Origin == string(audienceRunSchedule) {
		decision, decisionErr := b.state.GetScheduledDecision(ctx, session, publicRunRef)
		if decisionErr != nil {
			return AudienceRunRecord{}, inspection.Run{}, mapStateNotFound(decisionErr)
		}
		template, assignment, request, planSHA256 = decision.Template, decision.Assignment, decision.RunRequest, decision.PlanSHA256
	} else if audienceRun.Origin == string(audienceRunChannel) {
		decision, decisionErr := b.state.GetStandardDecision(ctx, session, publicRunRef)
		if decisionErr != nil {
			return AudienceRunRecord{}, inspection.Run{}, mapStateNotFound(decisionErr)
		}
		template, assignment, request, planSHA256 = decision.Template, decision.Assignment, decision.RunRequest, decision.PlanSHA256
	} else {
		return AudienceRunRecord{}, inspection.Run{}, httpapi.ErrNotFound
	}
	plan, err := inspection.CompilePlan(template, assignment, request)
	if err != nil || plan.PlanSHA256 != planSHA256 {
		return AudienceRunRecord{}, inspection.Run{}, errors.New("inspection audience mapping has an invalid frozen decision")
	}
	run, err := b.authoritativeBoundRun(ctx, audienceRun.InternalRunID, plan)
	return audienceRun, run, err
}

func (b *Backend) getScopedTemporaryRun(ctx context.Context, session httpapi.SessionBinding, publicRunRef string) (RequestRecord, temporary.Record, error) {
	if validateSession(session) != nil || !validRef(publicRunRef) {
		return RequestRecord{}, temporary.Record{}, httpapi.ErrNotFound
	}
	record, err := b.state.GetRunMapping(ctx, session, publicRunRef)
	if err != nil {
		return RequestRecord{}, temporary.Record{}, mapStateNotFound(err)
	}
	if record.RequestKind != "temporary" || record.Resolution != requestTemporaryBound {
		return RequestRecord{}, temporary.Record{}, httpapi.ErrNotFound
	}
	decision, err := b.state.GetTemporaryDecision(ctx, session, publicRunRef)
	if err != nil {
		return RequestRecord{}, temporary.Record{}, mapStateNotFound(err)
	}
	submission, err := buildTemporarySubmission(record, decision.Decision)
	if err != nil {
		return RequestRecord{}, temporary.Record{}, errors.New("temporary channel mapping has an invalid frozen decision")
	}
	run, err := b.temporaryRepository.Get(ctx, record.InternalRunID)
	if err != nil {
		return RequestRecord{}, temporary.Record{}, mapTemporaryRuntimeError(err)
	}
	if err := validateTemporaryRunBinding(run, submission); err != nil {
		return RequestRecord{}, temporary.Record{}, errors.New("temporary repository run failed its frozen decision binding")
	}
	return record, run, nil
}

func (b *Backend) projectTemporaryResult(ctx context.Context, session httpapi.SessionBinding, request RequestRecord, run temporary.Record) (httpapi.ResultView, error) {
	if !run.State.Terminal() {
		return httpapi.ResultView{}, httpapi.ErrResultNotReady
	}
	view := httpapi.ResultView{
		RunRef: request.PublicRunRef, Sections: []httpapi.ResultSection{}, Limitations: []string{},
		CompletedAt: run.CompletedAt.UTC(),
	}
	now := b.now().UTC()
	switch run.State {
	case temporary.StateSucceeded:
		if run.Observation == nil || !run.Observation.ExpiresAt.After(now) {
			view.Summary = "本次现场查看结果已过期。"
			view.Limitations = append(view.Limitations, "现场画面及观察结果已经超过有效时间。")
			return view, nil
		}
		observation := run.Observation
		if !validPublicText(observation.Summary, 1, 512) || len(observation.VisibleFacts) > 16 || len(observation.Limitations) > 8 {
			return httpapi.ResultView{}, errors.New("temporary observation result is unsafe to publish")
		}
		section := httpapi.ResultSection{
			Title: run.Spec.Region + " · " + run.Spec.Subject, Conclusion: "现场可见情况",
			Details: append([]string{}, observation.VisibleFacts...), Evidence: []httpapi.MediaCapability{},
		}
		if !validPublicText(section.Title, 1, 321) {
			return httpapi.ResultView{}, errors.New("temporary observation title is unsafe to publish")
		}
		for _, text := range append(append([]string(nil), section.Details...), observation.Limitations...) {
			if !validPublicText(text, 1, 256) {
				return httpapi.ResultView{}, errors.New("temporary observation text is unsafe to publish")
			}
		}
		capability, include, err := b.issueTemporaryMediaCapability(ctx, session, request, run)
		if err != nil {
			return httpapi.ResultView{}, err
		}
		if include {
			section.Evidence = append(section.Evidence, capability)
		}
		view.Summary = observation.Summary
		view.Limitations = append(view.Limitations, observation.Limitations...)
		view.Sections = append(view.Sections, section)
		view.Answer = deriveTemporaryAnswer(observation.Summary)
		if view.Answer != "" {
			view.Question = run.Spec.Observable
		}
	case temporary.StateInvalidCandidate:
		view.Summary = "当前画面没有形成可展示的观察结果。"
		view.Limitations = append(view.Limitations, "本次返回内容无法可靠展示。")
	case temporary.StateExpired:
		view.Summary = "本次现场查看已过期。"
		view.Limitations = append(view.Limitations, "未在有效时间内完成查看。")
	case temporary.StateOutcomeUnknown:
		view.Summary = "本次现场查看的执行结果暂时无法确认。"
		view.Limitations = append(view.Limitations, "为避免重复处理，本次不会自动重新执行。")
	case temporary.StateFailed:
		view.Summary = "本次现场查看未能完成。"
		view.Limitations = append(view.Limitations, "当前暂时无法提供观察结果。")
	default:
		return httpapi.ResultView{}, errors.New("temporary observation terminal state is unsupported")
	}
	return view, nil
}

// deriveTemporaryAnswer maps the fixed observation summary text (set by
// temporaryCandidateJSON in internal/operator/inspectionlive/temporary.go)
// to the closed API answer kind. Returns "" for any unrecognised summary,
// which leaves Answer/Question empty and triggers the safe regex-fallback
// path in the Python client.
func deriveTemporaryAnswer(summary string) string {
	switch summary {
	case "本次现场查看得到肯定结果":
		return "yes"
	case "本次现场查看暂未得到肯定结果":
		return "no"
	case "当前画面暂时无法判断":
		return "unable"
	default:
		return ""
	}
}

func (b *Backend) authoritativeBoundRun(ctx context.Context, runID string, expected inspection.ExecutionPlan) (inspection.Run, error) {
	run, err := b.repository.GetRun(ctx, runID)
	if err != nil {
		return inspection.Run{}, mapRepositoryError(err)
	}
	if err := validateRunPlanBinding(run, expected); err != nil {
		return inspection.Run{}, errors.New("inspection repository run failed its frozen decision binding")
	}
	storedPlan, err := b.repository.GetPlan(ctx, runID)
	if err != nil {
		return inspection.Run{}, mapRepositoryError(err)
	}
	if err := storedPlan.Validate(); err != nil || storedPlan.PlanSHA256 != expected.PlanSHA256 ||
		storedPlan.RequestKey != expected.RequestKey || storedPlan.TenantID != expected.TenantID || storedPlan.SiteID != expected.SiteID ||
		storedPlan.RequestID != expected.RequestID || !storedPlan.RequestedAt.Equal(expected.RequestedAt) || !storedPlan.Deadline.Equal(expected.Deadline) {
		return inspection.Run{}, errors.New("inspection repository plan failed its frozen decision binding")
	}
	return run, nil
}

func validateRunPlanBinding(run inspection.Run, plan inspection.ExecutionPlan) error {
	if !validRef(run.RunID) || run.TenantID != plan.TenantID || run.SiteID != plan.SiteID ||
		run.RequestKey != plan.RequestKey || run.PlanSHA256 != plan.PlanSHA256 || !run.Deadline.Equal(plan.Deadline) ||
		run.CreatedAt.IsZero() || run.UpdatedAt.Before(run.CreatedAt) || run.CreatedAt.Before(plan.RequestedAt) {
		return errors.New("run immutable fields do not match the frozen plan")
	}
	return nil
}

func (b *Backend) issueMediaCapability(ctx context.Context, session httpapi.SessionBinding, publicRunRef string, run inspection.Run, evidence ProjectionEvidence) (httpapi.MediaCapability, bool, error) {
	descriptor, err := b.media.Describe(evidence.InternalMediaRef)
	if err != nil {
		return httpapi.MediaCapability{}, false, nil
	}
	if descriptor.Kind != media.KindImage {
		return httpapi.MediaCapability{}, false, nil
	}
	if descriptor.MediaRef != evidence.InternalMediaRef || descriptor.Binding.TenantID != session.TenantID ||
		descriptor.Binding.SiteID != session.SiteID || descriptor.Binding.RunID != run.RunID ||
		descriptor.Integrity.SHA256 != evidence.ExpectedSHA256 || descriptor.Availability != media.AvailabilityAvailable ||
		!validImageContentType(descriptor.Encoding.MIMEType) || descriptor.Integrity.SizeBytes < 1 || descriptor.Integrity.SizeBytes > httpapi.MaxMediaBytes {
		return httpapi.MediaCapability{}, false, errors.New("inspection evidence failed its media descriptor binding")
	}
	if !containsExact(descriptor.Governance.Audience, b.mediaAudience) {
		return httpapi.MediaCapability{}, false, errors.New("inspection evidence is not authorized for the delivery audience")
	}
	now := b.now().UTC()
	expiresAt := now.Add(b.mediaTTL)
	if descriptor.Governance.ExpiresAt.Before(expiresAt) {
		expiresAt = descriptor.Governance.ExpiresAt.UTC()
	}
	if !expiresAt.After(now) {
		return httpapi.MediaCapability{}, false, nil
	}
	publicMediaRef, err := b.newID("media")
	if err != nil || !validRef(publicMediaRef) {
		return httpapi.MediaCapability{}, false, errors.New("generate inspection public media reference")
	}
	capability, err := b.state.EnsureMediaCapability(ctx, MediaCapabilityRecord{
		Session: session, PublicRunRef: publicRunRef, PublicMediaRef: publicMediaRef,
		InternalRunID: run.RunID, MediaBindingRunID: run.RunID, InternalMediaRef: descriptor.MediaRef,
		SHA256: descriptor.Integrity.SHA256, SizeBytes: descriptor.Integrity.SizeBytes,
		ContentType: descriptor.Encoding.MIMEType, Title: evidence.Title, Audience: b.mediaAudience,
		CreatedAt: now, ExpiresAt: expiresAt,
	}, now)
	if err != nil {
		return httpapi.MediaCapability{}, false, mapStateError(err)
	}
	return httpapi.MediaCapability{
		MediaRef: capability.PublicMediaRef, Capability: "inspection.media.deliver",
		MediaType: capability.ContentType, Title: capability.Title,
	}, true, nil
}

func (b *Backend) issueTemporaryMediaCapability(ctx context.Context, session httpapi.SessionBinding, request RequestRecord, run temporary.Record) (httpapi.MediaCapability, bool, error) {
	if run.Media == nil || run.Observation == nil || run.Media.MIMEType == "video/mp4" {
		return httpapi.MediaCapability{}, false, nil
	}
	descriptor, err := b.media.Describe(run.MediaRef)
	if err != nil {
		return httpapi.MediaCapability{}, false, nil
	}
	stepID, stepErr := temporary.MediaStepIDForRun(run.RunID)
	if descriptor.Kind != media.KindImage || descriptor.MediaRef != run.MediaRef ||
		descriptor.Binding.TenantID != session.TenantID || descriptor.Binding.SiteID != session.SiteID ||
		stepErr != nil || descriptor.Binding.RunID != run.RunID || descriptor.Binding.StepID != stepID || descriptor.Binding.Attempt != 1 ||
		descriptor.Integrity.SHA256 != run.Media.SHA256 ||
		descriptor.Integrity.SizeBytes != run.Media.SizeBytes || descriptor.Encoding.MIMEType != run.Media.MIMEType ||
		descriptor.Availability != media.AvailabilityAvailable || !equalMediaTemporal(descriptor.Temporal, run.Media.Temporal) ||
		!descriptor.Governance.ExpiresAt.Equal(run.Media.ExpiresAt) || !validImageContentType(descriptor.Encoding.MIMEType) ||
		descriptor.Integrity.SizeBytes < 1 || descriptor.Integrity.SizeBytes > httpapi.MaxMediaBytes {
		return httpapi.MediaCapability{}, false, errors.New("temporary observation media failed its frozen binding")
	}
	if len(descriptor.Governance.Audience) != 1 || descriptor.Governance.Audience[0] != run.AudienceBindingRef {
		return httpapi.MediaCapability{}, false, errors.New("temporary observation media is not authorized for delivery")
	}
	now := b.now().UTC()
	expiresAt := now.Add(b.mediaTTL)
	for _, candidate := range []time.Time{descriptor.Governance.ExpiresAt, run.Observation.ExpiresAt} {
		if candidate.Before(expiresAt) {
			expiresAt = candidate.UTC()
		}
	}
	if !expiresAt.After(now) {
		return httpapi.MediaCapability{}, false, nil
	}
	publicMediaRef, err := b.newID("media")
	if err != nil || !validRef(publicMediaRef) {
		return httpapi.MediaCapability{}, false, errors.New("generate temporary observation media reference")
	}
	title := run.Spec.Region + "现场快照"
	if !validPublicText(title, 1, 256) {
		return httpapi.MediaCapability{}, false, errors.New("temporary observation media title is unsafe")
	}
	capability, err := b.state.EnsureMediaCapability(ctx, MediaCapabilityRecord{
		Session: session, PublicRunRef: request.PublicRunRef, PublicMediaRef: publicMediaRef,
		InternalRunID: run.RunID, MediaBindingRunID: run.RunID, InternalMediaRef: descriptor.MediaRef,
		SHA256: descriptor.Integrity.SHA256, SizeBytes: descriptor.Integrity.SizeBytes,
		ContentType: descriptor.Encoding.MIMEType, Title: title, Audience: run.AudienceBindingRef,
		CreatedAt: now, ExpiresAt: expiresAt,
	}, now)
	if err != nil {
		return httpapi.MediaCapability{}, false, mapStateError(err)
	}
	return httpapi.MediaCapability{
		MediaRef: capability.PublicMediaRef, Capability: "inspection.media.deliver",
		MediaType: capability.ContentType, Title: capability.Title,
	}, true, nil
}

func validateTechnicalDecision(ctx context.Context, tasks InstalledTaskValidator, session httpapi.SessionBinding, record RequestRecord, decision PlanningDecision) (inspection.CreateRunRequest, error) {
	request, err := decision.Submission.PlanRequest()
	if err != nil {
		return inspection.CreateRunRequest{}, fmt.Errorf("%w: planner did not return a frozen submission", httpapi.ErrConflict)
	}
	if request.TenantID != session.TenantID || request.SiteID != session.SiteID || request.RequestID != record.RuntimeRequestID ||
		!request.RequestedAt.Equal(record.CreatedAt) || (request.Origin != inspection.OriginUser && request.Origin != inspection.OriginAPI) {
		return inspection.CreateRunRequest{}, fmt.Errorf("%w: planner returned a cross-scope or unstable submission", httpapi.ErrConflict)
	}
	identity, err := decision.Submission.ExecutionIdentity()
	wantIdentity, identityErr := inspectionauthority.ExecutionIdentityForOrigin(request.Origin, session.PrincipalSHA256)
	if err != nil || identityErr != nil || identity != wantIdentity || record.Session != session {
		return inspection.CreateRunRequest{}, fmt.Errorf("%w: planner returned an unbound execution identity", httpapi.ErrConflict)
	}
	if err := decision.Template.Validate(); err != nil || decision.Template.State != inspection.TemplatePublished {
		return inspection.CreateRunRequest{}, fmt.Errorf("%w: planner returned an unpublished template", httpapi.ErrConflict)
	}
	if err := decision.Assignment.Validate(); err != nil || !decision.Assignment.Published {
		return inspection.CreateRunRequest{}, fmt.Errorf("%w: planner returned an unpublished assignment", httpapi.ErrConflict)
	}
	if decision.Template.TenantID != session.TenantID || decision.Assignment.TenantID != session.TenantID || decision.Assignment.SiteID != session.SiteID ||
		request.TemplateID != decision.Template.TemplateID || request.TemplateRevision != decision.Template.Revision ||
		request.AssignmentID != decision.Assignment.AssignmentID || request.AssignmentRevision != decision.Assignment.Revision {
		return inspection.CreateRunRequest{}, fmt.Errorf("%w: planner returned inconsistent catalog bindings", httpapi.ErrConflict)
	}
	for _, target := range decision.Assignment.Targets {
		for _, installedTask := range target.InstalledTasks {
			if err := tasks.ValidateInstalledTask(ctx, session.TenantID, session.SiteID, installedTask); err != nil {
				return inspection.CreateRunRequest{}, fmt.Errorf("%w: installed task binding is stale", httpapi.ErrConflict)
			}
		}
	}
	return request, nil
}

func buildTemporarySubmission(request RequestRecord, decision TemporaryDecision) (temporary.Submission, error) {
	if validateSession(request.Session) != nil || !validRef(request.PublicRunRef) || !validRef(request.RuntimeRequestID) ||
		validateTemporaryDecision(decision, request.CreatedAt) != nil {
		return temporary.Submission{}, errors.New("invalid temporary observation binding")
	}
	preparation, err := decision.PreparationRequest()
	if err != nil {
		return temporary.Submission{}, err
	}
	binding := temporary.AuthenticatedBinding{
		TenantID: request.Session.TenantID, SiteID: request.Session.SiteID,
		RequestKey: request.RuntimeRequestID, PublicRunRef: request.PublicRunRef,
		Channel: request.Session.Channel, ConversationRef: request.Session.ConversationRef,
		RecipientRef: request.Session.RecipientRef, PrincipalSHA256: request.Session.PrincipalSHA256,
	}
	audience, err := temporary.FreezeAudience(temporary.ChannelSession{
		TenantID: binding.TenantID, SiteID: binding.SiteID, Channel: binding.Channel,
		ConversationRef: binding.ConversationRef, RecipientRef: binding.RecipientRef,
		PrincipalSHA256: binding.PrincipalSHA256,
	})
	expectedPreparation, preparationErr := mediaprep.PreparationRefForScope(binding.TenantID, binding.SiteID, binding.RequestKey)
	expectedRunID, runErr := temporary.RunIDForScope(binding.TenantID, binding.SiteID, binding.RequestKey)
	expectedStepID, stepErr := temporary.MediaStepIDForRun(expectedRunID)
	if err != nil || preparationErr != nil || runErr != nil || stepErr != nil ||
		preparation.TenantID != binding.TenantID || preparation.SiteID != binding.SiteID || preparation.RequestID != binding.RequestKey ||
		audience.Ref != preparation.AudienceBindingRef || audience.SHA256 != preparation.AudienceSHA256 ||
		preparation.Media.RunID != expectedRunID || preparation.Media.StepID != expectedStepID || preparation.Media.Attempt != 1 {
		return temporary.Submission{}, errors.New("temporary decision is not bound to the authenticated channel session")
	}
	submission := temporary.Submission{
		Binding: binding, Spec: decision.Spec, PreparationRef: expectedPreparation, MediaKind: preparation.Media.Kind,
		AudienceBindingRef: preparation.AudienceBindingRef, AudienceSHA256: preparation.AudienceSHA256,
		EvidenceExpiresAt: preparation.EvidenceExpiresAt,
		SubmittedAt:       request.CreatedAt.UTC(), DeadlineAt: decision.DeadlineAt.UTC(),
	}
	if err := submission.Validate(); err != nil {
		return temporary.Submission{}, err
	}
	return submission, nil
}

func validatePreparationRegistration(status mediaprep.Status, expectedRef string) error {
	if !temporaryPrepRefPattern.MatchString(expectedRef) || status.Validate(expectedRef) != nil {
		return errors.New("invalid durable preparation registration")
	}
	return nil
}

func validateTemporaryRunBinding(run temporary.Record, submission temporary.Submission) error {
	if err := run.Validate(); err != nil || submission.Validate() != nil || !validRef(run.RunID) || !validDigest(run.IdentitySHA256) ||
		run.Binding != submission.Binding || run.Spec != submission.Spec || run.PreparationRef != submission.PreparationRef || run.MediaKind != submission.MediaKind ||
		run.AudienceBindingRef != submission.AudienceBindingRef || run.AudienceSHA256 != submission.AudienceSHA256 ||
		!run.EvidenceExpiresAt.Equal(submission.EvidenceExpiresAt) ||
		!run.SubmittedAt.Equal(submission.SubmittedAt) || !run.DeadlineAt.Equal(submission.DeadlineAt) {
		return errors.New("temporary run immutable fields do not match the frozen decision")
	}
	return nil
}

func projectTemporaryRun(publicRunRef string, run temporary.Record, now time.Time) httpapi.RunView {
	status, message := httpapi.RunUnable, "现场查看未能完成"
	switch run.State {
	case temporary.StateQueued:
		status, message = httpapi.RunAccepted, "现场查看请求已受理"
	case temporary.StateRunning:
		status, message = httpapi.RunWorking, "正在查看现场画面"
	case temporary.StateSucceeded:
		if run.Observation != nil && run.Observation.ExpiresAt.After(now) {
			status, message = httpapi.RunReady, "现场查看已完成"
		} else {
			status, message = httpapi.RunExpired, "现场查看结果已过期"
		}
	case temporary.StateInvalidCandidate:
		status, message = httpapi.RunUnable, "当前画面没有形成可展示的结果"
	case temporary.StateExpired:
		status, message = httpapi.RunExpired, "现场查看请求已过期"
	case temporary.StateOutcomeUnknown:
		status, message = httpapi.RunUnable, "现场查看的执行结果暂时无法确认"
	case temporary.StateFailed:
		status, message = httpapi.RunUnable, "现场查看未能完成"
	}
	return httpapi.RunView{
		RunRef: publicRunRef, Status: status, Message: message,
		SubmittedAt: run.SubmittedAt.UTC(), UpdatedAt: run.UpdatedAt.UTC(),
	}
}

func projectRun(publicRunRef string, run inspection.Run) httpapi.RunView {
	status, message := httpapi.RunUnable, "巡检未能完成"
	switch run.State {
	case inspection.RunRequested, inspection.RunAdmitted, inspection.RunQueued:
		status, message = httpapi.RunAccepted, "巡检请求已受理"
	case inspection.RunRunning:
		status, message = httpapi.RunWorking, "正在巡检"
	case inspection.RunReconciliationRequired:
		status, message = httpapi.RunWorking, "正在核对巡检执行结果"
	case inspection.RunFinalizing:
		status, message = httpapi.RunWorking, "正在整理巡检结果"
	case inspection.RunCompleted:
		status, message = httpapi.RunReady, "巡检已完成"
	case inspection.RunPartial:
		status, message = httpapi.RunReady, "巡检已完成，部分内容无法确认"
	case inspection.RunBlocked:
		status, message = httpapi.RunUnable, "当前条件不足，无法完成巡检"
	case inspection.RunUnknown:
		status, message = httpapi.RunUnable, "巡检执行结果暂时无法确认"
	case inspection.RunFailed:
		status, message = httpapi.RunUnable, "巡检未能完成"
	case inspection.RunCancelled:
		status, message = httpapi.RunCancelled, "巡检已取消"
	case inspection.RunExpired:
		status, message = httpapi.RunExpired, "巡检请求已过期"
	}
	return httpapi.RunView{RunRef: publicRunRef, Status: status, Message: message, SubmittedAt: run.CreatedAt.UTC(), UpdatedAt: run.UpdatedAt.UTC()}
}

func canonicalRequest(request httpapi.InspectionRequest) ([]byte, string, error) {
	if !validInputText(request.Instruction, 1, 2000) || inputguard.ValidateText(request.Instruction) != nil || len(request.Context) > 16 {
		return nil, "", errors.New("invalid inspection business request")
	}
	seen := map[string]struct{}{}
	for _, item := range request.Context {
		if !validInputText(item.Name, 1, 128) || !validInputText(item.Value, 1, 512) ||
			inputguard.ValidateText(item.Name) != nil || inputguard.ValidateText(item.Value) != nil {
			return nil, "", errors.New("invalid inspection business context")
		}
		key := strings.ToLower(item.Name)
		if _, duplicate := seen[key]; duplicate {
			return nil, "", errors.New("duplicate inspection business context")
		}
		seen[key] = struct{}{}
	}
	raw, err := json.Marshal(request)
	if err != nil {
		return nil, "", err
	}
	digest := sha256.Sum256(raw)
	return raw, hex.EncodeToString(digest[:]), nil
}

func validateSession(session httpapi.SessionBinding) error {
	if !validAudienceRef(session.TenantID) || !validAudienceRef(session.SiteID) || !validAudienceRef(session.Channel) ||
		!validAudienceRef(session.ConversationRef) || !validAudienceRef(session.RecipientRef) || !validDigest(session.PrincipalSHA256) {
		return errors.New("invalid inspection session")
	}
	return nil
}

func validAudienceRef(value string) bool {
	return value == strings.TrimSpace(value) && audienceRefPattern.MatchString(value)
}

func validateCapabilitySet(set httpapi.CapabilitySet) error {
	if !validPublicText(set.ContextLabel, 1, 256) || len(set.Capabilities) < 1 || len(set.Capabilities) > 100 {
		return errors.New("invalid capability set")
	}
	seen := map[string]struct{}{}
	for _, value := range set.Capabilities {
		if !validRef(value.CapabilityRef) || !validPublicText(value.Title, 1, 256) || !validPublicText(value.Description, 1, 1024) || len(value.Examples) > 8 {
			return errors.New("invalid capability")
		}
		if _, duplicate := seen[value.CapabilityRef]; duplicate {
			return errors.New("duplicate capability")
		}
		seen[value.CapabilityRef] = struct{}{}
		for _, example := range value.Examples {
			if !validPublicText(example, 1, 512) {
				return errors.New("invalid capability example")
			}
		}
	}
	return nil
}

func validateInteraction(value httpapi.InteractionRequired) error {
	if !validPublicText(value.Title, 1, 256) || !validPublicText(value.Message, 1, 1024) ||
		!validPublicText(value.ActionLabel, 1, 128) || !httpapi.ValidInteractionCapability(value.Capability) || !validRef(value.HandoffRef) {
		return errors.New("invalid local operator interaction")
	}
	return nil
}

func decodeInteraction(raw []byte) (httpapi.InteractionRequired, error) {
	var result httpapi.InteractionRequired
	if err := json.Unmarshal(raw, &result); err != nil || validateInteraction(result) != nil {
		return httpapi.InteractionRequired{}, errors.New("stored local operator interaction is invalid")
	}
	canonical, _ := json.Marshal(result)
	if string(canonical) != string(raw) {
		return httpapi.InteractionRequired{}, errors.New("stored local operator interaction is not canonical")
	}
	return result, nil
}

func validRef(value string) bool {
	return value == strings.TrimSpace(value) && publicRefPattern.MatchString(value)
}

func validInputText(value string, minimum, maximum int) bool {
	if !utf8.ValidString(value) || value != strings.TrimSpace(value) || len(value) < minimum || len(value) > maximum {
		return false
	}
	for _, character := range value {
		if character != '\n' && character != '\t' && unicode.IsControl(character) {
			return false
		}
	}
	return true
}

func validPublicText(value string, minimum, maximum int) bool {
	return validInputText(value, minimum, maximum) && !protectedText.MatchString(value) && inputguard.ValidateText(value) == nil
}

func validImageContentType(value string) bool {
	switch value {
	case "image/jpeg", "image/png":
		return true
	default:
		return false
	}
}

func validImageMagic(contentType string, raw []byte) bool {
	switch contentType {
	case "image/png":
		return len(raw) >= 8 && string(raw[:8]) == "\x89PNG\r\n\x1a\n"
	case "image/jpeg":
		return len(raw) >= 3 && raw[0] == 0xff && raw[1] == 0xd8 && raw[2] == 0xff
	default:
		return false
	}
}

func validateMediaDescriptor(descriptor media.Descriptor, capability MediaCapabilityRecord, session httpapi.SessionBinding) error {
	if descriptor.MediaRef != capability.InternalMediaRef || descriptor.Kind != media.KindImage || descriptor.Availability != media.AvailabilityAvailable ||
		descriptor.Binding.TenantID != session.TenantID || descriptor.Binding.SiteID != session.SiteID || descriptor.Binding.RunID != capability.MediaBindingRunID ||
		descriptor.Integrity.SHA256 != capability.SHA256 || descriptor.Integrity.SizeBytes != capability.SizeBytes || descriptor.Encoding.MIMEType != capability.ContentType ||
		!containsExact(descriptor.Governance.Audience, capability.Audience) {
		return errors.New("media descriptor mismatch")
	}
	return nil
}

func containsExact(values []string, wanted string) bool {
	for _, value := range values {
		if value == wanted {
			return true
		}
	}
	return false
}

func equalMediaTemporal(left, right media.Temporal) bool {
	if left.DurationMillis != right.DurationMillis || left.SampleOrdinal != right.SampleOrdinal ||
		(left.WindowStart == nil) != (right.WindowStart == nil) || (left.WindowEnd == nil) != (right.WindowEnd == nil) {
		return false
	}
	if left.WindowStart != nil && !left.WindowStart.Equal(*right.WindowStart) {
		return false
	}
	return left.WindowEnd == nil || left.WindowEnd.Equal(*right.WindowEnd)
}

func cloneCapabilitySet(value httpapi.CapabilitySet) httpapi.CapabilitySet {
	result := value
	result.Capabilities = append([]httpapi.CapabilityView(nil), value.Capabilities...)
	for index := range result.Capabilities {
		result.Capabilities[index].Examples = append([]string(nil), value.Capabilities[index].Examples...)
	}
	return result
}

func cloneRequest(value httpapi.InspectionRequest) httpapi.InspectionRequest {
	value.Context = append([]httpapi.BusinessContext(nil), value.Context...)
	if value.TemporaryIntent != nil {
		clone := *value.TemporaryIntent
		value.TemporaryIntent = &clone
	}
	return value
}

func randomID(prefix string) (string, error) {
	if !validRef(prefix) || len(prefix) > 16 {
		return "", errors.New("invalid inspection identity prefix")
	}
	value := make([]byte, 16)
	if _, err := rand.Read(value); err != nil {
		return "", err
	}
	return prefix + "_" + hex.EncodeToString(value), nil
}

func mapStateError(err error) error {
	switch {
	case errors.Is(err, ErrStateConflict):
		return httpapi.ErrConflict
	case errors.Is(err, ErrStateNotFound):
		return httpapi.ErrNotFound
	default:
		return err
	}
}

func mapStateNotFound(err error) error {
	if errors.Is(err, ErrStateNotFound) || errors.Is(err, ErrStateExpired) {
		return httpapi.ErrNotFound
	}
	return err
}

func mapRepositoryError(err error) error {
	switch {
	case errors.Is(err, inspectionstore.ErrNotFound):
		return httpapi.ErrNotFound
	case errors.Is(err, inspectionstore.ErrConflict):
		return httpapi.ErrConflict
	default:
		return err
	}
}

func mapTemporaryRuntimeError(err error) error {
	switch {
	case errors.Is(err, temporary.ErrRuntimeNotFound):
		return httpapi.ErrNotFound
	case errors.Is(err, temporary.ErrRuntimeConflict), errors.Is(err, temporary.ErrRuntimeInvalid):
		return httpapi.ErrConflict
	default:
		return err
	}
}

func sortedUnique(values []string) []string {
	set := make(map[string]struct{}, len(values))
	for _, value := range values {
		set[value] = struct{}{}
	}
	result := make([]string, 0, len(set))
	for value := range set {
		result = append(result, value)
	}
	sort.Strings(result)
	return result
}

var _ httpapi.Backend = (*Backend)(nil)
