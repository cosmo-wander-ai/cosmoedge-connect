package inspectioneval

import (
	"context"
	"errors"
	"reflect"
	"time"

	"github.com/cosmo-wander-ai/cosmoedge-connect/internal/inspection"
	"github.com/cosmo-wander-ai/cosmoedge-connect/internal/inspection/application"
	"github.com/cosmo-wander-ai/cosmoedge-connect/internal/inspection/delivery"
	"github.com/cosmo-wander-ai/cosmoedge-connect/internal/inspection/httpapi"
	"github.com/cosmo-wander-ai/cosmoedge-connect/internal/inspection/temporary"
)

// StandardRuntimeEvidenceReader is the read-only subset implemented by the
// authoritative inspection store. It deliberately omits every mutation,
// execution-authority, media-payload, and device operation.
type StandardRuntimeEvidenceReader interface {
	GetRun(context.Context, string) (inspection.Run, error)
	GetPlan(context.Context, string) (inspection.ExecutionPlan, error)
	ListObservations(context.Context, string) ([]inspection.Observation, error)
}

// TemporaryRuntimeEvidenceReader is the read-only subset implemented by both
// the persistent temporary store and the temporary runtime manager.
type TemporaryRuntimeEvidenceReader interface {
	Get(context.Context, string) (temporary.Record, error)
}

// AuthoritativeRuntimeEvidenceAdapter verifies caller-supplied evidence by
// exact comparison with authoritative read-only repository projections.
// Either reader may be nil when a composition intentionally supports only one
// observation mode; attempts to use the missing mode fail closed.
type AuthoritativeRuntimeEvidenceAdapter struct {
	standard  StandardRuntimeEvidenceReader
	temporary TemporaryRuntimeEvidenceReader
}

func NewAuthoritativeRuntimeEvidenceAdapter(standard StandardRuntimeEvidenceReader, temporary TemporaryRuntimeEvidenceReader) *AuthoritativeRuntimeEvidenceAdapter {
	return &AuthoritativeRuntimeEvidenceAdapter{standard: standard, temporary: temporary}
}

func (a *AuthoritativeRuntimeEvidenceAdapter) VerifyStandardEvidence(ctx context.Context, evidence StandardEvidence) error {
	if a == nil || a.standard == nil || ctx == nil || !validOpaqueRef(evidence.Run.RunID) {
		return ErrRuntimeEvidenceUnavailable
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	run, err := a.standard.GetRun(ctx, evidence.Run.RunID)
	if err != nil {
		return ErrRuntimeEvidenceUnavailable
	}
	plan, err := a.standard.GetPlan(ctx, evidence.Run.RunID)
	if err != nil {
		return ErrRuntimeEvidenceUnavailable
	}
	observations, err := a.standard.ListObservations(ctx, evidence.Run.RunID)
	if err != nil {
		return ErrRuntimeEvidenceUnavailable
	}
	if !reflect.DeepEqual(run, evidence.Run) || !reflect.DeepEqual(plan, evidence.Plan) {
		return errors.New("authoritative standard run or plan evidence differs")
	}
	matches := 0
	for _, observation := range observations {
		if observation.Result.Binding.ResultID == evidence.Result.Binding.ResultID {
			matches++
			if !reflect.DeepEqual(observation.Result, evidence.Result) {
				return errors.New("authoritative standard result evidence differs")
			}
		}
	}
	if matches != 1 {
		return errors.New("authoritative standard result evidence is missing or duplicated")
	}
	return nil
}

func (a *AuthoritativeRuntimeEvidenceAdapter) VerifyTemporaryEvidence(ctx context.Context, evidence temporary.Record) error {
	if a == nil || a.temporary == nil || ctx == nil || !validOpaqueRef(evidence.RunID) {
		return ErrRuntimeEvidenceUnavailable
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	stored, err := a.temporary.Get(ctx, evidence.RunID)
	if err != nil {
		return ErrRuntimeEvidenceUnavailable
	}
	if !reflect.DeepEqual(stored, evidence) {
		return errors.New("authoritative temporary runtime evidence differs")
	}
	return nil
}

// ApplicationRunBindingReader is the protected, read-only subset already
// implemented by application.StateStore. The adapter reconstructs the scoped
// session only from the authoritative internal-run lookup; callers never
// supply a principal or use a partial-audience search.
type ApplicationRunBindingReader interface {
	ResolveRunAudience(context.Context, string) (application.RunAudience, error)
	GetAudienceRun(context.Context, httpapi.SessionBinding, string) (application.AudienceRunRecord, error)
	GetRunMapping(context.Context, httpapi.SessionBinding, string) (application.RequestRecord, error)
	GetStandardDecision(context.Context, httpapi.SessionBinding, string) (application.StandardDecisionRecord, error)
	GetTemporaryDecision(context.Context, httpapi.SessionBinding, string) (application.TemporaryDecisionRecord, error)
	GetScheduledDecision(context.Context, httpapi.SessionBinding, string) (application.ScheduledDecisionRecord, error)
}

// ApplicationRunBindingAdapter proves an exact public/internal run, run kind,
// frozen-plan, and full delivery-audience binding without exposing the
// application store or its protected records to AssembleRecord.
type ApplicationRunBindingAdapter struct {
	reader ApplicationRunBindingReader
}

func NewApplicationRunBindingAdapter(reader ApplicationRunBindingReader) *ApplicationRunBindingAdapter {
	return &ApplicationRunBindingAdapter{reader: reader}
}

func (a *ApplicationRunBindingAdapter) VerifyPublicRunBinding(ctx context.Context, query PublicRunBindingQuery) error {
	if a == nil || a.reader == nil || ctx == nil || !validRunBindingQuery(query) {
		return ErrRunBindingUnavailable
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	resolved, err := a.reader.ResolveRunAudience(ctx, query.InternalRunID)
	if err != nil || !digestPattern.MatchString(resolved.PrincipalSHA256) || resolved.PublicRunRef != query.PublicRunRef ||
		resolved.Audience != query.Audience {
		return ErrRunBindingUnavailable
	}
	session := httpapi.SessionBinding{
		TenantID: resolved.Audience.TenantID, SiteID: resolved.Audience.SiteID, Channel: resolved.Audience.Channel,
		ConversationRef: resolved.Audience.ConversationRef, RecipientRef: resolved.Audience.RecipientRef,
		PrincipalSHA256: resolved.PrincipalSHA256,
	}
	audienceRun, err := a.reader.GetAudienceRun(ctx, session, query.PublicRunRef)
	if err != nil || audienceRun.Session != session || audienceRun.PublicRunRef != query.PublicRunRef ||
		audienceRun.InternalRunID != query.InternalRunID || audienceRun.BindingState != "bound" ||
		audienceRun.RunKind != string(query.RunKind) {
		return ErrRunBindingUnavailable
	}

	switch audienceRun.Origin {
	case "channel":
		mapping, mappingErr := a.reader.GetRunMapping(ctx, session, query.PublicRunRef)
		if mappingErr != nil || mapping.Session != session || mapping.PublicRunRef != query.PublicRunRef ||
			mapping.InternalRunID != query.InternalRunID || mapping.RequestKind != string(query.RunKind) {
			return ErrRunBindingUnavailable
		}
		switch query.RunKind {
		case ObservationStandard:
			decision, decisionErr := a.reader.GetStandardDecision(ctx, session, query.PublicRunRef)
			if decisionErr != nil || decision.Session != session || decision.PublicRunRef != query.PublicRunRef ||
				decision.PlanSHA256 != query.PlanSHA256 {
				return ErrRunBindingUnavailable
			}
		case ObservationTemporary:
			decision, decisionErr := a.reader.GetTemporaryDecision(ctx, session, query.PublicRunRef)
			if decisionErr != nil || decision.Session != session || decision.PublicRunRef != query.PublicRunRef {
				return ErrRunBindingUnavailable
			}
		default:
			return ErrRunBindingUnavailable
		}
	case "schedule":
		if query.RunKind != ObservationStandard {
			return ErrRunBindingUnavailable
		}
		decision, decisionErr := a.reader.GetScheduledDecision(ctx, session, query.PublicRunRef)
		if decisionErr != nil || decision.Session != session || decision.PublicRunRef != query.PublicRunRef ||
			decision.InternalRunID != query.InternalRunID || decision.PlanSHA256 != query.PlanSHA256 ||
			decision.AudienceSHA256 != query.AudienceSHA256 {
			return ErrRunBindingUnavailable
		}
	default:
		return ErrRunBindingUnavailable
	}
	return nil
}

func validRunBindingQuery(query PublicRunBindingQuery) bool {
	if !validOpaqueRef(query.PublicRunRef) || !validOpaqueRef(query.InternalRunID) || !validOpaqueRef(query.TenantID) ||
		!validOpaqueRef(query.SiteID) || query.Audience.Validate() != nil || query.Audience.TenantID != query.TenantID ||
		query.Audience.SiteID != query.SiteID || !digestPattern.MatchString(query.AudienceSHA256) {
		return false
	}
	audienceSHA256, err := query.Audience.SHA256()
	if err != nil || audienceSHA256 != query.AudienceSHA256 {
		return false
	}
	switch query.RunKind {
	case ObservationStandard:
		return digestPattern.MatchString(query.PlanSHA256)
	case ObservationTemporary:
		return query.PlanSHA256 == ""
	default:
		return false
	}
}

// ClockFunc adapts a Product-owned trusted clock without granting evaluation
// access to the Product or to any mutable state.
type ClockFunc func() time.Time

func (f ClockFunc) Now() time.Time {
	if f == nil {
		return time.Time{}
	}
	return f()
}

// ApplicationFeedbackReader is the comment-free, read-only projection
// implemented by application.StateStore. It exposes no raw JSON, idempotency
// key, principal, conversation, recipient, or channel-native identifier.
type ApplicationFeedbackReader interface {
	GetEvaluationFeedback(context.Context, string, string) (application.EvaluationFeedbackProjection, error)
}

type ApplicationFeedbackAdapter struct {
	reader ApplicationFeedbackReader
}

func NewFeedbackProjectionAdapter(reader ApplicationFeedbackReader) *ApplicationFeedbackAdapter {
	return &ApplicationFeedbackAdapter{reader: reader}
}

func (a *ApplicationFeedbackAdapter) GetFeedback(ctx context.Context, query FeedbackQuery) (FeedbackRecord, bool, error) {
	if a == nil || a.reader == nil || ctx == nil || !validOpaqueRef(query.PublicRunRef) ||
		!validOpaqueRef(query.ResultRef) || !digestPattern.MatchString(query.AudienceSHA256) {
		return FeedbackRecord{}, false, ErrFeedbackUnavailable
	}
	if err := ctx.Err(); err != nil {
		return FeedbackRecord{}, false, err
	}
	wantResultRef, err := delivery.ResultRefForRun(query.PublicRunRef)
	if err != nil || wantResultRef != query.ResultRef {
		return FeedbackRecord{}, false, ErrFeedbackUnavailable
	}
	projection, err := a.reader.GetEvaluationFeedback(ctx, query.PublicRunRef, query.AudienceSHA256)
	if errors.Is(err, application.ErrStateNotFound) {
		return FeedbackRecord{}, false, nil
	}
	if err != nil {
		if contextErr := ctx.Err(); contextErr != nil {
			return FeedbackRecord{}, false, contextErr
		}
		return FeedbackRecord{}, false, ErrFeedbackUnavailable
	}
	if projection.PublicRunRef != query.PublicRunRef || projection.AudienceSHA256 != query.AudienceSHA256 || projection.ReceivedAt.IsZero() {
		return FeedbackRecord{}, false, ErrFeedbackUnavailable
	}
	identitySHA256, err := digestValue(struct {
		Domain         string    `json:"domain"`
		PublicRunRef   string    `json:"publicRunRef"`
		ResultRef      string    `json:"resultRef"`
		AudienceSHA256 string    `json:"audienceSha256"`
		Helpful        bool      `json:"helpful"`
		ReceivedAt     time.Time `json:"receivedAt"`
	}{"inspection-evaluation-feedback-v1", query.PublicRunRef, query.ResultRef, query.AudienceSHA256,
		projection.Helpful, projection.ReceivedAt.UTC()})
	if err != nil {
		return FeedbackRecord{}, false, ErrFeedbackUnavailable
	}
	result := FeedbackRecord{Schema: FeedbackSchema, FeedbackID: "feedback_" + identitySHA256[:32],
		PublicRunRef: query.PublicRunRef, ResultRef: query.ResultRef, AudienceSHA256: query.AudienceSHA256,
		Helpful: projection.Helpful, ReceivedAt: projection.ReceivedAt.UTC()}
	result.RecordSHA256, err = FeedbackProjectionSHA256(result)
	if err != nil {
		return FeedbackRecord{}, false, ErrFeedbackUnavailable
	}
	return result, true, nil
}

// TemporaryReviewProjectionFunc and TemporaryReviewVerificationFunc are the
// final narrow composition seams for the independently governed review
// service. They cannot be sourced from dataset review rows because temporary
// review binds additional runtime/media/spec/observation identities.
type TemporaryReviewProjectionFunc func(context.Context, TemporaryReviewQuery) ([]TemporaryReviewRecord, error)

func (f TemporaryReviewProjectionFunc) ListTemporaryReviews(ctx context.Context, query TemporaryReviewQuery) ([]TemporaryReviewRecord, error) {
	if f == nil {
		return nil, ErrReviewUnavailable
	}
	return f(ctx, query)
}

type TemporaryReviewVerificationFunc func(context.Context, TemporaryReviewRecord) error

func (f TemporaryReviewVerificationFunc) VerifyTemporaryReview(ctx context.Context, record TemporaryReviewRecord) error {
	if f == nil {
		return ErrReviewUnavailable
	}
	return f(ctx, record)
}

func NewTemporaryReviewAdapters(list TemporaryReviewProjectionFunc, verify TemporaryReviewVerificationFunc) (TemporaryReviewRepository, TemporaryReviewVerifier) {
	return list, verify
}

var _ RuntimeEvidenceVerifier = (*AuthoritativeRuntimeEvidenceAdapter)(nil)
var _ PublicRunBindingVerifier = (*ApplicationRunBindingAdapter)(nil)
var _ EvaluationClock = ClockFunc(nil)
var _ DeliveryRepository = (delivery.Store)(nil)
var _ FeedbackRepository = (*ApplicationFeedbackAdapter)(nil)
var _ TemporaryReviewRepository = TemporaryReviewProjectionFunc(nil)
var _ TemporaryReviewVerifier = TemporaryReviewVerificationFunc(nil)
