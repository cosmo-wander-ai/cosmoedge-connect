package inspectioneval

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/cosmo-wander-ai/cosmoedge-connect/internal/inspection"
	"github.com/cosmo-wander-ai/cosmoedge-connect/internal/inspection/application"
	"github.com/cosmo-wander-ai/cosmoedge-connect/internal/inspection/delivery"
	"github.com/cosmo-wander-ai/cosmoedge-connect/internal/inspection/httpapi"
	inspectionstore "github.com/cosmo-wander-ai/cosmoedge-connect/internal/inspection/store"
	"github.com/cosmo-wander-ai/cosmoedge-connect/internal/inspection/temporary"
)

var _ StandardRuntimeEvidenceReader = (*inspectionstore.Store)(nil)
var _ TemporaryRuntimeEvidenceReader = (*temporary.SQLiteStore)(nil)
var _ ApplicationRunBindingReader = (*application.StateStore)(nil)
var _ ApplicationFeedbackReader = (*application.StateStore)(nil)

type adapterStandardReader struct {
	run          inspection.Run
	plan         inspection.ExecutionPlan
	observations []inspection.Observation
	err          error
}

func (r *adapterStandardReader) GetRun(context.Context, string) (inspection.Run, error) {
	return r.run, r.err
}

func (r *adapterStandardReader) GetPlan(context.Context, string) (inspection.ExecutionPlan, error) {
	return r.plan, r.err
}

func (r *adapterStandardReader) ListObservations(context.Context, string) ([]inspection.Observation, error) {
	return append([]inspection.Observation(nil), r.observations...), r.err
}

type adapterTemporaryReader struct {
	record temporary.Record
	err    error
}

func (r *adapterTemporaryReader) Get(context.Context, string) (temporary.Record, error) {
	return r.record, r.err
}

func TestAuthoritativeRuntimeEvidenceAdapterUsesExactRepositoryProjection(t *testing.T) {
	fixture := newStandardAssemblyFixture(t)
	evidence := *fixture.input.Standard
	reader := &adapterStandardReader{run: evidence.Run, plan: evidence.Plan,
		observations: []inspection.Observation{{ObservationID: "observation-one", SampleID: "sample-one", Result: evidence.Result}}}
	adapter := NewAuthoritativeRuntimeEvidenceAdapter(reader, nil)
	if err := adapter.VerifyStandardEvidence(context.Background(), evidence); err != nil {
		t.Fatal(err)
	}
	reader.observations[0].Result.Integrity.ContractSHA256 = strings.Repeat("f", 64)
	if err := adapter.VerifyStandardEvidence(context.Background(), evidence); err == nil || !strings.Contains(err.Error(), "differs") {
		t.Fatalf("tampered result err=%v", err)
	}
	reader.err = errors.New("repository unavailable")
	if err := adapter.VerifyStandardEvidence(context.Background(), evidence); !errors.Is(err, ErrRuntimeEvidenceUnavailable) {
		t.Fatalf("repository error=%v", err)
	}
}

func TestAuthoritativeRuntimeEvidenceAdapterUsesExactTemporaryRecord(t *testing.T) {
	record := temporary.Record{RunID: "temporary-run-one"}
	reader := &adapterTemporaryReader{record: record}
	adapter := NewAuthoritativeRuntimeEvidenceAdapter(nil, reader)
	if err := adapter.VerifyTemporaryEvidence(context.Background(), record); err != nil {
		t.Fatal(err)
	}
	record.ResultRef = "temporary-result-other"
	if err := adapter.VerifyTemporaryEvidence(context.Background(), record); err == nil || !strings.Contains(err.Error(), "differs") {
		t.Fatalf("tampered temporary record err=%v", err)
	}
}

type adapterApplicationReader struct {
	resolved  application.RunAudience
	audience  application.AudienceRunRecord
	mapping   application.RequestRecord
	standard  application.StandardDecisionRecord
	temporary application.TemporaryDecisionRecord
	scheduled application.ScheduledDecisionRecord
	err       error
}

func (r *adapterApplicationReader) ResolveRunAudience(context.Context, string) (application.RunAudience, error) {
	return r.resolved, r.err
}

func (r *adapterApplicationReader) GetAudienceRun(context.Context, httpapi.SessionBinding, string) (application.AudienceRunRecord, error) {
	return r.audience, r.err
}

func (r *adapterApplicationReader) GetRunMapping(context.Context, httpapi.SessionBinding, string) (application.RequestRecord, error) {
	return r.mapping, r.err
}

func (r *adapterApplicationReader) GetStandardDecision(context.Context, httpapi.SessionBinding, string) (application.StandardDecisionRecord, error) {
	return r.standard, r.err
}

func (r *adapterApplicationReader) GetTemporaryDecision(context.Context, httpapi.SessionBinding, string) (application.TemporaryDecisionRecord, error) {
	return r.temporary, r.err
}

func (r *adapterApplicationReader) GetScheduledDecision(context.Context, httpapi.SessionBinding, string) (application.ScheduledDecisionRecord, error) {
	return r.scheduled, r.err
}

func TestApplicationRunBindingAdapterVerifiesChannelAndScheduleBindings(t *testing.T) {
	query, reader := applicationBindingFixture(t, "channel")
	adapter := NewApplicationRunBindingAdapter(reader)
	if err := adapter.VerifyPublicRunBinding(context.Background(), query); err != nil {
		t.Fatal(err)
	}
	reader.standard.PlanSHA256 = strings.Repeat("f", 64)
	if err := adapter.VerifyPublicRunBinding(context.Background(), query); !errors.Is(err, ErrRunBindingUnavailable) {
		t.Fatalf("plan substitution err=%v", err)
	}

	query, reader = applicationBindingFixture(t, "schedule")
	adapter = NewApplicationRunBindingAdapter(reader)
	if err := adapter.VerifyPublicRunBinding(context.Background(), query); err != nil {
		t.Fatal(err)
	}
	reader.scheduled.AudienceSHA256 = strings.Repeat("f", 64)
	if err := adapter.VerifyPublicRunBinding(context.Background(), query); !errors.Is(err, ErrRunBindingUnavailable) {
		t.Fatalf("schedule audience substitution err=%v", err)
	}
}

func TestApplicationRunBindingAdapterVerifiesTemporaryChannelBinding(t *testing.T) {
	query, reader := applicationBindingFixture(t, "channel")
	query.RunKind, query.PlanSHA256 = ObservationTemporary, ""
	reader.audience.RunKind, reader.mapping.RequestKind = "temporary", "temporary"
	reader.temporary = application.TemporaryDecisionRecord{Session: reader.audience.Session, PublicRunRef: query.PublicRunRef}
	if err := NewApplicationRunBindingAdapter(reader).VerifyPublicRunBinding(context.Background(), query); err != nil {
		t.Fatal(err)
	}
	reader.audience.Origin = "schedule"
	if err := NewApplicationRunBindingAdapter(reader).VerifyPublicRunBinding(context.Background(), query); !errors.Is(err, ErrRunBindingUnavailable) {
		t.Fatalf("scheduled temporary err=%v", err)
	}
}

type adapterFeedbackReader struct {
	projection application.EvaluationFeedbackProjection
	err        error
	publicRun  string
	audience   string
}

func (r *adapterFeedbackReader) GetEvaluationFeedback(_ context.Context, publicRunRef, audienceSHA256 string) (application.EvaluationFeedbackProjection, error) {
	r.publicRun, r.audience = publicRunRef, audienceSHA256
	return r.projection, r.err
}

func TestApplicationFeedbackAdapterBuildsCanonicalCommentFreeProjection(t *testing.T) {
	publicRunRef := "feedback-public-run-one"
	resultRef, err := delivery.ResultRefForRun(publicRunRef)
	if err != nil {
		t.Fatal(err)
	}
	audienceSHA256 := strings.Repeat("a", 64)
	receivedAt := time.Date(2026, 7, 19, 12, 0, 0, 0, time.UTC)
	reader := &adapterFeedbackReader{projection: application.EvaluationFeedbackProjection{PublicRunRef: publicRunRef,
		AudienceSHA256: audienceSHA256, Helpful: true, ReceivedAt: receivedAt}}
	adapter := NewFeedbackProjectionAdapter(reader)
	record, found, err := adapter.GetFeedback(context.Background(), FeedbackQuery{PublicRunRef: publicRunRef,
		ResultRef: resultRef, AudienceSHA256: audienceSHA256})
	if err != nil || !found || record.Schema != FeedbackSchema || record.PublicRunRef != publicRunRef || record.ResultRef != resultRef ||
		record.AudienceSHA256 != audienceSHA256 || !record.Helpful || !record.ReceivedAt.Equal(receivedAt) ||
		!strings.HasPrefix(record.FeedbackID, "feedback_") {
		t.Fatalf("record=%#v found=%v err=%v", record, found, err)
	}
	wantSHA256, err := FeedbackProjectionSHA256(record)
	if err != nil || record.RecordSHA256 != wantSHA256 || reader.publicRun != publicRunRef || reader.audience != audienceSHA256 {
		t.Fatalf("canonical digest=%s want=%s err=%v", record.RecordSHA256, wantSHA256, err)
	}

	reader.err = application.ErrStateNotFound
	if _, found, err := adapter.GetFeedback(context.Background(), FeedbackQuery{PublicRunRef: publicRunRef,
		ResultRef: resultRef, AudienceSHA256: audienceSHA256}); err != nil || found {
		t.Fatalf("missing feedback found=%v err=%v", found, err)
	}
	reader.err = nil
	if _, _, err := adapter.GetFeedback(context.Background(), FeedbackQuery{PublicRunRef: publicRunRef,
		ResultRef: "result_wrong", AudienceSHA256: audienceSHA256}); !errors.Is(err, ErrFeedbackUnavailable) {
		t.Fatalf("substituted result err=%v", err)
	}
	reader.projection.AudienceSHA256 = strings.Repeat("b", 64)
	if _, _, err := adapter.GetFeedback(context.Background(), FeedbackQuery{PublicRunRef: publicRunRef,
		ResultRef: resultRef, AudienceSHA256: audienceSHA256}); !errors.Is(err, ErrFeedbackUnavailable) {
		t.Fatalf("substituted audience err=%v", err)
	}
}

func applicationBindingFixture(t *testing.T, origin string) (PublicRunBindingQuery, *adapterApplicationReader) {
	t.Helper()
	audience := deliveryAudienceFixture()
	audienceSHA256, err := audience.SHA256()
	if err != nil {
		t.Fatal(err)
	}
	query := PublicRunBindingQuery{PublicRunRef: "public-run-one", InternalRunID: "internal-run-one", RunKind: ObservationStandard,
		TenantID: audience.TenantID, SiteID: audience.SiteID, PlanSHA256: strings.Repeat("a", 64), Audience: audience, AudienceSHA256: audienceSHA256}
	session := httpapi.SessionBinding{TenantID: audience.TenantID, SiteID: audience.SiteID, Channel: audience.Channel,
		ConversationRef: audience.ConversationRef, RecipientRef: audience.RecipientRef, PrincipalSHA256: strings.Repeat("b", 64)}
	reader := &adapterApplicationReader{
		resolved: application.RunAudience{PublicRunRef: query.PublicRunRef, PrincipalSHA256: session.PrincipalSHA256, Audience: audience},
		audience: application.AudienceRunRecord{Session: session, PublicRunRef: query.PublicRunRef, InternalRunID: query.InternalRunID,
			Origin: origin, RunKind: string(query.RunKind), BindingState: "bound", CreatedAt: time.Now().UTC(), UpdatedAt: time.Now().UTC()},
		mapping: application.RequestRecord{Session: session, PublicRunRef: query.PublicRunRef, InternalRunID: query.InternalRunID,
			RequestKind: string(query.RunKind)},
		standard: application.StandardDecisionRecord{Session: session, PublicRunRef: query.PublicRunRef, PlanSHA256: query.PlanSHA256},
		scheduled: application.ScheduledDecisionRecord{Session: session, PublicRunRef: query.PublicRunRef, InternalRunID: query.InternalRunID,
			PlanSHA256: query.PlanSHA256, AudienceSHA256: audienceSHA256},
	}
	return query, reader
}

func deliveryAudienceFixture() delivery.Audience {
	return delivery.Audience{TenantID: "tenant-one", SiteID: "site-one", Channel: "workbuddy-wechat",
		ConversationRef: "conversation-one", RecipientRef: "recipient-one"}
}
