package application

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/cosmo-wander-ai/cosmoedge-connect/internal/localstate"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/cosmo-wander-ai/cosmoedge-connect/internal/inspection"
	"github.com/cosmo-wander-ai/cosmoedge-connect/internal/inspection/delivery"
	"github.com/cosmo-wander-ai/cosmoedge-connect/internal/inspection/httpapi"
	"github.com/cosmo-wander-ai/cosmoedge-connect/internal/inspection/temporary"
	_ "modernc.org/sqlite"
)

var stateTestTime = time.Date(2026, 7, 19, 9, 0, 0, 0, time.UTC)

func TestStatePersistsIdempotentScopedRunFeedbackAndMedia(t *testing.T) {
	ctx := context.Background()
	path := protectedStatePath(t, "application-v2.db")
	store, err := OpenState(testStateConfig(path))
	if err != nil {
		t.Fatal(err)
	}
	session := testSession()
	request := httpapi.InspectionRequest{Instruction: "查看装卸口现在是否畅通", Context: []httpapi.BusinessContext{{Name: "关注点", Value: "人员通行"}}}
	raw, digest, err := canonicalRequest(request)
	if err != nil {
		t.Fatal(err)
	}
	reservation := RequestReservation{
		Session: session, IdempotencyKey: "request-key-one", RequestJSON: raw, RequestSHA256: digest,
		PublicRunRef: "run-public-one", RuntimeRequestID: "request-runtime-one", CreatedAt: stateTestTime,
	}
	record, created, err := store.ReserveRequest(ctx, reservation)
	if err != nil || !created || record.Resolution != requestReserved {
		t.Fatalf("ReserveRequest() record=%+v created=%v err=%v", record, created, err)
	}
	duplicate := reservation
	duplicate.PublicRunRef, duplicate.RuntimeRequestID = "run-unused", "request-unused"
	record, created, err = store.ReserveRequest(ctx, duplicate)
	if err != nil || created || record.PublicRunRef != reservation.PublicRunRef || record.RuntimeRequestID != reservation.RuntimeRequestID {
		t.Fatalf("duplicate reservation record=%+v created=%v err=%v", record, created, err)
	}
	var audienceCount int
	if err := store.db.QueryRow(`SELECT COUNT(*) FROM audience_runs`).Scan(&audienceCount); err != nil || audienceCount != 1 {
		t.Fatalf("duplicate reservation audience count=%d err=%v", audienceCount, err)
	}
	conflictRequest := httpapi.InspectionRequest{Instruction: "查看另一处区域"}
	conflictRaw, conflictDigest, _ := canonicalRequest(conflictRequest)
	duplicate.RequestJSON, duplicate.RequestSHA256 = conflictRaw, conflictDigest
	if _, _, err := store.ReserveRequest(ctx, duplicate); !errors.Is(err, ErrStateConflict) {
		t.Fatalf("conflicting reservation error=%v", err)
	}
	freezeStateTestDecision(t, store, record, stateTestTime)
	bound, changed, err := store.BindRun(ctx, session, record.PublicRunRef, "runtime-run-one", stateTestTime.Add(time.Second))
	if err != nil || !changed || bound.InternalRunID != "runtime-run-one" {
		t.Fatalf("BindRun() record=%+v changed=%v err=%v", bound, changed, err)
	}
	if _, changed, err := store.BindRun(ctx, session, record.PublicRunRef, "runtime-run-one", stateTestTime.Add(2*time.Second)); err != nil || changed {
		t.Fatalf("idempotent BindRun() changed=%v err=%v", changed, err)
	}

	feedback := httpapi.FeedbackRequest{Helpful: boolPointer(true), Comment: "结论清楚"}
	feedbackJSON, _ := json.Marshal(feedback)
	feedbackHash := sha256.Sum256(feedbackJSON)
	feedbackRecord := FeedbackRecord{
		Session: session, PublicRunRef: record.PublicRunRef, IdempotencyKey: "feedback-key-one",
		FeedbackJSON: feedbackJSON, FeedbackSHA256: hex.EncodeToString(feedbackHash[:]), CreatedAt: stateTestTime.Add(3 * time.Second),
	}
	if created, err := store.RecordFeedback(ctx, feedbackRecord); err != nil || !created {
		t.Fatalf("RecordFeedback() created=%v err=%v", created, err)
	}
	if created, err := store.RecordFeedback(ctx, feedbackRecord); err != nil || created {
		t.Fatalf("duplicate RecordFeedback() created=%v err=%v", created, err)
	}
	changedFeedback := httpapi.FeedbackRequest{Helpful: boolPointer(false), Comment: "结论不够清楚"}
	feedbackRecord.FeedbackJSON, _ = json.Marshal(changedFeedback)
	changedHash := sha256.Sum256(feedbackRecord.FeedbackJSON)
	feedbackRecord.FeedbackSHA256 = hex.EncodeToString(changedHash[:])
	if _, err := store.RecordFeedback(ctx, feedbackRecord); !errors.Is(err, ErrStateConflict) {
		t.Fatalf("conflicting feedback error=%v", err)
	}

	mediaRecord := MediaCapabilityRecord{
		Session: session, PublicRunRef: record.PublicRunRef, PublicMediaRef: "media-public-one",
		InternalRunID: "runtime-run-one", MediaBindingRunID: "runtime-run-one", InternalMediaRef: "media-internal-one",
		SHA256: testDigest("image-one"), SizeBytes: 123, ContentType: "image/jpeg", Audience: "run-owner", Title: "装卸口现场快照",
		CreatedAt: stateTestTime.Add(4 * time.Second), ExpiresAt: stateTestTime.Add(10 * time.Minute),
	}
	storedMedia, err := store.EnsureMediaCapability(ctx, mediaRecord, stateTestTime.Add(4*time.Second))
	if err != nil || storedMedia.PublicMediaRef != mediaRecord.PublicMediaRef {
		t.Fatalf("EnsureMediaCapability()=%+v err=%v", storedMedia, err)
	}
	secondMedia := mediaRecord
	secondMedia.PublicMediaRef = "media-unused"
	storedMedia, err = store.EnsureMediaCapability(ctx, secondMedia, stateTestTime.Add(5*time.Second))
	if err != nil || storedMedia.PublicMediaRef != mediaRecord.PublicMediaRef {
		t.Fatalf("idempotent media capability=%+v err=%v", storedMedia, err)
	}

	otherSession := session
	otherSession.ConversationRef = "conversation-two"
	if _, err := store.GetRunMapping(ctx, otherSession, record.PublicRunRef); !errors.Is(err, ErrStateNotFound) {
		t.Fatalf("cross-channel run lookup error=%v", err)
	}
	if _, err := store.GetMediaCapability(ctx, otherSession, mediaRecord.PublicMediaRef, stateTestTime.Add(5*time.Second)); !errors.Is(err, ErrStateNotFound) {
		t.Fatalf("cross-channel media lookup error=%v", err)
	}
	otherPrincipal := session
	otherPrincipal.PrincipalSHA256 = testDigest("principal-two")
	if _, err := store.MatchRequest(ctx, otherPrincipal, reservation.IdempotencyKey, raw, digest); !errors.Is(err, ErrStateNotFound) {
		t.Fatalf("cross-principal request replay error=%v", err)
	}
	if _, err := store.GetStandardDecision(ctx, otherPrincipal, record.PublicRunRef); !errors.Is(err, ErrStateNotFound) {
		t.Fatalf("cross-principal decision lookup error=%v", err)
	}
	if _, err := store.GetRunMapping(ctx, otherPrincipal, record.PublicRunRef); !errors.Is(err, ErrStateNotFound) {
		t.Fatalf("cross-principal run lookup error=%v", err)
	}
	if _, err := store.GetMediaCapability(ctx, otherPrincipal, mediaRecord.PublicMediaRef, stateTestTime.Add(5*time.Second)); !errors.Is(err, ErrStateNotFound) {
		t.Fatalf("cross-principal media lookup error=%v", err)
	}
	if _, err := store.GetMediaCapability(ctx, session, mediaRecord.PublicMediaRef, mediaRecord.ExpiresAt); !errors.Is(err, ErrStateExpired) {
		t.Fatalf("expired media lookup error=%v", err)
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
	reopened, err := OpenState(testStateConfig(path))
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.Close()
	persisted, err := reopened.GetRunMapping(ctx, session, record.PublicRunRef)
	if err != nil || persisted.InternalRunID != "runtime-run-one" {
		t.Fatalf("reopened run mapping=%+v err=%v", persisted, err)
	}
	if err := localstate.ValidateFile(path); err != nil {
		t.Fatalf("state file is not private: %v", err)
	}
}

func TestEvaluationFeedbackProjectionIsExactlyAudienceBoundAndCommentFree(t *testing.T) {
	ctx := context.Background()
	store, err := OpenState(testStateConfig(protectedStatePath(t, "evaluation-feedback.db")))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close() })
	session := testSession()
	request := httpapi.InspectionRequest{Instruction: "查看入口当前情况"}
	raw, digest, err := canonicalRequest(request)
	if err != nil {
		t.Fatal(err)
	}
	reserved, created, err := store.ReserveRequest(ctx, RequestReservation{Session: session, IdempotencyKey: "evaluation-request-one",
		RequestJSON: raw, RequestSHA256: digest, PublicRunRef: "evaluation-public-run-one",
		RuntimeRequestID: "evaluation-runtime-request-one", CreatedAt: stateTestTime})
	if err != nil || !created {
		t.Fatalf("reserve created=%v err=%v", created, err)
	}
	freezeStateTestDecision(t, store, reserved, stateTestTime)
	if _, changed, err := store.BindRun(ctx, session, reserved.PublicRunRef, "evaluation-runtime-run-one", stateTestTime.Add(time.Second)); err != nil || !changed {
		t.Fatalf("bind changed=%v err=%v", changed, err)
	}
	audience := delivery.Audience{TenantID: session.TenantID, SiteID: session.SiteID, Channel: session.Channel,
		ConversationRef: session.ConversationRef, RecipientRef: session.RecipientRef}
	audienceSHA256, err := audience.SHA256()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.GetEvaluationFeedback(ctx, reserved.PublicRunRef, audienceSHA256); !errors.Is(err, ErrStateNotFound) {
		t.Fatalf("missing feedback err=%v", err)
	}
	feedback := httpapi.FeedbackRequest{Helpful: boolPointer(true), Comment: "包含仅应留在应用状态内的现场说明"}
	feedbackJSON, _ := json.Marshal(feedback)
	feedbackSHA256 := sha256.Sum256(feedbackJSON)
	value := FeedbackRecord{Session: session, PublicRunRef: reserved.PublicRunRef, IdempotencyKey: "evaluation-feedback-one",
		FeedbackJSON: feedbackJSON, FeedbackSHA256: hex.EncodeToString(feedbackSHA256[:]), CreatedAt: stateTestTime.Add(2 * time.Second)}
	if created, err := store.RecordFeedback(ctx, value); err != nil || !created {
		t.Fatalf("record feedback created=%v err=%v", created, err)
	}
	projection, err := store.GetEvaluationFeedback(ctx, reserved.PublicRunRef, audienceSHA256)
	if err != nil || projection.PublicRunRef != reserved.PublicRunRef || projection.AudienceSHA256 != audienceSHA256 ||
		!projection.Helpful || !projection.ReceivedAt.Equal(value.CreatedAt) {
		t.Fatalf("projection=%#v err=%v", projection, err)
	}
	if _, err := json.Marshal(projection); !errors.Is(err, ErrProtectedStateProjection) {
		t.Fatalf("projection unexpectedly serializable: %v", err)
	}
	if rendered := fmt.Sprintf("%v %#v", projection, projection); strings.Contains(rendered, feedback.Comment) ||
		strings.Contains(rendered, value.IdempotencyKey) || strings.Contains(rendered, session.ConversationRef) {
		t.Fatalf("protected feedback material rendered: %s", rendered)
	}
	if _, err := store.GetEvaluationFeedback(ctx, reserved.PublicRunRef, testDigest("wrong-audience")); !errors.Is(err, ErrStateNotFound) {
		t.Fatalf("cross-audience feedback err=%v", err)
	}
	second := value
	second.IdempotencyKey = "evaluation-feedback-two"
	second.CreatedAt = value.CreatedAt.Add(time.Second)
	if created, err := store.RecordFeedback(ctx, second); err != nil || !created {
		t.Fatalf("record second feedback created=%v err=%v", created, err)
	}
	if _, err := store.GetEvaluationFeedback(ctx, reserved.PublicRunRef, audienceSHA256); !errors.Is(err, ErrCorruptState) {
		t.Fatalf("duplicate projection err=%v", err)
	}
}

func TestReserveRequestConcurrentStoresConvergeWithoutOrphanAudience(t *testing.T) {
	ctx := context.Background()
	path := protectedStatePath(t, "concurrent-reservation.db")
	first, err := OpenState(testStateConfig(path))
	if err != nil {
		t.Fatal(err)
	}
	defer first.Close()
	second, err := OpenState(testStateConfig(path))
	if err != nil {
		t.Fatal(err)
	}
	defer second.Close()

	raw, digest, err := canonicalRequest(httpapi.InspectionRequest{Instruction: "查看入口是否畅通"})
	if err != nil {
		t.Fatal(err)
	}
	base := RequestReservation{
		Session: testSession(), IdempotencyKey: "concurrent-key", RequestJSON: raw,
		RequestSHA256: digest, CreatedAt: stateTestTime,
	}
	reservations := []RequestReservation{base, base}
	reservations[0].PublicRunRef, reservations[0].RuntimeRequestID = "run-concurrent-one", "request-concurrent-one"
	reservations[1].PublicRunRef, reservations[1].RuntimeRequestID = "run-concurrent-two", "request-concurrent-two"
	stores := []*StateStore{first, second}
	type result struct {
		record  RequestRecord
		created bool
		err     error
	}
	results := make([]result, len(stores))
	start := make(chan struct{})
	var wait sync.WaitGroup
	for index := range stores {
		wait.Add(1)
		go func(index int) {
			defer wait.Done()
			<-start
			results[index].record, results[index].created, results[index].err = stores[index].ReserveRequest(ctx, reservations[index])
		}(index)
	}
	close(start)
	wait.Wait()
	for index, result := range results {
		if result.err != nil {
			t.Fatalf("ReserveRequest() result %d error=%v", index, result.err)
		}
	}
	if results[0].record.PublicRunRef != results[1].record.PublicRunRef ||
		results[0].record.RuntimeRequestID != results[1].record.RuntimeRequestID {
		t.Fatalf("concurrent reservations diverged: first=%+v second=%+v", results[0].record, results[1].record)
	}
	if results[0].created == results[1].created {
		t.Fatalf("concurrent reservations created flags=%v,%v", results[0].created, results[1].created)
	}
	var audienceCount, requestCount int
	if err := first.db.QueryRow(`SELECT COUNT(*) FROM audience_runs`).Scan(&audienceCount); err != nil {
		t.Fatal(err)
	}
	if err := first.db.QueryRow(`SELECT COUNT(*) FROM channel_requests`).Scan(&requestCount); err != nil {
		t.Fatal(err)
	}
	if audienceCount != 1 || requestCount != 1 {
		t.Fatalf("concurrent reservation rows: audience=%d requests=%d", audienceCount, requestCount)
	}
}

func TestStateRejectsMediaCapabilityWhoseBindingRunDiffersFromBoundRun(t *testing.T) {
	ctx := context.Background()
	store, err := OpenState(testStateConfig(protectedStatePath(t, "media-binding-tamper.db")))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	session := testSession()
	raw, digest, err := canonicalRequest(httpapi.InspectionRequest{Instruction: "查看入口"})
	if err != nil {
		t.Fatal(err)
	}
	request, _, err := store.ReserveRequest(ctx, RequestReservation{
		Session: session, IdempotencyKey: "media-binding-tamper", RequestJSON: raw, RequestSHA256: digest,
		PublicRunRef: "run-media-binding-tamper", RuntimeRequestID: "request-media-binding-tamper", CreatedAt: stateTestTime,
	})
	if err != nil {
		t.Fatal(err)
	}
	freezeStateTestDecision(t, store, request, stateTestTime)
	if _, _, err := store.BindRun(ctx, session, request.PublicRunRef, "runtime-media-binding", stateTestTime.Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	capability, err := store.EnsureMediaCapability(ctx, MediaCapabilityRecord{
		Session: session, PublicRunRef: request.PublicRunRef, PublicMediaRef: "media-binding-public",
		InternalRunID: "runtime-media-binding", MediaBindingRunID: "runtime-media-binding", InternalMediaRef: "media-binding-internal",
		SHA256: testDigest("media-binding-content"), SizeBytes: 100, ContentType: "image/jpeg", Audience: "run-owner", Title: "入口现场快照",
		CreatedAt: stateTestTime.Add(2 * time.Second), ExpiresAt: stateTestTime.Add(10 * time.Minute),
	}, stateTestTime.Add(2*time.Second))
	if err != nil {
		t.Fatal(err)
	}
	tampered := capability
	tampered.MediaBindingRunID = "runtime-media-other"
	tampered.RecordSHA256 = mediaRecordDigest(tampered)
	if _, err := store.db.Exec(`DROP TRIGGER media_capabilities_no_update`); err != nil {
		t.Fatal(err)
	}
	if _, err := store.db.Exec(`UPDATE media_capabilities SET media_binding_run_id=?,record_sha256=? WHERE public_media_ref=?`,
		tampered.MediaBindingRunID, tampered.RecordSHA256, tampered.PublicMediaRef); err != nil {
		t.Fatal(err)
	}
	if _, err := store.db.Exec(createMediaUpdateGuardSQL); err != nil {
		t.Fatal(err)
	}
	if _, err := store.GetMediaCapability(ctx, session, tampered.PublicMediaRef, stateTestTime.Add(3*time.Second)); !errors.Is(err, ErrCorruptState) {
		t.Fatalf("cross-run media binding lookup error=%v", err)
	}
}

func TestStateFreezesAndBindsTemporaryDecisionAcrossReopen(t *testing.T) {
	ctx := context.Background()
	path := protectedStatePath(t, "temporary-decision.db")
	store, err := OpenState(testStateConfig(path))
	if err != nil {
		t.Fatal(err)
	}
	session := testSession()
	raw, digest, _ := canonicalRequest(httpapi.InspectionRequest{Instruction: "临时查看入口"})
	request, _, err := store.ReserveRequest(ctx, RequestReservation{
		Session: session, IdempotencyKey: "temporary-state", RequestJSON: raw, RequestSHA256: digest,
		PublicRunRef: "run-temporary-state", RuntimeRequestID: "request-temporary-state", CreatedAt: stateTestTime,
	})
	if err != nil {
		t.Fatal(err)
	}
	spec, err := temporary.NewSpec(temporary.Intent{
		Subject: "入口", Region: "主入口", Observable: "当前是否便于通行", Locale: "zh-CN",
		TimeScope: temporary.TimeScope{Kind: temporary.TimeScopeCurrent}, EvidenceTTLSeconds: 600,
	})
	if err != nil {
		t.Fatal(err)
	}
	decision, err := temporaryDecisionForTestInput(PlanningRequest{
		Session: session, RequestID: request.RuntimeRequestID, RequestedAt: stateTestTime,
	}, spec, stateTestTime.Add(5*time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := NewTemporaryDecision(spec, decision.request, stateTestTime.Add(5*time.Minute).In(time.FixedZone("offset", 8*60*60))); err == nil {
		t.Fatal("temporary decision accepted a non-UTC deadline")
	}
	value := TemporaryDecisionRecord{
		Session: session, PublicRunRef: request.PublicRunRef, RuntimeRequestID: request.RuntimeRequestID,
		Decision:  decision,
		CreatedAt: stateTestTime,
	}
	poisoned, err := temporaryDecisionForTestInput(PlanningRequest{
		Session: session, RequestID: "request-attacker", RequestedAt: stateTestTime,
	}, spec, stateTestTime.Add(5*time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	poisonedValue := value
	poisonedValue.Decision = poisoned
	if _, _, err := store.FreezeTemporaryDecision(ctx, poisonedValue); !errors.Is(err, ErrStateConflict) {
		t.Fatalf("unbound temporary decision freeze error=%v", err)
	}
	var resolution string
	var decisionRows int
	if err := store.db.QueryRow(`SELECT resolution FROM channel_requests WHERE public_run_ref=?`, request.PublicRunRef).Scan(&resolution); err != nil || resolution != string(requestReserved) {
		t.Fatalf("unbound decision poisoned request resolution=%q err=%v", resolution, err)
	}
	if err := store.db.QueryRow(`SELECT COUNT(*) FROM temporary_decisions WHERE public_run_ref=?`, request.PublicRunRef).Scan(&decisionRows); err != nil || decisionRows != 0 {
		t.Fatalf("unbound decision persisted rows=%d err=%v", decisionRows, err)
	}
	stored, changed, err := store.FreezeTemporaryDecision(ctx, value)
	if err != nil || !changed || stored.Decision != value.Decision || stored.DecisionSHA256 == "" {
		t.Fatalf("FreezeTemporaryDecision()=%+v changed=%v err=%v", stored, changed, err)
	}
	if _, err := json.Marshal(stored.Decision); err == nil {
		t.Fatal("protected temporary decision allowed ordinary JSON projection")
	}
	if formatted := fmt.Sprintf("%v %+v %#v", stored.Decision, stored.Decision, stored.Decision); strings.Contains(formatted, "opaque-temporary-source") {
		t.Fatalf("protected temporary decision leaked through formatting: %s", formatted)
	}
	var frozenJSON string
	if err := store.db.QueryRow(`SELECT decision_json FROM temporary_decisions WHERE public_run_ref=?`, request.PublicRunRef).Scan(&frozenJSON); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(frozenJSON, "opaque-temporary-source") || !strings.Contains(frozenJSON, "snapshot-read") ||
		strings.Contains(frozenJSON, "rtsp://") || strings.Contains(frozenJSON, "password=") {
		t.Fatalf("dedicated temporary decision storage wire is incomplete or unsafe: %s", frozenJSON)
	}
	if _, changed, err := store.FreezeTemporaryDecision(ctx, value); err != nil || changed {
		t.Fatalf("idempotent temporary freeze changed=%v err=%v", changed, err)
	}
	conflict := value
	conflict.Decision.request.AudienceSHA256 = testDigest("different-audience")
	if _, _, err := store.FreezeTemporaryDecision(ctx, conflict); !errors.Is(err, ErrStateConflict) {
		t.Fatalf("conflicting temporary decision error=%v", err)
	}
	bound, changed, err := store.BindTemporaryRun(ctx, session, request.PublicRunRef, "temporary-runtime-state", stateTestTime.Add(time.Second))
	if err != nil || !changed || bound.Resolution != requestTemporaryBound || bound.InternalRunID != "temporary-runtime-state" {
		t.Fatalf("BindTemporaryRun()=%+v changed=%v err=%v", bound, changed, err)
	}
	if _, changed, err := store.BindTemporaryRun(ctx, session, request.PublicRunRef, "temporary-runtime-state", stateTestTime.Add(2*time.Second)); err != nil || changed {
		t.Fatalf("idempotent temporary bind changed=%v err=%v", changed, err)
	}
	if _, _, err := store.BindRun(ctx, session, request.PublicRunRef, "standard-runtime", stateTestTime.Add(2*time.Second)); !errors.Is(err, ErrStateConflict) {
		t.Fatalf("temporary-to-standard bind error=%v", err)
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
	reopened, err := OpenState(testStateConfig(path))
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.Close()
	persisted, err := reopened.GetTemporaryDecision(ctx, session, request.PublicRunRef)
	if err != nil || persisted.RecordSHA256 != stored.RecordSHA256 || persisted.Decision != value.Decision {
		t.Fatalf("reopened temporary decision=%+v err=%v", persisted, err)
	}
	mapping, err := reopened.GetRunMapping(ctx, session, request.PublicRunRef)
	if err != nil || mapping.InternalRunID != "temporary-runtime-state" || mapping.RequestKind != "temporary" {
		t.Fatalf("reopened temporary mapping=%+v err=%v", mapping, err)
	}
}

func TestStatePersistsSafeInteractionAndRejectsCrossResolution(t *testing.T) {
	store, err := OpenState(testStateConfig(protectedStatePath(t, "interaction.db")))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	session := testSession()
	raw, digest, _ := canonicalRequest(httpapi.InspectionRequest{Instruction: "查看入口"})
	record, _, err := store.ReserveRequest(context.Background(), RequestReservation{
		Session: session, IdempotencyKey: "interaction-key", RequestJSON: raw, RequestSHA256: digest,
		PublicRunRef: "run-interaction", RuntimeRequestID: "request-interaction", CreatedAt: stateTestTime,
	})
	if err != nil {
		t.Fatal(err)
	}
	interaction := httpapi.InteractionRequired{
		Title: "需要先完成现场接入", Message: "请在本机管理页面完成设备接入。", ActionLabel: "前往本机管理页面",
		Capability: "operator.onboarding", HandoffRef: "handoff-local-one",
	}
	stored, changed, err := store.MarkInteraction(context.Background(), session, record.PublicRunRef, interaction, stateTestTime.Add(time.Second))
	if err != nil || !changed || stored.Resolution != requestInteraction {
		t.Fatalf("MarkInteraction()=%+v changed=%v err=%v", stored, changed, err)
	}
	if _, _, err := store.MarkInteraction(context.Background(), session, record.PublicRunRef, interaction, stateTestTime.Add(2*time.Second)); err != nil {
		t.Fatalf("idempotent MarkInteraction() err=%v", err)
	}
	if _, _, err := store.BindRun(context.Background(), session, record.PublicRunRef, "runtime-run-one", stateTestTime.Add(2*time.Second)); !errors.Is(err, ErrStateConflict) {
		t.Fatalf("interaction-to-run transition error=%v", err)
	}
}

func TestStateRejectsRowTamperAndUnknownSchema(t *testing.T) {
	ctx := context.Background()
	path := protectedStatePath(t, "tamper.db")
	store, err := OpenState(testStateConfig(path))
	if err != nil {
		t.Fatal(err)
	}
	session := testSession()
	raw, digest, _ := canonicalRequest(httpapi.InspectionRequest{Instruction: "查看入口"})
	if _, _, err := store.ReserveRequest(ctx, RequestReservation{
		Session: session, IdempotencyKey: "tamper-key", RequestJSON: raw, RequestSHA256: digest,
		PublicRunRef: "run-tamper", RuntimeRequestID: "request-tamper", CreatedAt: stateTestTime,
	}); err != nil {
		t.Fatal(err)
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
	database, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := database.Exec(`PRAGMA foreign_keys=ON; DROP TRIGGER channel_requests_transition_guard`); err != nil {
		database.Close()
		t.Fatal(err)
	}
	if _, err := database.Exec(`UPDATE channel_requests SET request_kind='standard', resolution='standard_bound', internal_run_id='tampered-run' WHERE public_run_ref='run-tamper'`); err != nil {
		database.Close()
		t.Fatal(err)
	}
	if _, err := database.Exec(createRequestUpdateGuardSQL); err != nil {
		database.Close()
		t.Fatal(err)
	}
	if err := database.Close(); err != nil {
		t.Fatal(err)
	}
	if reopened, err := OpenState(testStateConfig(path)); err == nil || !errors.Is(err, ErrCorruptState) {
		if reopened != nil {
			reopened.Close()
		}
		t.Fatalf("tampered state open error=%v", err)
	}

	unknownPath := protectedStatePath(t, "unknown.db")
	unknown, err := sql.Open("sqlite", unknownPath)
	if err != nil {
		t.Fatal(err)
	}
	// Version 2 is deliberately rejected. This release directly replaces the
	// pre-production schema instead of carrying a compatibility migration.
	if _, err := unknown.Exec(`CREATE TABLE old_state(value TEXT); PRAGMA user_version=2; PRAGMA application_id=1128616242`); err != nil {
		t.Fatal(err)
	}
	unknown.Close()
	if err := localstate.ProtectFile(unknownPath); err != nil {
		t.Fatal(err)
	}
	if _, err := OpenState(testStateConfig(unknownPath)); !errors.Is(err, ErrUnsupportedStateSchema) {
		t.Fatalf("previous v2 schema error=%v", err)
	}
}

func TestStateRecoversOnlyAnEmptyVersionZeroInitializationFile(t *testing.T) {
	path := protectedStatePath(t, "interrupted-initialization.db")
	file, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_RDWR, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	if err := file.Close(); err != nil {
		t.Fatal(err)
	}
	if err := localstate.ProtectFile(path); err != nil {
		t.Fatal(err)
	}
	store, err := OpenState(testStateConfig(path))
	if err != nil {
		t.Fatalf("recover empty version-zero state: %v", err)
	}
	defer store.Close()

	tooShort := testStateConfig(protectedStatePath(t, "short-retention.db"))
	tooShort.RequestRetention = 24 * time.Hour
	if _, err := OpenState(tooShort); !errors.Is(err, ErrUnsupportedStateSchema) {
		t.Fatalf("24h request retention error=%v", err)
	}
}

func TestStateResolvesOneDeliveryAudienceAndPurgesProtectedBindings(t *testing.T) {
	ctx := context.Background()
	store, err := OpenState(testStateConfig(protectedStatePath(t, "retention.db")))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	session := testSession()
	raw, digest, _ := canonicalRequest(httpapi.InspectionRequest{Instruction: "查看入口"})
	record, _, err := store.ReserveRequest(ctx, RequestReservation{
		Session: session, IdempotencyKey: "retention-run", RequestJSON: raw, RequestSHA256: digest,
		PublicRunRef: "run-retention", RuntimeRequestID: "request-retention", CreatedAt: stateTestTime,
	})
	if err != nil {
		t.Fatal(err)
	}
	freezeStateTestDecision(t, store, record, stateTestTime)
	if _, _, err := store.BindRun(ctx, session, record.PublicRunRef, "runtime-retention", stateTestTime.Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	audience, err := store.ResolveRunAudience(ctx, "runtime-retention")
	if err != nil || audience.PublicRunRef != record.PublicRunRef || audience.Audience.Channel != session.Channel ||
		audience.Audience.ConversationRef != session.ConversationRef || audience.Audience.RecipientRef != session.RecipientRef ||
		audience.PrincipalSHA256 != session.PrincipalSHA256 {
		t.Fatalf("ResolveRunAudience()=%+v err=%v", audience, err)
	}
	projected, err := json.Marshal(audience)
	if err != nil || strings.Contains(string(projected), session.PrincipalSHA256) || strings.Contains(fmt.Sprintf("%+v %#v", audience, audience), session.PrincipalSHA256) {
		t.Fatalf("protected run audience leaked principal json=%s formatted=%+v err=%v", projected, audience, err)
	}

	other := session
	other.ConversationRef = "conversation-two"
	other.RecipientRef = "recipient-two"
	secondRaw, secondDigest, _ := canonicalRequest(httpapi.InspectionRequest{Instruction: "查看出口"})
	second, _, err := store.ReserveRequest(ctx, RequestReservation{
		Session: other, IdempotencyKey: "retention-second", RequestJSON: secondRaw, RequestSHA256: secondDigest,
		PublicRunRef: "run-retention-two", RuntimeRequestID: "request-retention-two", CreatedAt: stateTestTime,
	})
	if err != nil {
		t.Fatal(err)
	}
	freezeStateTestDecision(t, store, second, stateTestTime)
	if _, _, err := store.BindRun(ctx, other, second.PublicRunRef, "runtime-retention", stateTestTime.Add(time.Second)); !errors.Is(err, ErrStateConflict) {
		t.Fatalf("duplicate internal run audience error=%v", err)
	}

	mediaRecord := MediaCapabilityRecord{
		Session: session, PublicRunRef: record.PublicRunRef, PublicMediaRef: "media-retention",
		InternalRunID: "runtime-retention", MediaBindingRunID: "runtime-retention", InternalMediaRef: "internal-retention-image",
		SHA256: testDigest("retention-image"), SizeBytes: 100, ContentType: "image/jpeg", Audience: "run-owner", Title: "入口现场快照",
		CreatedAt: stateTestTime.Add(time.Minute), ExpiresAt: stateTestTime.Add(10 * time.Minute),
	}
	if _, err := store.EnsureMediaCapability(ctx, mediaRecord, mediaRecord.CreatedAt); err != nil {
		t.Fatal(err)
	}
	feedback := httpapi.FeedbackRequest{Helpful: boolPointer(true), Comment: "有帮助"}
	feedbackJSON, _ := json.Marshal(feedback)
	feedbackDigest := sha256.Sum256(feedbackJSON)
	if _, err := store.RecordFeedback(ctx, FeedbackRecord{
		Session: session, PublicRunRef: record.PublicRunRef, IdempotencyKey: "retention-feedback",
		FeedbackJSON: feedbackJSON, FeedbackSHA256: hex.EncodeToString(feedbackDigest[:]), CreatedAt: stateTestTime.Add(2 * time.Minute),
	}); err != nil {
		t.Fatal(err)
	}
	report, err := store.PurgeExpired(ctx, stateTestTime.Add(11*time.Minute))
	if err != nil || report.MediaCapabilities != 1 || report.FeedbackRecords != 0 || report.RequestRecords != 0 {
		t.Fatalf("early PurgeExpired()=%+v err=%v", report, err)
	}
	var retainedMediaBindings int
	if err := store.db.QueryRow(`SELECT COUNT(*) FROM media_capabilities WHERE internal_media_ref='internal-retention-image'`).Scan(&retainedMediaBindings); err != nil || retainedMediaBindings != 0 {
		t.Fatalf("expired internal media bindings=%d err=%v", retainedMediaBindings, err)
	}
	report, err = store.PurgeExpired(ctx, stateTestTime.Add(31*24*time.Hour))
	if err != nil || report.FeedbackRecords != 1 || report.StandardDecisions != 2 || report.RequestRecords != 2 {
		t.Fatalf("retention PurgeExpired()=%+v err=%v", report, err)
	}
	if _, err := store.ResolveRunAudience(ctx, "runtime-retention"); !errors.Is(err, ErrStateNotFound) {
		t.Fatalf("purged run audience error=%v", err)
	}
}

func TestScheduledBindingsRequireExplicitProductProofForRetentionOrAbandonment(t *testing.T) {
	ctx := context.Background()
	store, err := OpenState(testStateConfig(protectedStatePath(t, "scheduled-retention.db")))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	retained := freezeScheduledStateTestDecision(t, store, "retained", stateTestTime)
	abandoned := freezeScheduledStateTestDecision(t, store, "abandoned", stateTestTime.Add(time.Second))

	report, err := store.PurgeExpired(ctx, stateTestTime.Add(31*24*time.Hour))
	if err != nil || report.ScheduledDecisions != 0 {
		t.Fatalf("generic PurgeExpired()=%+v err=%v", report, err)
	}
	if _, err := store.GetScheduledDecisionByRunID(ctx, retained.InternalRunID); err != nil {
		t.Fatalf("generic purge removed submitted schedule state: %v", err)
	}
	if audience, err := store.ResolveRunAudience(ctx, retained.InternalRunID); err != nil || audience.PublicRunRef != retained.PublicRunRef {
		t.Fatalf("retention-expired scheduled audience became unusable before coordinated cleanup: %+v err=%v", audience, err)
	}
	candidates, err := store.ListScheduledPurgeCandidates(ctx, stateTestTime.Add(31*24*time.Hour), 10)
	if err != nil || len(candidates) != 2 {
		t.Fatalf("ListScheduledPurgeCandidates()=%d err=%v", len(candidates), err)
	}
	var retainedCandidate ScheduledPurgeCandidate
	for _, candidate := range candidates {
		if candidate.InternalRunID == retained.InternalRunID {
			retainedCandidate = candidate
		}
	}
	if retainedCandidate.InternalRunID == "" {
		t.Fatal("retained candidate missing")
	}
	changed, err := store.PurgeScheduledCandidate(ctx, retainedCandidate, stateTestTime.Add(31*24*time.Hour))
	if err != nil || !changed {
		t.Fatalf("PurgeScheduledCandidate() changed=%v err=%v", changed, err)
	}
	if _, err := store.GetScheduledDecisionByRunID(ctx, retained.InternalRunID); !errors.Is(err, ErrStateNotFound) {
		t.Fatalf("explicitly purged decision remained: %v", err)
	}
	changed, err = store.AbandonScheduledDecision(ctx, abandoned)
	if err != nil || !changed {
		t.Fatalf("AbandonScheduledDecision() changed=%v err=%v", changed, err)
	}
	if _, err := store.ResolveRunAudience(ctx, abandoned.InternalRunID); !errors.Is(err, ErrStateNotFound) {
		t.Fatalf("abandoned audience remained: %v", err)
	}
}

func boolPointer(value bool) *bool { return &value }

func freezeStateTestDecision(t *testing.T, store *StateStore, record RequestRecord, createdAt time.Time) StandardDecisionRecord {
	t.Helper()
	template, assignment := genericCatalogFixture(record.Session)
	request := inspection.CreateRunRequest{
		Schema: inspection.SchemaVersion, TenantID: record.Session.TenantID, SiteID: record.Session.SiteID,
		TemplateID: template.TemplateID, TemplateRevision: template.Revision,
		AssignmentID: assignment.AssignmentID, AssignmentRevision: assignment.Revision,
		Origin: inspection.OriginUser, RequestID: record.RuntimeRequestID,
		Variables: map[string]string{"focus": "entrance"}, RequestedAt: record.CreatedAt,
		Deadline: record.CreatedAt.Add(5 * time.Minute),
	}
	plan, err := inspection.CompilePlan(template, assignment, request)
	if err != nil {
		t.Fatal(err)
	}
	decision, changed, err := store.FreezeStandardDecision(context.Background(), StandardDecisionRecord{
		Session: record.Session, PublicRunRef: record.PublicRunRef, PlanSHA256: plan.PlanSHA256,
		Template: template, Assignment: assignment, RunRequest: request, CreatedAt: createdAt,
	})
	if err != nil || !changed {
		t.Fatalf("FreezeStandardDecision()=%+v changed=%v err=%v", decision, changed, err)
	}
	return decision
}

func freezeScheduledStateTestDecision(t *testing.T, store *StateStore, suffix string, createdAt time.Time) ScheduledDecisionRecord {
	t.Helper()
	session := testSession()
	template, assignment := genericCatalogFixture(session)
	request := inspection.CreateRunRequest{
		Schema: inspection.SchemaVersion, TenantID: session.TenantID, SiteID: session.SiteID,
		TemplateID: template.TemplateID, TemplateRevision: template.Revision,
		AssignmentID: assignment.AssignmentID, AssignmentRevision: assignment.Revision,
		Origin: inspection.OriginSchedule, RequestID: "scheduled-request-" + suffix,
		Variables: map[string]string{"focus": "entrance"}, RequestedAt: createdAt,
		Deadline: createdAt.Add(5 * time.Minute),
	}
	plan, err := inspection.CompilePlan(template, assignment, request)
	if err != nil {
		t.Fatal(err)
	}
	requestJSON, err := json.Marshal(request)
	if err != nil {
		t.Fatal(err)
	}
	audience := delivery.Audience{
		TenantID: session.TenantID, SiteID: session.SiteID, Channel: session.Channel,
		ConversationRef: session.ConversationRef, RecipientRef: session.RecipientRef,
	}
	audienceSHA, err := audience.SHA256()
	if err != nil {
		t.Fatal(err)
	}
	value := ScheduledDecisionRecord{
		Session: session, PublicRunRef: "scheduled-public-" + suffix, InternalRunID: "runtime-scheduled-" + suffix,
		OccurrenceID: "occurrence-scheduled-" + suffix, SubmissionRef: "submission-scheduled-" + suffix,
		BindingRef: "binding-" + suffix, BindingRevision: 1, AudienceSHA256: audienceSHA,
		DeliverySHA256: testDigest("delivery-" + suffix), ServicePrincipalSHA256: testDigest("service-" + suffix),
		OccurrenceSHA256: testDigest("occurrence-" + suffix), RequestSHA256: testDigest(string(requestJSON)),
		PlanSHA256: plan.PlanSHA256, Template: template, Assignment: assignment, RunRequest: request, CreatedAt: createdAt,
	}
	stored, created, err := store.FreezeScheduledDecision(context.Background(), value)
	if err != nil || !created {
		t.Fatalf("FreezeScheduledDecision() created=%v err=%v", created, err)
	}
	return stored
}

func testDigest(value string) string {
	digest := sha256.Sum256([]byte(value))
	return hex.EncodeToString(digest[:])
}

func protectedStatePath(t *testing.T, name string) string {
	t.Helper()
	root := filepath.Join(t.TempDir(), "protected")
	if err := localstate.PrepareStateRoot(root); err != nil {
		t.Fatal(err)
	}
	return filepath.Join(root, name)
}

func testSession() httpapi.SessionBinding {
	return httpapi.SessionBinding{
		TenantID: "tenant-alpha", SiteID: "site-north", Channel: "workbuddy_wechat",
		ConversationRef: "conversation-one", RecipientRef: "recipient-one", PrincipalSHA256: testDigest("principal-one"),
	}
}

func testStateConfig(path string) StateConfig {
	return StateConfig{
		Path: path, RequestRetention: 30 * 24 * time.Hour, FeedbackRetention: 30 * 24 * time.Hour,
		Now: func() time.Time { return stateTestTime },
	}
}
