package store

import (
	"context"
	"encoding/json"
	"fmt"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/cosmo-wander-ai/cosmoedge-connect/internal/inspection"
)

func TestInspectionTemplateAndAssignmentReadsRejectStoredTampering(t *testing.T) {
	store := openStore(t, filepath.Join(t.TempDir(), "operator.db"))
	defer store.Close()
	ctx := context.Background()
	now := fixtureNow()
	template, assignment := fixtureInspectionTemplate(now), fixtureAssignment()
	if err := store.SaveInspectionTemplate(ctx, template); err != nil {
		t.Fatal(err)
	}
	if err := store.SaveAssignment(ctx, assignment, now); err != nil {
		t.Fatal(err)
	}

	var templateJSON string
	if err := store.db.QueryRow(`SELECT template_json FROM inspection_templates WHERE tenant_id=? AND template_id=? AND revision=?`, template.TenantID, template.TemplateID, template.Revision).Scan(&templateJSON); err != nil {
		t.Fatal(err)
	}
	tamperedTemplate := strings.Replace(templateJSON, "Visible hygiene", "Changed hygiene", 1)
	if _, err := store.db.Exec(`UPDATE inspection_templates SET template_json=? WHERE tenant_id=? AND template_id=? AND revision=?`, tamperedTemplate, template.TenantID, template.TemplateID, template.Revision); err == nil {
		t.Fatal("immutable template trigger allowed tampering")
	}
	if _, err := store.db.Exec(`DROP TRIGGER inspection_templates_no_update`); err != nil {
		t.Fatal(err)
	}
	if _, err := store.db.Exec(`UPDATE inspection_templates SET template_json=? WHERE tenant_id=? AND template_id=? AND revision=?`, tamperedTemplate, template.TenantID, template.TemplateID, template.Revision); err != nil {
		t.Fatal(err)
	}
	if _, err := store.GetInspectionTemplate(ctx, template.TenantID, template.TemplateID, template.Revision); err == nil {
		t.Fatal("template digest tampering was accepted")
	}
	if _, err := store.ListInspectionTemplates(ctx, template.TenantID); err == nil {
		t.Fatal("template list accepted digest tampering")
	}
	if err := store.SaveInspectionTemplate(ctx, template); err == nil {
		t.Fatal("idempotent template save accepted stored tampering")
	}

	var assignmentJSON string
	if err := store.db.QueryRow(`SELECT assignment_json FROM inspection_assignments WHERE tenant_id=? AND assignment_id=? AND revision=?`, assignment.TenantID, assignment.AssignmentID, assignment.Revision).Scan(&assignmentJSON); err != nil {
		t.Fatal(err)
	}
	tamperedAssignment := strings.Replace(assignmentJSON, "source-east", "source-west", 1)
	if _, err := store.db.Exec(`UPDATE inspection_assignments SET assignment_json=? WHERE tenant_id=? AND assignment_id=? AND revision=?`, tamperedAssignment, assignment.TenantID, assignment.AssignmentID, assignment.Revision); err == nil {
		t.Fatal("immutable assignment trigger allowed tampering")
	}
	if _, err := store.db.Exec(`DROP TRIGGER inspection_assignments_no_update`); err != nil {
		t.Fatal(err)
	}
	if _, err := store.db.Exec(`UPDATE inspection_assignments SET assignment_json=? WHERE tenant_id=? AND assignment_id=? AND revision=?`, tamperedAssignment, assignment.TenantID, assignment.AssignmentID, assignment.Revision); err != nil {
		t.Fatal(err)
	}
	if _, err := store.GetAssignment(ctx, assignment.TenantID, assignment.AssignmentID, assignment.Revision); err == nil {
		t.Fatal("assignment digest tampering was accepted")
	}
	if err := store.SaveAssignment(ctx, assignment, now.Add(time.Second)); err == nil {
		t.Fatal("idempotent assignment save accepted stored tampering")
	}
	if _, err := store.db.Exec(`UPDATE inspection_assignments SET assignment_json=?, site_id='site-tampered' WHERE tenant_id=? AND assignment_id=? AND revision=?`, assignmentJSON, assignment.TenantID, assignment.AssignmentID, assignment.Revision); err != nil {
		t.Fatal(err)
	}
	if _, err := store.GetAssignment(ctx, assignment.TenantID, assignment.AssignmentID, assignment.Revision); err == nil {
		t.Fatal("assignment row metadata tampering was accepted")
	}
}

func TestPlanReadsAndExecutionPathsRejectStoredTampering(t *testing.T) {
	ctx := context.Background()
	now := fixtureNow()

	t.Run("get and claim", func(t *testing.T) {
		store := openStore(t, filepath.Join(t.TempDir(), "operator.db"))
		defer store.Close()
		plan := fixturePlan(t, now, "tamper-claim", 5*time.Minute)
		if _, _, err := store.CreateQueuedRun(ctx, plan, "run-tamper-claim", now); err != nil {
			t.Fatal(err)
		}
		tamperStoredPlan(t, store, "run-tamper-claim")
		if _, err := store.GetPlan(ctx, "run-tamper-claim"); err == nil {
			t.Fatal("GetPlan accepted a tampered plan")
		}
		if _, _, ok, err := store.ClaimNext(ctx, "worker-a", now.Add(time.Second), time.Minute); err == nil || ok {
			t.Fatalf("ClaimNext tampered plan ok=%v err=%v", ok, err)
		}
		var state inspection.RunState
		if err := store.db.QueryRow(`SELECT state FROM inspection_runs WHERE run_id='run-tamper-claim'`).Scan(&state); err != nil || state != inspection.RunQueued {
			t.Fatalf("failed claim was not rolled back: state=%s err=%v", state, err)
		}
	})

	t.Run("run metadata", func(t *testing.T) {
		store := openStore(t, filepath.Join(t.TempDir(), "operator.db"))
		defer store.Close()
		plan := fixturePlan(t, now, "tamper-binding", 5*time.Minute)
		if _, _, err := store.CreateQueuedRun(ctx, plan, "run-tamper-binding", now); err != nil {
			t.Fatal(err)
		}
		if _, err := store.db.Exec(`UPDATE inspection_runs SET site_id='site-tampered' WHERE run_id='run-tamper-binding'`); err != nil {
			t.Fatal(err)
		}
		if _, err := store.GetPlan(ctx, "run-tamper-binding"); err == nil {
			t.Fatal("GetPlan accepted mismatched run metadata")
		}
	})

	t.Run("typed result and recovery", func(t *testing.T) {
		store := openStore(t, filepath.Join(t.TempDir(), "operator.db"))
		defer store.Close()
		plan := fixturePlan(t, now, "tamper-running", 5*time.Minute)
		if _, _, err := store.CreateQueuedRun(ctx, plan, "run-tamper-running", now); err != nil {
			t.Fatal(err)
		}
		if _, _, ok, err := store.ClaimNext(ctx, "worker-a", now.Add(time.Second), time.Minute); err != nil || !ok {
			t.Fatalf("claim ok=%v err=%v", ok, err)
		}
		tamperStoredPlan(t, store, "run-tamper-running")
		observation := fixtureObservation(t, plan, "run-tamper-running", "media_0123456789abcdef0123456789abcdef", now.Add(4*time.Second))
		if err := store.RecordObservation(ctx, "worker-a", observation, now.Add(5*time.Second)); err == nil {
			t.Fatal("observation persistence accepted a tampered plan")
		}
		if recovered, err := store.RecoverInterrupted(ctx, now.Add(62*time.Second)); err == nil || recovered != 0 {
			t.Fatalf("recovery accepted tampered plan: recovered=%d err=%v", recovered, err)
		}
		var state inspection.RunState
		if err := store.db.QueryRow(`SELECT state FROM inspection_runs WHERE run_id='run-tamper-running'`).Scan(&state); err != nil || state != inspection.RunRunning {
			t.Fatalf("tampered recovery mutated run state=%s err=%v", state, err)
		}
	})
}

func TestRunReadsRejectMalformedStateResourcesAndBindings(t *testing.T) {
	ctx := context.Background()
	now := fixtureNow()
	tests := map[string]string{
		"request-key":             `UPDATE inspection_runs SET request_key='req_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa' WHERE run_id='run-integrity'`,
		"plan-digest":             `UPDATE inspection_runs SET plan_sha256='not-a-digest' WHERE run_id='run-integrity'`,
		"state":                   `UPDATE inspection_runs SET state='invented' WHERE run_id='run-integrity'`,
		"non-terminal-conclusion": `UPDATE inspection_runs SET conclusion='premature' WHERE run_id='run-integrity'`,
		"persistent-write":        `UPDATE inspection_runs SET persistent_config_writes=1 WHERE run_id='run-integrity'`,
		"resource-bound":          `UPDATE inspection_runs SET temporary_resources=4097 WHERE run_id='run-integrity'`,
		"cleanup-bound":           `UPDATE inspection_runs SET temporary_resources=1, cleanup_pending=2 WHERE run_id='run-integrity'`,
		"time-order":              `UPDATE inspection_runs SET updated_at='2026-07-18T09:59:59.000000000Z' WHERE run_id='run-integrity'`,
	}
	for name, mutation := range tests {
		t.Run(name, func(t *testing.T) {
			store := openStore(t, filepath.Join(t.TempDir(), "operator.db"))
			defer store.Close()
			plan := fixturePlan(t, now, "run-integrity-"+name, 5*time.Minute)
			if _, _, err := store.CreateQueuedRun(ctx, plan, "run-integrity", now); err != nil {
				t.Fatal(err)
			}
			if _, err := store.db.Exec(mutation); err != nil {
				if name == "persistent-write" || name == "cleanup-bound" {
					return
				}
				t.Fatal(err)
			}
			if _, err := store.GetRun(ctx, "run-integrity"); err == nil {
				t.Fatal("GetRun accepted malformed stored run metadata")
			}
		})
	}
}

func TestEventReadsRejectBrokenHistoryAndNoncanonicalPublicData(t *testing.T) {
	ctx := context.Background()
	now := fixtureNow()

	t.Run("state does not match history", func(t *testing.T) {
		store := openStore(t, filepath.Join(t.TempDir(), "operator.db"))
		defer store.Close()
		plan := fixturePlan(t, now, "event-state-binding", 5*time.Minute)
		if _, _, err := store.CreateQueuedRun(ctx, plan, "run-event-state", now); err != nil {
			t.Fatal(err)
		}
		if _, err := store.db.Exec(`UPDATE inspection_runs SET state='running', reason='worker_claimed' WHERE run_id='run-event-state'`); err != nil {
			t.Fatal(err)
		}
		if _, err := store.ListEvents(ctx, "run-event-state"); err == nil {
			t.Fatal("ListEvents accepted history that did not reach the stored run state")
		}
	})

	t.Run("transition from wrong state", func(t *testing.T) {
		store := openStore(t, filepath.Join(t.TempDir(), "operator.db"))
		defer store.Close()
		plan := fixturePlan(t, now, "event-transition", 5*time.Minute)
		if _, _, err := store.CreateQueuedRun(ctx, plan, "run-event-transition", now); err != nil {
			t.Fatal(err)
		}
		if _, err := store.db.Exec(`INSERT INTO inspection_run_events(run_id, event_type, from_state, to_state, reason, occurred_at, public_json) VALUES('run-event-transition', 'state_changed', 'running', 'failed', 'invented_failure', ?, '{}')`, formatTime(now.Add(time.Second))); err != nil {
			t.Fatal(err)
		}
		if _, err := store.ListEvents(ctx, "run-event-transition"); err == nil {
			t.Fatal("ListEvents accepted a transition detached from prior state")
		}
	})

	t.Run("duplicate public key", func(t *testing.T) {
		store := openStore(t, filepath.Join(t.TempDir(), "operator.db"))
		defer store.Close()
		plan := fixturePlan(t, now, "event-public-json", 5*time.Minute)
		if _, _, err := store.CreateQueuedRun(ctx, plan, "run-event-public", now); err != nil {
			t.Fatal(err)
		}
		if _, _, ok, err := store.ClaimNext(ctx, "worker-a", now.Add(time.Second), time.Minute); err != nil || !ok {
			t.Fatalf("claim ok=%v err=%v", ok, err)
		}
		raw := `{"assessment":"meets_rule","assessment":"meets_rule","criterionId":"criterion-1","outputKind":"enum","resultId":"result-1","targetId":"target-1"}`
		if _, err := store.db.Exec(`INSERT INTO inspection_run_events(run_id, event_type, reason, occurred_at, public_json) VALUES('run-event-public', 'result_recorded', 'typed_result_validated', ?, ?)`, formatTime(now.Add(2*time.Second)), raw); err != nil {
			t.Fatal(err)
		}
		if _, err := store.ListEvents(ctx, "run-event-public"); err == nil {
			t.Fatal("ListEvents accepted duplicate public JSON keys")
		}
	})
}

func TestResourceUsageRejectsRuntimeWideOverflow(t *testing.T) {
	store := openStore(t, filepath.Join(t.TempDir(), "operator.db"))
	defer store.Close()
	ctx := context.Background()
	now := fixtureNow()
	plan := fixturePlan(t, now, "resource-overflow", 5*time.Minute)
	if _, _, err := store.CreateQueuedRun(ctx, plan, "run-resource-overflow", now); err != nil {
		t.Fatal(err)
	}
	if _, _, ok, err := store.ClaimNext(ctx, "worker-a", now.Add(time.Second), time.Minute); err != nil || !ok {
		t.Fatalf("claim ok=%v err=%v", ok, err)
	}
	if err := store.RecordResourceUsage(ctx, "run-resource-overflow", "worker-a", maxStoredTemporaryResources+1, 0, now.Add(2*time.Second)); err == nil {
		t.Fatal("RecordResourceUsage accepted more resources than the runtime-wide bound")
	}
}

func TestResultMediaIsBoundToTypedResultAndAppendOnly(t *testing.T) {
	store := openStore(t, filepath.Join(t.TempDir(), "operator.db"))
	defer store.Close()
	ctx := context.Background()
	now := fixtureNow()
	plan := fixturePlan(t, now, "result-media-binding", 5*time.Minute)
	if _, _, err := store.CreateQueuedRun(ctx, plan, "run-result-media", now); err != nil {
		t.Fatal(err)
	}
	if _, _, ok, err := store.ClaimNext(ctx, "worker-a", now.Add(time.Second), time.Minute); err != nil || !ok {
		t.Fatalf("claim ok=%v err=%v", ok, err)
	}
	mediaRef := "media_0123456789abcdef0123456789abcdef"
	completeStepsThroughFirstMedia(t, store, plan, "run-result-media", "worker-a", now.Add(2*time.Second), mediaRef)
	observation := fixtureObservation(t, plan, "run-result-media", mediaRef, now.Add(3*time.Second))
	if err := store.RecordObservation(ctx, "worker-a", observation, now.Add(4*time.Second)); err != nil {
		t.Fatal(err)
	}
	var count int
	if err := store.db.QueryRow(`SELECT COUNT(*) FROM inspection_result_media WHERE observation_id=? AND media_ref=? AND content_sha256=?`, observation.ObservationID, mediaRef, strings.Repeat("a", 64)).Scan(&count); err != nil || count != 1 {
		t.Fatalf("result media count=%d err=%v", count, err)
	}
	if _, err := store.db.Exec(`UPDATE inspection_result_media SET content_sha256=? WHERE observation_id=?`, strings.Repeat("b", 64), observation.ObservationID); err == nil {
		t.Fatal("append-only result media trigger allowed update")
	}
	if _, err := store.db.Exec(`DELETE FROM inspection_result_media WHERE observation_id=?`, observation.ObservationID); err == nil {
		t.Fatal("append-only result media trigger allowed delete")
	}
	if _, err := store.db.Exec(`DROP TRIGGER inspection_result_media_no_delete`); err != nil {
		t.Fatal(err)
	}
	if _, err := store.db.Exec(`DELETE FROM inspection_result_media WHERE observation_id=?`, observation.ObservationID); err != nil {
		t.Fatal(err)
	}
	if _, err := store.ListObservations(ctx, "run-result-media"); err == nil {
		t.Fatal("ListObservations accepted an incomplete media binding")
	}
}

func TestStoredObservationOutcomeEventAndOutboxReadsFailClosed(t *testing.T) {
	store := openStore(t, filepath.Join(t.TempDir(), "operator.db"))
	defer store.Close()
	ctx := context.Background()
	now := fixtureNow()
	plan := fixturePlan(t, now, "tamper-reads", 5*time.Minute)
	if _, _, err := store.CreateQueuedRun(ctx, plan, "run-tamper-reads", now); err != nil {
		t.Fatal(err)
	}
	if _, _, ok, err := store.ClaimNext(ctx, "worker-a", now.Add(time.Second), time.Minute); err != nil || !ok {
		t.Fatalf("claim ok=%v err=%v", ok, err)
	}
	mediaRef := "media_0123456789abcdef0123456789abcdef"
	completeStepsThroughFirstMedia(t, store, plan, "run-tamper-reads", "worker-a", now.Add(2*time.Second), mediaRef)
	observation := fixtureObservation(t, plan, "run-tamper-reads", mediaRef, now.Add(3*time.Second))
	if err := store.RecordObservation(ctx, "worker-a", observation, now.Add(4*time.Second)); err != nil {
		t.Fatal(err)
	}
	if _, err := store.db.Exec(`UPDATE inspection_results SET assessment='meets_rule' WHERE observation_id=?`, observation.ObservationID); err == nil {
		t.Fatal("append-only result trigger allowed tampering")
	}
	if _, err := store.db.Exec(`DROP TRIGGER inspection_results_no_update`); err != nil {
		t.Fatal(err)
	}
	if _, err := store.db.Exec(`UPDATE inspection_results SET assessment='meets_rule' WHERE observation_id=?`, observation.ObservationID); err != nil {
		t.Fatal(err)
	}
	if err := store.RecordObservation(ctx, "worker-a", observation, now.Add(4*time.Second)); err == nil {
		t.Fatal("idempotent observation persistence accepted row tampering")
	}
	if _, err := store.db.Exec(`UPDATE inspection_results SET assessment=? WHERE observation_id=?`, observation.Result.Assessment, observation.ObservationID); err != nil {
		t.Fatal(err)
	}
	if err := store.BeginFinalization(ctx, "run-tamper-reads", "worker-a", now.Add(4*time.Second)); err != nil {
		t.Fatal(err)
	}
	outcome, err := inspection.Evaluate(plan, []inspection.Observation{observation})
	if err != nil {
		t.Fatal(err)
	}
	if err := store.Finalize(ctx, "run-tamper-reads", "worker-a", outcome, now.Add(5*time.Second)); err != nil {
		t.Fatal(err)
	}

	if _, err := store.db.Exec(`UPDATE inspection_results SET assessment='meets_rule' WHERE observation_id=?`, observation.ObservationID); err != nil {
		t.Fatal(err)
	}
	if _, err := store.ListObservations(ctx, "run-tamper-reads"); err == nil {
		t.Fatal("ListObservations accepted row tampering")
	}
	if _, err := store.db.Exec(`UPDATE inspection_runs SET conclusion='tampered conclusion' WHERE run_id='run-tamper-reads'`); err != nil {
		t.Fatal(err)
	}
	if _, present, err := store.GetOutcome(ctx, "run-tamper-reads"); err == nil || present {
		t.Fatalf("GetOutcome accepted row tampering: present=%v err=%v", present, err)
	}
	if _, err := store.db.Exec(`UPDATE inspection_run_events SET reason='invalid
reason' WHERE run_id='run-tamper-reads' AND sequence=(SELECT MAX(sequence) FROM inspection_run_events WHERE run_id='run-tamper-reads')`); err == nil {
		// The append-only trigger is itself an integrity boundary. Verify reads
		// separately by inserting a corrupt legacy-style row directly.
		t.Fatal("append-only event trigger allowed tampering")
	}
	if _, err := store.db.Exec(`INSERT INTO inspection_run_events(run_id, event_type, reason, occurred_at, public_json) VALUES('run-tamper-reads', 'tampered_event', 'invalid
reason', ?, '{}')`, formatTime(now.Add(6*time.Second))); err != nil {
		t.Fatal(err)
	}
	if _, err := store.ListEvents(ctx, "run-tamper-reads"); err == nil {
		t.Fatal("ListEvents accepted invalid stored metadata")
	}
	if _, err := store.db.Exec(`UPDATE inspection_outbox SET payload_json='{}' WHERE run_id='run-tamper-reads'`); err != nil {
		t.Fatal(err)
	}
	if _, err := store.ListOutbox(ctx, "run-tamper-reads"); err == nil {
		t.Fatal("ListOutbox accepted payload tampering")
	}
}

func TestOutcomeValidationEnforcesBoundedUniquePublicReferences(t *testing.T) {
	observedAt := fixtureNow()
	projection := func(index int, evidence string) inspection.ResultProjection {
		return inspection.ResultProjection{
			ResultID: fmt.Sprintf("result-%d", index), SampleID: fmt.Sprintf("sample-%d", index), OutputKind: inspection.ResultEnum,
			Value:        &inspection.ResultValue{Kind: inspection.ResultEnum, Enum: &inspection.EnumValue{Value: "clear"}},
			EvidenceRefs: []string{evidence}, TimeWindow: inspection.ResultTimeWindow{StartAt: observedAt, EndAt: observedAt},
		}
	}
	valid := func() inspection.Outcome {
		return inspection.Outcome{
			State: inspection.RunCompleted, OverallAssessment: inspection.AssessmentMeetsRule,
			Coverage: inspection.Coverage{Required: 1, Conclusive: 1, Ratio: 1},
			Findings: []inspection.Finding{{
				TargetID: "target-1", CriterionID: "criterion-1", Assessment: inspection.AssessmentMeetsRule,
				SampleCount: 1, ReasonCodes: []string{"criterion_met"}, EvidenceRefs: []string{"media-1"},
				Results: []inspection.ResultProjection{projection(1, "media-1")}, ObservedAt: observedAt, Limitations: []string{"fixture_scope"},
			}},
			Conclusion: "Inspection completed.", Reason: "completed",
		}
	}
	refs := func(prefix string, count int) []string {
		values := make([]string, count)
		for index := range values {
			values[index] = prefix + "-" + strings.Repeat("x", index/10) + string(rune('a'+index%10))
		}
		return values
	}

	boundary := valid()
	boundary.Findings[0].SampleCount = 100
	boundary.Findings[0].ReasonCodes = refs("reason", 32)
	boundary.Findings[0].Limitations = refs("limit", 16)
	boundary.Findings[0].EvidenceRefs = refs("media", 32)
	boundary.Findings[0].Results = make([]inspection.ResultProjection, 100)
	for index := range boundary.Findings[0].Results {
		boundary.Findings[0].Results[index] = projection(index, boundary.Findings[0].EvidenceRefs[index%len(boundary.Findings[0].EvidenceRefs)])
	}
	if err := validateOutcome(boundary); err != nil {
		t.Fatalf("valid boundary outcome rejected: %v", err)
	}

	tests := map[string]func(*inspection.Outcome){
		"findings": func(value *inspection.Outcome) {
			value.Findings = make([]inspection.Finding, 10001)
		},
		"sample-count": func(value *inspection.Outcome) {
			value.Findings[0].SampleCount = 101
		},
		"reason-count": func(value *inspection.Outcome) {
			value.Findings[0].ReasonCodes = refs("reason", 33)
		},
		"limitation-count": func(value *inspection.Outcome) {
			value.Findings[0].Limitations = refs("limit", 17)
		},
		"evidence-count": func(value *inspection.Outcome) {
			value.Findings[0].EvidenceRefs = refs("media", 33)
		},
		"duplicate-reason": func(value *inspection.Outcome) {
			value.Findings[0].ReasonCodes = []string{"duplicate", "duplicate"}
		},
		"duplicate-limitation": func(value *inspection.Outcome) {
			value.Findings[0].Limitations = []string{"duplicate", "duplicate"}
		},
		"duplicate-evidence": func(value *inspection.Outcome) {
			value.Findings[0].EvidenceRefs = []string{"duplicate", "duplicate"}
		},
		"invalid-reference": func(value *inspection.Outcome) {
			value.Findings[0].ReasonCodes = []string{"not a ref"}
		},
		"long-conclusion": func(value *inspection.Outcome) {
			value.Conclusion = strings.Repeat("x", 1001)
		},
		"protected-conclusion": func(value *inspection.Outcome) {
			value.Conclusion = "Evidence at rtsp://camera/live"
		},
		"invalid-reason": func(value *inspection.Outcome) {
			value.Reason = "invalid\nreason"
		},
	}
	for name, mutate := range tests {
		t.Run(name, func(t *testing.T) {
			outcome := valid()
			mutate(&outcome)
			if err := validateOutcome(outcome); err == nil {
				t.Fatalf("invalid outcome %s was accepted", name)
			}
		})
	}
}

func tamperStoredPlan(t *testing.T, store *Store, runID string) {
	t.Helper()
	var raw string
	if err := store.db.QueryRow(`SELECT plan_json FROM inspection_runs WHERE run_id=?`, runID).Scan(&raw); err != nil {
		t.Fatal(err)
	}
	tampered := strings.Replace(raw, `"sourceHandle":"source-east"`, `"sourceHandle":"source-tampered"`, 1)
	if tampered == raw || !json.Valid([]byte(tampered)) {
		t.Fatal("fixture plan could not be tampered deterministically")
	}
	if _, err := store.db.Exec(`UPDATE inspection_runs SET plan_json=? WHERE run_id=?`, tampered, runID); err != nil {
		t.Fatal(err)
	}
}
