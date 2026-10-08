package store

import (
	"context"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestListAssignmentsIsStrictlyScopedSortedAndIntegrityChecked(t *testing.T) {
	ctx := context.Background()
	store := openStore(t, filepath.Join(t.TempDir(), "inspection.db"))
	defer store.Close()
	now := fixtureNow()
	template := fixtureInspectionTemplate(now)
	if err := store.SaveInspectionTemplate(ctx, template); err != nil {
		t.Fatal(err)
	}
	second := fixtureAssignment()
	second.AssignmentID = "assignment-z"
	first := fixtureAssignment()
	first.AssignmentID = "assignment-a"
	for _, assignment := range []struct {
		value string
	}{
		{second.AssignmentID}, {first.AssignmentID},
	} {
		item := fixtureAssignment()
		item.AssignmentID = assignment.value
		if err := store.SaveAssignment(ctx, item, now); err != nil {
			t.Fatal(err)
		}
	}
	values, err := store.ListAssignments(ctx, first.TenantID, first.SiteID)
	if err != nil || len(values) != 2 || values[0].AssignmentID != first.AssignmentID || values[1].AssignmentID != second.AssignmentID {
		t.Fatalf("assignments=%#v err=%v", values, err)
	}
	if values, err := store.ListAssignments(ctx, first.TenantID, "other-site"); err != nil || len(values) != 0 {
		t.Fatalf("cross-site assignments=%#v err=%v", values, err)
	}
	if _, err := store.ListAssignments(ctx, "bad tenant", first.SiteID); err == nil {
		t.Fatal("invalid tenant scope was accepted")
	}

	if _, err := store.db.ExecContext(ctx, `DROP TRIGGER inspection_assignments_no_update`); err != nil {
		t.Fatal(err)
	}
	if _, err := store.db.ExecContext(ctx, `UPDATE inspection_assignments SET assignment_json=replace(assignment_json, ?, ?) WHERE tenant_id=? AND assignment_id=?`,
		`"friendlyName":"Dining east"`, `"friendlyName":"Tampered"`, first.TenantID, first.AssignmentID); err != nil {
		t.Fatal(err)
	}
	if _, err := store.ListAssignments(ctx, first.TenantID, first.SiteID); err == nil || !strings.Contains(err.Error(), "integrity binding") {
		t.Fatalf("tampered assignment list error=%v", err)
	}
}

func TestListAssignmentsReturnsLatestAndHistoricalRevisionsInCanonicalOrder(t *testing.T) {
	ctx := context.Background()
	store := openStore(t, filepath.Join(t.TempDir(), "inspection.db"))
	defer store.Close()
	now := fixtureNow()
	template := fixtureInspectionTemplate(now)
	if err := store.SaveInspectionTemplate(ctx, template); err != nil {
		t.Fatal(err)
	}
	first := fixtureAssignment()
	second := first
	second.Revision = 2
	second.Published = false
	if err := store.SaveAssignment(ctx, second, now.Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	if err := store.SaveAssignment(ctx, first, now); err != nil {
		t.Fatal(err)
	}
	values, err := store.ListAssignments(ctx, first.TenantID, first.SiteID)
	if err != nil || len(values) != 2 || values[0].Revision != 1 || values[1].Revision != 2 {
		t.Fatalf("assignment revisions=%#v err=%v", values, err)
	}
}
