package catalog

import (
	"bytes"
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/cosmo-wander-ai/cosmoedge-connect/internal/inspection"
)

func TestDeviceTaskCreateFreezeSummaryAndReopen(t *testing.T) {
	path := filepath.Join(protectedCatalogTestRoot(t), "catalog.db")
	store, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, 7, 19, 14, 0, 0, 0, time.UTC)
	store.now = func() time.Time { return now }
	createTaskSources(t, store, "source-east", "source-west")
	before, err := store.Fingerprint(context.Background(), "tenant-a", "site-a")
	if err != nil {
		t.Fatal(err)
	}
	input := fixtureDeviceTask("task-dining-hygiene", "就餐区卫生巡检", []string{"source-west", "source-east"}, now.Add(-time.Minute))
	created, err := store.CreateTask(context.Background(), input)
	if err != nil {
		t.Fatal(err)
	}
	if created.Revision != 1 || created.SourceHandles[0] != "source-east" ||
		created.Capabilities[0].Ref != "task-cap-count" || created.Capabilities[1].Ref != "task-cap-event" ||
		created.Capabilities[0].Digest == "" || created.ObservedAt != input.ObservedAt {
		t.Fatalf("task was not canonicalized: %#v", created)
	}
	idempotent, err := store.CreateTask(context.Background(), input)
	if err != nil || idempotent.Revision != created.Revision || idempotent.TaskHandle != created.TaskHandle {
		t.Fatalf("same installed identity did not merge safely: %#v err=%v", idempotent, err)
	}
	newObservation := input
	newObservation.ObservedAt = input.ObservedAt.Add(time.Second)
	if _, err := store.CreateTask(context.Background(), newObservation); !errors.Is(err, ErrTaskConflict) {
		t.Fatalf("Create silently consumed a newer observation instead of requiring CAS refresh: %v", err)
	}
	duplicateIdentity := input
	duplicateIdentity.TaskHandle = "task-duplicate-identity"
	if _, err := store.CreateTask(context.Background(), duplicateIdentity); !errors.Is(err, ErrTaskConflict) {
		t.Fatalf("duplicate device identity error=%v", err)
	}
	after, err := store.Fingerprint(context.Background(), "tenant-a", "site-a")
	if err != nil || before == after {
		t.Fatalf("task fact did not change site catalog fingerprint: before=%q after=%q err=%v", before, after, err)
	}

	assertProtectedTaskProjection(t, created)
	summary, err := created.Summary()
	if err != nil {
		t.Fatal(err)
	}
	rawSummary, err := json.Marshal(summary)
	if err != nil {
		t.Fatal(err)
	}
	for _, forbidden := range []string{"native-task-id", "dpf_", created.IdentityFingerprint, "tenant-a", "site-a"} {
		if strings.Contains(string(rawSummary), forbidden) {
			t.Fatalf("business task summary exposed %q: %s", forbidden, rawSummary)
		}
	}

	frozen, err := store.FreezeInstalledTask(context.Background(), "tenant-a", "site-a", created.TaskHandle,
		[]string{"task-cap-event", "task-cap-count", "task-cap-event"})
	if err != nil {
		t.Fatal(err)
	}
	if frozen.TaskID != created.TaskHandle || frozen.TaskRevision != created.Revision || !digestPattern.MatchString(frozen.BindingFingerprint) ||
		len(frozen.Sources) != 2 || frozen.Sources[0].SourceHandle != "source-east" ||
		len(frozen.Capabilities) != 2 || frozen.Capabilities[0].Ref != "task-cap-count" ||
		frozen.Capabilities[0].ResultSchema != "cosmoedge.count.v1" {
		t.Fatalf("unexpected frozen task ref: %#v", frozen)
	}
	rawFrozen, err := json.Marshal(frozen)
	if err != nil {
		t.Fatal(err)
	}
	for _, forbidden := range []string{created.NativeLocator, created.DeviceProfileID, created.TenantID, created.SiteID} {
		if strings.Contains(string(rawFrozen), forbidden) {
			t.Fatalf("frozen task ref exposed protected field %q: %s", forbidden, rawFrozen)
		}
	}
	if err := store.ValidateInstalledTask(context.Background(), "tenant-a", "site-a", frozen); err != nil {
		t.Fatalf("fresh task ref was rejected: %v", err)
	}
	tamperedFrozen := frozen
	tamperedFrozen.Capabilities = append([]inspection.InstalledTaskCapabilityBinding(nil), frozen.Capabilities...)
	tamperedFrozen.Capabilities[0].Digest = strings.Repeat("f", 64)
	if err := store.ValidateInstalledTask(context.Background(), "tenant-a", "site-a", tamperedFrozen); !errors.Is(err, ErrTaskStale) {
		t.Fatalf("tampered frozen task ref error=%v", err)
	}

	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
	reopened, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = reopened.Close() })
	loaded, err := reopened.GetTask(context.Background(), "tenant-a", "site-a", created.TaskHandle)
	if err != nil || loaded.NativeLocator != created.NativeLocator || loaded.Revision != created.Revision ||
		loaded.Capabilities[0].Digest != created.Capabilities[0].Digest {
		t.Fatalf("reopened task=%#v err=%v", loaded, err)
	}
}

func TestDeviceTaskCASRefreshScopeAndProfileBinding(t *testing.T) {
	store := openTestStore(t)
	now := time.Date(2026, 7, 19, 15, 0, 0, 0, time.UTC)
	store.now = func() time.Time { return now }
	createTaskSources(t, store, "source-east", "source-west")
	created, err := store.CreateTask(context.Background(), fixtureDeviceTask("task-east", "东区人数", []string{"source-east"}, now))
	if err != nil {
		t.Fatal(err)
	}
	for _, scope := range [][2]string{{"tenant-b", "site-a"}, {"tenant-a", "site-b"}} {
		if _, err := store.GetTask(context.Background(), scope[0], scope[1], created.TaskHandle); !errors.Is(err, ErrTaskNotFound) {
			t.Fatalf("cross-scope task get %v error=%v", scope, err)
		}
		if values, err := store.ListTasks(context.Background(), scope[0], scope[1]); err != nil || len(values) != 0 {
			t.Fatalf("cross-scope task list %v=%#v err=%v", scope, values, err)
		}
		if _, err := store.FreezeInstalledTask(context.Background(), scope[0], scope[1], created.TaskHandle, []string{"task-cap-count"}); !errors.Is(err, ErrTaskNotFound) {
			t.Fatalf("cross-scope task freeze %v error=%v", scope, err)
		}
	}
	wrongScope := refreshTaskFrom(created)
	wrongScope.SiteID = "site-b"
	if _, err := store.RefreshTask(context.Background(), wrongScope); !errors.Is(err, ErrTaskNotFound) {
		t.Fatalf("cross-site refresh error=%v", err)
	}
	wrongProfile := refreshTaskFrom(created)
	wrongProfile.DeviceProfileID = "dpf_ffffffffffffffffffffffffffffffff"
	if _, err := store.RefreshTask(context.Background(), wrongProfile); !errors.Is(err, ErrInvalidTask) {
		t.Fatalf("cross-profile refresh error=%v", err)
	}

	otherProfileSource := fixtureSource("source-other-profile")
	otherProfileSource.DeviceProfileID = "dpf_ffffffffffffffffffffffffffffffff"
	if _, err := store.Create(context.Background(), otherProfileSource); err != nil {
		t.Fatal(err)
	}
	invalidTask := fixtureDeviceTask("task-cross-profile", "错误绑定", []string{"source-other-profile"}, now)
	if _, err := store.CreateTask(context.Background(), invalidTask); !errors.Is(err, ErrInvalidTask) {
		t.Fatalf("cross-profile source binding error=%v", err)
	}

	now = now.Add(time.Minute)
	refresh := refreshTaskFrom(created)
	refresh.Alias = "东区人数刷新"
	refresh.ObservedAt = now
	updated, err := store.RefreshTask(context.Background(), refresh)
	if err != nil || updated.Revision != 2 || updated.Alias != refresh.Alias {
		t.Fatalf("refreshed task=%#v err=%v", updated, err)
	}
	if _, err := store.RefreshTask(context.Background(), refresh); !errors.Is(err, ErrTaskConflict) {
		t.Fatalf("stale task revision was accepted: %v", err)
	}
	staleRef, err := createdTaskRefForTest(store, updated)
	if err != nil {
		t.Fatal(err)
	}
	now = now.Add(time.Minute)
	nextRefresh := refreshTaskFrom(updated)
	nextRefresh.ObservedAt = now
	if _, err := store.RefreshTask(context.Background(), nextRefresh); err != nil {
		t.Fatal(err)
	}
	if err := store.ValidateInstalledTask(context.Background(), "tenant-a", "site-a", staleRef); !errors.Is(err, ErrTaskStale) {
		t.Fatalf("stale assignment task ref error=%v", err)
	}
}

func TestDeviceTaskConcurrentCASAllowsOneRefresh(t *testing.T) {
	store := openTestStore(t)
	now := time.Date(2026, 7, 19, 15, 30, 0, 0, time.UTC)
	store.now = func() time.Time { return now }
	createTaskSources(t, store, "source-east")
	created, err := store.CreateTask(context.Background(), fixtureDeviceTask("task-concurrent", "并发任务", []string{"source-east"}, now))
	if err != nil {
		t.Fatal(err)
	}
	now = now.Add(time.Minute)
	start := make(chan struct{})
	results := make(chan error, 2)
	var wait sync.WaitGroup
	for index := 0; index < 2; index++ {
		wait.Add(1)
		go func(index int) {
			defer wait.Done()
			<-start
			input := refreshTaskFrom(created)
			input.Alias = []string{"并发任务 A", "并发任务 B"}[index]
			input.ObservedAt = now
			_, err := store.RefreshTask(context.Background(), input)
			results <- err
		}(index)
	}
	close(start)
	wait.Wait()
	close(results)
	success, conflict := 0, 0
	for err := range results {
		if err == nil {
			success++
		} else if errors.Is(err, ErrTaskConflict) {
			conflict++
		} else {
			t.Fatalf("unexpected concurrent refresh error=%v", err)
		}
	}
	if success != 1 || conflict != 1 {
		t.Fatalf("concurrent task refresh success=%d conflict=%d", success, conflict)
	}
}

func TestDeviceTaskIdentityDriftRequiresExplicitRepin(t *testing.T) {
	store := openTestStore(t)
	now := time.Date(2026, 7, 19, 16, 0, 0, 0, time.UTC)
	store.now = func() time.Time { return now }
	sources := createTaskSources(t, store, "source-east")
	created, err := store.CreateTask(context.Background(), fixtureDeviceTask("task-drift", "漂移任务", []string{"source-east"}, now))
	if err != nil {
		t.Fatal(err)
	}
	now = now.Add(time.Minute)
	drift := refreshTaskFrom(created)
	drift.IdentityFingerprint = strings.Repeat("b", 64)
	drift.NativeLocator = "untrusted-native-task"
	drift.Alias = "untrusted alias"
	drift.SourceHandles = nil
	drift.Capabilities = nil
	drift.ObservedAt = now
	drifted, err := store.RefreshTask(context.Background(), drift)
	if !errors.Is(err, ErrTaskIdentityDrift) || !errors.Is(err, ErrIdentityDrift) ||
		drifted.State != StateIdentityDrift || drifted.IdentityFingerprint != created.IdentityFingerprint ||
		drifted.NativeLocator != created.NativeLocator || drifted.Alias != created.Alias ||
		len(drifted.Capabilities) != len(created.Capabilities) {
		t.Fatalf("drifted task=%#v err=%v", drifted, err)
	}
	if _, err := store.FreezeInstalledTask(context.Background(), "tenant-a", "site-a", created.TaskHandle, []string{"task-cap-count"}); !errors.Is(err, ErrTaskIdentityDrift) {
		t.Fatalf("identity-drift task produced frozen ref: %v", err)
	}
	invalidRepin := refreshTaskFrom(drifted)
	invalidRepin.ObservedAt = now
	if _, err := store.RepinTask(context.Background(), invalidRepin); !errors.Is(err, ErrInvalidTask) {
		t.Fatalf("same-identity repin error=%v", err)
	}

	now = now.Add(time.Minute)
	repin := refreshTaskFrom(drifted)
	repin.IdentityFingerprint = strings.Repeat("b", 64)
	repin.NativeLocator = "confirmed-native-task-v2"
	repin.Alias = "已确认漂移任务"
	repin.SourceHandles = []string{"source-east"}
	repin.Capabilities = fixtureTaskCapabilities()
	repin.State = StateActive
	repin.ObservedAt = now
	repinned, err := store.RepinTask(context.Background(), repin)
	if err != nil || repinned.State != StateActive || repinned.IdentityFingerprint != repin.IdentityFingerprint ||
		repinned.NativeLocator != repin.NativeLocator {
		t.Fatalf("repinned task=%#v err=%v", repinned, err)
	}
	if _, err := store.FreezeInstalledTask(context.Background(), "tenant-a", "site-a", repinned.TaskHandle, []string{"task-cap-event"}); err != nil {
		t.Fatalf("repinned task did not freeze: %v", err)
	}

	now = now.Add(time.Minute)
	sourceDrift := updateFrom(sources[0])
	sourceDrift.IdentityFingerprint = strings.Repeat("c", 64)
	sourceDrift.NativeLocator = "untrusted-source"
	sourceDrift.Capabilities = nil
	if _, err := store.Update(context.Background(), sourceDrift); !errors.Is(err, ErrIdentityDrift) {
		t.Fatalf("source drift error=%v", err)
	}
	if _, err := store.FreezeInstalledTask(context.Background(), "tenant-a", "site-a", repinned.TaskHandle, []string{"task-cap-event"}); !errors.Is(err, ErrIdentityDrift) {
		t.Fatalf("task froze through source identity drift: %v", err)
	}
}

func TestDeviceTaskAliasResolutionFailsClosedOnAmbiguityAndScope(t *testing.T) {
	store := openTestStore(t)
	now := time.Date(2026, 7, 19, 17, 0, 0, 0, time.UTC)
	store.now = func() time.Time { return now }
	createTaskSources(t, store, "source-east", "source-west")
	for _, fixture := range []NewDeviceTaskBinding{
		fixtureDeviceTask("task-alias-a", "卫生巡检", []string{"source-east"}, now),
		fixtureDeviceTask("task-alias-b", "卫生巡检", []string{"source-west"}, now),
	} {
		if _, err := store.CreateTask(context.Background(), fixture); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := store.ResolveTaskAlias(context.Background(), "tenant-a", "site-a", "卫生巡检"); !errors.Is(err, ErrTaskAmbiguous) {
		t.Fatalf("ambiguous alias resolution error=%v", err)
	}
	if _, err := store.ResolveTaskAlias(context.Background(), "tenant-a", "site-b", "卫生巡检"); !errors.Is(err, ErrTaskNotFound) {
		t.Fatalf("cross-site alias resolution error=%v", err)
	}

	siteBSource := fixtureSource("source-site-b")
	siteBSource.SiteID = "site-b"
	if _, err := store.Create(context.Background(), siteBSource); err != nil {
		t.Fatal(err)
	}
	siteBTask := fixtureDeviceTask("task-site-b", "卫生巡检", []string{"source-site-b"}, now)
	siteBTask.SiteID = "site-b"
	resolved, err := store.CreateTask(context.Background(), siteBTask)
	if err != nil {
		t.Fatal(err)
	}
	matched, err := store.ResolveTaskAlias(context.Background(), "tenant-a", "site-b", "卫生巡检")
	if err != nil || matched.TaskHandle != resolved.TaskHandle {
		t.Fatalf("site-scoped alias match=%#v err=%v", matched, err)
	}
}

func TestDeviceTaskRequiresTypedEvidenceCapabilities(t *testing.T) {
	store := openTestStore(t)
	now := time.Date(2026, 7, 19, 17, 30, 0, 0, time.UTC)
	store.now = func() time.Time { return now }
	createTaskSources(t, store, "source-east")
	wrongKind := fixtureDeviceTask("task-wrong-kind", "错误能力", []string{"source-east"}, now)
	wrongKind.Capabilities[0].Kind = CapabilitySnapshot
	if _, err := store.CreateTask(context.Background(), wrongKind); !errors.Is(err, ErrInvalidTask) {
		t.Fatalf("non-task-evidence capability error=%v", err)
	}
	missingSchema := fixtureDeviceTask("task-missing-schema", "缺少结果结构", []string{"source-east"}, now)
	missingSchema.Capabilities[0].ResultSchema = ""
	if _, err := store.CreateTask(context.Background(), missingSchema); !errors.Is(err, ErrInvalidTask) {
		t.Fatalf("missing result schema error=%v", err)
	}
	duplicateSource := fixtureDeviceTask("task-duplicate-source", "重复来源", []string{"source-east", "source-east"}, now)
	if _, err := store.CreateTask(context.Background(), duplicateSource); !errors.Is(err, ErrInvalidTask) {
		t.Fatalf("duplicate source handle error=%v", err)
	}
	created, err := store.CreateTask(context.Background(), fixtureDeviceTask("task-valid-evidence", "有效能力", []string{"source-east"}, now))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.FreezeInstalledTask(context.Background(), created.TenantID, created.SiteID, created.TaskHandle, []string{"missing-capability"}); !errors.Is(err, ErrTaskCapability) {
		t.Fatalf("missing task capability error=%v", err)
	}

	inputs := []any{
		fixtureDeviceTask("task-projection", "投影", []string{"source-east"}, now),
		refreshTaskFrom(created),
	}
	for _, input := range inputs {
		if _, err := json.Marshal(input); !errors.Is(err, ErrProtectedProjection) {
			t.Fatalf("protected task input JSON error=%v", err)
		}
		projected := fmt.Sprintf("%+v %#v", input, input)
		for _, forbidden := range []string{"native-task-id-private", "dpf_00112233445566778899aabbccddeeff"} {
			if strings.Contains(projected, forbidden) {
				t.Fatalf("protected task input leaked %q: %s", forbidden, projected)
			}
		}
	}
}

func TestDeviceTaskCatalogRejectsOldShapeAndTampering(t *testing.T) {
	t.Run("old source-only shape", func(t *testing.T) {
		path := filepath.Join(protectedCatalogTestRoot(t), "old-shape.db")
		store, err := Open(path)
		if err != nil {
			t.Fatal(err)
		}
		if err := store.Close(); err != nil {
			t.Fatal(err)
		}
		database := openCatalogDatabaseForTamper(t, path)
		if _, err := database.Exec(`DROP TABLE device_task_binding_events; DROP TABLE device_task_bindings`); err != nil {
			t.Fatal(err)
		}
		if err := database.Close(); err != nil {
			t.Fatal(err)
		}
		if _, err := Open(path); !errors.Is(err, ErrUnsupportedSchema) {
			t.Fatalf("old source-only catalog error=%v", err)
		}
	})

	t.Run("schema impostor", func(t *testing.T) {
		path := filepath.Join(protectedCatalogTestRoot(t), "impostor.db")
		store, err := Open(path)
		if err != nil {
			t.Fatal(err)
		}
		if err := store.Close(); err != nil {
			t.Fatal(err)
		}
		database := openCatalogDatabaseForTamper(t, path)
		if _, err := database.Exec(`ALTER TABLE device_task_bindings ADD COLUMN attacker_value TEXT`); err != nil {
			t.Fatal(err)
		}
		if err := database.Close(); err != nil {
			t.Fatal(err)
		}
		if _, err := Open(path); !errors.Is(err, ErrUnsupportedSchema) {
			t.Fatalf("schema impostor error=%v", err)
		}
	})

	t.Run("protected row tamper", func(t *testing.T) {
		path := filepath.Join(protectedCatalogTestRoot(t), "row-tamper.db")
		store, err := Open(path)
		if err != nil {
			t.Fatal(err)
		}
		now := time.Date(2026, 7, 19, 18, 0, 0, 0, time.UTC)
		store.now = func() time.Time { return now }
		createTaskSources(t, store, "source-east")
		created, err := store.CreateTask(context.Background(), fixtureDeviceTask("task-tamper", "防篡改", []string{"source-east"}, now))
		if err != nil {
			t.Fatal(err)
		}
		if err := store.Close(); err != nil {
			t.Fatal(err)
		}
		database := openCatalogDatabaseForTamper(t, path)
		if _, err := database.Exec(`UPDATE device_task_bindings SET capabilities_json=? WHERE task_handle=?`,
			[]byte(`[{"ref":"task-cap-count","kind":"task_evidence","revision":1,"resultSchema":"cosmoedge.count.v1","constraints":{"mediaKinds":["metric"],"maxBytes":0,"maxFrames":0,"maxDurationSeconds":0,"maxFreshnessSeconds":30},"digest":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","unexpected":true}]`),
			created.TaskHandle); err != nil {
			t.Fatal(err)
		}
		if err := database.Close(); err != nil {
			t.Fatal(err)
		}
		reopened, err := Open(path)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = reopened.Close() })
		if _, err := reopened.GetTask(context.Background(), "tenant-a", "site-a", created.TaskHandle); !errors.Is(err, ErrInvalidTask) {
			t.Fatalf("tampered task row error=%v", err)
		}
	})

	t.Run("cross-site source row tamper", func(t *testing.T) {
		path := filepath.Join(protectedCatalogTestRoot(t), "scope-tamper.db")
		store, err := Open(path)
		if err != nil {
			t.Fatal(err)
		}
		now := time.Date(2026, 7, 19, 18, 30, 0, 0, time.UTC)
		store.now = func() time.Time { return now }
		createTaskSources(t, store, "source-east")
		siteBSource := fixtureSource("source-site-b-only")
		siteBSource.SiteID = "site-b"
		if _, err := store.Create(context.Background(), siteBSource); err != nil {
			t.Fatal(err)
		}
		created, err := store.CreateTask(context.Background(), fixtureDeviceTask("task-scope-tamper", "范围防篡改", []string{"source-east"}, now))
		if err != nil {
			t.Fatal(err)
		}
		if err := store.Close(); err != nil {
			t.Fatal(err)
		}
		database := openCatalogDatabaseForTamper(t, path)
		if _, err := database.Exec(`UPDATE device_task_bindings SET source_handles_json=? WHERE task_handle=?`,
			[]byte(`["source-site-b-only"]`), created.TaskHandle); err != nil {
			t.Fatal(err)
		}
		if err := database.Close(); err != nil {
			t.Fatal(err)
		}
		reopened, err := Open(path)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = reopened.Close() })
		if _, err := reopened.GetTask(context.Background(), "tenant-a", "site-a", created.TaskHandle); !errors.Is(err, ErrInvalidTask) {
			t.Fatalf("cross-site source tamper error=%v", err)
		}
	})
}

func fixtureDeviceTask(handle, alias string, sources []string, observedAt time.Time) NewDeviceTaskBinding {
	fingerprint := sha256.Sum256([]byte("installed-task:" + handle))
	return NewDeviceTaskBinding{
		TenantID: "tenant-a", SiteID: "site-a", DeviceProfileID: "dpf_00112233445566778899aabbccddeeff",
		TaskHandle: handle, IdentityFingerprint: fmt.Sprintf("%x", fingerprint[:]),
		NativeLocator: "native-task-id-private-" + strings.TrimPrefix(handle, "task-"), Alias: alias,
		SourceHandles: append([]string(nil), sources...), Capabilities: fixtureTaskCapabilities(), ObservedAt: observedAt,
	}
}

func fixtureTaskCapabilities() []Capability {
	return []Capability{
		{
			Ref: "task-cap-event", Kind: CapabilityTaskEvidence, Revision: 3, ResultSchema: "cosmoedge.event.v1",
			Constraints: Constraints{MediaKinds: []MediaKind{MediaDetection, MediaEvent}, MaxBytes: 1 << 20, MaxFreshnessSeconds: 60},
		},
		{
			Ref: "task-cap-count", Kind: CapabilityTaskEvidence, Revision: 2, ResultSchema: "cosmoedge.count.v1",
			Constraints: Constraints{MediaKinds: []MediaKind{MediaMetric}, MaxBytes: 64 << 10, MaxFreshnessSeconds: 30},
		},
	}
}

func createTaskSources(t *testing.T, store *Store, handles ...string) []Source {
	t.Helper()
	result := make([]Source, 0, len(handles))
	for _, handle := range handles {
		created, err := store.Create(context.Background(), fixtureSource(handle))
		if err != nil {
			t.Fatalf("create task source %q: %v", handle, err)
		}
		result = append(result, created)
	}
	return result
}

func refreshTaskFrom(task DeviceTaskBinding) RefreshDeviceTaskBinding {
	return RefreshDeviceTaskBinding{
		TenantID: task.TenantID, SiteID: task.SiteID, TaskHandle: task.TaskHandle, ExpectedRevision: task.Revision,
		DeviceProfileID: task.DeviceProfileID, IdentityFingerprint: task.IdentityFingerprint,
		NativeLocator: task.NativeLocator, Alias: task.Alias, SourceHandles: append([]string(nil), task.SourceHandles...),
		Capabilities: cloneTaskCapabilities(task.Capabilities), State: task.State, ObservedAt: task.ObservedAt,
	}
}

func assertProtectedTaskProjection(t *testing.T, task DeviceTaskBinding) {
	t.Helper()
	if _, err := json.Marshal(task); !errors.Is(err, ErrProtectedProjection) {
		t.Fatalf("protected task JSON error=%v", err)
	}
	projected := fmt.Sprintf("%v %+v %#v", task, task, task)
	var logOutput bytes.Buffer
	slog.New(slog.NewTextHandler(&logOutput, nil)).Info("task", "value", task)
	projected += logOutput.String()
	for _, forbidden := range []string{task.NativeLocator, task.DeviceProfileID, task.IdentityFingerprint, task.TenantID, task.SiteID} {
		if strings.Contains(projected, forbidden) {
			t.Fatalf("protected task projection leaked %q: %s", forbidden, projected)
		}
	}
}

func openCatalogDatabaseForTamper(t *testing.T, path string) *sql.DB {
	t.Helper()
	database, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	return database
}

func createdTaskRefForTest(store *Store, task DeviceTaskBinding) (inspection.InstalledTaskBinding, error) {
	return store.FreezeInstalledTask(context.Background(), task.TenantID, task.SiteID, task.TaskHandle, []string{"task-cap-count"})
}
