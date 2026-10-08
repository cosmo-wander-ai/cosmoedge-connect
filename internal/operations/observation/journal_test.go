package observation

import (
	"context"
	"strconv"
	"strings"
	"testing"

	"github.com/cosmo-wander-ai/cosmoedge-connect/internal/inspection/mediaprep"
	"github.com/cosmo-wander-ai/cosmoedge-connect/internal/inspection/temporary"
	"github.com/cosmo-wander-ai/cosmoedge-connect/internal/operator/livevision"
)

func TestCleanupSelectionDoesNotStarveBehindHistoricalEpochs(t *testing.T) {
	service, _, _ := newObservationHarness(t)
	ctx := context.Background()
	result, err := service.Observe(ctx, testOwner, Request{RequestID: "journal-seed", SourceName: "室内", Question: "画面中是否有人"})
	if err != nil {
		t.Fatal(err)
	}
	result = awaitTerminal(t, service, testOwner, result.OperationRef)
	seed, err := service.resource.operations.get(ctx, testOwner, result.OperationRef)
	if err != nil {
		t.Fatal(err)
	}
	epoch, ok := livevision.CurrentTemporaryConnectionEpoch(service.config.Vault)
	if !ok {
		t.Fatal("current epoch absent")
	}
	var wanted livevision.TemporaryTask
	for i := 0; i < 33; i++ {
		value := seed
		id := digestText("historical-cleanup-" + strconv.Itoa(i))
		value.Ref = "observation_" + id[:32]
		value.Request.RequestID = "historical-cleanup-" + strconv.Itoa(i)
		value.RequestKey = "obsreq_" + id
		value.RunID, err = temporary.RunIDForScope(livevision.TenantID, livevision.SiteID, value.RequestKey)
		if err != nil {
			t.Fatal(err)
		}
		value.PreparationRef, err = mediaprep.PreparationRefForScope(livevision.TenantID, livevision.SiteID, value.RequestKey)
		if err != nil {
			t.Fatal(err)
		}
		if err := service.resource.operations.put(ctx, value); err != nil {
			t.Fatal(err)
		}
		task := livevision.TemporaryTask{RunID: value.RunID, TaskID: "inspection-" + id[:32], AlgorithmCode: "synthetic-vlm", DeviceIdentitySHA256: strings.Repeat("a", 64)}
		if i >= 16 {
			task.ConnectionEpoch = strings.Repeat("f", 64)
		}
		if i == 32 {
			task.ConnectionEpoch = epoch
			wanted = task
		}
		if err := service.resource.journal.BeforeCreate(ctx, task); err != nil {
			t.Fatal(err)
		}
	}
	pending, err := service.resource.journal.pending(ctx, epoch)
	if err != nil || len(pending) != 1 || pending[0] != wanted {
		t.Fatalf("current cleanup starved: selected=%d error=%v", len(pending), err)
	}
	var preserved int
	if err := service.resource.operations.db.QueryRow("SELECT count(*) FROM temporary_tasks WHERE disposition='reserved' AND cancel_attempts=0").Scan(&preserved); err != nil || preserved != 33 {
		t.Fatalf("selection changed historical cleanup: count=%d error=%v", preserved, err)
	}
}
