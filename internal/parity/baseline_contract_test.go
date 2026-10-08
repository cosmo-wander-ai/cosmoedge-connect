package parity

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"sync/atomic"
	"testing"
	"time"
)

func TestBaselineConnectionAdmissionGolden(t *testing.T) {
	operatorPath := baselineOperatorPath(t)
	fixture := NewDeviceFixture("admission-user", "admission-password", "PARITY-ADMISSION-739184") // gitleaks:allow -- Synthetic credential for an isolated local test fixture.
	deviceURL, closeFixture, err := fixture.Start()
	if err != nil {
		t.Fatal(err)
	}
	defer closeFixture()
	parsed, err := url.Parse(deviceURL)
	if err != nil {
		t.Fatal(err)
	}
	run := startBaselineOperator(t, operatorPath)
	defer run.Close()
	browser, err := ConsumeBootstrap(run.BootstrapURL)
	if err != nil {
		t.Fatal(err)
	}
	host := parsed.Hostname()
	for _, endpoint := range []string{
		"http://user:password@" + host + ":8000",
		"http://" + host + ":8000/path",
		"http://" + host + ":8000?query=1",
		"http://" + host + ":8000#fragment",
		"ftp://" + host + ":8000",
		"http://127.0.0.1:8000",
		"http://169.254.169.254:8000",
		"https://example.com",
		"device.internal",
	} {
		status, _, requestErr := browser.Form("/api/connection/prepare", url.Values{
			"endpoint": {endpoint}, "username": {"admission-user"},
		})
		if requestErr != nil || status == http.StatusOK {
			t.Fatalf("unsafe destination %q status=%d err=%v", endpoint, status, requestErr)
		}
	}
	if requests := totalRequests(fixture.Snapshot()); requests != 0 {
		t.Fatalf("destination admission performed %d device requests", requests)
	}
	status, raw, err := browser.Form("/api/connection/prepare", url.Values{
		"endpoint": {host}, "username": {"admission-user"},
	})
	if err != nil || status != http.StatusOK || StringField(mustObject(t, raw), "connectionToken") == "" {
		t.Fatalf("private literal destination status=%d err=%v body=%s", status, err, raw)
	}
	if requests := totalRequests(fixture.Snapshot()); requests != 0 {
		t.Fatalf("destination confirmation boundary performed %d device requests", requests)
	}
	recordNormalized(t, NormalizedResult{Scenario: "G-CONN-01/private-literal-preview", Class: "in_progress"})
	recordNormalized(t, NormalizedResult{Scenario: "G-CONN-02/unsafe-destinations", Class: "blocked"})
}

func TestBaselineAuthenticationFailureGolden(t *testing.T) {
	operatorPath := baselineOperatorPath(t)
	fixture := NewDeviceFixture("auth-user", "correct-password-never-submitted", "PARITY-AUTH-739184")
	deviceURL, closeFixture, err := fixture.Start()
	if err != nil {
		t.Fatal(err)
	}
	defer closeFixture()
	parsed, _ := url.Parse(deviceURL)
	run := startBaselineOperator(t, operatorPath)
	defer run.Close()
	browser, err := ConsumeBootstrap(run.BootstrapURL)
	if err != nil {
		t.Fatal(err)
	}
	status, raw, err := browser.Form("/api/connection/prepare", url.Values{
		"endpoint": {parsed.Hostname()}, "username": {"auth-user"},
	})
	if err != nil || status != http.StatusOK {
		t.Fatalf("auth prepare status=%d err=%v body=%s", status, err, raw)
	}
	token := StringField(mustObject(t, raw), "connectionToken")
	wrongPassword := "wrong-password-private"
	status, _, err = browser.Form("/api/connection/connect", url.Values{
		"connectionToken": {token}, "password": {wrongPassword},
	})
	if err != nil || status == http.StatusOK {
		t.Fatalf("invalid credential status=%d err=%v", status, err)
	}
	status, raw, err = browser.Form("/api/connection/prepare", url.Values{
		"endpoint": {parsed.Hostname()}, "username": {"auth-user"},
	})
	if err != nil || status != http.StatusOK || StringField(mustObject(t, raw), "connectionToken") == "" {
		t.Fatalf("auth retry preview status=%d err=%v body=%s", status, err, raw)
	}
	snapshot := fixture.Snapshot()
	if snapshot.Requests["/gtw/cwai/login/DoLogin"] != 1 || snapshot.TaskWrites != 0 || snapshot.ParameterWrites != 0 || snapshot.SourceWrites != 0 {
		t.Fatalf("authentication failure snapshot=%#v", snapshot)
	}
	if err := ScanProtected(browser.Bodies(), wrongPassword, "correct-password-never-submitted", "PARITY-AUTH-739184"); err != nil {
		t.Fatal(err)
	}
	recordNormalized(t, NormalizedResult{Scenario: "G-CONN-04/authentication-failure", Class: "blocked", Dispatches: 1})
}

func TestBaselineLoginRedirectGolden(t *testing.T) {
	operatorPath := baselineOperatorPath(t)
	fixture := NewDeviceFixture("redirect-user", "redirect-password", "PARITY-REDIRECT-739184")
	deviceURL, closeFixture, err := fixture.Start()
	if err != nil {
		t.Fatal(err)
	}
	defer closeFixture()
	var redirectedCalls atomic.Int32
	redirectTarget := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		redirectedCalls.Add(1)
	}))
	defer redirectTarget.Close()
	fixture.SetRedirect("/gtw/cwai/login/DoLogin", redirectTarget.URL)
	parsed, _ := url.Parse(deviceURL)
	run := startBaselineOperator(t, operatorPath)
	defer run.Close()
	browser, err := ConsumeBootstrap(run.BootstrapURL)
	if err != nil {
		t.Fatal(err)
	}
	preview := mustPostConnectionPreview(t, browser, parsed.Hostname(), "redirect-user")
	status, _, err := browser.Form("/api/connection/connect", url.Values{
		"connectionToken": {StringField(preview, "connectionToken")}, "password": {"redirect-password"},
	})
	if err != nil || status == http.StatusOK || redirectedCalls.Load() != 0 {
		t.Fatalf("redirected login status=%d err=%v targetCalls=%d", status, err, redirectedCalls.Load())
	}
	snapshot := fixture.Snapshot()
	if snapshot.Requests["/gtw/cwai/login/DoLogin"] != 1 || snapshot.TaskWrites != 0 || snapshot.ParameterWrites != 0 || snapshot.SourceWrites != 0 {
		t.Fatalf("redirected login snapshot=%#v", snapshot)
	}
	if err := ScanProtected(browser.Bodies(), "redirect-password", "PARITY-REDIRECT-739184"); err != nil {
		t.Fatal(err)
	}
	recordNormalized(t, NormalizedResult{Scenario: "G-CONN-03/login-redirect", Class: "blocked", Dispatches: 1})
}

func TestBaselineReadViewsGolden(t *testing.T) {
	session := newConnectedBaseline(t, "read")
	home := mustGetObject(t, session.Browser, "/api/journey?intent=home&window=today")
	if StringField(home, "state") != "ready" || StringField(home, "view") != "home" || StringField(home, "device", "maskedId") != "***9184" || StringField(home, "device", "type") != "parity-edge-gateway" {
		t.Fatalf("home identity view=%#v", home)
	}
	if len(ArrayField(home, "read", "tasks")) != 0 || StringField(home, "read", "choiceSetId") != "" || len(ArrayField(home, "operationsSummaries")) != 4 {
		t.Fatalf("home progressive disclosure=%#v", home)
	}
	assertBaselineSummary(t, ArrayField(home, "operationsSummaries")[0], "today")

	manage := mustGetObject(t, session.Browser, "/api/journey?intent=manage_tasks&window=today")
	tasks := ArrayField(manage, "read", "tasks")
	if StringField(manage, "view") != "manage_tasks" || len(tasks) != 1 || StringField(manage, "read", "choiceSetId") == "" {
		t.Fatalf("manage tasks view=%#v", manage)
	}
	task, _ := tasks[0].(map[string]any)
	if StringField(task, "displayName") != "Parity Algorithm + Parity Camera" || StringField(task, "cameraName") != "Parity Camera" || StringField(task, "algorithmName") != "Parity Algorithm" || StringField(task, "enabledState") != "已启用" {
		t.Fatalf("manage task binding=%#v", task)
	}

	for _, item := range []struct {
		view   string
		window string
	}{
		{view: "inspect_runtime", window: "last_24h"},
		{view: "inspect_alerts", window: "last_1h"},
		{view: "manage_sources", window: "today"},
	} {
		object := mustGetObject(t, session.Browser, "/api/journey?intent="+item.view+"&window="+item.window)
		if StringField(object, "view") != item.view || len(ArrayField(object, "read", "tasks")) != 0 || len(ArrayField(object, "operationsSummaries")) != 1 {
			t.Fatalf("%s progressive view=%#v", item.view, object)
		}
		assertBaselineSummary(t, ArrayField(object, "operationsSummaries")[0], item.window)
	}
	if snapshot := session.Fixture.Snapshot(); snapshot.TaskWrites != 0 || snapshot.ParameterWrites != 0 || snapshot.SourceWrites != 0 {
		t.Fatalf("read views wrote device: %#v", snapshot)
	}
	if err := ScanProtected(session.Browser.Bodies(), session.Password, session.FullSN, "parity-task-internal", "parity-camera-internal", "parity-algorithm-internal"); err != nil {
		t.Fatal(err)
	}
	recordNormalized(t, NormalizedResult{
		Scenario: "G-READ-01/complete-facts", Class: "completed",
		TaskName: "Parity Algorithm + Parity Camera", CameraName: "Parity Camera", AlgorithmName: "Parity Algorithm",
	})
	recordNormalized(t, NormalizedResult{Scenario: "G-READ-02/empty-alarms", Class: "completed"})
	recordNormalized(t, NormalizedResult{Scenario: "G-READ-05/product-views", Class: "completed"})
}

func TestBaselineOperationsWindowsAndAlarmAccuracyGolden(t *testing.T) {
	session := newConnectedBaseline(t, "windowed-alarms")
	now := time.Now().UTC()
	session.Fixture.SetEvents(
		FixtureEvent{
			ID: "event-private-recent", AlgorithmCode: "parity-algorithm-internal", AlgorithmName: "Parity Algorithm",
			VideoChannelID: "parity-camera-internal", ChannelName: "Parity Camera", Timestamp: now.Add(-30 * time.Minute).UnixMilli(),
		},
		FixtureEvent{
			ID: "event-private-older", AlgorithmCode: "parity-algorithm-internal", AlgorithmName: "Parity Algorithm",
			VideoChannelID: "parity-camera-internal", ChannelName: "Parity Camera", Timestamp: now.Add(-2 * time.Hour).UnixMilli(),
		},
	)
	lastHour := mustGetObject(t, session.Browser, "/api/journey?intent=inspect_alerts&window=last_1h")
	lastHourSummary, _ := ArrayField(lastHour, "operationsSummaries")[0].(map[string]any)
	if IntField(lastHourSummary, "alarmCount") != 1 || StringField(lastHourSummary, "alarmAccuracy") != "exact" || StringField(lastHourSummary, "alarmText") != "1 条告警" {
		t.Fatalf("last-hour summary=%#v", lastHourSummary)
	}
	recent, _ := ArrayField(lastHourSummary, "recentAlarms")[0].(map[string]any)
	if StringField(recent, "cameraName") != "Parity Camera" || StringField(recent, "taskName") != "Parity Algorithm + Parity Camera" || StringField(recent, "algorithmName") != "Parity Algorithm" {
		t.Fatalf("last-hour alarm=%#v", recent)
	}
	lastDay := mustGetObject(t, session.Browser, "/api/journey?intent=inspect_runtime&window=last_24h")
	lastDaySummary, _ := ArrayField(lastDay, "operationsSummaries")[0].(map[string]any)
	if IntField(lastDaySummary, "alarmCount") != 2 || StringField(lastDaySummary, "alarmAccuracy") != "exact" || StringField(lastDaySummary, "alarmText") != "2 条告警" {
		t.Fatalf("last-day summary=%#v", lastDaySummary)
	}
	if err := ScanProtected(session.Browser.Bodies(), session.Password, session.FullSN, "event-private-recent", "event-private-older", "parity-camera-internal", "parity-algorithm-internal"); err != nil {
		t.Fatal(err)
	}
	recordNormalized(t, NormalizedResult{
		Scenario: "G-READ-06/windowed-alarms", Class: "completed",
		TaskName: "Parity Algorithm + Parity Camera", CameraName: "Parity Camera", AlgorithmName: "Parity Algorithm",
	})
}

func TestBaselineReadAndBindingDriftGolden(t *testing.T) {
	t.Run("malformed catalog", func(t *testing.T) {
		session := newConnectedBaseline(t, "malformed-read")
		session.Fixture.SetFault("/gtw/cwai/Camera/Page", FaultMalformed)
		status, raw, err := session.Browser.Get("/api/journey?intent=manage_tasks&window=today")
		object := mustObject(t, raw)
		if err != nil || status != http.StatusOK || StringField(object, "state") != "disconnected" || StringField(object, "read", "state") != "catalog_incomplete" || BoolField(object, "capabilities", "canPrepare") {
			t.Fatalf("malformed catalog status=%d err=%v body=%s", status, err, raw)
		}
		if snapshot := session.Fixture.Snapshot(); snapshot.TaskWrites != 0 || snapshot.ParameterWrites != 0 || snapshot.SourceWrites != 0 {
			t.Fatalf("malformed catalog created authority: %#v", snapshot)
		}
		recordNormalized(t, NormalizedResult{Scenario: "G-READ-03/malformed-catalog", Class: "blocked"})
	})

	t.Run("stale catalog", func(t *testing.T) {
		session := newConnectedBaseline(t, "stale-catalog")
		session.Fixture.SetTaskEnabled(0)
		status, raw, err := session.Browser.JSON(http.MethodPost, "/api/journey/select", map[string]any{
			"choiceIndex": 1, "choiceSetId": StringField(session.Ready, "read", "choiceSetId"),
		})
		object := mustObject(t, raw)
		if err != nil || status != http.StatusOK || StringField(object, "state") != "target_unresolved" || StringField(object, "selection", "status") != "target_stale" || BoolField(object, "capabilities", "canPrepare") || session.Fixture.Snapshot().TaskWrites != 0 {
			t.Fatalf("stale catalog selection status=%d err=%v body=%s snapshot=%#v", status, err, raw, session.Fixture.Snapshot())
		}
		recordNormalized(t, NormalizedResult{Scenario: "G-READ-04/stale-choice", Class: "blocked"})
	})

	t.Run("identity drift", func(t *testing.T) {
		session := newConnectedBaseline(t, "identity-drift")
		session.selectOnlyTask(t)
		session.Fixture.SetFullSN("PARITY-DRIFTED-SN-111111")
		status, raw, err := session.Browser.JSON(http.MethodPost, "/api/journey/prepare-persistent", map[string]any{"targetEnabled": 0})
		object := mustObject(t, raw)
		if err != nil || status != http.StatusOK || StringField(object, "state") == "awaiting_confirmation" || BoolField(object, "capabilities", "canConfirm") || StringField(object, "businessConfirmationToken") != "" || session.Fixture.Snapshot().TaskWrites != 0 {
			t.Fatalf("identity drift preparation status=%d err=%v body=%s snapshot=%#v", status, err, raw, session.Fixture.Snapshot())
		}
		recordNormalized(t, NormalizedResult{Scenario: "G-CONN-06/identity-drift", Class: "blocked"})
	})
}

func TestBaselineTaskCancelAndRejectGolden(t *testing.T) {
	session := newConnectedBaseline(t, "cancel")
	session.selectOnlyTask(t)
	prepared := mustPostObject(t, session.Browser, "/api/journey/prepare-persistent", map[string]any{"targetEnabled": 0})
	token := StringField(prepared, "businessConfirmationToken")
	if token == "" || session.Fixture.Snapshot().TaskWrites != 0 {
		t.Fatalf("cancel preparation=%#v snapshot=%#v", prepared, session.Fixture.Snapshot())
	}
	cancelled := mustPostObject(t, session.Browser, "/api/journey/cancel", map[string]any{})
	if StringField(cancelled, "state") != "cancelled" || session.Fixture.Snapshot().TaskWrites != 0 {
		t.Fatalf("cancelled state=%#v snapshot=%#v", cancelled, session.Fixture.Snapshot())
	}
	status, _, err := session.Browser.JSON(http.MethodPost, "/api/journey/confirm-business", map[string]any{"businessConfirmationToken": token})
	if err != nil || status != http.StatusConflict || session.Fixture.Snapshot().TaskWrites != 0 {
		t.Fatalf("cancelled token status=%d err=%v snapshot=%#v", status, err, session.Fixture.Snapshot())
	}

	prepared = mustPostObject(t, session.Browser, "/api/journey/prepare-persistent", map[string]any{"targetEnabled": 0})
	session.Fixture.SetFault("/gtw/cwai/Task/SwitchTask", FaultReject)
	mustPostObject(t, session.Browser, "/api/journey/confirm-business", map[string]any{"businessConfirmationToken": StringField(prepared, "businessConfirmationToken")})
	terminal, err := session.Browser.WaitJSON("/api/journey?intent=manage_tasks&window=today", 30*time.Second, func(value map[string]any) bool {
		return StringField(value, "report", "businessConclusion") == "设备明确拒绝或尚未开始本次写入。" && StringField(value, "report", "evidenceStatus") != ""
	})
	if err != nil {
		t.Fatalf("known rejection terminal: %v last=%#v", err, terminal)
	}
	state := StringField(terminal, "state")
	evidence := StringField(terminal, "report", "evidenceStatus")
	stateOK := state == "recovery_required" || state == "ready"
	if !baselineImplementation() {
		stateOK = state == "blocked"
	}
	if !stateOK || (evidence != "evidence_pending" && evidence != "sealed") || session.Fixture.Snapshot().TaskWrites != 0 || session.Fixture.Snapshot().Requests["/gtw/cwai/Task/SwitchTask"] != 1 {
		t.Fatalf("known rejection terminal=%#v snapshot=%#v", terminal, session.Fixture.Snapshot())
	}
	recordNormalized(t, NormalizedResult{Scenario: "G-ACT-06/task-known-rejection", Class: "blocked", EvidenceStatus: "pending_or_sealed", Dispatches: 1})
}

func TestBaselineTaskAmbiguousWriteGolden(t *testing.T) {
	session := newConnectedBaseline(t, "ambiguous")
	session.selectOnlyTask(t)
	prepared := mustPostObject(t, session.Browser, "/api/journey/prepare-persistent", map[string]any{"targetEnabled": 0})
	session.Fixture.SetFault("/gtw/cwai/Task/SwitchTask", FaultCloseAfterWrite)
	mustPostObject(t, session.Browser, "/api/journey/confirm-business", map[string]any{"businessConfirmationToken": StringField(prepared, "businessConfirmationToken")})
	terminal, err := session.Browser.WaitJSON("/api/journey?intent=manage_tasks&window=today", 30*time.Second, func(value map[string]any) bool {
		return StringField(value, "state") == "outcome_unknown"
	})
	if err != nil {
		t.Fatalf("ambiguous write terminal: %v last=%#v", err, terminal)
	}
	if StringField(terminal, "conclusion") != "写入结果尚不明确；系统不会重发目标写入。" || session.Fixture.Snapshot().TaskWrites != 1 || session.Fixture.Snapshot().Requests["/gtw/cwai/Task/SwitchTask"] != 1 {
		t.Fatalf("ambiguous write terminal=%#v snapshot=%#v", terminal, session.Fixture.Snapshot())
	}
	for i := 0; i < 4; i++ {
		mustGetObject(t, session.Browser, "/api/journey?intent=manage_tasks&window=today")
	}
	if session.Fixture.Snapshot().TaskWrites != 1 || session.Fixture.Snapshot().Requests["/gtw/cwai/Task/SwitchTask"] != 1 {
		t.Fatalf("ambiguous refresh replayed write: %#v", session.Fixture.Snapshot())
	}
	recordNormalized(t, NormalizedResult{Scenario: "G-ACT-07/task-write-response-lost", Class: "unknown", DeviceWrites: 1, Dispatches: 1})
}

func assertBaselineSummary(t *testing.T, raw any, window string) {
	t.Helper()
	summary, ok := raw.(map[string]any)
	if !ok {
		t.Fatalf("operations summary is not an object: %#v", raw)
	}
	if StringField(summary, "window") != window || StringField(summary, "conclusion") != "运营摘要读取完成" || IntField(summary, "cameraCount") != 1 || IntField(summary, "taskCount") != 1 || IntField(summary, "running") != 1 || IntField(summary, "stopped") != 0 || IntField(summary, "unknown") != 0 || IntField(summary, "alarmCount") != 0 || StringField(summary, "alarmAccuracy") != "exact" || StringField(summary, "alarmText") != "0 条告警" || len(ArrayField(summary, "recentAlarms")) != 0 {
		t.Fatalf("operations summary=%#v", summary)
	}
}

func mustPostConnectionPreview(t *testing.T, browser *Browser, host, username string) map[string]any {
	t.Helper()
	status, raw, err := browser.Form("/api/connection/prepare", url.Values{"endpoint": {host}, "username": {username}})
	if err != nil || status != http.StatusOK {
		t.Fatalf("connection preview status=%d err=%v body=%s", status, err, raw)
	}
	return mustObject(t, raw)
}
