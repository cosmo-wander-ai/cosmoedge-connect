package session

import (
	"errors"
	"testing"
	"time"
)

func TestDeploymentBootstrapCannotBorrowInspectionOrAnotherBrowser(t *testing.T) {
	v := New(nil)
	now := time.Now()
	v.now = func() time.Time { return now }
	for _, bad := range []OpenIntent{{View: ViewDeploymentConfirmation}, {View: ViewDeploymentConfirmation, HandoffRef: "exact", TaskName: "override"}, {View: ViewDeploymentConfirmation, HandoffRef: "exact", TaskAction: "disable"}} {
		if _, err := v.IssueBootstrapForIntent(bad); err == nil {
			t.Fatal("accepted forged intent")
		}
	}
	token, err := v.IssueBootstrapForIntent(OpenIntent{View: ViewDeploymentConfirmation, HandoffRef: "deployment_exact"})
	if err != nil {
		t.Fatal(err)
	}
	auth, err := v.ConsumeBootstrap(token)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := v.ConsumeBootstrap(token); !errors.Is(err, ErrConflict) {
		t.Fatal("bootstrap replay accepted")
	}
	if ref, err := v.DeploymentHandoff(auth); err != nil || ref != "deployment_exact" {
		t.Fatal("wrong deployment handoff")
	}
	if _, err := v.InspectionHandoff(auth); !errors.Is(err, ErrUnauthorized) {
		t.Fatal("deployment auth became inspection auth")
	}
	for _, mutate := range []func(*BrowserAuth){func(a *BrowserAuth) { a.inspectionHandoffRef = "another" }, func(a *BrowserAuth) { a.View = ViewInspectionInteraction }, func(a *BrowserAuth) { a.seal = [32]byte{} }, func(a *BrowserAuth) { a.CSRF = "forged" }} {
		forged := auth
		mutate(&forged)
		if _, err := v.DeploymentHandoff(forged); !errors.Is(err, ErrUnauthorized) {
			t.Fatal("forged browser accepted")
		}
	}
	if _, err := New(nil).DeploymentHandoff(auth); !errors.Is(err, ErrUnauthorized) {
		t.Fatal("another vault accepted auth")
	}
	now = now.Add(browserTTL + time.Second)
	if _, err := v.DeploymentHandoff(auth); !errors.Is(err, ErrUnauthorized) {
		t.Fatal("expired auth accepted")
	}
}
