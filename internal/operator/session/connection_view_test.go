package session

import "testing"

func TestConnectionBootstrapPreservesViewWithoutBusinessIntent(t *testing.T) {
	vault := New(nil)
	token, err := vault.IssueBootstrapForView(ViewConnection)
	if err != nil {
		t.Fatal(err)
	}
	auth, err := vault.ConsumeBootstrap(token)
	if err != nil || auth.View != ViewConnection || auth.TaskName != "" || auth.TaskAction != "" {
		t.Fatalf("connection view was not preserved: view=%q err=%v", auth.View, err)
	}
	for _, intent := range []OpenIntent{
		{View: ViewConnection, TaskName: "task", TaskAction: "enable"},
		{View: ViewConnection, HandoffRef: "proposal"},
	} {
		if _, err := vault.IssueBootstrapForIntent(intent); err == nil {
			t.Fatal("connection page accepted a business action intent")
		}
	}
}
