package web

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/cosmo-wander-ai/cosmoedge-connect/internal/operator/read"
	"github.com/cosmo-wander-ai/cosmoedge-connect/internal/operator/session"
)

// Execute the served JavaScript with a small DOM and recording fetch. Merely
// finding a form in the template would not catch an initial journey fetch or
// an automatic saved-connection retry before the form can be used.
func TestConnectionViewRendersWithoutDeviceRequests(t *testing.T) {
	for _, test := range []struct {
		name, view, existingState string
		retry, connectClick       bool
		wantInitialRequests       int
	}{
		{name: "first use", view: session.ViewConnection, existingState: "disconnected"},
		{name: "saved retry", view: session.ViewConnection, existingState: "disconnected", retry: true},
		{name: "already connected", view: session.ViewConnection, existingState: "ready"},
		{name: "confirmed connection returns to home", view: session.ViewConnection, connectClick: true},
		{name: "ordinary home still loads facts", view: "home", wantInitialRequests: 1},
	} {
		t.Run(test.name, func(t *testing.T) {
			vault := session.New(nil)
			backend := &connectionPageBackend{retry: test.retry, state: test.existingState}
			host := New("http://127.0.0.1:12345", "private-control", backend, vault, nil)
			bootstrap, err := host.BootstrapURL(test.view)
			if err != nil {
				t.Fatal(err)
			}
			response := httptest.NewRecorder()
			host.ServeHTTP(response, httptest.NewRequest(http.MethodGet, bootstrap, nil))
			if response.Code != http.StatusSeeOther {
				t.Fatal("bootstrap failed", response.Code)
			}
			request := httptest.NewRequest(http.MethodGet, host.baseURL+"/", nil)
			for _, cookie := range response.Result().Cookies() {
				request.AddCookie(cookie)
			}
			response = httptest.NewRecorder()
			host.ServeHTTP(response, request)
			if response.Code != http.StatusOK || backend.journeys != 0 {
				t.Fatal("serving the page fetched device facts")
			}
			wantLocalChecks := 0
			if test.view == session.ViewConnection {
				wantLocalChecks = 1
			}
			if backend.localChecks != wantLocalChecks {
				t.Fatalf("local retry checks=%d want=%d", backend.localChecks, wantLocalChecks)
			}
			page := response.Body.String()
			start, end := strings.Index(page, "<script>"), strings.LastIndex(page, "</script>")
			if start < 0 || end <= start {
				t.Fatal("page has no script")
			}
			path := filepath.Join(t.TempDir(), "page.js")
			if err := os.WriteFile(path, []byte(page[start+len("<script>"):end]), 0600); err != nil {
				t.Fatal(err)
			}
			mode := "initial"
			if test.connectClick {
				mode = "connect"
			}
			output, err := exec.Command("node", "-e", connectionPageHarness, path, mode).CombinedOutput()
			if err != nil {
				t.Fatalf("page JavaScript: %v\n%s", err, output)
			}
			var result struct {
				InitialRequests []string `json:"initialRequests"`
				Requests        []string `json:"requests"`
				Text            string   `json:"text"`
				ActiveView      string   `json:"activeView"`
				DelayedLoad     bool     `json:"delayedLoad"`
			}
			if err := json.Unmarshal(output, &result); err != nil {
				t.Fatal(err, string(output))
			}
			if len(result.InitialRequests) != test.wantInitialRequests {
				t.Fatalf("initial requests=%v", result.InitialRequests)
			}
			if test.view == session.ViewConnection {
				if !strings.Contains(result.Text, "设备 IP") || !strings.Contains(result.Text, "确认设备地址") || strings.Contains(result.Text, "重试已保存连接") != test.retry {
					t.Fatal("connection form or saved retry entry was not rendered", result.Text)
				}
			} else if result.InitialRequests[0] != "/api/journey?intent=home&window=today" {
				t.Fatal("ordinary home no longer loads its journey")
			}
			if test.connectClick {
				if strings.Join(result.Requests, ",") != "/api/connection/prepare,/api/connection/connect" || result.ActiveView != "home" || !result.DelayedLoad {
					t.Fatalf("confirmed connection did not return to home: %+v", result)
				}
			} else if len(result.Requests) != test.wantInitialRequests {
				t.Fatal("page sent additional requests without a user action", result.Requests)
			}
		})
	}
}

type connectionPageBackend struct {
	fakeBackend
	retry                 bool
	state                 string
	journeys, localChecks int
}

func (b *connectionPageBackend) Journey(context.Context, string, string, string) (read.Projection, error) {
	b.journeys++
	return read.Projection{State: b.state}, nil
}

func (b *connectionPageBackend) CanRetrySavedConnection() bool {
	b.localChecks++
	return b.retry
}

const connectionPageHarness = `
const fs = require('node:fs'), vm = require('node:vm');
class Element {
  constructor(tag) { this.tag = tag; this.children = []; this.textContent = ''; this.value = ''; this.dataset = {}; this.classList = {add(){}, toggle(){}}; }
  append(...children) { this.children.push(...children); }
  replaceChildren(...children) { this.children = children; }
  insertBefore(child, before) { this.children.splice(this.children.indexOf(before), 0, child); }
  querySelectorAll(tag) { return this.children.flatMap(c => [...(c.tag === tag ? [c] : []), ...c.querySelectorAll(tag)]); }
}
const roots = Object.fromEntries(['content','identity','tabs'].map(id => [id, new Element('div')]));
const requests = [], timers = [];
const context = vm.createContext({
  document: {getElementById: id => roots[id], createElement: tag => new Element(tag)},
  clearTimeout(){}, setTimeout(fn, delay){timers.push(delay);}, URLSearchParams,
  fetch: async (path, options) => {
    requests.push(path);
    if (path.startsWith('/api/journey')) return new Promise(() => {});
    if (path === '/api/connection/prepare') return {ok:true, json:async()=>({connectionToken:'local-preview', replacementRequired:false})};
    if (path === '/api/connection/connect') {
      if (options.body.get('replaceSavedDevice') !== 'false') throw new Error('automatic replacement');
      return {ok:true, json:async()=>({state:'connected'})};
    }
    throw new Error('unexpected request: ' + path);
  }
});
function text(node) { return node.textContent + node.children.map(text).join(''); }
vm.runInContext(fs.readFileSync(process.argv[1], 'utf8'), context);
const initialRequests = [...requests], initialText = text(roots.content);
(async () => {
  if (process.argv[2] === 'connect') {
    await roots.content.querySelectorAll('button').find(b => b.textContent === '确认设备地址').onclick();
    await roots.content.querySelectorAll('button').find(b => b.textContent === '确认连接').onclick();
  }
  console.log(JSON.stringify({initialRequests, requests, text:initialText, activeView:vm.runInContext('activeView', context), delayedLoad:timers.includes(120)}));
})().catch(error => {console.error(error); process.exitCode = 1;});
`
