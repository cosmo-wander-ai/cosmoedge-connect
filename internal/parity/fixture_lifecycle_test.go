package parity

import (
	"errors"
	"net"
	"net/http"
	"testing"
	"time"
)

func TestFixtureStopAllowsImmediateRebind(t *testing.T) {
	for _, waitForRequest := range []bool{false, true} {
		name := "before_first_request"
		if waitForRequest {
			name = "after_request"
		}
		t.Run(name, func(t *testing.T) {
			// Exercise the same serving lifecycle without reserving the parity
			// fixture's private standard device address or port.
			client := &http.Client{Timeout: time.Second, Transport: &http.Transport{DisableKeepAlives: true}}
			defer client.CloseIdleConnections()
			for i := 0; i < 25; i++ {
				listener, err := net.Listen("tcp4", "127.0.0.1:0")
				if err != nil {
					t.Fatal(err)
				}
				address := listener.Addr().String()
				stop := serveFixture(listener, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
					w.WriteHeader(http.StatusNoContent)
				}))
				t.Cleanup(func() { _ = stop() })
				if waitForRequest {
					response, err := client.Get("http://" + address)
					if err != nil {
						t.Fatal(err)
					}
					_ = response.Body.Close()
					if response.StatusCode != http.StatusNoContent {
						t.Fatalf("fixture response status=%d", response.StatusCode)
					}
				}
				if err := stop(); err != nil {
					t.Fatalf("stop iteration %d: %v", i, err)
				}
				rebound, err := net.Listen("tcp4", address)
				if err != nil {
					t.Fatalf("Stop returned before address could be rebound, iteration %d: %v", i, err)
				}
				if err := stop(); err != nil {
					_ = rebound.Close()
					t.Fatalf("repeated Stop failed: %v", err)
				}
				if err := rebound.Close(); err != nil {
					t.Fatal(err)
				}
			}
		})
	}
}

func TestFixtureStopRetainsUnexpectedCloseError(t *testing.T) {
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	address := listener.Addr().String()
	closeErr := errors.New("synthetic listener close error")
	stop := serveFixture(&closeErrorListener{Listener: listener, closeErr: closeErr}, http.NotFoundHandler())
	t.Cleanup(func() { _ = stop() })
	if err := stop(); !errors.Is(err, closeErr) {
		t.Fatalf("unexpected listener close error was lost: %v", err)
	}
	if err := stop(); !errors.Is(err, closeErr) {
		t.Fatalf("repeated Stop lost original close error: %v", err)
	}
	rebound, err := net.Listen("tcp4", address)
	if err != nil {
		t.Fatalf("Stop left the owned listener bound after close error: %v", err)
	}
	_ = rebound.Close()
}

type closeErrorListener struct {
	net.Listener
	closeErr error
}

func (l *closeErrorListener) Close() error {
	if err := l.Listener.Close(); err != nil {
		return err
	}
	return l.closeErr
}
