package main

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"html/template"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/cosmo-wander-ai/cosmoedge-connect/internal/devauthority"
	"github.com/cosmo-wander-ai/cosmoedge-connect/internal/localstate"
)

const localAuthorizeHTML = `<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<meta name="referrer" content="no-referrer"><title>CosmoEdge Development Authority</title>
<style>body{font:15px system-ui;margin:0;background:#f5f6f8;color:#18202a}main{max-width:620px;margin:48px auto;padding:28px;background:#fff;border:1px solid #d8dde5;border-radius:6px}h1{font-size:22px;margin:0 0 8px}p{color:#53606f}label{display:block;margin:16px 0 5px;font-weight:600}input[type=text],input[type=password],input[type=number]{box-sizing:border-box;width:100%;height:40px;padding:8px;border:1px solid #aeb7c3;border-radius:4px}.check{display:flex;gap:8px;align-items:center;font-weight:500}.check input{width:18px;height:18px}button{margin-top:20px;height:42px;border:0;border-radius:4px;padding:0 18px;background:#146c43;color:#fff;font-weight:700}.status{font-weight:700;color:#146c43}.error{font-weight:700;color:#ad2f2f}</style></head>
<body><main><h1>Development device authorization</h1><p>This one-time local page stores an expiring, machine-bound DPAPI credential. It is not part of the Operator release.</p>
{{if .Authorized}}<p id="authorization-status" class="status">authorized</p><p>You may close this page.</p>{{else}}
{{if .Failed}}<p id="authorization-status" class="error">authorization_failed</p>{{end}}
<form method="post" autocomplete="off">
<label for="endpoint">Device IP or private URL</label><input id="endpoint" name="endpoint" type="text" required autocomplete="off">
<label for="username">Device account</label><input id="username" name="username" type="text" required autocomplete="off">
<label for="password">Device password</label><input id="password" name="password" type="password" required autocomplete="off">
<label for="validDays">Validity in days</label><input id="validDays" name="validDays" type="number" min="1" max="90" value="30" required>
<label class="check"><input id="allowTaskSwitchRoundTrip" name="allowTaskSwitchRoundTrip" type="checkbox" value="true" checked>Allow reversible task-switch round-trip validation</label>
<button id="authorize" type="submit">Authorize this development machine</button>
</form>{{end}}</main></body></html>`

var localAuthorizeTemplate = template.Must(template.New("authorize").Parse(localAuthorizeHTML))

type authorizationIssuer interface {
	Authorize(context.Context, devauthority.AuthorizationRequest) (devauthority.AuthorizationResult, error)
}

func serveLocalAuthorize(authority authorizationIssuer, out io.Writer, handoffPath string) error {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return err
	}
	defer listener.Close()
	tokenBytes := make([]byte, 32)
	if _, err := rand.Read(tokenBytes); err != nil {
		return err
	}
	token := hex.EncodeToString(tokenBytes)
	baseURL := "http://" + listener.Addr().String()
	path := "/authorize/" + token
	completed := make(chan struct{}, 1)
	var completion sync.Once
	mux := http.NewServeMux()
	mux.HandleFunc(path, func(writer http.ResponseWriter, request *http.Request) {
		writer.Header().Set("Cache-Control", "no-store, max-age=0")
		writer.Header().Set("Content-Security-Policy", "default-src 'none'; style-src 'unsafe-inline'; form-action 'self'; base-uri 'none'; frame-ancestors 'none'")
		writer.Header().Set("X-Content-Type-Options", "nosniff")
		writer.Header().Set("Referrer-Policy", "no-referrer")
		if request.Host != listener.Addr().String() {
			http.Error(writer, "invalid host", http.StatusBadRequest)
			return
		}
		switch request.Method {
		case http.MethodGet:
			writer.Header().Set("Content-Type", "text/html; charset=utf-8")
			_ = localAuthorizeTemplate.Execute(writer, map[string]bool{})
		case http.MethodPost:
			if request.Header.Get("Origin") != baseURL {
				http.Error(writer, "invalid origin", http.StatusForbidden)
				return
			}
			request.Body = http.MaxBytesReader(writer, request.Body, 16<<10)
			if err := request.ParseForm(); err != nil {
				http.Error(writer, "invalid request", http.StatusBadRequest)
				return
			}
			days, err := strconv.Atoi(request.PostForm.Get("validDays"))
			if err != nil || days < 1 || days > 90 {
				http.Error(writer, "invalid lifetime", http.StatusBadRequest)
				return
			}
			password := []byte(request.PostForm.Get("password"))
			result, authorizeErr := authority.Authorize(request.Context(), devauthority.AuthorizationRequest{
				Endpoint: request.PostForm.Get("endpoint"), Username: request.PostForm.Get("username"),
				PasswordBase64: base64.StdEncoding.EncodeToString(password), ValidForHours: days * 24,
				AllowTaskSwitchRoundTrip: strings.EqualFold(request.PostForm.Get("allowTaskSwitchRoundTrip"), "true"),
			})
			for index := range password {
				password[index] = 0
			}
			writer.Header().Set("Content-Type", "text/html; charset=utf-8")
			if authorizeErr != nil || result.Status != "authorized" {
				writer.WriteHeader(http.StatusUnauthorized)
				_ = localAuthorizeTemplate.Execute(writer, map[string]bool{"Failed": true})
				return
			}
			_ = localAuthorizeTemplate.Execute(writer, map[string]bool{"Authorized": true})
			completion.Do(func() { completed <- struct{}{} })
		default:
			writer.Header().Set("Allow", "GET, POST")
			http.Error(writer, "method not allowed", http.StatusMethodNotAllowed)
		}
	})
	server := &http.Server{Handler: mux, ReadHeaderTimeout: 5 * time.Second}
	serveErrors := make(chan error, 1)
	go func() { serveErrors <- server.Serve(listener) }()
	handoff := map[string]string{"status": "waiting", "url": baseURL + path}
	if err := writeHandoff(handoffPath, handoff); err != nil {
		return err
	}
	defer os.Remove(handoffPath)
	if err := json.NewEncoder(out).Encode(handoff); err != nil {
		return err
	}
	select {
	case <-completed:
		shutdownContext, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		if err := server.Shutdown(shutdownContext); err != nil {
			return err
		}
		return nil
	case err := <-serveErrors:
		if errors.Is(err, http.ErrServerClosed) {
			return nil
		}
		return err
	case <-time.After(5 * time.Minute):
		_ = server.Close()
		return fmt.Errorf("local authorization expired")
	}
}

func writeHandoff(path string, value map[string]string) error {
	root := filepath.Dir(path)
	if err := localstate.PrepareStateRoot(root); err != nil {
		return err
	}
	raw, err := json.Marshal(value)
	if err != nil {
		return err
	}
	temporary := path + ".tmp"
	defer os.Remove(temporary)
	if err := os.WriteFile(temporary, raw, 0o600); err != nil {
		return err
	}
	if err := localstate.ProtectFile(temporary); err != nil {
		return err
	}
	if _, err := os.Lstat(path); err == nil {
		if err := localstate.ValidateFile(path); err != nil {
			return err
		}
		if err := os.Remove(path); err != nil {
			return err
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	if err := os.Rename(temporary, path); err != nil {
		return err
	}
	return localstate.ProtectFile(path)
}
