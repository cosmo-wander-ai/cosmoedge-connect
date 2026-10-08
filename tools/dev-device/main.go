package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/cosmo-wander-ai/cosmoedge-connect/internal/devauthority"
	"github.com/cosmo-wander-ai/cosmoedge-connect/internal/devwrite"
)

func main() {
	if err := run(os.Args[1:], os.Stdin, os.Stdout); err != nil {
		_ = json.NewEncoder(os.Stderr).Encode(map[string]string{
			"status": "failed", "reason": failureReason(err),
		})
		os.Exit(1)
	}
}

func run(args []string, in io.Reader, out io.Writer) error {
	if len(args) == 0 {
		return errors.New("command is required")
	}
	store, err := devauthority.NewStore("")
	if err != nil {
		return err
	}
	authority, err := devauthority.New(store)
	if err != nil {
		return err
	}
	encode := json.NewEncoder(out)
	encode.SetEscapeHTML(false)
	switch args[0] {
	case "authorize":
		if len(args) != 1 {
			return errors.New("authorize accepts its request only on stdin")
		}
		var request devauthority.AuthorizationRequest
		decoder := json.NewDecoder(io.LimitReader(in, 32<<10))
		if err := decoder.Decode(&request); err != nil {
			return errors.New("authorization request is invalid")
		}
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
		defer cancel()
		result, err := authority.Authorize(ctx, request)
		request.PasswordBase64 = ""
		if err != nil {
			return err
		}
		return encode.Encode(result)
	case "authorize-local":
		if len(args) != 1 {
			return errors.New("authorize-local accepts no arguments")
		}
		return serveLocalAuthorize(authority, out, filepath.Join(store.Root(), "enroll-url.json"))
	case "status":
		if len(args) != 1 {
			return errors.New("status accepts no arguments")
		}
		return encode.Encode(authority.Status())
	case "verify-read":
		if len(args) != 1 {
			return errors.New("verify-read accepts no arguments")
		}
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
		defer cancel()
		result, err := authority.VerifyRead(ctx)
		if err != nil {
			return err
		}
		return encode.Encode(result)
	case "verify-task-roundtrip":
		if len(args) != 2 {
			return errors.New("verify-task-roundtrip requires one displayed task list number")
		}
		index, err := strconv.Atoi(args[1])
		if err != nil || index < 1 || index > 10000 {
			return errors.New("displayed task list number is unavailable")
		}
		ctx, cancel := context.WithTimeout(context.Background(), 4*time.Minute)
		defer cancel()
		validator, err := devwrite.New(authority)
		if err != nil {
			return err
		}
		result, verifyErr := validator.VerifyTaskRoundTrip(ctx, index)
		if result.RunID != "" {
			if err := encode.Encode(result); err != nil {
				return err
			}
		}
		return verifyErr
	case "revoke":
		if len(args) != 1 {
			return errors.New("revoke accepts no arguments")
		}
		if err := authority.Revoke(); err != nil {
			return err
		}
		return encode.Encode(map[string]string{"status": "revoked"})
	default:
		return fmt.Errorf("unsupported development device command %q", args[0])
	}
}

func failureReason(err error) string {
	message := strings.ToLower(err.Error())
	switch {
	case strings.Contains(message, "login:"):
		return "device_login_failed"
	case strings.Contains(message, "identify device:") || strings.Contains(message, "device identity is incomplete"):
		return "device_identity_read_failed"
	case strings.Contains(message, "read camera catalog page"):
		return "device_catalog_page_failed"
	case strings.Contains(message, "rows are unavailable"):
		return "device_catalog_rows_unavailable"
	case strings.Contains(message, "total changed"):
		return "device_catalog_total_drift"
	case strings.Contains(message, "row is malformed"):
		return "device_catalog_row_malformed"
	case strings.Contains(message, "camera binding is incomplete"):
		return "device_camera_binding_incomplete"
	case strings.Contains(message, "task row is malformed"):
		return "device_task_row_malformed"
	case strings.Contains(message, "task binding is incomplete"):
		return "device_task_binding_incomplete"
	case strings.Contains(message, "page safety limit exceeded"):
		return "device_catalog_page_limit"
	case strings.Contains(message, "read camera catalog:"):
		return "device_catalog_read_failed"
	case strings.Contains(message, "expired"):
		return "authority_expired"
	case strings.Contains(message, "does not allow"):
		return "action_not_authorized"
	case strings.Contains(message, "identity drift"):
		return "device_identity_drift"
	case strings.Contains(message, "not exist") || strings.Contains(message, "cannot find"):
		return "authority_not_found"
	case strings.Contains(message, "timed out") || errors.Is(err, context.DeadlineExceeded):
		return "verification_timed_out"
	case strings.Contains(message, "task restoration") || strings.Contains(message, "recovery"):
		return "recovery_required"
	default:
		return "verification_failed"
	}
}
