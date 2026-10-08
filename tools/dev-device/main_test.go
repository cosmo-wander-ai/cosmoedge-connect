package main

import (
	"errors"
	"testing"
)

func TestFailureReasonProjectsDeviceHandshakeStages(t *testing.T) {
	tests := map[string]struct {
		err  error
		want string
	}{
		"login":        {errors.New("login: private device response"), "device_login_failed"},
		"identity":     {errors.New("identify device: private device response"), "device_identity_read_failed"},
		"catalog page": {errors.New("read camera catalog page 1: private device response"), "device_catalog_page_failed"},
		"catalog rows": {errors.New("read camera catalog: rows are unavailable"), "device_catalog_rows_unavailable"},
		"task binding": {errors.New("read camera catalog: task binding is incomplete"), "device_task_binding_incomplete"},
		"catalog":      {errors.New("read camera catalog: private device response"), "device_catalog_read_failed"},
		"default":      {errors.New("private device response"), "verification_failed"},
	}
	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			if got := failureReason(test.err); got != test.want {
				t.Fatalf("failureReason() = %q, want %q", got, test.want)
			}
		})
	}
}
