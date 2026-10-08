package observation

import (
	"context"
	"errors"
	"time"

	"github.com/cosmo-wander-ai/cosmoedge-connect/internal/inspection/mediaprep"
)

// captureProgress observes the existing acquisition. It cannot acquire or
// submit analysis, including after an interrupted request or a service restart.
func captureProgress(ctx context.Context, r *resources, value operation, now time.Time) (status string, pending bool, mediaRef string, err error) {
	preparation, err := r.preparations.Get(ctx, value.PreparationRef)
	if err != nil && !errors.Is(err, mediaprep.ErrNotFound) {
		return "", false, "", err
	}
	found := err == nil
	if found && preparation.Validate(value.PreparationRef) != nil {
		return "", false, "", ErrUnavailable
	}
	if found && preparation.State == mediaprep.StateReady {
		mediaRef = preparation.MediaRef
	}
	if value.Stage == "terminal" {
		if value.Failure != "" {
			return value.Failure, false, mediaRef, nil
		}
		return "captured", false, mediaRef, nil
	}
	if found {
		switch preparation.State {
		case mediaprep.StateReady:
			return "captured", false, mediaRef, nil
		case mediaprep.StateFailed:
			if preparation.Reason == mediaprep.ReasonEvidenceExpired {
				return "expired", false, "", nil
			}
			return "capture_failed", false, "", nil
		}
	}
	if !now.Before(value.DeadlineAt) {
		if !found || preparation.State == mediaprep.StatePrepared {
			return "expired", false, "", nil
		}
		return "outcome_unknown", false, "", nil
	}
	if found {
		return "capturing", true, "", nil
	}
	return "queued", true, "", nil
}
