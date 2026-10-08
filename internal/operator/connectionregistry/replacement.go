package connectionregistry

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"log/slog"
	"strings"

	"github.com/cosmo-wander-ai/cosmoedge-connect/internal/operator/authority"
	"github.com/cosmo-wander-ai/cosmoedge-connect/internal/operator/credential"
	"github.com/cosmo-wander-ai/cosmoedge-connect/internal/operator/onboarding"
	"github.com/cosmo-wander-ai/cosmoedge-connect/internal/operator/profile"
)

// ConnectionPlan is protected local confirmation state, frozen before login.
// It binds an explicit replacement to the current selection and target account.
type ConnectionPlan struct {
	Selection                                             Selection
	ProfileGeneration                                     uint64
	TargetTransportFingerprint                            string
	CurrentEndpoint                                       string
	Configured, ReplacementRequired, ReplacementAvailable bool
}

func (ConnectionPlan) MarshalJSON() ([]byte, error) { return nil, credential.ErrProtectedProjection }
func (ConnectionPlan) MarshalText() ([]byte, error) { return nil, credential.ErrProtectedProjection }
func (ConnectionPlan) String() string               { return "[protected-connection-plan]" }
func (ConnectionPlan) GoString() string             { return "connectionregistry.ConnectionPlan([redacted])" }
func (ConnectionPlan) LogValue() slog.Value         { return slog.StringValue("[protected-connection-plan]") }

func (r *Registry) selection(ctx context.Context) (Selection, error) {
	if r.current == nil {
		return Selection{ProfileID: r.profileID, Revision: 1}, nil
	}
	return r.current.Current(ctx)
}
func (r *Registry) currentProfile(ctx context.Context) (profile.DeviceProfile, error) {
	selected, err := r.selection(ctx)
	if err != nil {
		return profile.DeviceProfile{}, err
	}
	return r.profiles.Get(ctx, r.tenantID, r.siteID, selected.ProfileID)
}
func (r *Registry) ConnectionEpoch(ctx context.Context) (string, error) {
	if r.current == nil {
		return "", nil
	}
	selected, err := r.selection(ctx)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256([]byte(fmt.Sprintf("cosmoedge-connect.connection-epoch.v1\x00%s\x00%d", selected.ProfileID, selected.Revision)))
	return hex.EncodeToString(sum[:]), nil
}
func (r *Registry) PrepareConnection(ctx context.Context, endpoint, username string) (ConnectionPlan, error) {
	transport, err := profile.ComputeTransportFingerprint(endpoint, username)
	if err != nil {
		return ConnectionPlan{}, err
	}
	selected, err := r.selection(ctx)
	if err != nil {
		return ConnectionPlan{}, err
	}
	plan := ConnectionPlan{Selection: selected, TargetTransportFingerprint: strings.TrimPrefix(transport, "sha256:")}
	current, err := r.profiles.Get(ctx, r.tenantID, r.siteID, selected.ProfileID)
	if errors.Is(err, profile.ErrNotFound) && selected.ProfileID == r.profileID {
		return plan, nil
	}
	if err != nil {
		return ConnectionPlan{}, err
	}
	if current.Validate() != nil {
		return ConnectionPlan{}, ErrBindingConflict
	}
	plan.Configured, plan.ReplacementAvailable = true, r.current != nil
	plan.ProfileGeneration, plan.CurrentEndpoint = current.Generation, current.Endpoint
	plan.ReplacementRequired = current.TransportFingerprint != transport || current.State != profile.StateActive
	return plan, nil
}

// CommitPrepared is only called for a consumed browser confirmation. Ordinary
// CommitVerified and automatic Restore never perform profile replacement.
func (r *Registry) CommitPrepared(ctx context.Context, plan ConnectionPlan, confirmationID string, replace bool, verified VerifiedConnection, secret []byte) error {
	defer clear(secret)
	if !r.validVerified(verified) || verified.TransportFingerprint != plan.TargetTransportFingerprint || len(secret) == 0 {
		return ErrBindingConflict
	}
	if err := r.ValidatePlan(ctx, plan); err != nil {
		return err
	}
	selected := plan.Selection
	if !replace {
		if plan.ReplacementRequired {
			return ErrBindingConflict
		}
		return r.CommitVerified(ctx, verified, secret)
	}
	if !plan.Configured || !plan.ReplacementAvailable || r.current == nil || !digestPattern.MatchString(confirmationID) {
		return ErrBindingConflict
	}
	identity := sha256.Sum256([]byte("cosmoedge-connect.connection-replacement.v1\x00" + confirmationID))
	id := hex.EncodeToString(identity[:16])
	operationID, newProfileID := "onb_"+id, "dpf_"+id
	target := sha256.Sum256([]byte(verified.TransportFingerprint + "\x00" + verified.PinnedSerial + "\x00" + verified.PinnedType))
	targetDigest := hex.EncodeToString(target[:])
	if err := r.current.prepare(ctx, selected, operationID, newProfileID, targetDigest); err != nil {
		return err
	}
	access, err := r.access([]string{authority.OpProfileCreate}, "connection-registry-replace", "")
	if err != nil {
		return err
	}
	result, err := r.onboarding.Create(ctx, onboarding.CreateRequest{
		OperationID: operationID, Access: access, ProfileID: newProfileID, Alias: fmt.Sprintf("本地接入 %d · %s", selected.Revision+1, id[:8]),
		Endpoint: verified.Endpoint, Username: verified.Username, Secret: secret, PinnedSerial: verified.PinnedSerial, PinnedType: verified.PinnedType,
	})
	if err != nil {
		return err
	}
	if result.Status != onboarding.StatusCompleted || result.Phase != onboarding.PhaseCompleted || result.Summary == nil || result.Summary.ProfileID != newProfileID || result.Summary.State != "ready" {
		return ErrBindingConflict
	}
	// The old profile/credential remains untouched even if this CAS fails.
	return r.current.switchCurrent(ctx, selected, operationID, newProfileID, targetDigest)
}

func (r *Registry) ValidatePlan(ctx context.Context, plan ConnectionPlan) error {
	selected, err := r.selection(ctx)
	if err != nil {
		return err
	}
	if selected != plan.Selection {
		return ErrBindingConflict
	}
	current, err := r.profiles.Get(ctx, r.tenantID, r.siteID, selected.ProfileID)
	if plan.Configured {
		if err != nil {
			return err
		}
		if current.Generation != plan.ProfileGeneration {
			return ErrBindingConflict
		}
		return nil
	}
	if errors.Is(err, profile.ErrNotFound) {
		return nil
	}
	if err != nil {
		return err
	}
	return ErrBindingConflict
}
