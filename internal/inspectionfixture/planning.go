package inspectionfixture

import (
	"context"
	"errors"
	"time"

	"github.com/cosmo-wander-ai/cosmoedge-connect/internal/inspection/media"
	"github.com/cosmo-wander-ai/cosmoedge-connect/internal/inspection/mediaprep"
	"github.com/cosmo-wander-ai/cosmoedge-connect/internal/inspection/planning"
	"github.com/cosmo-wander-ai/cosmoedge-connect/internal/inspection/resolver"
	"github.com/cosmo-wander-ai/cosmoedge-connect/internal/inspection/temporary"
)

const (
	InstructionTemporary  = "临时查看公共区域是否有需要关注的情况"
	InstructionConnection = "准备现场接入"
)

type closedInterpreter struct{ clipWindowSeconds int }

func (i closedInterpreter) Interpret(_ context.Context, request planning.InterpretationRequest) (planning.InterpretedIntent, error) {
	if !containsString(request.Vocabulary.SourceNames, SourceAlias) || !containsString(request.Vocabulary.ObservableNames, ObservableName) {
		return planning.InterpretedIntent{}, errors.New("fixture business vocabulary is incomplete")
	}
	base := planning.InspectionIntent{
		Mode: planning.ModeStandard, SourceName: SourceAlias, ObservableName: ObservableName,
		TimeScope: temporary.TimeScope{Kind: temporary.TimeScopeCurrent},
	}
	if request.Instruction == InstructionConnection {
		purpose := planning.ConnectNew
		return planning.InterpretedIntent{Goal: planning.IntentConnect, Connection: &purpose}, nil
	}
	switch request.Instruction {
	case InstructionExisting:
		base.Preference = planning.PreferExistingTask
		base.TaskName = TaskAlias
		base.TimeScope = temporary.TimeScope{Kind: temporary.TimeScopeRecentWindow, WindowSeconds: 60}
	case InstructionSnapshot:
		base.Preference = planning.PreferSnapshot
	case InstructionClip:
		base.Preference = planning.PreferClip
		if i.clipWindowSeconds < 1 {
			return planning.InterpretedIntent{}, errors.New("fixture clip window is unavailable")
		}
		base.TimeScope = temporary.TimeScope{Kind: temporary.TimeScopeRecentWindow, WindowSeconds: i.clipWindowSeconds}
	case InstructionHybrid:
		base.Preference = planning.PreferHybrid
		base.TaskName = TaskAlias
	case InstructionTemporary:
		base = planning.InspectionIntent{
			Mode: planning.ModeTemporaryVisual, SourceName: SourceAlias, Preference: planning.PreferSnapshot,
			TimeScope: temporary.TimeScope{Kind: temporary.TimeScopeCurrent},
			Temporary: &planning.TemporaryObservationIntent{
				Subject: "公共区域", Region: "当前画面", Observable: "是否有需要关注的可见情况",
				Locale: "zh-CN", EvidenceTTLSeconds: 600,
			},
		}
	default:
		if !naturalFixtureInstruction(request.Instruction) {
			return planning.InterpretedIntent{}, errors.New("fixture accepts only its closed business instruction set")
		}
		base.Preference = planning.PreferAuto
	}
	return planning.InterpretedIntent{Goal: planning.IntentInspect, Inspection: &base}, nil
}

func naturalFixtureInstruction(value string) bool {
	for _, sourceName := range []string{SourceAlias, "当前区域"} {
		if value == "帮我查看"+sourceName+"的"+ObservableName || value == "帮我看看"+sourceName+"的"+ObservableName {
			return true
		}
	}
	return false
}

type staticAuthorities struct {
	config Config
}

func (a staticAuthorities) AvailableAuthorities(_ context.Context, scope resolver.AuthenticatedScope) ([]resolver.AuthorityAvailability, error) {
	if scope.TenantID != a.config.TenantID || scope.SiteID != a.config.SiteID || scope.PrincipalSHA256 != a.config.PrincipalSHA256 {
		return nil, errors.New("fixture authority scope is not bound to the configured session")
	}
	now := time.Now().UTC()
	result := make([]resolver.AuthorityAvailability, 0, 3)
	for _, class := range []resolver.AuthorityClass{
		resolver.AuthorityConnectionProfileWrite, resolver.AuthorityDeviceRead, resolver.AuthorityInspectionExecution,
	} {
		authority := resolver.AuthorityAvailability{
			Class: class, TenantID: scope.TenantID, SiteID: scope.SiteID, PrincipalSHA256: scope.PrincipalSHA256,
			VerifiedAt: now.Add(-time.Second), ExpiresAt: now.Add(10 * time.Minute),
		}
		if class == resolver.AuthorityDeviceRead || class == resolver.AuthorityInspectionExecution {
			authority.SourceHandles = []string{fixtureSourceID}
		}
		result = append(result, authority)
	}
	return result, nil
}

type temporaryCompiler struct{}

func (temporaryCompiler) Compile(_ context.Context, input planning.TemporaryMediaCompilation) (mediaprep.FrozenRequest, error) {
	start, end := input.RequestedAt.UTC(), input.RequestedAt.UTC()
	kind := media.KindImage
	if input.Spec.TimeScope.Kind == temporary.TimeScopeRecentWindow {
		start = end.Add(-time.Duration(input.Spec.TimeScope.WindowSeconds) * time.Second)
		kind = media.KindVideoClip
	}
	return mediaprep.FrozenRequest{
		Schema: mediaprep.RequestSchema, TenantID: input.TenantID, SiteID: input.SiteID, RequestID: input.RequestID,
		SourceRef: input.SourceRef, CapabilityRef: input.CapabilityRef,
		TimeScope:          mediaprep.TimeScope{WindowStart: start, WindowEnd: end, DurationMillis: end.Sub(start).Milliseconds()},
		AudienceBindingRef: input.AudienceBindingRef, AudienceSHA256: input.AudienceSHA256,
		EvidenceExpiresAt: input.EvidenceExpiresAt,
		Media: mediaprep.MediaSpec{
			Kind: kind, RunID: input.RuntimeRunID, StepID: input.RuntimeStepID, Attempt: 1,
			PrivacyClass: "internal", RedactionPolicyRef: "offline-default-redaction",
			RetentionPolicyRef: "offline-fixture-retention",
		},
	}, nil
}

var (
	_ planning.IntentInterpreter             = closedInterpreter{}
	_ planning.AuthorityProvider             = staticAuthorities{}
	_ planning.TemporaryMediaRequestCompiler = temporaryCompiler{}
)
