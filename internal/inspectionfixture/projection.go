package inspectionfixture

import (
	"context"
	"errors"
	"time"

	"github.com/cosmo-wander-ai/cosmoedge-connect/internal/inspection/application"
	"github.com/cosmo-wander-ai/cosmoedge-connect/internal/inspection/media"
)

const simulatedMediaLimitation = "本次观察仅基于模拟素材，不代表现场实时画面。"

type fixtureProjector struct {
	inner           application.ResultProjector
	store           *media.Store
	clipFrameSHA256 string
	clipFrameOffset int64
}

func (p fixtureProjector) Project(ctx context.Context, input application.ProjectionInput) (application.Projection, error) {
	if p.inner == nil || p.store == nil || p.clipFrameSHA256 == "" {
		return application.Projection{}, errors.New("fixture business projector is unavailable")
	}
	for findingIndex := range input.Findings {
		deliverable := make([]application.ProjectionEvidence, 0, len(input.Findings[findingIndex].Evidence))
		for _, evidence := range input.Findings[findingIndex].Evidence {
			resolved, include, err := p.resolveDeliverableEvidence(evidence)
			if err != nil {
				return application.Projection{}, err
			}
			if include {
				deliverable = append(deliverable, resolved)
			}
		}
		input.Findings[findingIndex].Evidence = deliverable
	}
	result, err := p.inner.Project(ctx, input)
	if err != nil {
		return application.Projection{}, err
	}
	for sectionIndex := range result.Sections {
		for detailIndex, detail := range result.Sections[sectionIndex].Details {
			if detail == "识别结果：attention" {
				result.Sections[sectionIndex].Details[detailIndex] = "识别结果：建议关注"
			}
		}
	}
	result.Limitations = append(result.Limitations, simulatedMediaLimitation)
	return result, nil
}

func (p fixtureProjector) resolveDeliverableEvidence(evidence application.ProjectionEvidence) (application.ProjectionEvidence, bool, error) {
	descriptor, err := p.store.Describe(evidence.InternalMediaRef)
	if err != nil {
		return application.ProjectionEvidence{}, false, errors.New("fixture projection evidence is unavailable")
	}
	if descriptor.Kind == media.KindImage {
		return evidence, true, nil
	}
	if descriptor.Kind != media.KindFrameSet {
		return application.ProjectionEvidence{}, false, nil
	}
	if descriptor.Integrity.SHA256 != evidence.ExpectedSHA256 || descriptor.Availability != media.AvailabilityAvailable ||
		len(descriptor.FrameMembers) != 1 {
		return application.ProjectionEvidence{}, false, errors.New("fixture frame set is not the unique frozen evidence set")
	}
	member := descriptor.FrameMembers[0]
	if member.Ordinal != 0 || member.MediaRef == "" || member.SHA256 != p.clipFrameSHA256 ||
		member.OffsetMillis != p.clipFrameOffset || member.TransformPolicyRef == "" {
		return application.ProjectionEvidence{}, false, errors.New("fixture frame member is not bound to the prepared clip manifest")
	}
	child, err := p.store.Describe(member.MediaRef)
	if err != nil {
		return application.ProjectionEvidence{}, false, errors.New("fixture frame member is unavailable")
	}
	if child.Kind != media.KindImage || child.Encoding.MIMEType != "image/jpeg" || child.Availability != media.AvailabilityAvailable ||
		child.Integrity.SHA256 != member.SHA256 || child.Integrity.SizeBytes < 1 || child.Binding != descriptor.Binding ||
		child.Lineage.ParentMediaRef != descriptor.MediaRef || child.Lineage.Ordinal != member.Ordinal ||
		child.Lineage.OffsetMillis != member.OffsetMillis || child.Lineage.TransformPolicyRef != member.TransformPolicyRef ||
		!frameMemberTimeBound(descriptor, child, member.OffsetMillis) ||
		child.Governance.PrivacyClass != descriptor.Governance.PrivacyClass ||
		child.Governance.RedactionPolicyRef != descriptor.Governance.RedactionPolicyRef ||
		child.Governance.RetentionPolicyRef != descriptor.Governance.RetentionPolicyRef ||
		!child.Governance.ExpiresAt.Equal(descriptor.Governance.ExpiresAt) ||
		!equalProjectedAudience(child.Governance.Audience, descriptor.Governance.Audience) || child.CreatedAt.After(descriptor.CreatedAt) {
		return application.ProjectionEvidence{}, false, errors.New("fixture frame member failed its parent, audience, expiry, or run binding")
	}
	return application.ProjectionEvidence{
		InternalMediaRef: child.MediaRef, ExpectedSHA256: child.Integrity.SHA256, Title: evidence.Title,
	}, true, nil
}

func frameMemberTimeBound(parent, child media.Descriptor, offsetMillis int64) bool {
	if parent.Temporal.WindowStart == nil || child.Temporal.WindowStart == nil || child.Temporal.WindowEnd == nil {
		return false
	}
	expected := parent.Temporal.WindowStart.Add(time.Duration(offsetMillis) * time.Millisecond)
	return child.Temporal.WindowStart.Equal(expected) && child.Temporal.WindowEnd.Equal(expected)
}

func equalProjectedAudience(left, right []string) bool {
	if len(left) != len(right) {
		return false
	}
	for index := range left {
		if left[index] != right[index] {
			return false
		}
	}
	return true
}

var _ application.ResultProjector = fixtureProjector{}
