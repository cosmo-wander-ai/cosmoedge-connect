package inspectionlive

import (
	"context"
	"errors"
	"strings"

	"github.com/cosmo-wander-ai/cosmoedge-connect/internal/inspection"
	"github.com/cosmo-wander-ai/cosmoedge-connect/internal/inspection/application"
)

type liveProjector struct{ inner application.ResultProjector }

func (p liveProjector) Project(ctx context.Context, input application.ProjectionInput) (application.Projection, error) {
	if p.inner == nil {
		return application.Projection{}, errors.New("live inspection projector is unavailable")
	}
	result, err := p.inner.Project(ctx, input)
	if err != nil {
		return application.Projection{}, err
	}
	switch input.OverallAssessment {
	case inspection.AssessmentMeetsRule:
		result.Summary = "本次现场快照中未发现明显需要关注的情况。"
	case inspection.AssessmentNeedsAttention:
		result.Summary = "本次现场快照中发现需要关注的情况。"
	default:
		result.Summary = "本次现场快照暂时无法形成明确判断。"
	}
	for sectionIndex := range result.Sections {
		section := &result.Sections[sectionIndex]
		switch input.Findings[sectionIndex].Assessment {
		case inspection.AssessmentMeetsRule:
			section.Conclusion = "当前画面未发现明显需关注情况"
		case inspection.AssessmentNeedsAttention:
			section.Conclusion = "当前画面发现需要关注的情况"
		default:
			section.Conclusion = "当前画面暂时无法判断"
		}
		for detailIndex, detail := range section.Details {
			if !strings.HasPrefix(detail, "识别结果：") {
				continue
			}
			switch input.Findings[sectionIndex].Assessment {
			case inspection.AssessmentNeedsAttention:
				section.Details[detailIndex] = "画面中可见需要进一步关注的情况。"
			case inspection.AssessmentMeetsRule:
				section.Details[detailIndex] = "当前画面未见明显需要关注的情况。"
			default:
				section.Details[detailIndex] = "当前画面暂时无法形成明确判断。"
			}
		}
	}
	result.Limitations = append(result.Limitations, "本结果仅基于本次现场快照提供辅助观察，不代表卫生、安全或法规合规结论。")
	return result, nil
}

var _ application.ResultProjector = liveProjector{}
