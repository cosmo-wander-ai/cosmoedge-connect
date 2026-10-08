package observation

import (
	"context"
	"errors"

	"github.com/cosmo-wander-ai/cosmoedge-connect/internal/inspection/media"
	"github.com/cosmo-wander-ai/cosmoedge-connect/internal/inspection/mediaprep"
	"github.com/cosmo-wander-ai/cosmoedge-connect/internal/inspection/temporary"
	"github.com/cosmo-wander-ai/cosmoedge-connect/internal/operator/livevision"
)

func (s *Service) result(ctx context.Context, r *resources, value operation) (Result, error) {
	result := Result{Kind: "edge_observation", AnalysisSource: "edge", OperationRef: value.Ref, RequestID: value.Request.RequestID, Pending: true, Status: "queued", Question: value.Request.Question, SourceName: value.ResolvedSourceName, SourceKind: value.SourceKind, TimeMeaning: "image_retrieved_at", Facts: []string{}, Limitations: []string{}, Attachments: []Attachment{}}
	if value.Request.Mode == CaptureOnly {
		result.Kind, result.AnalysisSource = "capture", "none"
		status, pending, _, err := captureProgress(ctx, r, value, s.config.Now().UTC())
		if err != nil {
			return Result{}, err
		}
		result.Status, result.Pending = status, pending
		if !pending && value.Stage != "terminal" {
			// Wait for the worker to seal capture metadata before exposing success.
			result.Status, result.Pending = "capturing", true
		}
		if result.Pending && s.workerErr != nil {
			result.Status, result.Pending = "unavailable", false
		}
		return resultWithMedia(ctx, r, value, result, temporary.Record{})
	}
	record, err := r.runner.Get(ctx, value.RunID)
	if err != nil && !errors.Is(err, temporary.ErrRuntimeNotFound) {
		return Result{}, err
	}
	if err == nil {
		if record.Validate() != nil || record.Binding.PrincipalSHA256 != value.OwnerHash || record.Binding.PublicRunRef != value.Ref || record.PreparationRef != value.PreparationRef {
			return Result{}, ErrUnavailable
		}
		result.Status = string(record.State)
		result.Pending = !record.State.Terminal()
		if record.State.Terminal() {
			result.Answer = temporary.AnswerUnable
			if record.State == temporary.StateSucceeded && record.Observation != nil && record.Observation.Answer.Valid() {
				result.Answer = record.Observation.Answer
				result.Facts = append(result.Facts, record.Observation.VisibleFacts...)
				result.Limitations = append(result.Limitations, record.Observation.Limitations...)
			} else {
				if record.State == temporary.StateSucceeded {
					result.Status = "invalid_candidate"
				}
				result.Limitations = append(result.Limitations, failureMessage(result.Status))
			}
		}
	} else if value.Stage == "terminal" {
		result.Status = value.Failure
		result.Pending = false
		result.Answer = temporary.AnswerUnable
		result.Limitations = append(result.Limitations, failureMessage(value.Failure))
	}
	if result.Pending && s.workerErr != nil {
		result.Status = "unavailable"
		result.Pending = false
		result.Answer = temporary.AnswerUnable
		result.Limitations = append(result.Limitations, "本次观察的处理暂不可用；续查不会重新拍照或派发分析。")
	}
	return resultWithMedia(ctx, r, value, result, record)
}

// Media availability is independent of either capture or analysis outcome.
// Retained metadata can describe an expired original but cannot authorize bytes.
func resultWithMedia(ctx context.Context, r *resources, value operation, result Result, record temporary.Record) (Result, error) {
	mediaRef := record.MediaRef
	if value.CaptureMedia != nil {
		mediaRef = value.CaptureMedia.MediaRef
	}
	if mediaRef == "" {
		status, err := r.preparations.Get(ctx, value.PreparationRef)
		if err == nil && status.State == mediaprep.StateReady {
			mediaRef = status.MediaRef
		} else if err != nil && !errors.Is(err, mediaprep.ErrNotFound) {
			return Result{}, err
		}
	}
	if mediaRef != "" {
		descriptor, err := r.media.Describe(mediaRef)
		if err == nil && !matchesMedia(value, descriptor) {
			return Result{}, ErrUnavailable
		}
		attachment := Attachment{MediaRef: mediaRef, Status: "unavailable"}
		if matchesMedia(value, descriptor) {
			attachment.MIMEType, attachment.SHA256, attachment.SizeBytes = descriptor.Encoding.MIMEType, descriptor.Integrity.SHA256, descriptor.Integrity.SizeBytes
			attachment.ExpiresAt = descriptor.Governance.ExpiresAt
			if descriptor.Temporal.WindowEnd != nil {
				at := descriptor.Temporal.WindowEnd.UTC()
				result.ObservedAt = &at
			}
		} else if value.CaptureMedia != nil && value.CaptureMedia.MediaRef == mediaRef {
			retained := value.CaptureMedia
			attachment.MIMEType, attachment.SHA256, attachment.SizeBytes = retained.Encoding.MIMEType, retained.Integrity.SHA256, retained.Integrity.SizeBytes
			attachment.ExpiresAt = retained.Governance.ExpiresAt
			if retained.Temporal.WindowEnd != nil {
				at := retained.Temporal.WindowEnd.UTC()
				result.ObservedAt = &at
			}
		} else if record.Media != nil && record.Media.MediaRef == mediaRef {
			// A validated runtime record retains evidence metadata even when the
			// media descriptor is unreadable. It cannot authorize reading bytes.
			attachment.MIMEType, attachment.SHA256, attachment.SizeBytes = record.Media.MIMEType, record.Media.SHA256, record.Media.SizeBytes
			attachment.ExpiresAt = record.Media.ExpiresAt
			if record.Media.Temporal.WindowEnd != nil {
				at := record.Media.Temporal.WindowEnd.UTC()
				result.ObservedAt = &at
			}
		}
		if err == nil {
			attachment.Status = "available"
		}
		result.Attachments = append(result.Attachments, attachment)
		if attachment.Status != "available" {
			result.Limitations = append(result.Limitations, "原图已过期或暂不可读取，不能把历史结果当成本次新画面。")
		}
	}
	if result.SourceKind == "test_video" {
		result.Limitations = append(result.Limitations, "来源是测试视频，本次画面不代表现场此刻。")
	}
	if result.ObservedAt != nil && value.Request.Mode != CaptureOnly {
		result.Limitations = append(result.Limitations, "时间表示本次取图时间，摄像头画面时刻尚未独立校验。")
	}
	if value.Request.Mode == CaptureOnly {
		return result, nil
	}
	cleanup, err := r.journal.status(ctx, value.RunID)
	if err != nil {
		return Result{}, err
	}
	result.CleanupStatus = cleanup
	if cleanup == livevision.TaskCleanupUnconfirmed {
		result.Limitations = append(result.Limitations, "临时分析任务的清理尚未确认。")
	}
	return result, nil
}
func matchesMedia(value operation, descriptor media.Descriptor) bool {
	audience, err := audienceFor(value)
	return err == nil && descriptor.Binding.TenantID == livevision.TenantID && descriptor.Binding.SiteID == livevision.SiteID && descriptor.Binding.RunID == value.RunID && descriptor.Binding.SourceRef == value.Source.SourceRef && descriptor.Kind == media.KindImage && len(descriptor.Governance.Audience) == 1 && descriptor.Governance.Audience[0] == audience.Ref
}
func failureMessage(status string) string {
	switch status {
	case "outcome_unknown":
		return "本次分析是否完成无法确认，续查不会自动重拍或重复派发。"
	case "expired":
		return "本次观察已超过等待期限，没有可用的本次判断。"
	case "invalid_candidate":
		return "设备分析没有返回可验证的三态答案。"
	default:
		return "本次取图或设备分析未能完成，暂时无法判断。"
	}
}
