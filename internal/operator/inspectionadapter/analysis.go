package inspectionadapter

import (
	"context"
	"errors"
	"io"
	"reflect"
	"time"

	"github.com/cosmo-wander-ai/cosmoedge-connect/internal/inspection"
	"github.com/cosmo-wander-ai/cosmoedge-connect/internal/inspection/analysiscontract"
	"github.com/cosmo-wander-ai/cosmoedge-connect/internal/inspection/media"
	inspectionruntime "github.com/cosmo-wander-ai/cosmoedge-connect/internal/inspection/runtime"
)

func (a *Adapter) analyze(ctx context.Context, request inspectionruntime.AnalyzeRequest) (inspectionruntime.AnalysisReference, error) {
	if err := ctx.Err(); err != nil {
		return inspectionruntime.AnalysisReference{}, err
	}
	if request.RunID == "" || request.StepID == "" || request.TenantID == "" || request.SiteID == "" ||
		request.TargetID == "" || request.CriterionID == "" || request.Attempt < 1 || request.AnalysisPolicyRef == "" ||
		request.IdempotencyKey == "" || len(request.Inputs) == 0 || len(request.Inputs) > 16 ||
		request.Output.Validate() != nil || request.Budget.MaxBytes < 1 || request.Budget.MaxFrames < 1 ||
		contentSHA256([]byte(request.Prompt)) != request.PromptSHA256 || !supportedMethod(request.Method) {
		return inspectionruntime.AnalysisReference{}, inspectionruntime.ErrBindingStale
	}
	if err := requestDeadline(a.now().UTC(), request.Deadline); err != nil {
		return inspectionruntime.AnalysisReference{}, err
	}

	requestSHA, err := analysisRequestDigest(request)
	if err != nil {
		return inspectionruntime.AnalysisReference{}, err
	}
	resultRef := deterministicRef("analysis", requestSHA)
	if stored, storedErr := a.records.Analysis(ctx, resultRef); storedErr == nil {
		if stored.RequestSHA256 != requestSHA || stored.Result.ResultRef != resultRef || stored.Result.AdapterVersion != a.adapterVersion {
			return inspectionruntime.AnalysisReference{}, errors.New("durable live analysis conflicts with replay")
		}
		if err := a.verifyAnalysisRecord(ctx, stored); err != nil {
			return inspectionruntime.AnalysisReference{}, err
		}
		return stored.Result, nil
	} else if !errors.Is(storedErr, ErrRecordNotFound) {
		return inspectionruntime.AnalysisReference{}, storedErr
	}

	descriptors, profileID, err := a.analysisDescriptors(ctx, request)
	if err != nil {
		return inspectionruntime.AnalysisReference{}, err
	}
	client, err := a.client(ctx, request.TenantID, request.SiteID, profileID)
	if err != nil {
		return inspectionruntime.AnalysisReference{}, err
	}
	readers := make([]io.ReadCloser, 0, len(descriptors))
	inputs := make([]AnalysisMedia, 0, len(descriptors))
	for index, descriptor := range descriptors {
		stored, reader, openErr := a.media.Open(ctx, descriptor.MediaRef)
		if openErr != nil {
			closeAll(readers)
			return inspectionruntime.AnalysisReference{}, openErr
		}
		if !reflect.DeepEqual(stored, descriptor) {
			_ = reader.Close()
			closeAll(readers)
			return inspectionruntime.AnalysisReference{}, errors.New("analysis media changed after descriptor validation")
		}
		readers = append(readers, reader)
		inputs = append(inputs, AnalysisMedia{Ordinal: index + 1, Descriptor: descriptor, Content: reader})
	}
	startedAt := a.now().UTC()
	response, callErr := client.Analyze(ctx, AnalysisRequest{
		RunID: request.RunID, StepID: request.StepID, Attempt: request.Attempt,
		IdempotencyKey: operationKey("analyze", request.IdempotencyKey, requestSHA), DeviceProfileID: profileID,
		CriterionID: request.CriterionID, Method: request.Method, AnalysisPolicyRef: request.AnalysisPolicyRef,
		Prompt: request.Prompt, PromptSHA256: request.PromptSHA256, Output: request.Output,
		Inputs: inputs, Deadline: request.Deadline.UTC(), MaxBytes: request.Budget.MaxBytes, MaxFrames: request.Budget.MaxFrames,
	})
	closeErr := closeAll(readers)
	if callErr != nil {
		return inspectionruntime.AnalysisReference{}, mapClientError(callErr)
	}
	if closeErr != nil {
		return inspectionruntime.AnalysisReference{}, closeErr
	}
	completedAt := a.now().UTC()
	if completedAt.Before(startedAt) || completedAt.After(request.Deadline.UTC()) || !validOpaque(response.ModelVersion) {
		return inspectionruntime.AnalysisReference{}, ErrInvalidResponse
	}
	candidate, err := bindCandidate(response.Candidate, response.EvidenceOrdinals, descriptors)
	if err != nil {
		return inspectionruntime.AnalysisReference{}, err
	}
	if !candidateSatisfiesOutput(candidate, request.Output) {
		return inspectionruntime.AnalysisReference{}, ErrInvalidResponse
	}
	result := inspectionruntime.AnalysisReference{
		RunID: request.RunID, StepID: request.StepID, Attempt: request.Attempt,
		ResultRef: resultRef, Candidate: candidate, ModelVersion: response.ModelVersion,
		AdapterVersion: a.adapterVersion, StartedAt: startedAt, CompletedAt: completedAt,
	}
	record := AnalysisRecord{RequestSHA256: requestSHA, DeviceProfileID: profileID, Result: result}
	if err := a.persistAnalysis(ctx, record); err != nil {
		return inspectionruntime.AnalysisReference{}, errors.Join(inspectionruntime.ErrOutcomeUnknown, err)
	}
	return result, nil
}

func (a *Adapter) analysisResult(ctx context.Context, ref string) (inspectionruntime.AnalysisReference, error) {
	if err := ctx.Err(); err != nil {
		return inspectionruntime.AnalysisReference{}, err
	}
	record, err := a.records.Analysis(ctx, ref)
	if err != nil {
		return inspectionruntime.AnalysisReference{}, err
	}
	if record.Result.ResultRef != ref || record.Result.AdapterVersion != a.adapterVersion {
		return inspectionruntime.AnalysisReference{}, errors.New("durable live analysis is invalid")
	}
	if err := a.verifyAnalysisRecord(ctx, record); err != nil {
		return inspectionruntime.AnalysisReference{}, err
	}
	return record.Result, nil
}

func analysisRequestDigest(request inspectionruntime.AnalyzeRequest) (string, error) {
	type safeInput struct {
		ProducerStepID string              `json:"producerStepId"`
		ProducerKind   inspection.StepKind `json:"producerKind"`
		Attempt        int                 `json:"attempt"`
		ValueRef       string              `json:"valueRef"`
		SHA256         string              `json:"sha256"`
		Descriptor     *media.Descriptor   `json:"descriptor,omitempty"`
		EvidenceRef    string              `json:"evidenceRef,omitempty"`
		EvidenceMedia  *media.Descriptor   `json:"evidenceMedia,omitempty"`
	}
	inputs := make([]safeInput, len(request.Inputs))
	for index, input := range request.Inputs {
		inputs[index] = safeInput{
			ProducerStepID: input.ProducerStepID, ProducerKind: input.ProducerKind,
			Attempt: input.Attempt, ValueRef: input.ValueRef, SHA256: input.SHA256, Descriptor: input.Descriptor,
		}
		if input.Evidence != nil {
			inputs[index].EvidenceRef = input.Evidence.EvidenceRef
			inputs[index].EvidenceMedia = &input.Evidence.Descriptor
		}
	}
	return canonicalDigest(struct {
		RunID             string                    `json:"runId"`
		StepID            string                    `json:"stepId"`
		TenantID          string                    `json:"tenantId"`
		SiteID            string                    `json:"siteId"`
		TargetID          string                    `json:"targetId"`
		CriterionID       string                    `json:"criterionId"`
		Attempt           int                       `json:"attempt"`
		Method            inspection.Method         `json:"method"`
		AnalysisPolicyRef string                    `json:"analysisPolicyRef"`
		Prompt            string                    `json:"prompt"`
		PromptSHA256      string                    `json:"promptSha256"`
		Output            inspection.OutputContract `json:"output"`
		Inputs            []safeInput               `json:"inputs"`
		IdempotencyKey    string                    `json:"idempotencyKey"`
		Deadline          time.Time                 `json:"deadline"`
		Budget            inspection.StepBudget     `json:"budget"`
	}{request.RunID, request.StepID, request.TenantID, request.SiteID, request.TargetID, request.CriterionID,
		request.Attempt, request.Method, request.AnalysisPolicyRef, request.Prompt, request.PromptSHA256,
		request.Output, inputs, request.IdempotencyKey, request.Deadline.UTC(), request.Budget})
}

func (a *Adapter) analysisDescriptors(ctx context.Context, request inspectionruntime.AnalyzeRequest) ([]media.Descriptor, string, error) {
	descriptors := make([]media.Descriptor, 0, len(request.Inputs))
	profileID := ""
	seen := make(map[string]struct{}, len(request.Inputs))
	var totalBytes int64
	frames := 0
	for _, input := range request.Inputs {
		if input.ProducerStepID == "" || input.Attempt < 1 || input.ValueRef == "" || !validDigest(input.SHA256) ||
			(input.Descriptor == nil) == (input.Evidence == nil) {
			return nil, "", inspectionruntime.ErrBindingStale
		}
		var descriptor media.Descriptor
		switch {
		case input.Descriptor != nil:
			if input.ProducerKind != inspection.StepAcquireMedia && input.ProducerKind != inspection.StepOpenMedia && input.ProducerKind != inspection.StepTransformMedia ||
				input.ValueRef != input.Descriptor.MediaRef || input.SHA256 != input.Descriptor.Integrity.SHA256 {
				return nil, "", inspectionruntime.ErrBindingStale
			}
			descriptor = *input.Descriptor
		case input.Evidence != nil:
			if input.ProducerKind != inspection.StepReadExisting || input.ValueRef != input.Evidence.EvidenceRef {
				return nil, "", inspectionruntime.ErrBindingStale
			}
			record, err := a.records.Existing(ctx, input.ValueRef)
			if err != nil || !reflect.DeepEqual(record.Result, *input.Evidence) || record.DeviceProfileID == "" {
				return nil, "", inspectionruntime.ErrBindingStale
			}
			if profileID == "" {
				profileID = record.DeviceProfileID
			} else if profileID != record.DeviceProfileID {
				return nil, "", inspectionruntime.ErrUnsupported
			}
			descriptor = input.Evidence.Descriptor
		}
		if descriptor.Validate() != nil || descriptor.Binding.TenantID != request.TenantID || descriptor.Binding.SiteID != request.SiteID ||
			descriptor.Binding.RunID != request.RunID || descriptor.Integrity.SizeBytes < 1 {
			return nil, "", inspectionruntime.ErrBindingStale
		}
		stored, err := a.media.Describe(descriptor.MediaRef)
		if err != nil || !reflect.DeepEqual(stored, descriptor) {
			return nil, "", errors.New("analysis input media cannot be verified")
		}
		switch descriptor.Kind {
		case media.KindImage:
			frames++
		case media.KindMetric, media.KindDetection, media.KindEvent:
		default:
			return nil, "", inspectionruntime.ErrUnsupported
		}
		if _, duplicate := seen[descriptor.MediaRef]; duplicate {
			return nil, "", inspectionruntime.ErrBindingStale
		}
		seen[descriptor.MediaRef] = struct{}{}
		totalBytes += descriptor.Integrity.SizeBytes
		if totalBytes > request.Budget.MaxBytes || frames > request.Budget.MaxFrames {
			return nil, "", inspectionruntime.ErrUnsupported
		}
		if profileID == "" {
			source, err := a.catalog.Get(ctx, request.TenantID, request.SiteID, descriptor.Binding.SourceRef)
			if err != nil {
				return nil, "", mapCatalogError(err)
			}
			profileID = source.DeviceProfileID
		} else {
			source, err := a.catalog.Get(ctx, request.TenantID, request.SiteID, descriptor.Binding.SourceRef)
			if err != nil {
				return nil, "", mapCatalogError(err)
			}
			if profileID != source.DeviceProfileID {
				return nil, "", inspectionruntime.ErrUnsupported
			}
		}
		descriptors = append(descriptors, descriptor)
	}
	if profileID == "" || frames == 0 {
		// The current real CosmoEdge analyzer is picture-based. Structured
		// evidence may augment an image, but cannot be analyzed on its own here.
		return nil, "", inspectionruntime.ErrUnsupported
	}
	return descriptors, profileID, nil
}

func (a *Adapter) verifyAnalysisRecord(ctx context.Context, record AnalysisRecord) error {
	if record.RequestSHA256 == "" || record.DeviceProfileID == "" || record.Result.Candidate.Validate() != nil ||
		record.Result.StartedAt.IsZero() || record.Result.CompletedAt.Before(record.Result.StartedAt) ||
		!validOpaque(record.Result.ModelVersion) {
		return errors.New("durable live analysis result is invalid")
	}
	for _, ref := range record.Result.Candidate.EvidenceRefs {
		if _, err := a.media.Describe(ref); err != nil {
			return errors.New("durable live analysis evidence cannot be verified")
		}
	}
	return nil
}

func candidateSatisfiesOutput(candidate analysiscontract.Candidate, output inspection.OutputContract) bool {
	allowed := false
	for _, assessment := range output.AllowedAssessments {
		allowed = allowed || assessment == candidate.Assessment
	}
	if !allowed {
		return false
	}
	return candidate.Value == nil || candidate.Value.Kind == output.Mode
}

func supportedMethod(method inspection.Method) bool {
	return method == inspection.MethodCV || method == inspection.MethodVLM || method == inspection.MethodHybrid
}

func closeAll(readers []io.ReadCloser) error {
	var result error
	for _, reader := range readers {
		if err := reader.Close(); err != nil {
			result = errors.Join(result, err)
		}
	}
	return result
}
