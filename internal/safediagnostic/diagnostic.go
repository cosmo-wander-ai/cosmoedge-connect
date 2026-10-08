// Package safediagnostic carries bounded machine facts across error boundaries.
// It deliberately has no field for messages, URLs, paths, prompts or answers.
package safediagnostic

import (
	"errors"
	"strconv"
)

const (
	OperationCameraPicture       = "camera_picture"
	OperationPictureDownload     = "picture_download"
	OperationPictureCreate       = "picture_create"
	OperationPictureDetect       = "picture_detect"
	OperationPictureCancel       = "picture_cancel"
	OperationTaskSwitch          = "task_switch"
	OperationDeploymentSave      = "deployment_save"
	OperationAnalysis            = "analysis"
	OperationUploadCapabilities  = "upload_capabilities"
	OperationPictureUpload       = "picture_upload"
	OperationPictureUploadCancel = "picture_upload_cancel"

	PhaseBeforeDispatch           = "before_dispatch"
	PhaseNativeResponse           = "native_response"
	PhaseTransport                = "transport"
	PhaseDecodeJSON               = "decode_json"
	PhaseDecodeTypedResponse      = "decode_typed_response"
	PhaseValidateTypedResponse    = "validate_typed_response"
	PhaseValidateReference        = "validate_reference"
	PhaseDownload                 = "download"
	PhaseValidateJPEG             = "validate_jpeg"
	PhaseExtractLabel             = "extract_label"
	PhaseValidateClosedVocabulary = "validate_closed_vocabulary"
	PhaseBindCandidate            = "bind_candidate"
	PhaseCleanup                  = "cleanup"
	PhaseSourceBinding            = "source_binding"
	PhaseInputValidation          = "input_validation"
	PhaseAlgorithmSelection       = "algorithm_selection"
	PhaseJournal                  = "journal"

	ClassAccepted              = "accepted"
	ClassNativeRejected        = "native_rejected"
	ClassAuthRejected          = "auth_rejected"
	ClassOutcomeUnknown        = "outcome_unknown"
	ClassTransportFailed       = "transport_failed"
	ClassProtocolInvalid       = "protocol_invalid"
	ClassLocalContractRejected = "local_contract_rejected"
	ClassPersistenceFailed     = "persistence_failed"
	ClassUnavailable           = "unavailable"

	ValidationInvalidRequest       = "invalid_request"
	ValidationInvalidResponse      = "invalid_response"
	ValidationUnsafeReference      = "unsafe_reference"
	ValidationCachedReference      = "cached_reference"
	ValidationRedirect             = "redirect"
	ValidationTooLarge             = "too_large"
	ValidationInvalidJPEG          = "invalid_jpeg"
	ValidationLabelCountInvalid    = "label_count_invalid"
	ValidationConfidenceInvalid    = "confidence_invalid"
	ValidationEncodingInvalid      = "encoding_invalid"
	ValidationNormalizationInvalid = "normalization_invalid"
	ValidationVocabularyInvalid    = "vocabulary_invalid"
	ValidationBindingInvalid       = "binding_invalid"
	ValidationAlgorithmUnavailable = "algorithm_unavailable"
	ValidationJournalFailed        = "journal_failed"
	ValidationDeadlineExpired      = "deadline_expired"
)

// Diagnostic contains only allowlisted classifications and numeric device codes.
// Timestamps and operation/run/task identities belong to the owning ledger.
type Diagnostic struct {
	Operation      string `json:"operation"`
	Phase          string `json:"phase"`
	Class          string `json:"class"`
	HTTPStatus     int    `json:"httpStatus,omitempty"`
	ResCode        *int   `json:"resCode,omitempty"`
	MsgCode        string `json:"msgCode,omitempty"`
	ValidationCode string `json:"validationCode,omitempty"`
}

var ErrInvalidDiagnostic = errors.New("invalid safe diagnostic")

// Carrier is implemented by errors that expose a safe diagnostic copy.
type Carrier interface{ SafeDiagnostic() *Diagnostic }

func (d Diagnostic) Validate() error {
	if !oneOf(d.Operation, OperationCameraPicture, OperationPictureDownload, OperationPictureCreate, OperationPictureDetect, OperationPictureCancel, OperationTaskSwitch, OperationDeploymentSave, OperationAnalysis, OperationUploadCapabilities, OperationPictureUpload, OperationPictureUploadCancel) ||
		!oneOf(d.Phase, PhaseBeforeDispatch, PhaseNativeResponse, PhaseTransport, PhaseDecodeJSON, PhaseDecodeTypedResponse, PhaseValidateTypedResponse, PhaseValidateReference, PhaseDownload, PhaseValidateJPEG, PhaseExtractLabel, PhaseValidateClosedVocabulary, PhaseBindCandidate, PhaseCleanup, PhaseSourceBinding, PhaseInputValidation, PhaseAlgorithmSelection, PhaseJournal) ||
		!oneOf(d.Class, ClassAccepted, ClassNativeRejected, ClassAuthRejected, ClassOutcomeUnknown, ClassTransportFailed, ClassProtocolInvalid, ClassLocalContractRejected, ClassPersistenceFailed, ClassUnavailable) {
		return ErrInvalidDiagnostic
	}
	if d.HTTPStatus != 0 && (d.HTTPStatus < 100 || d.HTTPStatus > 599) {
		return ErrInvalidDiagnostic
	}
	if d.ResCode != nil && (*d.ResCode < 0 || uint64(*d.ResCode) > 0xffffffff) {
		return ErrInvalidDiagnostic
	}
	if d.MsgCode != "" && !NumericCode(d.MsgCode) {
		return ErrInvalidDiagnostic
	}
	if d.ValidationCode != "" && !oneOf(d.ValidationCode, ValidationInvalidRequest, ValidationInvalidResponse, ValidationUnsafeReference, ValidationCachedReference, ValidationRedirect, ValidationTooLarge, ValidationInvalidJPEG, ValidationLabelCountInvalid, ValidationConfidenceInvalid, ValidationEncodingInvalid, ValidationNormalizationInvalid, ValidationVocabularyInvalid, ValidationBindingInvalid, ValidationAlgorithmUnavailable, ValidationJournalFailed, ValidationDeadlineExpired) {
		return ErrInvalidDiagnostic
	}
	return nil
}

// NumericCode accepts only an ASCII decimal uint32, never opaque textual codes.
func NumericCode(value string) bool {
	if len(value) < 1 || len(value) > 10 {
		return false
	}
	for _, ch := range value {
		if ch < '0' || ch > '9' {
			return false
		}
	}
	_, err := strconv.ParseUint(value, 10, 32)
	return err == nil
}

// Clone returns an independent copy, including the optional numeric value.
func (d Diagnostic) Clone() *Diagnostic {
	copy := d
	if d.ResCode != nil {
		value := *d.ResCode
		copy.ResCode = &value
	}
	return &copy
}

// Wrap preserves errors.Is/As through Unwrap. A nil cause remains nil. Invalid
// diagnostics are not exposed; ErrInvalidDiagnostic is added to the error chain.
func Wrap(cause error, diagnostic Diagnostic) error {
	if cause == nil {
		return nil
	}
	if diagnostic.Validate() != nil {
		return &diagnosticError{cause: errors.Join(cause, ErrInvalidDiagnostic)}
	}
	return &diagnosticError{cause: cause, diagnostic: diagnostic.Clone()}
}

type diagnosticError struct {
	cause      error
	diagnostic *Diagnostic
}

func (e *diagnosticError) Error() string { return "operation failed (safe diagnostic)" }
func (e *diagnosticError) Unwrap() error { return e.cause }
func (e *diagnosticError) SafeDiagnostic() *Diagnostic {
	if e.diagnostic == nil {
		return nil
	}
	return e.diagnostic.Clone()
}

// FromError extracts the first valid diagnostic, including joined errors. It
// never derives fields from Error() text and returns an independent copy.
func FromError(err error) *Diagnostic { return fromError(err, 0) }
func fromError(err error, depth int) *Diagnostic {
	if err == nil || depth >= 64 {
		return nil
	}
	if carrier, ok := err.(Carrier); ok {
		if d := carrier.SafeDiagnostic(); d != nil && d.Validate() == nil {
			return d.Clone()
		}
	}
	switch e := err.(type) {
	case interface{ Unwrap() []error }:
		for _, cause := range e.Unwrap() {
			if d := fromError(cause, depth+1); d != nil {
				return d
			}
		}
	case interface{ Unwrap() error }:
		return fromError(e.Unwrap(), depth+1)
	}
	return nil
}

func oneOf(value string, allowed ...string) bool {
	for _, candidate := range allowed {
		if value == candidate {
			return true
		}
	}
	return false
}
