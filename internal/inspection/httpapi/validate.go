package httpapi

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"mime"
	"regexp"
	"strings"
	"unicode"
	"unicode/utf8"

	"github.com/cosmo-wander-ai/cosmoedge-connect/internal/inspection/inputguard"
)

var (
	sessionAudienceRefPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$`)
	sessionPrincipalPattern   = regexp.MustCompile(`^[0-9a-f]{64}$`)
)

const (
	maxCapabilities = 100
	maxSections     = 100
	maxTextBytes    = 4 << 10
)

func validateSessionBinding(binding SessionBinding) error {
	if !validSessionAudienceRef(binding.TenantID) || !validSessionAudienceRef(binding.SiteID) || !validSessionAudienceRef(binding.Channel) ||
		!validSessionAudienceRef(binding.ConversationRef) || !validSessionAudienceRef(binding.RecipientRef) ||
		!sessionPrincipalPattern.MatchString(binding.PrincipalSHA256) {
		return errors.New("invalid inspection session binding")
	}
	return nil
}

func validSessionAudienceRef(value string) bool {
	return value == strings.TrimSpace(value) && sessionAudienceRefPattern.MatchString(value)
}

func validateCapabilitySet(set CapabilitySet) error {
	if !validDisplayText(set.ContextLabel, 1, 256) || len(set.Capabilities) == 0 || len(set.Capabilities) > maxCapabilities {
		return errors.New("invalid inspection capabilities")
	}
	seen := make(map[string]struct{}, len(set.Capabilities))
	for _, capability := range set.Capabilities {
		if !validPublicRef(capability.CapabilityRef) || !validDisplayText(capability.Title, 1, 256) ||
			!validDisplayText(capability.Description, 1, 1024) || len(capability.Examples) > 8 {
			return errors.New("invalid inspection capability")
		}
		if _, duplicate := seen[capability.CapabilityRef]; duplicate {
			return errors.New("duplicate inspection capability")
		}
		seen[capability.CapabilityRef] = struct{}{}
		for _, example := range capability.Examples {
			if !validDisplayText(example, 1, 512) {
				return errors.New("invalid inspection capability example")
			}
		}
	}
	return nil
}

func validateContinuationResolution(value ContinuationResolution) error {
	switch value.Status {
	case ContinuationNone:
		if value.Run != nil || len(value.Candidates) != 0 {
			return errors.New("invalid empty continuation resolution")
		}
	case ContinuationResolved:
		if value.Run == nil || validateRunView(*value.Run) != nil || len(value.Candidates) != 0 {
			return errors.New("invalid resolved continuation")
		}
	case ContinuationAmbiguous:
		if value.Run != nil || len(value.Candidates) < 2 || len(value.Candidates) > 4 {
			return errors.New("invalid ambiguous continuation")
		}
		for _, candidate := range value.Candidates {
			if !validPublicRef(candidate.RunRef) || !validDisplayText(candidate.Area, 1, 256) || !validDisplayText(candidate.Goal, 1, 512) || candidate.StartedAt.IsZero() {
				return errors.New("invalid continuation candidate")
			}
		}
	default:
		return errors.New("invalid continuation resolution")
	}
	return nil
}

func validateInspectionRequest(request InspectionRequest) error {
	if !validBusinessInput(request.Instruction, 1, 2000) || inputguard.ValidateText(request.Instruction) != nil || len(request.Context) > 16 {
		return errors.New("invalid inspection request")
	}
	if request.TemporaryIntent != nil {
		if !validBusinessInput(request.TemporaryIntent.Subject, 1, 160) ||
			inputguard.ValidateText(request.TemporaryIntent.Subject) != nil ||
			!validBusinessInput(request.TemporaryIntent.Region, 1, 160) ||
			inputguard.ValidateText(request.TemporaryIntent.Region) != nil ||
			!validBusinessInput(request.TemporaryIntent.Observable, 1, 512) ||
			inputguard.ValidateText(request.TemporaryIntent.Observable) != nil {
			return errors.New("invalid inspection request")
		}
	}
	seen := make(map[string]struct{}, len(request.Context))
	for _, item := range request.Context {
		if !validBusinessInput(item.Name, 1, 128) || !validBusinessInput(item.Value, 1, 512) ||
			inputguard.ValidateText(item.Name) != nil || inputguard.ValidateText(item.Value) != nil {
			return errors.New("invalid inspection context")
		}
		key := strings.ToLower(item.Name)
		if _, duplicate := seen[key]; duplicate {
			return errors.New("duplicate inspection context")
		}
		seen[key] = struct{}{}
	}
	return nil
}

func validateRunView(run RunView) error {
	if !validPublicRef(run.RunRef) || !run.Status.Valid() || !validDisplayText(run.Message, 1, 1024) ||
		run.SubmittedAt.IsZero() || run.UpdatedAt.Before(run.SubmittedAt) {
		return errors.New("invalid inspection run")
	}
	return nil
}

func (status RunStatus) Valid() bool {
	switch status {
	case RunAccepted, RunWorking, RunReady, RunInteractionRequired, RunUnable, RunCancelled, RunExpired:
		return true
	default:
		return false
	}
}

func validateResultView(result ResultView) error {
	if !validPublicRef(result.RunRef) || !validDisplayText(result.Summary, 1, maxTextBytes) ||
		result.CompletedAt.IsZero() || len(result.Sections) > maxSections || len(result.Limitations) > 32 {
		return errors.New("invalid inspection result")
	}
	for _, limitation := range result.Limitations {
		if !validDisplayText(limitation, 1, 1024) {
			return errors.New("invalid inspection result limitation")
		}
	}
	seenMedia := map[string]struct{}{}
	for _, section := range result.Sections {
		if !validDisplayText(section.Title, 1, 256) || !validDisplayText(section.Conclusion, 1, maxTextBytes) ||
			len(section.Details) > 100 || len(section.Evidence) > 32 {
			return errors.New("invalid inspection result section")
		}
		for _, detail := range section.Details {
			if !validDisplayText(detail, 1, 1024) {
				return errors.New("invalid inspection result detail")
			}
		}
		for _, evidence := range section.Evidence {
			if validateMediaCapability(evidence) != nil {
				return errors.New("invalid inspection result evidence")
			}
			if _, duplicate := seenMedia[evidence.MediaRef]; duplicate {
				return errors.New("duplicate inspection result evidence")
			}
			seenMedia[evidence.MediaRef] = struct{}{}
		}
	}
	if result.Answer != "" || result.Question != "" {
		if result.Answer != "yes" && result.Answer != "no" && result.Answer != "unable" {
			return errors.New("invalid inspection result answer")
		}
		if !validDisplayText(result.Question, 1, 512) {
			return errors.New("invalid inspection result question")
		}
	}
	return nil
}

func validateMediaCapability(media MediaCapability) error {
	if !validPublicRef(media.MediaRef) || media.Capability != "inspection.media.deliver" ||
		!validImageContentType(media.MediaType) || !validDisplayText(media.Title, 1, 256) {
		return errors.New("invalid media capability")
	}
	return nil
}

func validateMediaPayload(payload MediaPayload) error {
	if !validImageContentType(payload.ContentType) || len(payload.Bytes) == 0 || len(payload.Bytes) > MaxMediaBytes ||
		len(payload.SHA256) != sha256.Size*2 {
		return errors.New("invalid media payload")
	}
	digest := sha256.Sum256(payload.Bytes)
	if !strings.EqualFold(payload.SHA256, hex.EncodeToString(digest[:])) || !validImageMagic(payload.ContentType, payload.Bytes) {
		return errors.New("invalid media payload integrity")
	}
	return nil
}

func validateFeedbackRequest(request FeedbackRequest) error {
	if request.Helpful == nil || (request.Comment != "" && (!validBusinessInput(request.Comment, 1, 1000) || inputguard.ValidateText(request.Comment) != nil)) {
		return errors.New("invalid inspection feedback")
	}
	return nil
}

func validateInteractionRequired(interaction InteractionRequired) error {
	if !validDisplayText(interaction.Title, 1, 256) || !validDisplayText(interaction.Message, 1, 1024) ||
		!validDisplayText(interaction.ActionLabel, 1, 128) || !ValidInteractionCapability(interaction.Capability) ||
		!validPublicRef(interaction.HandoffRef) {
		return errors.New("invalid inspection interaction handoff")
	}
	return nil
}

func validDisplayText(value string, minimum, maximum int) bool {
	if !validBusinessInput(value, minimum, maximum) || inputguard.ValidateText(value) != nil {
		return false
	}
	for _, character := range value {
		if character == '\n' {
			continue
		}
		if unicode.IsControl(character) {
			return false
		}
	}
	return true
}

func validBusinessInput(value string, minimum, maximum int) bool {
	if !utf8.ValidString(value) || value != strings.TrimSpace(value) || len(value) < minimum || len(value) > maximum {
		return false
	}
	for _, character := range value {
		if character == '\n' || character == '\t' {
			continue
		}
		if unicode.IsControl(character) {
			return false
		}
	}
	return true
}

func validImageContentType(value string) bool {
	mediaType, parameters, err := mime.ParseMediaType(value)
	if err != nil || len(parameters) != 0 || mediaType != value {
		return false
	}
	switch mediaType {
	case "image/jpeg", "image/png":
		return true
	default:
		return false
	}
}

func validImageMagic(contentType string, value []byte) bool {
	switch contentType {
	case "image/png":
		return len(value) >= 8 && string(value[:8]) == "\x89PNG\r\n\x1a\n"
	case "image/jpeg":
		return len(value) >= 3 && value[0] == 0xff && value[1] == 0xd8 && value[2] == 0xff
	default:
		return false
	}
}
