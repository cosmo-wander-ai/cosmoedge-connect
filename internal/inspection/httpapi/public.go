package httpapi

import "errors"

// ValidatePublicResponse applies the Product's semantic and protected-content
// rules to a decoded response at a client boundary as well as at the HTTP host.
func ValidatePublicResponse(value any) error {
	var err error
	switch view := value.(type) {
	case CapabilitySet:
		err = validateCapabilitySet(view)
	case RunView:
		err = validateRunView(view)
		if view.Status == RunInteractionRequired {
			return errors.New("interaction is not a run")
		}
	case ResultView:
		err = validateResultView(view)
	case ContinuationResolution:
		err = validateContinuationResolution(view)
		if view.Run != nil && view.Run.Status == RunInteractionRequired {
			return errors.New("interaction is not a run")
		}
	case InteractionRequired:
		err = validateInteractionRequired(view)
	default:
		return errors.New("unsupported inspection response")
	}
	if err != nil {
		return err
	}
	_, err = MarshalPublicJSON(value)
	return err
}
