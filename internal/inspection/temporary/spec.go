package temporary

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
)

type normalizedIntentDigest struct {
	Schema             string    `json:"schema"`
	Subject            string    `json:"subject"`
	Region             string    `json:"region"`
	Observable         string    `json:"observable"`
	Locale             string    `json:"locale"`
	TimeScope          TimeScope `json:"timeScope"`
	EvidenceTTLSeconds int       `json:"evidenceTtlSeconds"`
}

// NewSpec validates and normalizes semantic fields before computing the
// durable intent digest. It accepts no raw channel message.
func NewSpec(intent Intent) (TemporaryObservationSpec, error) {
	subject, err := normalizeApprovedText("subject", intent.Subject, 160)
	if err != nil {
		return TemporaryObservationSpec{}, err
	}
	region, err := normalizeApprovedText("region", intent.Region, 160)
	if err != nil {
		return TemporaryObservationSpec{}, err
	}
	observable, err := normalizeApprovedText("observable", intent.Observable, 512)
	if err != nil {
		return TemporaryObservationSpec{}, err
	}
	if err := validateLocale(intent.Locale); err != nil {
		return TemporaryObservationSpec{}, err
	}
	if err := validateTimeScope(intent.TimeScope); err != nil {
		return TemporaryObservationSpec{}, err
	}
	if err := validateEvidenceTTL(intent.EvidenceTTLSeconds); err != nil {
		return TemporaryObservationSpec{}, err
	}

	spec := TemporaryObservationSpec{
		Schema:             SpecSchemaVersion,
		Subject:            subject,
		Region:             region,
		Observable:         observable,
		Locale:             intent.Locale,
		TimeScope:          intent.TimeScope,
		EvidenceTTLSeconds: intent.EvidenceTTLSeconds,
	}
	digest, err := digestNormalizedIntent(spec)
	if err != nil {
		return TemporaryObservationSpec{}, err
	}
	spec.NormalizedIntentSHA256 = digest
	return spec, nil
}

func (s TemporaryObservationSpec) Validate() error {
	if s.Schema != SpecSchemaVersion {
		return fmt.Errorf("temporary observation schema must equal %q", SpecSchemaVersion)
	}
	for _, field := range []struct {
		name    string
		value   string
		maximum int
	}{
		{name: "subject", value: s.Subject, maximum: 160},
		{name: "region", value: s.Region, maximum: 160},
		{name: "observable", value: s.Observable, maximum: 512},
	} {
		normalized, err := normalizeApprovedText(field.name, field.value, field.maximum)
		if err != nil {
			return err
		}
		if normalized != field.value {
			return fmt.Errorf("temporary observation %s is not normalized", field.name)
		}
	}
	if err := validateLocale(s.Locale); err != nil {
		return err
	}
	if err := validateTimeScope(s.TimeScope); err != nil {
		return err
	}
	if err := validateEvidenceTTL(s.EvidenceTTLSeconds); err != nil {
		return err
	}
	if !sha256Pattern.MatchString(s.NormalizedIntentSHA256) {
		return errors.New("temporary observation normalized intent digest is invalid")
	}
	digest, err := digestNormalizedIntent(s)
	if err != nil {
		return err
	}
	if digest != s.NormalizedIntentSHA256 {
		return errors.New("temporary observation normalized intent digest does not match its fields")
	}
	return nil
}

func digestNormalizedIntent(spec TemporaryObservationSpec) (string, error) {
	raw, err := json.Marshal(normalizedIntentDigest{
		Schema: SpecSchemaVersion, Subject: spec.Subject, Region: spec.Region,
		Observable: spec.Observable, Locale: spec.Locale, TimeScope: spec.TimeScope,
		EvidenceTTLSeconds: spec.EvidenceTTLSeconds,
	})
	if err != nil {
		return "", err
	}
	digest := sha256.Sum256(raw)
	return hex.EncodeToString(digest[:]), nil
}

func validateLocale(locale string) error {
	switch locale {
	case "zh-CN", "zh-TW", "en-US":
		return nil
	default:
		return errors.New("temporary observation locale is outside the allowlist")
	}
}

func validateTimeScope(scope TimeScope) error {
	switch scope.Kind {
	case TimeScopeCurrent:
		if scope.WindowSeconds != 0 {
			return errors.New("current temporary observation must have a zero-second window")
		}
	case TimeScopeRecentWindow:
		if scope.WindowSeconds < 1 || scope.WindowSeconds > MaxRecentWindowSeconds {
			return fmt.Errorf("recent temporary observation window must be between 1 and %d seconds", MaxRecentWindowSeconds)
		}
	default:
		return errors.New("temporary observation time scope is invalid")
	}
	return nil
}

func validateEvidenceTTL(seconds int) error {
	if seconds < MinEvidenceTTLSeconds || seconds > MaxEvidenceTTLSeconds {
		return fmt.Errorf("temporary observation evidence TTL must be between %d and %d seconds", MinEvidenceTTLSeconds, MaxEvidenceTTLSeconds)
	}
	return nil
}
