package profile

// BusinessSummary is the only device-profile shape intended for Skill or
// business-channel projection. Endpoint, username, credential reference,
// pinned serial, transport fingerprint, tenant, and site remain inside the
// trusted Operator boundary.
type BusinessSummary struct {
	ProfileID       string `json:"profileId"`
	Alias           string `json:"alias"`
	DeviceType      string `json:"deviceType,omitempty"`
	State           string `json:"state"`
	NeedsCredential bool   `json:"needsCredential"`
	Generation      uint64 `json:"generation"`
}

func (p DeviceProfile) BusinessSummary() BusinessSummary {
	state := "ready"
	switch {
	case p.State == StateIdentityDrift:
		state = "identity_changed"
	case p.State == StateDisabled:
		state = "disabled"
	case p.CredentialState != CredentialReady:
		state = "credential_attention"
	}
	return BusinessSummary{
		ProfileID: p.ProfileID, Alias: p.Alias, DeviceType: p.PinnedType,
		State: state, NeedsCredential: p.CredentialState != CredentialReady,
		Generation: p.Generation,
	}
}
