package deployment

import (
	"context"
	"encoding/json"
)

// LocalReview is a snapshot of the original proposal for the protected local
// page. It never re-prepares or refreshes authority from device state.
type LocalReview struct {
	Proposal        Proposal
	CanConfirm      bool
	ParameterCount  int
	AreaPointCounts []int
}

func (s *Service) LocalReview(ctx context.Context, owner, actionRef string) (LocalReview, error) {
	record, err := s.store.Get(ctx, actionRef)
	if err != nil {
		return LocalReview{}, err
	}
	var meta metadata
	if record.Kind != Kind || record.SessionBinding != digest("deployment-session", owner) || json.Unmarshal([]byte(record.PublicJSON), &meta) != nil {
		return LocalReview{}, ErrConflict
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.sweepLocked()
	view := LocalReview{Proposal: s.proposalLocked(record, meta)}
	item := s.materials[actionRef]
	if item == nil || item.session != record.SessionBinding || item.confirmed || record.State != "proposed" {
		view.Proposal.ConfirmationToken = ""
		return view, nil
	}
	connection, _, err := s.connection()
	if err != nil || connection.Serial != item.serial || connection.EndpointFingerprint != item.transport {
		view.Proposal.ConfirmationToken = ""
		return view, nil
	}
	var config struct {
		TaskConfig struct {
			Params []json.RawMessage `json:"params"`
			Areas  []struct {
				Points []json.RawMessage `json:"points"`
			} `json:"areas"`
		} `json:"taskConfig"`
	}
	if json.Unmarshal(item.target.Document, &config) != nil {
		return LocalReview{}, ErrUnavailable
	}
	view.CanConfirm = true
	view.ParameterCount = len(config.TaskConfig.Params)
	for _, area := range config.TaskConfig.Areas {
		view.AreaPointCounts = append(view.AreaPointCounts, len(area.Points))
	}
	return view, nil
}
