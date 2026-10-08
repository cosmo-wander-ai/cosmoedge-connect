package dataset

import (
	"context"
	"sort"
	"sync"
)

// memoryDatasetStore is deliberately test-only. Production admission has one
// persistence contract: SQLiteRepository.
type memoryDatasetStore struct {
	mu        sync.RWMutex
	datasets  map[string]Dataset
	ledger    map[string]Split
	intervals []sourceIntervalClaim
}

func newMemoryDatasetStore() *memoryDatasetStore {
	return &memoryDatasetStore{datasets: make(map[string]Dataset), ledger: make(map[string]Split)}
}

func (m *memoryDatasetStore) Create(ctx context.Context, dataset Dataset) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if m == nil || validateAdmission(dataset) != nil {
		return ErrInvalidRequest
	}
	key := datasetKey(dataset.TenantStratum, dataset.SiteStratum, dataset.DatasetID, dataset.Revision)
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, exists := m.datasets[key]; exists {
		return ErrConflict
	}
	for _, claim := range dataset.claims {
		ledgerKey := claim.Kind + "\x00" + claim.SHA256
		if split, exists := m.ledger[ledgerKey]; exists && split != claim.Split {
			return ErrLeakage
		}
	}
	for _, candidate := range dataset.sourceIntervals {
		for _, existing := range m.intervals {
			if sourceIntervalsCrossSplits(existing, candidate) {
				return ErrLeakage
			}
		}
	}
	for _, claim := range dataset.claims {
		m.ledger[claim.Kind+"\x00"+claim.SHA256] = claim.Split
	}
	for _, candidate := range dataset.sourceIntervals {
		duplicate := false
		for _, existing := range m.intervals {
			if existing.SourceSHA256 == candidate.SourceSHA256 && existing.IntervalSHA256 == candidate.IntervalSHA256 {
				duplicate = true
				break
			}
		}
		if !duplicate {
			m.intervals = append(m.intervals, candidate)
		}
	}
	m.datasets[key] = cloneDataset(dataset, false)
	return nil
}

func (m *memoryDatasetStore) Get(ctx context.Context, tenantStratum, siteStratum, datasetID string, revision uint64) (Dataset, error) {
	if err := ctx.Err(); err != nil {
		return Dataset{}, err
	}
	if m == nil || !validPseudonym("tenant", tenantStratum) || !validPseudonym("site", siteStratum) || !validNamespacedRef("dataset-", datasetID) || revision < 1 {
		return Dataset{}, ErrNotFound
	}
	m.mu.RLock()
	value, exists := m.datasets[datasetKey(tenantStratum, siteStratum, datasetID, revision)]
	m.mu.RUnlock()
	if !exists {
		return Dataset{}, ErrNotFound
	}
	return cloneDataset(value, false), nil
}

func (m *memoryDatasetStore) List(ctx context.Context, tenantStratum, siteStratum string) ([]Dataset, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if m == nil || !validPseudonym("tenant", tenantStratum) || !validPseudonym("site", siteStratum) {
		return nil, ErrNotFound
	}
	m.mu.RLock()
	result := make([]Dataset, 0)
	for _, value := range m.datasets {
		if value.TenantStratum == tenantStratum && value.SiteStratum == siteStratum {
			result = append(result, cloneDataset(value, false))
		}
	}
	m.mu.RUnlock()
	sort.Slice(result, func(i, j int) bool {
		if result[i].DatasetID != result[j].DatasetID {
			return result[i].DatasetID < result[j].DatasetID
		}
		return result[i].Revision < result[j].Revision
	})
	return result, nil
}

var _ Repository = (*SQLiteRepository)(nil)
var _ ReviewRepository = (*SQLiteRepository)(nil)
