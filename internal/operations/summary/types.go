// Package summary counts retained event facts independently of inspection runs
// and current task bindings. Retrieval completeness is never a claim about
// detector accuracy, source uptime, or the device's historical retention.
package summary

import (
	"context"
	"time"

	"github.com/cosmo-wander-ai/cosmoedge-connect/internal/operator/device"
)

type EventReader interface {
	ReadEventPage(context.Context, device.EventPageRequest) (device.EventPage, error)
}

// Request is a fixed, half-open time window [start,end). Empty ID filters mean
// all sources/algorithms, including events whose bindings no longer exist.
// Callers resolve natural-language references before submitting stable IDs.
type Request struct {
	Start        time.Time `json:"start"`
	End          time.Time `json:"end"`
	TimeZone     string    `json:"timeZone,omitempty"`
	SourceIDs    []string  `json:"sourceIds,omitempty"`
	AlgorithmIDs []string  `json:"algorithmIds,omitempty"`
	// SourceKinds is trusted current-catalog metadata keyed by stable source ID.
	// It annotates historical records and never restricts which records count.
	// Its known IDs also supply zero rows for an unfiltered daily/source grid.
	SourceKinds map[string]string `json:"-"`
}

type Window struct {
	Start time.Time `json:"start"`
	End   time.Time `json:"end"`
}

type Gap struct {
	Code   string `json:"code"`
	Window Window `json:"window"`
	Detail string `json:"detail"`
}

type Coverage struct {
	// exact_retained means all returned retained rows were read and usable,
	// not that all real-world occurrences were detected or retained.
	Accuracy          string `json:"accuracy"`
	RetrievalComplete bool   `json:"retrievalComplete"`
	HistoryCoverage   string `json:"historyCoverage"`
	PagesRead         int    `json:"pagesRead"`
	RowsRead          int    `json:"rowsRead"`
	ReportedTotal     *int   `json:"reportedTotal,omitempty"`
	Duplicates        int    `json:"duplicates"`
	ConflictingIDs    int    `json:"conflictingIds"`
	InvalidRows       int    `json:"invalidRows"`
	ExcludedRows      int    `json:"excludedRows"`
	Gaps              []Gap  `json:"gaps"`
}

type DailyCount struct {
	Date         string   `json:"date"`
	Count        int      `json:"count"`
	SharePercent *float64 `json:"sharePercent"`
}

type Count struct {
	ID           string   `json:"id"`
	Name         string   `json:"name,omitempty"`
	Count        int      `json:"count"`
	SharePercent *float64 `json:"sharePercent"`
}

// DaySourceCount uses the same retrieved-record scope and denominator as the
// other counts. Zero cells do not establish completeness; consult Coverage.
type DaySourceCount struct {
	Date         string   `json:"date"`
	SourceID     string   `json:"sourceId"`
	SourceName   string   `json:"sourceName,omitempty"`
	Count        int      `json:"count"`
	SharePercent *float64 `json:"sharePercent"`
}

type SourceAlgorithmCount struct {
	SourceID      string   `json:"sourceId"`
	SourceName    string   `json:"sourceName,omitempty"`
	AlgorithmID   string   `json:"algorithmId"`
	AlgorithmName string   `json:"algorithmName,omitempty"`
	Count         int      `json:"count"`
	SharePercent  *float64 `json:"sharePercent"`
}

type SourceKindCount struct {
	SourceKind          string `json:"sourceKind"`
	RetainedRecordCount int    `json:"retainedRecordCount"`
	// SourceCount counts distinct sources represented by these retained records,
	// not all configured sources or the number of records.
	SourceCount  int      `json:"sourceCount"`
	SharePercent *float64 `json:"sharePercent"`
}

// ShareBasis applies to every group's sharePercent. The numerator is the named
// existing count field, never SourceCount. Percentages are rounded to two decimal
// places and are null when Denominator is zero. Each dimension is independent;
// rounding can make its displayed percentages sum to something other than 100.
// Even after partial retrieval, the denominator is only the selected window's
// usable, deduplicated, retrieved records, not the device's reported total or an
// estimate of the missing records. Coverage describes completeness separately.
type ShareBasis struct {
	Scope           string            `json:"scope"`
	Denominator     int               `json:"denominator"`
	NumeratorFields map[string]string `json:"numeratorFields"`
}

type Result struct {
	Window               Window                   `json:"window"`
	TimeZone             string                   `json:"timeZone"`
	SourceIDs            []string                 `json:"sourceIds"`
	AlgorithmIDs         []string                 `json:"algorithmIds"`
	Count                int                      `json:"count"`
	ShareBasis           ShareBasis               `json:"shareBasis"`
	ByDay                []DailyCount             `json:"byDay"`
	ByDaySource          []DaySourceCount         `json:"byDaySource"`
	BySource             []Count                  `json:"bySource"`
	ByAlgorithm          []Count                  `json:"byAlgorithm"`
	BySourceAlgorithm    []SourceAlgorithmCount   `json:"bySourceAlgorithm"`
	BySourceKind         []SourceKindCount        `json:"bySourceKind"`
	SourceKindScope      string                   `json:"sourceKindScope"`
	SourceKindBasis      string                   `json:"sourceKindBasis"`
	RepresentativeEvents []device.HistoricalEvent `json:"representativeEvents"`
	Coverage             Coverage                 `json:"coverage"`
	Notes                []string                 `json:"notes"`
}
