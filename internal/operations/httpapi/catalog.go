package httpapi

import "github.com/cosmo-wander-ai/cosmoedge-connect/internal/operator/device"

// CatalogTotals counts the same entries returned in this catalog response.
// Runtime counts preserve the device adapter's sampled runtime semantics;
// neither an enabled switch nor a catalog entry proves processing progress.
type CatalogTotals struct {
	SourceCount             int            `json:"sourceCount"`
	SourcesByKind           map[string]int `json:"sourcesByKind"`
	AlgorithmCount          int            `json:"algorithmCount"`
	TaskCount               int            `json:"taskCount"`
	RunningTaskCount        int            `json:"runningTaskCount"`
	StoppedTaskCount        int            `json:"stoppedTaskCount"`
	UnknownRuntimeTaskCount int            `json:"unknownRuntimeTaskCount"`
}

func summarizeCatalog(sources []Source, algorithms []Algorithm, tasks []device.Task) CatalogTotals {
	totals := CatalogTotals{
		SourceCount: len(sources), AlgorithmCount: len(algorithms), TaskCount: len(tasks),
		SourcesByKind: map[string]int{"network_camera": 0, "test_video": 0, "usb_camera": 0, "unknown": 0},
	}
	for _, source := range sources {
		kind := source.Kind
		switch kind {
		case "network_camera", "test_video", "usb_camera":
		default:
			kind = "unknown"
		}
		totals.SourcesByKind[kind]++
	}
	for _, task := range tasks {
		switch task.Running {
		case "running":
			totals.RunningTaskCount++
		case "stopped":
			totals.StoppedTaskCount++
		default:
			totals.UnknownRuntimeTaskCount++
		}
	}
	return totals
}
