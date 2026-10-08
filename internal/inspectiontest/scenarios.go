package inspectiontest

import (
	"bytes"
	"errors"
	"image"
	"image/color"
	"image/jpeg"

	"github.com/cosmo-wander-ai/cosmoedge-connect/internal/inspection"
	inspectionruntime "github.com/cosmo-wander-ai/cosmoedge-connect/internal/inspection/runtime"
)

type FixtureScenario string

const (
	FixtureScenarioNormal             FixtureScenario = "normal"
	FixtureScenarioAcquisitionFailure FixtureScenario = "acquisition_failure"
	FixtureScenarioCatalogMismatch    FixtureScenario = "catalog_mismatch"
	FixtureScenarioResolveFailure     FixtureScenario = "resolve_failure"
	FixtureScenarioTimeout            FixtureScenario = "timeout"
	FixtureScenarioMalformedAnalysis  FixtureScenario = "malformed_analysis"
	FixtureScenarioPartialVisibility  FixtureScenario = "partial_visibility"
	FixtureScenarioResourceBusy       FixtureScenario = "resource_busy"
	FixtureScenarioOutcomeUnknown     FixtureScenario = "outcome_unknown"
	FixtureScenarioCleanupFailure     FixtureScenario = "cleanup_failure"
	FixtureScenarioDuplicateRestart   FixtureScenario = "duplicate_restart"
)

var AllFixtureScenarios = []FixtureScenario{
	FixtureScenarioNormal, FixtureScenarioAcquisitionFailure, FixtureScenarioCatalogMismatch, FixtureScenarioResolveFailure,
	FixtureScenarioTimeout, FixtureScenarioMalformedAnalysis, FixtureScenarioPartialVisibility,
	FixtureScenarioResourceBusy, FixtureScenarioOutcomeUnknown, FixtureScenarioCleanupFailure,
	FixtureScenarioDuplicateRestart,
}

var NeutralSceneJPEG = neutralSceneJPEGFixture()

func neutralSceneJPEGFixture() []byte {
	frame := image.NewRGBA(image.Rect(0, 0, 16, 12))
	for y := 0; y < 12; y++ {
		for x := 0; x < 16; x++ {
			frame.SetRGBA(x, y, color.RGBA{R: uint8(30 + x*4), G: uint8(40 + y*5), B: 90, A: 255})
		}
	}
	var output bytes.Buffer
	if err := jpeg.Encode(&output, frame, &jpeg.Options{Quality: 85}); err != nil {
		panic(err)
	}
	return output.Bytes()
}

func RuntimeScriptForScenario(scenario FixtureScenario) (RuntimeScript, error) {
	script := RuntimeScript{
		Name: scenario,
		Assessments: map[string]inspection.Assessment{
			SceneTargetAlphaID: inspection.AssessmentMeetsRule,
			SceneTargetBetaID:  inspection.AssessmentMeetsRule,
		},
	}
	switch scenario {
	case FixtureScenarioNormal:
	case FixtureScenarioAcquisitionFailure:
		script.AcquireErr = ErrFixtureAcquire
	case FixtureScenarioCatalogMismatch:
		script.ResolveErr = inspectionruntime.ErrBindingStale
	case FixtureScenarioResolveFailure:
		script.ResolveErr = ErrFixtureResolve
	case FixtureScenarioTimeout:
		script.WaitForAcquire = true
	case FixtureScenarioMalformedAnalysis:
		script.MalformedResult = true
	case FixtureScenarioPartialVisibility:
		script.Assessments[SceneTargetBetaID] = inspection.AssessmentNotObservable
	case FixtureScenarioResourceBusy:
		script.AcquireErr = inspectionruntime.ErrResourceBusy
	case FixtureScenarioOutcomeUnknown:
		script.AcquireErr = inspectionruntime.ErrOutcomeUnknown
	case FixtureScenarioCleanupFailure:
		script.CleanupErr = inspectionruntime.ErrOutcomeUnknown
	case FixtureScenarioDuplicateRestart:
	default:
		return RuntimeScript{}, errors.New("unknown inspection fixture scenario")
	}
	return script, nil
}
