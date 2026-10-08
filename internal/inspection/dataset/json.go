package dataset

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"

	"github.com/cosmo-wander-ai/cosmoedge-connect/internal/strictjson"
)

// datasetProjection prevents Dataset.MarshalJSON from recursing while keeping
// unexported admission claims outside every serialized representation.
type datasetProjection Dataset

func marshalDatasetProjection(value Dataset) ([]byte, error) {
	return json.Marshal(datasetProjection(value))
}

// DecodeIntake strictly decodes the public intake contract. Unknown fields,
// duplicate keys, case aliases, multiple values, and oversized input fail
// before authorization or media resolution.
func DecodeIntake(reader io.Reader) (IntakeRequest, error) {
	if reader == nil {
		return IntakeRequest{}, fmt.Errorf("%w: reader is required", ErrInvalidRequest)
	}
	raw, err := io.ReadAll(io.LimitReader(reader, maximumIntakeJSONBytes+1))
	if err != nil {
		return IntakeRequest{}, fmt.Errorf("%w: read input", ErrInvalidRequest)
	}
	if len(raw) == 0 || len(raw) > maximumIntakeJSONBytes {
		return IntakeRequest{}, fmt.Errorf("%w: input size is outside the bound", ErrInvalidRequest)
	}
	var request IntakeRequest
	if err := strictjson.ValidateExactFields(raw, &request, maximumIntakeJSONDepth); err != nil {
		return IntakeRequest{}, fmt.Errorf("%w: %v", ErrInvalidRequest, err)
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&request); err != nil {
		return IntakeRequest{}, fmt.Errorf("%w: decode input", ErrInvalidRequest)
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return IntakeRequest{}, fmt.Errorf("%w: trailing JSON value", ErrInvalidRequest)
	}
	if request.Schema != Schema {
		return IntakeRequest{}, ErrInvalidSchema
	}
	if intakeContainsNegativeZero(request) {
		return IntakeRequest{}, fmt.Errorf("%w: negative zero is not canonical", ErrInvalidRequest)
	}
	canonical, err := json.Marshal(request)
	if err != nil || !bytes.Equal(raw, canonical) {
		return IntakeRequest{}, fmt.Errorf("%w: input is not canonical JSON", ErrInvalidRequest)
	}
	return request, nil
}

func intakeContainsNegativeZero(request IntakeRequest) bool {
	for _, item := range request.Items {
		for _, annotation := range item.Annotations {
			label := annotation.Label
			if label.Metric != nil && label.Metric.Value == 0 && math.Signbit(label.Metric.Value) {
				return true
			}
			if label.Structured != nil {
				for _, field := range label.Structured.Fields {
					if field.Value.Number != nil && *field.Value.Number == 0 && math.Signbit(*field.Value.Number) {
						return true
					}
				}
			}
			if label.Detection != nil {
				for _, object := range label.Detection.Objects {
					for _, number := range []float64{object.Region.X, object.Region.Y, object.Region.Width, object.Region.Height} {
						if number == 0 && math.Signbit(number) {
							return true
						}
					}
				}
			}
		}
	}
	return false
}
