package livevision

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"image"
	"math"

	"github.com/cosmo-wander-ai/cosmoedge-connect/internal/inspection/temporary"
)

type temporaryImageQuality string

const (
	temporaryNearBlack    temporaryImageQuality = "near_black_low_detail"
	temporaryPixelLimit   temporaryImageQuality = "decoded_pixel_limit"
	maxTemporaryPixels                          = 16_000_000
	temporaryQualityBlock                       = 8
)

// assessTemporaryImage recognizes only a narrow near-black, low-contrast
// envelope. Passing it is not a claim of readability, focus, or model accuracy.
// No source name, device kind, question, or model response influences it.
func assessTemporaryImage(ctx context.Context, content []byte) (temporaryImageQuality, error) {
	if err := ctx.Err(); err != nil {
		return "", err
	}
	config, format, err := image.DecodeConfig(bytes.NewReader(content))
	if err != nil || format != "jpeg" || config.Width < 1 || config.Height < 1 {
		return "", errors.New("temporary image quality input is not a valid JPEG")
	}
	// Check before full decoding; the compressed byte bound alone cannot limit
	// image allocation. Division avoids overflowing width * height.
	if config.Width > maxTemporaryPixels/config.Height {
		return temporaryPixelLimit, nil
	}
	if err := ctx.Err(); err != nil {
		return "", err
	}
	decoded, format, err := image.Decode(bytes.NewReader(content))
	if err != nil || format != "jpeg" {
		return "", errors.New("temporary image quality JPEG decoding failed")
	}
	if err := ctx.Err(); err != nil {
		return "", err
	}
	bounds := decoded.Bounds()
	if bounds.Dx() != config.Width || bounds.Dy() != config.Height {
		return "", errors.New("temporary image quality dimensions changed")
	}
	columns := (config.Width + temporaryQualityBlock - 1) / temporaryQualityBlock
	rows := (config.Height + temporaryQualityBlock - 1) / temporaryQualityBlock
	blocks := make([]uint32, columns*rows)
	counts := make([]uint16, len(blocks))
	var sum, squared, above32 uint64
	for y := bounds.Min.Y; y < bounds.Max.Y; y++ {
		if (y-bounds.Min.Y)%32 == 0 {
			if err := ctx.Err(); err != nil {
				return "", err
			}
		}
		for x := bounds.Min.X; x < bounds.Max.X; x++ {
			r, g, b, _ := decoded.At(x, y).RGBA()
			// Rounded 8-bit Rec.601 approximation, consistently used in tests.
			value := uint64((77*(r>>8) + 150*(g>>8) + 29*(b>>8) + 128) >> 8)
			sum += value
			squared += value * value
			if value > 32 {
				above32++
			}
			index := (y-bounds.Min.Y)/temporaryQualityBlock*columns + (x-bounds.Min.X)/temporaryQualityBlock
			blocks[index] += uint32(value)
			counts[index]++
		}
	}
	pixels := uint64(config.Width) * uint64(config.Height)
	mean := float64(sum) / float64(pixels)
	variance := float64(squared)/float64(pixels) - mean*mean
	if mean > 16 || variance > 36 || above32*100 > pixels {
		return "", nil
	}
	// A coherent local contrast escapes the global darkness envelope, even
	// when the bright region is small. Block averages suppress pixel noise.
	average := func(index int) float64 { return float64(blocks[index]) / float64(counts[index]) }
	for y := 0; y < rows; y++ {
		if err := ctx.Err(); err != nil {
			return "", err
		}
		for x := 0; x < columns; x++ {
			index := y*columns + x
			value := average(index)
			if x > 0 && math.Abs(value-average(index-1)) > 8 || y > 0 && math.Abs(value-average(index-columns)) > 8 {
				return "", nil
			}
		}
	}
	return temporaryNearBlack, nil
}

// Quality rejection is a local typed conclusion, never invented VLM text.
func temporaryQualityCandidateJSON(quality temporaryImageQuality, evidenceRef string) ([]byte, error) {
	candidate := temporary.Candidate{
		Schema: temporary.CandidateSchemaVersion, Answer: temporary.AnswerUnable,
		VisibleFacts: []string{}, EvidenceRefs: []string{evidenceRef},
	}
	switch quality {
	case temporaryNearBlack:
		candidate.Summary = "画面过暗，无法判断"
		candidate.Limitations = []string{"本次画面过暗且可辨细节不足，无法可靠判断目标情况"}
	case temporaryPixelLimit:
		candidate.Summary = "图像尺寸超出本次处理范围，无法判断"
		candidate.Limitations = []string{"本次图像尺寸超出处理范围，暂时无法可靠判断目标情况"}
	default:
		return nil, errors.New("temporary image quality conclusion is invalid")
	}
	if err := candidate.Validate(); err != nil {
		return nil, err
	}
	return json.Marshal(candidate)
}
