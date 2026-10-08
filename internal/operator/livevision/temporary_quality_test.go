package livevision

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"image"
	"image/color"
	"image/jpeg"
	"os"
	"testing"

	"github.com/cosmo-wander-ai/cosmoedge-connect/internal/inspection/temporary"
)

func qualityJPEG(t *testing.T, width, height int, value func(int, int) uint8) []byte {
	t.Helper()
	frame := image.NewGray(image.Rect(0, 0, width, height))
	for y := 0; y < height; y++ {
		for x := 0; x < width; x++ {
			frame.SetGray(x, y, color.Gray{Y: value(x, y)})
		}
	}
	var output bytes.Buffer
	if err := jpeg.Encode(&output, frame, &jpeg.Options{Quality: 100}); err != nil {
		t.Fatal(err)
	}
	return output.Bytes()
}

func TestTemporaryNearBlackQualityEnvelope(t *testing.T) {
	cases := []struct {
		name  string
		value func(int, int) uint8
		want  temporaryImageQuality
	}{
		{"black", func(int, int) uint8 { return 0 }, temporaryNearBlack},
		{"near-black noise", func(x, y int) uint8 { return uint8(6 + (x*17+y*31)%9) }, temporaryNearBlack},
		{"mean boundary", func(int, int) uint8 { return 16 }, temporaryNearBlack},
		{"above darkness boundary", func(int, int) uint8 { return 17 }, ""},
		{"bright uniform is outside scope", func(int, int) uint8 { return 180 }, ""},
		{"dark coherent contrast", func(x, y int) uint8 {
			if x >= 64 && x < 72 && y >= 64 && y < 72 {
				return 28
			}
			return 4
		}, ""},
		{"small bright patch", func(x, y int) uint8 {
			if x >= 64 && x < 68 && y >= 64 && y < 68 {
				return 100
			}
			return 4
		}, ""},
		{"dim textured scene", func(x, y int) uint8 {
			if (x/16+y/16)%2 == 0 {
				return 24
			}
			return 4
		}, ""},
		{"variance alone escapes darkness", func(x, y int) uint8 {
			if (x+y)%2 == 0 {
				return 24
			}
			return 0
		}, ""},
		{"bright proportion alone escapes darkness", func(x, y int) uint8 {
			if x%8 == 0 && y%8 == 0 {
				return 40
			}
			return 8
		}, ""},
	}
	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			encoded := qualityJPEG(t, 128, 128, test.value)
			original := append([]byte(nil), encoded...)
			got, err := assessTemporaryImage(context.Background(), encoded)
			if err != nil || got != test.want || !bytes.Equal(original, encoded) {
				t.Fatalf("quality=%q want=%q error=%v inputUnchanged=%v", got, test.want, err, bytes.Equal(original, encoded))
			}
		})
	}
}

func TestTemporaryQualityBoundsAndFailures(t *testing.T) {
	encoded := qualityJPEG(t, 32, 24, func(int, int) uint8 { return 8 })
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if quality, err := assessTemporaryImage(ctx, encoded); quality != "" || !errors.Is(err, context.Canceled) {
		t.Fatalf("cancelled quality=%q error=%v", quality, err)
	}
	for _, invalid := range [][]byte{[]byte("not JPEG"), encoded[:len(encoded)-20]} {
		if quality, err := assessTemporaryImage(context.Background(), invalid); quality != "" || err == nil {
			t.Fatalf("damaged input became quality conclusion=%q error=%v", quality, err)
		}
	}
	// A valid large-size header with no corresponding pixel allocation proves
	// that the bound is enforced before full decoding the compressed image.
	oversized := append([]byte(nil), encoded...)
	marker := bytes.Index(oversized, []byte{0xff, 0xc0})
	if marker < 0 {
		t.Fatal("test JPEG has no baseline SOF")
	}
	binary.BigEndian.PutUint16(oversized[marker+5:marker+7], 65535)
	binary.BigEndian.PutUint16(oversized[marker+7:marker+9], 65535)
	if config, _, err := image.DecodeConfig(bytes.NewReader(oversized)); err != nil || config.Width != 65535 || config.Height != 65535 {
		t.Fatalf("oversized test header=%+v error=%v", config, err)
	}
	quality, err := assessTemporaryImage(context.Background(), oversized)
	if err != nil || quality != temporaryPixelLimit {
		t.Fatalf("oversized quality=%q error=%v", quality, err)
	}
}

func TestTemporaryQualityConclusionsAreTypedAndBound(t *testing.T) {
	const ref = "media_0123456789abcdef0123456789abcdef"
	for _, reason := range []temporaryImageQuality{temporaryNearBlack, temporaryPixelLimit} {
		raw, err := temporaryQualityCandidateJSON(reason, ref)
		if err != nil {
			t.Fatal(err)
		}
		candidate, err := temporary.ParseCandidate(raw)
		if err != nil || candidate.Answer != temporary.AnswerUnable || len(candidate.VisibleFacts) != 0 || len(candidate.Limitations) != 1 || len(candidate.EvidenceRefs) != 1 || candidate.EvidenceRefs[0] != ref {
			t.Fatalf("quality candidate=%+v error=%v", candidate, err)
		}
		if reason == temporaryPixelLimit && bytes.Contains(raw, []byte("过暗")) {
			t.Fatal("pixel limit was mislabeled as darkness")
		}
	}
	if _, err := temporaryQualityCandidateJSON("unrecognized", ref); err == nil {
		t.Fatal("unrecognized quality reason was accepted")
	}
}

// Optional, explicitly enumerated development material. No directory discovery
// or model answers are read; held-out acceptance images must stay unlisted.
func TestTemporaryImageQualityCalibration(t *testing.T) {
	manifest := os.Getenv("COSMOEDGE_CONNECT_IMAGE_QUALITY_CALIBRATION")
	if manifest == "" {
		t.Skip("no development calibration manifest supplied")
	}
	var cases []struct {
		Name    string                `json:"name"`
		Path    string                `json:"path"`
		Quality temporaryImageQuality `json:"quality"`
	}
	raw, err := os.ReadFile(manifest)
	if err != nil || json.Unmarshal(raw, &cases) != nil || len(cases) == 0 {
		t.Fatalf("invalid calibration manifest: %v", err)
	}
	for _, test := range cases {
		t.Run(test.Name, func(t *testing.T) {
			content, err := os.ReadFile(test.Path)
			if err != nil {
				t.Fatal(err)
			}
			quality, err := assessTemporaryImage(context.Background(), content)
			if err != nil || quality != test.Quality {
				t.Fatalf("quality=%q want=%q error=%v", quality, test.Quality, err)
			}
		})
	}
}
