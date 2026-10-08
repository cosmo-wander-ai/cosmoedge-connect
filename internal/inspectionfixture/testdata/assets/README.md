# Synthetic dining-area fixture

These assets are original, code-drawn test illustrations created for CosmoEdge
Connect. They contain no camera capture, photograph, identifiable person, logo,
external image, external font or model-generated visual. The drawing commands
and block-letter cells are maintained in
[`scripts/generate-inspection-fixture.py`](../../../../scripts/generate-inspection-fixture.py).
The generator and its generated assets are provided under the repository's
[Apache-2.0 license](../../../../LICENSE).

The scene is a top-down diagram of two dining tables. Table A has a used plate,
food residue, a drink spill, a napkin and utensils; Table B is empty. Visible
labels identify the scene as a synthetic fixture. The unchanged synthetic event
describes meal residue requiring routine cleaning. This supports the existing
fixture's business interpretation without claiming real visual-model accuracy.

## Media contract

- `scene.jpg`: 1280 x 720 JPEG rendered from deterministic geometric primitives.
- `scene.mp4`: 1280 x 720 H.264/yuv420p MP4, 15 frames/second, 75 frames, 5 seconds.
  The same synthetic scene is held throughout; it does not depict a cleanup event.
- `scene-frame.jpg`: JPEG extracted from the encoded clip at 1 second.
- `event.json`: fixed synthetic observation, not the result of a real detector.
- `manifest.json`: exact filenames, SHA-256 hashes and media metadata used by
  the fixture runtime. The schema is unchanged.

The initial public source import replaces development media whose original
source and redistribution terms were not documented. None of those previous
image or video bytes are inputs to this generator or included in these assets.

## Rebuilding and checking

The generator uses Python 3.9+ standard-library modules and a separately installed
FFmpeg with `mjpeg` and `libx264` encoders. These are asset-authoring tools, not
product runtime dependencies. No network access is required by the script.

From the repository root:

```sh
python3 scripts/generate-inspection-fixture.py --ffmpeg /absolute/path/to/ffmpeg
python3 scripts/generate-inspection-fixture.py --ffmpeg /absolute/path/to/ffmpeg --check
go test -p 1 -count=1 ./internal/inspectionfixture ./cmd/cosmoedge-inspection-fixture
```

The checked-in reference media was generated with Python 3.9.6 and FFmpeg 7.1
from the macOS arm64 wheel of `imageio-ffmpeg` 0.6.0. FFmpeg and that package are
not vendored or redistributed with this project. Single-threaded encoding,
disabled x264 assembly, fixed encoding parameters and omitted source metadata
make repeated generation deterministic with that reference toolchain. Other
FFmpeg/encoder builds can emit different valid bytes: regenerate and review
the complete asset set and manifest together when changing the toolchain.

`--check` creates a temporary asset set, decodes the entire video and compares
all five generated files byte-for-byte. It leaves the checked-in assets intact.
The Go tests continue to verify runtime integrity, original-media reuse and
business flow; synthetic fixtures do not qualify real devices or model accuracy.
