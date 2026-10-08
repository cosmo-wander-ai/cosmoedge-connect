#!/usr/bin/env python3
"""Rebuild original schematic fixture media using Python's standard library and FFmpeg.

No photographs, external fonts, network requests or random inputs are used.
FFmpeg must provide the mjpeg and libx264 encoders. See the assets README for
the reference tool versions and the scope of byte-for-byte reproducibility.
"""

import argparse
import hashlib
import json
from pathlib import Path
import shutil
import subprocess
import tempfile


ROOT = Path(__file__).resolve().parents[1]
ASSETS = ROOT / "internal/inspectionfixture/testdata/assets"
WIDTH, HEIGHT, FPS, SECONDS = 1280, 720, 15, 5
FILES = ("scene.jpg", "scene.mp4", "scene-frame.jpg", "event.json", "manifest.json")

# Original 5 x 7 block lettering, drawn from these explicit geometric cells.
GLYPHS = {
    "A": (14, 17, 17, 31, 17, 17, 17),
    "B": (30, 17, 17, 30, 17, 17, 30),
    "C": (14, 17, 16, 16, 16, 17, 14),
    "D": (30, 17, 17, 17, 17, 17, 30),
    "E": (31, 16, 16, 30, 16, 16, 31),
    "F": (31, 16, 16, 30, 16, 16, 16),
    "G": (14, 17, 16, 23, 17, 17, 14),
    "H": (17, 17, 17, 31, 17, 17, 17),
    "I": (31, 4, 4, 4, 4, 4, 31),
    "L": (16, 16, 16, 16, 16, 16, 31),
    "M": (17, 27, 21, 21, 17, 17, 17),
    "N": (17, 25, 25, 21, 19, 19, 17),
    "O": (14, 17, 17, 17, 17, 17, 14),
    "P": (30, 17, 17, 30, 16, 16, 16),
    "R": (30, 17, 17, 30, 20, 18, 17),
    "S": (15, 16, 16, 14, 1, 1, 30),
    "T": (31, 4, 4, 4, 4, 4, 4),
    "U": (17, 17, 17, 17, 17, 17, 14),
    "X": (17, 17, 10, 4, 10, 17, 17),
    "Y": (17, 17, 10, 4, 4, 4, 4),
}


def scene_ppm():
    pixels = bytearray(bytes((236, 240, 239)) * WIDTH * HEIGHT)

    def rect(x, y, width, height, color):
        left, top = max(0, x), max(0, y)
        right, bottom = min(WIDTH, x + width), min(HEIGHT, y + height)
        if left >= right or top >= bottom:
            return
        row = bytes(color) * (right - left)
        for yy in range(top, bottom):
            start = (yy * WIDTH + left) * 3
            pixels[start:start + len(row)] = row

    def ellipse(x, y, width, height, color):
        for yy in range(max(0, y), min(HEIGHT, y + height)):
            for xx in range(max(0, x), min(WIDTH, x + width)):
                dx, dy = 2 * (xx - x) + 1 - width, 2 * (yy - y) + 1 - height
                if dx * dx * height * height + dy * dy * width * width <= width * width * height * height:
                    offset = (yy * WIDTH + xx) * 3
                    pixels[offset:offset + 3] = bytes(color)

    def text(x, y, label, scale, color):
        for char in label:
            if char != " ":
                for row, cells in enumerate(GLYPHS[char]):
                    for column in range(5):
                        if cells & (1 << (4 - column)):
                            rect(x + column * scale, y + row * scale, scale, scale, color)
            x += 6 * scale

    ink, muted = (32, 52, 59), (86, 108, 111)
    rect(0, 0, WIDTH, 102, ink)
    text(48, 27, "SYNTHETIC FIXTURE", 6, (250, 250, 240))
    text(50, 130, "DINING AREA", 4, ink)
    for x in range(0, WIDTH, 80):
        rect(x, 186, 2, 414, (217, 225, 223))
    for y in range(186, 600, 69):
        rect(0, y, WIDTH, 2, (217, 225, 223))

    def table(x, dirty):
        for chair_x in (x + 42, x + 276):
            rect(chair_x, 205, 100, 53, muted)
            rect(chair_x + 8, 217, 84, 26, (152, 178, 175))
            rect(chair_x, 490, 100, 53, muted)
            rect(chair_x + 8, 505, 84, 26, (152, 178, 175))
        rect(x + 11, 273, 436, 220, (189, 195, 184))
        rect(x, 260, 436, 220, (134, 92, 57))
        rect(x + 8, 268, 420, 204, (215, 182, 129))
        for stripe in (294, 338, 382, 426):
            rect(x + 10, stripe, 416, 2, (203, 167, 113))
        if dirty:
            # Used plate, food residue, spilled drink, crumpled napkin and utensils.
            ellipse(x + 59, 296, 142, 142, (93, 108, 113))
            ellipse(x + 63, 300, 134, 134, (251, 250, 241))
            ellipse(x + 78, 315, 104, 104, (220, 226, 219))
            ellipse(x + 83, 346, 41, 26, (153, 82, 36))
            ellipse(x + 123, 356, 34, 20, (83, 132, 67))
            ellipse(x + 126, 328, 22, 24, (204, 115, 40))
            ellipse(x + 274, 313, 82, 43, (158, 116, 66))
            ellipse(x + 278, 297, 51, 51, (238, 244, 239))
            ellipse(x + 285, 304, 37, 37, (115, 79, 48))
            rect(x + 281, 388, 76, 50, (248, 247, 232))
            rect(x + 296, 396, 54, 3, (196, 198, 189))
            rect(x + 289, 410, 40, 3, (196, 198, 189))
            rect(x + 220, 314, 5, 114, (106, 119, 123))
            for fork_x in (214, 220, 226):
                rect(x + fork_x, 308, 3, 28, (106, 119, 123))
            rect(x + 243, 311, 7, 117, (106, 119, 123))
            for crumb_x, crumb_y in ((54, 445), (230, 446), (242, 450), (254, 441), (364, 378)):
                ellipse(x + crumb_x, crumb_y, 8, 6, (155, 98, 42))

    table(92, True)
    table(752, False)
    text(110, 566, "TABLE A", 3, ink)
    text(771, 566, "TABLE B", 3, ink)
    rect(0, 614, WIDTH, 106, ink)
    text(48, 635, "CLEANUP NEEDED AT TABLE A", 3, (248, 212, 147))
    text(48, 677, "NOT A CAMERA IMAGE", 2, (231, 240, 239))
    return f"P6\n{WIDTH} {HEIGHT}\n255\n".encode("ascii") + pixels


def run_ffmpeg(ffmpeg, *arguments):
    subprocess.run([ffmpeg, "-hide_banner", "-loglevel", "error", "-nostdin", "-y", *arguments], check=True)


def generate(destination, ffmpeg):
    destination.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix="cosmoedge-fixture-source-") as temporary:
        ppm = Path(temporary) / "scene.ppm"
        ppm.write_bytes(scene_ppm())
        jpeg_options = ["-frames:v", "1", "-c:v", "mjpeg", "-threads", "1", "-q:v", "2",
                        "-pix_fmt", "yuvj420p", "-fflags", "+bitexact", "-flags:v", "+bitexact",
                        "-map_metadata", "-1", "-update", "1"]
        run_ffmpeg(ffmpeg, "-i", str(ppm), *jpeg_options, str(destination / "scene.jpg"))
        run_ffmpeg(ffmpeg, "-loop", "1", "-framerate", str(FPS), "-i", str(ppm), "-an",
                   "-frames:v", str(FPS * SECONDS), "-c:v", "libx264", "-preset", "medium", "-crf", "20",
                   "-threads", "1", "-x264-params", "threads=1:lookahead_threads=1:scenecut=0:asm=0",
                   "-g", str(FPS), "-pix_fmt", "yuv420p", "-fflags", "+bitexact", "-flags:v", "+bitexact",
                   "-map_metadata", "-1", "-bsf:v", "filter_units=remove_types=6",
                   "-video_track_timescale", "15360", "-movflags", "+faststart", str(destination / "scene.mp4"))
        run_ffmpeg(ffmpeg, "-i", str(destination / "scene.mp4"), "-ss", "1",
                   *jpeg_options, str(destination / "scene-frame.jpg"))
        # Require every encoded frame to decode, rather than accepting an MP4 header alone.
        run_ffmpeg(ffmpeg, "-xerror", "-i", str(destination / "scene.mp4"), "-f", "null", "-")

    event = {"schema": "cosmoedge.fixture.observation.v1", "classification": "需要关注",
             "summary": "部分餐桌存在餐后残留，建议安排常规清理。", "synthetic": True}
    (destination / "event.json").write_text(json.dumps(event, ensure_ascii=False, separators=(",", ":")) + "\n", encoding="utf-8")

    def entry(name, mime, **fields):
        return dict(file=name, sha256=hashlib.sha256((destination / name).read_bytes()).hexdigest(), **fields, mimeType=mime)

    manifest = {
        "schema": "cosmoedge.inspection.fixture.assets.v1",
        "snapshot": entry("scene.jpg", "image/jpeg", width=WIDTH, height=HEIGHT),
        "clip": {**entry("scene.mp4", "video/mp4", width=WIDTH, height=HEIGHT),
                 "codec": "h264", "frameRate": FPS, "durationMillis": SECONDS * 1000},
        "clipFrame": {**entry("scene-frame.jpg", "image/jpeg", width=WIDTH, height=HEIGHT), "offsetMillis": 1000},
        "event": entry("event.json", "application/json"),
    }
    (destination / "manifest.json").write_text(json.dumps(manifest, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--ffmpeg", default="ffmpeg", help="FFmpeg executable with libx264 and mjpeg support")
    parser.add_argument("--output", type=Path, default=ASSETS, help="asset destination (default: repository fixtures)")
    parser.add_argument("--check", action="store_true", help="regenerate privately and compare all five files without updating the destination")
    args = parser.parse_args()
    ffmpeg = shutil.which(args.ffmpeg)
    if ffmpeg is None:
        parser.error("FFmpeg was not found; install it separately or supply --ffmpeg /absolute/path")
    if args.check:
        with tempfile.TemporaryDirectory(prefix="cosmoedge-fixture-check-") as temporary:
            generated = Path(temporary)
            generate(generated, ffmpeg)
            different = [name for name in FILES if not (args.output / name).is_file()
                         or (generated / name).read_bytes() != (args.output / name).read_bytes()]
        if different:
            parser.exit(1, "Fixture bytes differ: " + ", ".join(different) + ". See the reference toolchain in the assets README.\n")
        print("All five fixture files reproduce byte-for-byte.")
    else:
        generate(args.output, ffmpeg)
        print("Generated and decoded the five synthetic fixture files in " + str(args.output))


if __name__ == "__main__":
    main()
