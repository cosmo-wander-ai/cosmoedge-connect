"""Read-only, offline PostToolUse projection for paired CosmoEdge Connect report files."""
import hashlib
import hmac
import json
import os
from pathlib import Path
import re
import stat
import sys

MAX_REPORT_BYTES = 256 * 1024
MAX_METADATA_BYTES = 4096
MAX_HOOK_INPUT_BYTES = 1024 * 1024
REPORT_FILE = "统计报告.md"
PROVENANCE_FILE = "report-provenance.json"
CONTENT_TYPE = "text/markdown; charset=utf-8"
DIRECTORY_NAME = re.compile(r"cosmoedge-summary-[A-Za-z0-9_-]{6,80}\Z")
CANDIDATE_KEYS = {"product", "version", "revision", "modified", "platform"}
PROVENANCE_KEYS = {"schemaVersion", "kind", "reportFile", "sha256", "sizeBytes", "contentType", "candidate"}
UNAVAILABLE = "统计报告原件核验不可用，本次尚未交付。请保留此前已有的事实与限制，不要改写报告、重新统计或声称已交付。"


def unique_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate key")
        result[key] = value
    return result


def strict_json(data):
    return json.loads(data, object_pairs_hook=unique_object,
                      parse_constant=lambda _: (_ for _ in ()).throw(ValueError("nonfinite")))


def trusted_temp_roots():
    # Ignore arbitrary TMPDIR/TEMP overrides. These anchors are supplied by the OS.
    roots = ["/tmp"] if os.name == "posix" else []
    if sys.platform == "darwin":
        try:
            root = os.confstr(65537)  # Darwin _CS_DARWIN_USER_TEMP_DIR.
            if root:
                roots.append(root)
        except (OSError, ValueError):
            pass
    return tuple(dict.fromkeys(str(Path(p).absolute()) for p in roots))


def locate_target(path, roots):
    if not isinstance(path, str) or len(path) > 4096 or not os.path.isabs(path):
        return None
    normalized = Path(os.path.normpath(path))
    if normalized.name != REPORT_FILE or not DIRECTORY_NAME.fullmatch(normalized.parent.name):
        return None
    for root in roots:
        resolved = os.path.realpath(root)
        if str(normalized.parent.parent) in {os.path.normpath(root), resolved}:
            # Recognize a target even if '..' or controls later make verification fail.
            return resolved, normalized.parent.name
    return None


def checked_read_at(directory_fd, name, limit, private=True):
    flags = os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK
    fd = os.open(name, flags, dir_fd=directory_fd)
    try:
        before = os.fstat(fd)
        mode = stat.S_IMODE(before.st_mode)
        if (not stat.S_ISREG(before.st_mode) or before.st_uid != os.getuid()
                or not 0 < before.st_size <= limit
                or (mode != 0o600 if private else bool(mode & 0o022))):
            raise ValueError("file contract")
        data = b""
        while len(data) <= limit:
            part = os.read(fd, min(65536, limit + 1 - len(data)))
            if not part:
                break
            data += part
        after = os.fstat(fd)
        current = os.stat(name, dir_fd=directory_fd, follow_symlinks=False)
        signature = lambda s: (s.st_dev, s.st_ino, s.st_size, s.st_mtime_ns, s.st_ctime_ns, s.st_mode, s.st_uid)
        if (len(data) != before.st_size or signature(before) != signature(after)
                or signature(after) != signature(current)):
            raise ValueError("changed file")
        return data
    finally:
        os.close(fd)


def checked_candidate(value):
    if (not isinstance(value, dict) or set(value) != CANDIDATE_KEYS
            or value.get("product") != "cosmoedge-connect" or type(value.get("modified")) is not bool
            or not isinstance(value.get("version"), str)
            or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]{0,79}", value["version"])
            or not isinstance(value.get("revision"), str)
            or not re.fullmatch(r"[0-9a-f]{40,64}", value["revision"])
            or not isinstance(value.get("platform"), str)
            or not re.fullmatch(r"[a-z0-9]+/[a-z0-9]+", value["platform"])):
        raise ValueError("candidate contract")
    return value


def paired_candidate(candidate_path):
    directory = os.open(candidate_path.parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        value = strict_json(checked_read_at(directory, candidate_path.name, MAX_METADATA_BYTES, private=False))
    finally:
        os.close(directory)
    if (not isinstance(value, dict) or set(value) != {"schemaVersion", "candidate"}
            or type(value["schemaVersion"]) is not int or value["schemaVersion"] != 1):
        raise ValueError("paired candidate contract")
    return checked_candidate(value["candidate"])


def verify_report(path, located, candidate_path):
    if (str(Path(path)) != path or any(ord(c) < 32 for c in path)
            or ".." in Path(path).parts or "." in Path(path).parts):
        raise ValueError("noncanonical report path")
    root, dirname = located
    root_fd = os.open(root, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        parent_fd = os.open(dirname, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=root_fd)
    finally:
        os.close(root_fd)
    try:
        parent = os.fstat(parent_fd)
        if parent.st_uid != os.getuid() or stat.S_IMODE(parent.st_mode) != 0o700:
            raise ValueError("directory contract")
        provenance = strict_json(checked_read_at(parent_fd, PROVENANCE_FILE, MAX_METADATA_BYTES))
        if (not isinstance(provenance, dict) or set(provenance) != PROVENANCE_KEYS
                or type(provenance["schemaVersion"]) is not int or provenance["schemaVersion"] != 1
                or provenance["kind"] != "cosmoedge_summary_report" or provenance["reportFile"] != REPORT_FILE
                or provenance["contentType"] != CONTENT_TYPE
                or type(provenance["sizeBytes"]) is not int or not 0 < provenance["sizeBytes"] <= MAX_REPORT_BYTES
                or not isinstance(provenance["sha256"], str)
                or not re.fullmatch(r"[0-9a-f]{64}", provenance["sha256"])):
            raise ValueError("provenance contract")
        candidate = checked_candidate(provenance["candidate"])
        expected = paired_candidate(candidate_path)
        if any(type(candidate[k]) is not type(expected[k]) or candidate[k] != expected[k] for k in CANDIDATE_KEYS):
            raise ValueError("candidate mismatch")
        content = checked_read_at(parent_fd, REPORT_FILE, MAX_REPORT_BYTES)
        content.decode("utf-8")
        if len(content) != provenance["sizeBytes"] or not hmac.compare_digest(hashlib.sha256(content).hexdigest(), provenance["sha256"]):
            raise ValueError("report integrity")
        current_parent = os.stat(os.path.join(root, dirname), follow_symlinks=False)
        if ((parent.st_dev, parent.st_ino, parent.st_uid, parent.st_mode)
                != (current_parent.st_dev, current_parent.st_ino, current_parent.st_uid, current_parent.st_mode)):
            raise ValueError("changed report directory")
    finally:
        os.close(parent_fd)


def replacement(text):
    return {"hookSpecificOutput": {"hookEventName": "PostToolUse", "updatedToolOutput": text}}


def project(payload, roots, candidate_path, invalid_envelope=False):
    if (not isinstance(payload, dict) or payload.get("hook_event_name") != "PostToolUse"
            or payload.get("tool_name") != "Read" or not isinstance(payload.get("tool_input"), dict)):
        return None
    path = payload["tool_input"].get("file_path")
    located = locate_target(path, roots)
    if located is None:
        return None
    try:
        if invalid_envelope:
            raise ValueError("invalid envelope")
        verify_report(path, located, candidate_path)
    except (OSError, ValueError, TypeError, KeyError, UnicodeError):
        return replacement(UNAVAILABLE)
    return replacement("统计报告原件已准备，尚未交付。请用 WorkBuddy 原生 present_files 交付以下原路径，"
                       "以实际成功回执为准；不要改写报告或重新统计。\n报告原路径：" + path)


def header_before_response(data):
    """Recover only preceding metadata from a damaged/oversized native envelope.

    WorkBuddy serializes tool_input before tool_response. Never decode or echo the
    damaged response body. If the envelope cannot identify a target, do nothing.
    """
    decoder = json.JSONDecoder(object_pairs_hook=unique_object)
    text = data[:16384].decode("utf-8", errors="ignore")
    out, pos = {}, 0
    try:
        if not text.lstrip().startswith("{"):
            return None
        pos = text.index("{") + 1
        while True:
            while text[pos].isspace() or text[pos] == ",":
                pos += 1
            key, pos = decoder.raw_decode(text, pos)
            while text[pos].isspace():
                pos += 1
            if text[pos] != ":" or key in out:
                return None
            pos += 1
            if key == "tool_response":
                return out
            while text[pos].isspace():
                pos += 1
            out[key], pos = decoder.raw_decode(text, pos)
    except (ValueError, TypeError, IndexError):
        return None


def process_bytes(data, roots, candidate_path):
    try:
        if len(data) > MAX_HOOK_INPUT_BYTES:
            raise ValueError("input limit")
        return project(strict_json(data), roots, candidate_path)
    except (ValueError, TypeError, UnicodeError):
        return project(header_before_response(data), roots, candidate_path, invalid_envelope=True)


def main():
    # No state, environment dump, history access, subprocess, network or diagnostics
    # containing raw input. An unmatched Read produces no stdout at all.
    data = sys.stdin.buffer.read(MAX_HOOK_INPUT_BYTES + 1)
    expected = Path(__file__).absolute().parents[1] / "candidate.json"
    output = process_bytes(data, trusted_temp_roots(), expected)
    if output is not None:
        print(json.dumps(output, ensure_ascii=False))


if __name__ == "__main__":
    main()
