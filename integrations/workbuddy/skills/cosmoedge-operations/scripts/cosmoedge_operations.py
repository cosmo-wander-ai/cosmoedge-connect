#!/usr/bin/env python3
"""Bounded WorkBuddy client for the generic CosmoEdge inspection v2 API."""

from __future__ import annotations

import argparse
import hashlib
import hmac
import ipaddress
import json
import os
from pathlib import Path
import re
import socket
import stat
import sys
import tempfile
import time
from typing import Any, Dict, List, Mapping, Optional, Sequence, Tuple
import urllib.error
import urllib.parse
import urllib.request
import uuid
import local_files


DEFAULT_BASE_URL = "http://127.0.0.1:37789"
API_BASE = "/api/inspection"
REF_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$")
TOKEN_RE = re.compile(r"^[0-9a-f]{64}$")
SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
UNSAFE_TEXT_RE = re.compile(
    r"(?i)(?:https?|rtsps?|file|data)://|(?:password|token|secret|authorization)\s*[:=]|"
    r"(?:^|[\s\"'(])(?:/Users/|/home/|/var/|/tmp/|/private/|/etc/|/opt/|/Volumes/|[A-Za-z]:\\|\\\\)"
)
HAN_RE = re.compile(r"[\u3400-\u9fff]")
SYSTEM_TERM_RE = re.compile(
    r"(?i)(?<![A-Za-z0-9_])(?:accepted|working|ready|pending|created|interaction_required|result_not_ready|"
    r"unable|cancelled|expired|completed|partial|not_found|invalid_request|internal_error|conflict|forbidden|unauthenticated|"
    r"blocked|unknown|failed|queued|running|succeeded|invalid_candidate|outcome_unknown|"
    r"standard_pending|standard_bound|temporary_pending|temporary_bound|meets_rule|needs_attention|"
    r"not_observable|unsupported|synthetic[_-]mock)(?![A-Za-z0-9_])"
)
INTERNAL_REF_RE = re.compile(
    r"(?i)(?<![A-Za-z0-9_])(?:run|request|media|source|task|device|camera|handoff|tenant|site)[_:-][A-Za-z0-9._:-]+"
)
PROTECTED_PRESENTATION_RE = re.compile(
    r"(?i)/api/|(?<![A-Za-z0-9_])(?:api|rtsp|rtsps|vlm|llm|prompt|token|sha-?256|http|raw[_ -]?model[_ -]?output|"
    r"status[_ -]?code|error[_ -]?code)(?![A-Za-z0-9_])|"
    r"(?<![A-Za-z0-9_])(?:run|request|media|source|task|device|camera|handoff|tenant|site)(?:[_ -]?(?:id|ref|handle|identifier))?\s*[:=]\s*[A-Za-z0-9._:-]+|"
    r"(?:提示词|原始模型输出|模型原始输出|模型输出|模型回答|模型判断|模型结论|内部字段|内部引用|错误码|状态码)|"
    r"(?:设备|相机|摄像头|租户|站点)(?:编号|标识|id)\s*[:：=]?\s*[A-Za-z0-9._:-]+|"
    r"(?:\d{1,3}\.){3}\d{1,3}(?::\d+)?"
)
MAX_JSON_BYTES = 512 * 1024
MAX_MEDIA_BYTES = 8 * 1024 * 1024
MAX_OUTPUT_BYTES = 64 * 1024
DIAGNOSTIC_DIR = os.environ.get("COSMOEDGE_CONNECT_LOG_DIR", "")
DIAGNOSTIC_MAX_FILES = 256
ACTIVE_STATUSES = {"accepted", "working"}
TERMINAL_FAILURE_STATUSES = {"interaction_required", "unable", "cancelled", "expired"}
LOCAL_INTERACTION_CAPABILITIES = {"operator.onboarding", "operator.persistent_change"}
MEDIA_TYPES = {
    "image/png": (".png", b"\x89PNG\r\n\x1a\n"),
    "image/jpeg": (".jpg", b"\xff\xd8\xff"),
}
RETIRED_CLI_ARGUMENTS = frozenset(("check", "--area", "--focus"))


class ClientError(Exception):
    """Internal failure mapped to a fixed Chinese business response."""

    def __init__(self, code: str):
        super().__init__(code)
        self.code = code


class InteractionNeeded(ClientError):
    def __init__(self, message: str, action_label: str, capability: str, handoff_ref: str):
        super().__init__("interaction_required")
        self.message = message
        self.action_label = action_label
        self.capability = capability
        self.handoff_ref = handoff_ref


class RunPending(ClientError):
    def __init__(self, run_ref: str, message: str):
        super().__init__("run_pending")
        self.run_ref = run_ref
        self.message = message


class RunUnavailable(ClientError):
    def __init__(self, run_ref: str, message: str):
        super().__init__("run_unavailable")
        self.run_ref = run_ref
        self.message = message


class _ArgumentParser(argparse.ArgumentParser):
    def error(self, message: str) -> None:
        del message
        raise ClientError("invalid_arguments")


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):  # type: ignore[no-untyped-def]
        return None


def _default_token_file() -> Path:
    if sys.platform == "darwin":
        return Path.home() / "Library" / "Application Support" / "CosmoEdgeConnect" / "access.token"
    if os.name == "nt":
        root = os.environ.get("LOCALAPPDATA")
        if root:
            return Path(root) / "CosmoEdgeConnect" / "access.token"
    root = os.environ.get("XDG_CONFIG_HOME")
    if root:
        return Path(root) / "CosmoEdgeConnect" / "access.token"
    return Path.home() / ".config" / "CosmoEdgeConnect" / "access.token"


def _normalize_base_url(raw: str) -> str:
    try:
        parsed = urllib.parse.urlsplit(raw)
        port = parsed.port
    except (TypeError, ValueError) as error:
        raise ClientError("unsafe_endpoint") from error
    if (
        parsed.scheme != "http"
        or not parsed.hostname
        or parsed.username is not None
        or parsed.password is not None
        or parsed.query
        or parsed.fragment
        or parsed.path not in ("", "/")
    ):
        raise ClientError("unsafe_endpoint")
    try:
        address = ipaddress.ip_address(parsed.hostname)
    except ValueError as error:
        raise ClientError("unsafe_endpoint") from error
    if not address.is_loopback:
        raise ClientError("unsafe_endpoint")
    if port is None:
        port = 80
    host = "[{}]".format(address.compressed) if address.version == 6 else address.compressed
    return "http://{}:{}".format(host, port)


def _load_token(path: Path) -> str:
    candidate = path.expanduser()
    try:
        before = os.lstat(candidate)
    except (FileNotFoundError, OSError) as error:
        raise ClientError("connection_required") from error
    if stat.S_ISLNK(before.st_mode) or not stat.S_ISREG(before.st_mode):
        raise ClientError("connection_required")
    if hasattr(os, "getuid") and before.st_uid != os.getuid():
        raise ClientError("connection_required")
    if (not local_files.WINDOWS and before.st_mode & 0o077) or before.st_size <= 0 or before.st_size > 513:
        raise ClientError("connection_required")
    flags = os.O_RDONLY
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        descriptor = local_files.open_read(candidate)
        try:
            opened = os.fstat(descriptor)
            if not stat.S_ISREG(opened.st_mode) or (not local_files.WINDOWS and opened.st_mode & 0o077):
                raise ClientError("connection_required")
            if hasattr(os, "getuid") and opened.st_uid != os.getuid():
                raise ClientError("connection_required")
            raw = os.read(descriptor, 514)
        finally:
            os.close(descriptor)
    except ClientError:
        raise
    except OSError as error:
        raise ClientError("connection_required") from error
    try:
        token = raw.decode("ascii").strip()
    except UnicodeDecodeError as error:
        raise ClientError("connection_required") from error
    if not TOKEN_RE.fullmatch(token):
        raise ClientError("connection_required")
    return token


def _load_private_instruction(path: Path) -> str:
    candidate = path.expanduser()
    try:
        before = os.lstat(candidate)
        # Reject only group/other WRITABLE bits (tampering risk); allow read
        # bits so callers that write the temp instruction under the default
        # umask (0644) still work. The token loader stays strict (0600).
        if stat.S_ISLNK(before.st_mode) or not stat.S_ISREG(before.st_mode) or (not local_files.WINDOWS and before.st_mode & 0o022):
            raise ClientError("invalid_arguments")
        if hasattr(os, "getuid") and before.st_uid != os.getuid():
            raise ClientError("invalid_arguments")
        if before.st_size <= 0 or before.st_size > 8192:
            raise ClientError("invalid_arguments")
        flags = os.O_RDONLY
        if hasattr(os, "O_NOFOLLOW"):
            flags |= os.O_NOFOLLOW
        descriptor = local_files.open_read(candidate)
        try:
            opened = os.fstat(descriptor)
            if not stat.S_ISREG(opened.st_mode) or (not local_files.WINDOWS and opened.st_mode & 0o022):
                raise ClientError("invalid_arguments")
            raw = os.read(descriptor, 8193)
        finally:
            os.close(descriptor)
    except ClientError:
        raise
    except OSError as error:
        raise ClientError("invalid_arguments") from error
    try:
        return _business_text(raw.decode("utf-8").strip(), 2000)
    except UnicodeDecodeError as error:
        raise ClientError("invalid_arguments") from error


def _strict_json_loads(raw: bytes) -> Any:
    def reject_duplicates(pairs):  # type: ignore[no-untyped-def]
        result = {}
        for key, value in pairs:
            if key in result:
                raise ClientError("invalid_response")
            result[key] = value
        return result

    try:
        return json.loads(raw.decode("utf-8"), object_pairs_hook=reject_duplicates)
    except ClientError:
        raise
    except (UnicodeDecodeError, json.JSONDecodeError, RecursionError) as error:
        raise ClientError("invalid_response") from error


def _content_length(headers: Mapping[str, str], maximum: int) -> None:
    raw = headers.get("Content-Length")
    if raw is None:
        return
    try:
        size = int(raw)
    except ValueError as error:
        raise ClientError("invalid_response") from error
    if size < 0 or size > maximum:
        raise ClientError("response_too_large")


def _require_ref(value: Any) -> str:
    if not isinstance(value, str) or not REF_RE.fullmatch(value):
        raise ClientError("invalid_response")
    return value


def _business_text(value: Any, maximum: int = 4096) -> str:
    if (
        not isinstance(value, str)
        or not value
        or value != value.strip()
        or len(value.encode("utf-8")) > maximum
        or any(ord(character) < 32 and character != "\n" for character in value)
        or UNSAFE_TEXT_RE.search(value)
    ):
        raise ClientError("invalid_response")
    return value


def _presentation_text(value: Any, maximum: int = 4096) -> str:
    result = _business_text(value, maximum)
    if (
        not HAN_RE.search(result)
        or SYSTEM_TERM_RE.search(result)
        or INTERNAL_REF_RE.search(result)
        or PROTECTED_PRESENTATION_RE.search(result)
    ):
        raise ClientError("invalid_response")
    return result


def _strict_keys(value: Any, required: Sequence[str], optional: Sequence[str] = ()) -> Dict[str, Any]:
    if not isinstance(value, dict):
        raise ClientError("invalid_response")
    allowed = set(required) | set(optional)
    if set(value) - allowed or any(name not in value for name in required):
        raise ClientError("invalid_response")
    return value


def _safe_list(value: Any, maximum: int, item_limit: int = 1024) -> List[str]:
    if not isinstance(value, list) or len(value) > maximum:
        raise ClientError("invalid_response")
    return [_business_text(item, item_limit) for item in value]


class InspectionClient:
    def __init__(self, base_url: str, token: str):
        self.base_url = _normalize_base_url(base_url)
        self.token = token
        self._opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), _NoRedirect())

    def _open(
        self,
        method: str,
        path: str,
        *,
        payload: Optional[Mapping[str, Any]] = None,
        idempotency_key: Optional[str] = None,
        timeout: float = 10.0,
    ):
        if not path.startswith(API_BASE + "/") or path.startswith("//"):
            raise ClientError("internal_error")
        data = None
        headers = {
            "Accept": "application/json",
            "Authorization": "Bearer " + self.token,
            "User-Agent": "cosmoedge-workbuddy-inspection/2",
        }
        if payload is not None:
            data = json.dumps(payload, ensure_ascii=True, separators=(",", ":")).encode("utf-8")
            if len(data) > 32 * 1024:
                raise ClientError("invalid_arguments")
            headers["Content-Type"] = "application/json"
        if idempotency_key is not None:
            headers["Idempotency-Key"] = _require_ref(idempotency_key)
        request = urllib.request.Request(self.base_url + path, data=data, headers=headers, method=method)
        try:
            return self._opener.open(request, timeout=timeout)
        except urllib.error.HTTPError as error:
            try:
                _content_length(error.headers, MAX_JSON_BYTES)
                raw = error.read(MAX_JSON_BYTES + 1)
            finally:
                error.close()
            if len(raw) > MAX_JSON_BYTES:
                raise ClientError("response_too_large")
            self._raise_http_error(error.code, raw)
            raise ClientError("http_error")
        except (urllib.error.URLError, socket.timeout, TimeoutError, OSError) as error:
            raise ClientError("connection_failed") from error

    def _raise_http_error(self, status: int, raw: bytes) -> None:
        if 300 <= status < 400:
            raise ClientError("redirect_rejected")
        try:
            decoded = _strict_json_loads(raw)
        except ClientError:
            raise ClientError("http_error")
        envelope = _strict_keys(decoded, ["error"], ["interactionRequired"])
        error = _strict_keys(envelope["error"], ["code", "message"])
        code = error.get("code")
        if status == 409 and code == "interaction_required":
            interaction = _strict_keys(
                envelope.get("interactionRequired"),
                ["title", "message", "actionLabel", "capability", "handoffRef"],
            )
            _presentation_text(interaction["title"], 256)
            message = _presentation_text(interaction["message"], 1024)
            action_label = _presentation_text(interaction["actionLabel"], 128)
            capability = interaction["capability"]
            if capability not in LOCAL_INTERACTION_CAPABILITIES:
                raise ClientError("invalid_response")
            handoff_ref = _require_ref(interaction["handoffRef"])
            raise InteractionNeeded(message, action_label, capability, handoff_ref)
        if status in (401, 403):
            raise ClientError("connection_required")
        if status == 409 and code == "result_not_ready":
            raise ClientError("result_not_ready")
        if status == 404:
            raise ClientError("not_found")
        raise ClientError("http_error")

    def json(
        self,
        method: str,
        path: str,
        *,
        payload: Optional[Mapping[str, Any]] = None,
        idempotency_key: Optional[str] = None,
        timeout: float = 10.0,
    ) -> Dict[str, Any]:
        response = self._open(method, path, payload=payload, idempotency_key=idempotency_key, timeout=timeout)
        try:
            if response.headers.get("Content-Type", "").split(";", 1)[0].strip().lower() != "application/json":
                raise ClientError("invalid_response")
            if response.headers.get("Content-Encoding", "").strip().lower() not in ("", "identity"):
                raise ClientError("invalid_response")
            _content_length(response.headers, MAX_JSON_BYTES)
            raw = response.read(MAX_JSON_BYTES + 1)
            if len(raw) > MAX_JSON_BYTES:
                raise ClientError("response_too_large")
        finally:
            response.close()
        decoded = _strict_json_loads(raw)
        if not isinstance(decoded, dict):
            raise ClientError("invalid_response")
        return decoded

    def media(self, media_ref: str, expected_type: str, output_dir: Path, ordinal: int, *, timeout: float) -> Path:
        _require_ref(media_ref)
        if expected_type not in MEDIA_TYPES:
            raise ClientError("invalid_response")
        response = self._open("GET", API_BASE + "/media/" + urllib.parse.quote(media_ref, safe=""), timeout=timeout)
        temporary: Optional[Path] = None
        descriptor: Optional[int] = None
        try:
            content_type = response.headers.get("Content-Type", "").split(";", 1)[0].strip().lower()
            if content_type != expected_type:
                raise ClientError("invalid_media")
            if response.headers.get("Content-Encoding", "").strip().lower() not in ("", "identity"):
                raise ClientError("invalid_media")
            _content_length(response.headers, MAX_MEDIA_BYTES)
            expected_hash = response.headers.get("X-Content-SHA256", "").strip().lower()
            if not SHA256_RE.fullmatch(expected_hash):
                raise ClientError("invalid_media")
            descriptor, name = local_files.private_tempfile(prefix=".inspection-", directory=output_dir)
            temporary = Path(name)
            local_files.protect_descriptor(descriptor)
            digest = hashlib.sha256()
            prefix = bytearray()
            total = 0
            with os.fdopen(descriptor, "wb") as destination:
                descriptor = None
                while True:
                    chunk = response.read(64 * 1024)
                    if not chunk:
                        break
                    total += len(chunk)
                    if total > MAX_MEDIA_BYTES:
                        raise ClientError("invalid_media")
                    if len(prefix) < 16:
                        prefix.extend(chunk[: 16 - len(prefix)])
                    digest.update(chunk)
                    destination.write(chunk)
                destination.flush()
                os.fsync(destination.fileno())
            if not hmac.compare_digest(digest.hexdigest(), expected_hash) or not _valid_magic(content_type, bytes(prefix)):
                raise ClientError("invalid_media")
            suffix = MEDIA_TYPES[content_type][0]
            final_path = output_dir / "巡检图片-{:02d}{}".format(ordinal, suffix)
            if final_path.exists():
                raise ClientError("output_directory")
            local_files.replace_durable(temporary, final_path)
            temporary = None
            local_files.protect(final_path)
            return final_path.resolve(strict=True)
        finally:
            response.close()
            if descriptor is not None:
                try:
                    os.close(descriptor)
                except OSError:
                    pass
            if temporary is not None:
                try:
                    temporary.unlink()
                except FileNotFoundError:
                    pass


def _valid_magic(content_type: str, prefix: bytes) -> bool:
    magic = MEDIA_TYPES[content_type][1]
    return prefix.startswith(magic)


def _prepare_output_dir(raw: str) -> Path:
    candidate = Path(raw).expanduser()
    try:
        if candidate.exists() and candidate.is_symlink():
            raise ClientError("output_directory")
        candidate.mkdir(mode=0o700, parents=True, exist_ok=True)
        resolved = candidate.resolve(strict=True)
        info = os.stat(resolved, follow_symlinks=False)
        if not stat.S_ISDIR(info.st_mode) or (hasattr(os, "getuid") and info.st_uid != os.getuid()):
            raise ClientError("output_directory")
        local_files.protect(resolved, directory=True)
        return resolved
    except ClientError:
        raise
    except OSError as error:
        raise ClientError("output_directory") from error


def _parse_context(values: Sequence[str]) -> List[Dict[str, str]]:
    if len(values) > 16:
        raise ClientError("invalid_arguments")
    result: List[Dict[str, str]] = []
    seen = set()
    for raw in values:
        name, separator, value = raw.partition("=")
        if not separator:
            raise ClientError("invalid_arguments")
        name = _business_text(name, 128)
        value = _business_text(value, 512)
        normalized = name.casefold()
        if normalized in seen:
            raise ClientError("invalid_arguments")
        seen.add(normalized)
        result.append({"name": name, "value": value})
    return result


def _parse_temporary_intent(subject, region, observable):
    """Parse and validate structured temporary observation fields.

    Returns a dict suitable for the temporaryIntent JSON field, or None when
    not all three fields are provided.
    """
    if subject is None and region is None and observable is None:
        return None
    if subject is None or region is None or observable is None:
        raise ClientError("invalid_arguments")
    return {
        "subject": _business_text(subject, 160),
        "region": _business_text(region, 160),
        "observable": _business_text(observable, 512),
    }


def _validate_run(raw: Any, expected_ref: Optional[str] = None) -> Tuple[str, str, str]:
    run = _strict_keys(raw, ["runRef", "status", "message", "submittedAt", "updatedAt"])
    run_ref = _require_ref(run["runRef"])
    if expected_ref is not None and run_ref != expected_ref:
        raise ClientError("invalid_response")
    status = run.get("status")
    if status not in ACTIVE_STATUSES | TERMINAL_FAILURE_STATUSES | {"ready"}:
        raise ClientError("invalid_response")
    message = _presentation_text(run["message"], 1024)
    if not isinstance(run["submittedAt"], str) or not isinstance(run["updatedAt"], str):
        raise ClientError("invalid_response")
    return run_ref, status, message


def query_capabilities(client: InspectionClient, timeout: float) -> Dict[str, Any]:
    raw = _strict_keys(client.json("GET", API_BASE + "/capabilities", timeout=timeout), ["contextLabel", "capabilities"])
    context_label = _presentation_text(raw["contextLabel"], 256)
    capabilities = raw["capabilities"]
    if not isinstance(capabilities, list) or not capabilities or len(capabilities) > 100:
        raise ClientError("invalid_response")
    seen_references = set()
    grouped: List[Tuple[str, str, List[str]]] = []
    group_indexes: Dict[Tuple[str, str], int] = {}
    for item in capabilities:
        capability = _strict_keys(item, ["capabilityRef", "title", "description", "examples"])
        reference = _require_ref(capability["capabilityRef"])
        if reference in seen_references:
            raise ClientError("invalid_response")
        seen_references.add(reference)
        title = _presentation_text(capability["title"], 256)
        description = _presentation_text(capability["description"], 1024)
        examples = [_presentation_text(value, 512) for value in _safe_list(capability["examples"], 8, 512)]
        group_key = (title, description)
        if group_key not in group_indexes:
            group_indexes[group_key] = len(grouped)
            grouped.append((title, description, []))
        merged_examples = grouped[group_indexes[group_key]][2]
        for example in examples:
            if example not in merged_examples:
                merged_examples.append(example)

    lines = [context_label + "可用的巡检能力："]
    for title, description, examples in grouped:
        lines.append("- {}：{}".format(title, description))
        if examples:
            lines.append("  例如：" + "；".join(examples))
    lines.append("你可以直接告诉我想查看的区域和问题。")
    return {"ok": True, "userMessage": "\n".join(lines)}


def query_run_status(client: InspectionClient, run_ref: str, timeout: float) -> Dict[str, Any]:
    run_ref = _require_ref(run_ref)
    raw = client.json(
        "GET",
        API_BASE + "/runs/" + urllib.parse.quote(run_ref, safe=""),
        timeout=timeout,
    )
    _, status, message = _validate_run(raw, run_ref)
    return {
        "ok": True,
        "runRef": run_ref,
        "resultAvailable": status == "ready",
        "userMessage": message,
    }


def _poll_run(client: InspectionClient, run_ref: str, timeout: float) -> Tuple[str, str]:
    expires = time.monotonic() + timeout
    delay = 0.15
    last_message = "正在处理这次巡检"
    while True:
        remaining = expires - time.monotonic()
        if remaining <= 0:
            raise RunPending(run_ref, last_message)
        raw = client.json("GET", API_BASE + "/runs/" + urllib.parse.quote(run_ref, safe=""), timeout=min(5.0, remaining))
        _, status, message = _validate_run(raw, run_ref)
        last_message = message
        if status == "ready":
            return status, message
        if status in TERMINAL_FAILURE_STATUSES:
            raise RunUnavailable(run_ref, message)
        time.sleep(min(delay, max(0.0, expires - time.monotonic())))
        delay = min(delay * 1.6, 0.8)


def _validate_result(raw: Any, run_ref: str) -> Tuple[str, List[Dict[str, Any]], List[str], str, str]:
    result = _strict_keys(raw, ["runRef", "summary", "sections", "limitations", "completedAt"], ["answer", "question"])
    if _require_ref(result["runRef"]) != run_ref or not isinstance(result["completedAt"], str):
        raise ClientError("invalid_response")
    summary = _presentation_text(result["summary"], 4096)
    limitations = [_presentation_text(value, 1024) for value in _safe_list(result["limitations"], 32, 1024)]
    raw_sections = result["sections"]
    if not isinstance(raw_sections, list) or len(raw_sections) > 100:
        raise ClientError("invalid_response")
    sections: List[Dict[str, Any]] = []
    seen_media = set()
    for raw_section in raw_sections:
        section = _strict_keys(raw_section, ["title", "conclusion", "details", "evidence"])
        evidence_values = section["evidence"]
        if not isinstance(evidence_values, list) or len(evidence_values) > 32:
            raise ClientError("invalid_response")
        evidence: List[Dict[str, str]] = []
        for raw_media in evidence_values:
            media = _strict_keys(raw_media, ["mediaRef", "capability", "mediaType", "title"])
            media_ref = _require_ref(media["mediaRef"])
            if media_ref in seen_media or media["capability"] != "inspection.media.deliver" or media["mediaType"] not in MEDIA_TYPES:
                raise ClientError("invalid_response")
            seen_media.add(media_ref)
            evidence.append({
                "mediaRef": media_ref,
                "mediaType": media["mediaType"],
                "title": _presentation_text(media["title"], 256),
            })
        sections.append({
            "title": _presentation_text(section["title"], 256),
            "conclusion": _presentation_text(section["conclusion"], 4096),
            "details": [_presentation_text(value, 1024) for value in _safe_list(section["details"], 100, 1024)],
            "evidence": evidence,
        })
    answer = result.get("answer", "")
    question = result.get("question", "")
    return summary, sections, limitations, answer, question


def _result_message(summary: str, sections: Sequence[Mapping[str, Any]], limitations: Sequence[str], attachment_count: int) -> str:
    lines = [summary]
    for section in sections:
        lines.extend(section.get("details", []))
    if limitations:
        lines.extend(limitations)
    if attachment_count:
        lines.append("已附上本次巡检的现场图片。")
    return "\n".join(lines)


_OBSERVABLE_FROM_DETAIL = re.compile(r'针对“(.+)”，本次查看得到肯定结果')
_OBSERVABLE_FROM_LIMITATION = re.compile(r'当前画面不足以肯定回答“(.+)”')


def _derive_structured_result(
    sections: Sequence[Mapping[str, Any]],
    limitations: Sequence[str],
    api_answer: str = "",
    api_question: str = "",
) -> Dict[str, Any]:
    # Prefer API-provided answer/question when available (Go API v2).
    # The Go service already knows the answer from the VLM closed vocabulary
    # and the question from the spec — no regex needed.
    if api_answer:
        region = ""
        subject = ""
        for section in sections:
            title = section.get("title", "")
            parts = title.split(" · ", 1)
            if len(parts) == 2:
                region = parts[0]
                subject = parts[1]
                break
        return {
            "answer": api_answer,
            "question": api_question,
            "region": region,
            "subject": subject,
            "facts": [d for section in sections for d in section.get("details", [])],
            "limitations": list(limitations),
        }

    # Fallback: regex extraction for backward compat with older Go servers.
    has_details = any(section.get("details") for section in sections)
    has_limitations = bool(limitations)

    if has_details:
        answer_kind = "yes"
    elif has_limitations:
        answer_kind = "no"
    else:
        answer_kind = "unable"

    question = ""
    for section in sections:
        for detail in section.get("details", []):
            m = _OBSERVABLE_FROM_DETAIL.match(detail)
            if m:
                question = m.group(1)
                break
        if question:
            break
    if not question:
        for limitation in limitations:
            m = _OBSERVABLE_FROM_LIMITATION.match(limitation)
            if m:
                question = m.group(1)
                break

    region = ""
    subject = ""
    for section in sections:
        title = section.get("title", "")
        parts = title.split(" · ", 1)
        if len(parts) == 2:
            region = parts[0]
            subject = parts[1]
            break

    return {
        "answer": answer_kind,
        "question": question,
        "region": region,
        "subject": subject,
        "facts": [d for section in sections for d in section.get("details", [])],
        "limitations": list(limitations),
    }


def get_inspection_result(
    client: InspectionClient,
    *,
    run_ref: str,
    output_dir: str,
    timeout: float,
) -> Dict[str, Any]:
    run_ref = _require_ref(run_ref)
    destination = _prepare_output_dir(output_dir)
    try:
        raw_result = client.json(
            "GET",
            API_BASE + "/runs/{}/result".format(urllib.parse.quote(run_ref, safe="")),
            timeout=min(10.0, timeout),
        )
    except ClientError as error:
        if error.code == "result_not_ready":
            raise RunPending(run_ref, "巡检结果还在生成") from error
        raise
    summary, sections, limitations, api_answer, api_question = _validate_result(raw_result, run_ref)
    attachments: List[str] = []
    try:
        for section in sections:
            for media in section["evidence"]:
                attachments.append(
                    str(
                        client.media(
                            media["mediaRef"],
                            media["mediaType"],
                            destination,
                            len(attachments) + 1,
                            timeout=min(10.0, timeout),
                        )
                    )
                )
    except ClientError:
        for attachment in attachments:
            try:
                Path(attachment).unlink()
            except FileNotFoundError:
                pass
        raise
    structured = _derive_structured_result(sections, limitations, api_answer=api_answer, api_question=api_question)
    result: Dict[str, Any] = {
        "ok": True,
        "runRef": run_ref,
        "userMessage": _result_message(summary, sections, limitations, len(attachments)),
        "userMessageWithoutAttachments": _result_message(summary, sections, limitations, 0)
        + ("\n\n现场图片暂时未能发送，可以稍后重新获取。" if attachments else ""),
        "attachmentFiles": attachments,
    }
    if structured["question"]:
        result["structuredResult"] = structured
    return result


def run_inspection(
    client: InspectionClient,
    *,
    instruction: str,
    context: Sequence[str],
    output_dir: str,
    timeout: float,
    temporary_intent: Optional[Dict[str, str]] = None,
) -> Dict[str, Any]:
    if timeout < 1 or timeout > 120:
        raise ClientError("invalid_arguments")
    instruction = _business_text(instruction, 2000)
    _prepare_output_dir(output_dir)
    payload: Dict[str, Any] = {"instruction": instruction}
    if temporary_intent is not None:
        payload["temporaryIntent"] = temporary_intent
    parsed_context = _parse_context(context)
    if parsed_context:
        payload["context"] = parsed_context
    created = _strict_keys(
        client.json(
            "POST",
            API_BASE + "/requests",
            payload=payload,
            idempotency_key="wb-" + uuid.uuid4().hex,
            timeout=min(10.0, timeout),
        ),
        ["created", "run"],
    )
    if not isinstance(created["created"], bool):
        raise ClientError("invalid_response")
    run_ref, status, message = _validate_run(created["run"])
    if status in TERMINAL_FAILURE_STATUSES:
        raise RunUnavailable(run_ref, message)
    if status != "ready":
        _poll_run(client, run_ref, timeout)
    return get_inspection_result(client, run_ref=run_ref, output_dir=output_dir, timeout=timeout)


def submit_feedback(client: InspectionClient, run_ref: str, helpful: bool, comment: str, timeout: float) -> Dict[str, Any]:
    run_ref = _require_ref(run_ref)
    payload: Dict[str, Any] = {"helpful": helpful}
    if comment:
        payload["comment"] = _business_text(comment, 1000)
    raw = _strict_keys(
        client.json(
            "POST",
            API_BASE + "/runs/{}/feedback".format(urllib.parse.quote(run_ref, safe="")),
            payload=payload,
            idempotency_key="wb-feedback-" + uuid.uuid4().hex,
            timeout=timeout,
        ),
        ["created", "feedback"],
    )
    feedback = _strict_keys(raw["feedback"], ["accepted"])
    if not isinstance(raw["created"], bool) or feedback["accepted"] is not True:
        raise ClientError("invalid_response")
    return {"ok": True, "userMessage": "已收到你的反馈，谢谢。"}


def _interaction_envelope(interaction: InteractionNeeded) -> Dict[str, Any]:
    return {
        "ok": False,
        "interactionRequired": True,
        "userMessage": interaction.message,
        "interaction": {
            "actionLabel": interaction.action_label,
            "capability": interaction.capability,
            "handoffRef": interaction.handoff_ref,
        },
    }


def _pending_envelope(pending: RunPending) -> Dict[str, Any]:
    separator = "" if pending.message.endswith(("。", "！", "？")) else "。"
    return {
        "ok": False,
        "pending": True,
        "runRef": pending.run_ref,
        "userMessage": pending.message + separator + "\n\n可以稍后继续查看。",
    }


def _unavailable_envelope(unavailable: RunUnavailable) -> Dict[str, Any]:
    return {
        "ok": False,
        "runRef": unavailable.run_ref,
        "userMessage": unavailable.message,
    }


def _error_envelope(error: ClientError) -> Dict[str, Any]:
    if error.code == "skill_reload_required":
        return {
            "ok": False,
            "skillReloadRequired": True,
            "userMessage": "巡检功能已更新，本次没有执行。请重新发送刚才的巡检要求。",
        }
    messages = {
        "invalid_arguments": "没有理解这次要查看的内容，请再说清楚区域和关注的问题。",
        "timeout": "这次巡检还没有返回结果，可以稍后再试。",
        "result_not_ready": "巡检结果还在生成，可以稍后再看。",
        "run_unavailable": "这次巡检没有形成可用结果，可以调整问题后重试。",
        "connection_required": "当前会话还没有完成现场连接，请先在本机管理页面完成设置。",
        "output_directory": "现场图片暂时无法安全保存，本次没有发送图片。",
        "invalid_media": "巡检结果已返回，但现场图片未通过完整性检查，本次没有发送。",
    }
    return {"ok": False, "userMessage": messages.get(error.code, "巡检服务暂时无法完成这次请求，请稍后再试。")}


def _write_diagnostic(argv: Sequence[str], envelope: Mapping[str, Any]) -> None:
    if not DIAGNOSTIC_DIR:
        return
    try:
        log_dir = Path(DIAGNOSTIC_DIR).expanduser()
        log_dir.mkdir(mode=0o700, parents=True, exist_ok=True)
        local_files.protect(log_dir, directory=True)
        # Prune old files if over the limit.
        existing = sorted(log_dir.glob("inspection-*.json"), key=lambda p: p.stat().st_mtime)
        for stale in existing[:-(DIAGNOSTIC_MAX_FILES - 1)]:
            try:
                stale.unlink()
            except FileNotFoundError:
                pass
        timestamp = time.strftime("%Y-%m-%dT%H-%M-%S", time.localtime())
        name = "inspection-{}-{}.json".format(timestamp, uuid.uuid4().hex[:8])
        diagnostic_path = log_dir / name
        record = {
            "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "argv": list(argv),
            "envelope": envelope,
        }
        raw = json.dumps(record, ensure_ascii=False, indent=2, separators=(",", ": "))
        tmp_path = diagnostic_path.with_suffix(".tmp")
        with os.fdopen(local_files.create_file(tmp_path), "wb") as stream:
            stream.write(raw.encode("utf-8"))
            stream.flush()
            os.fsync(stream.fileno())
        local_files.replace_durable(tmp_path, diagnostic_path)
    except OSError:
        pass


def _print_envelope(envelope: Mapping[str, Any]) -> None:
    raw = json.dumps(envelope, ensure_ascii=False, separators=(",", ":"))
    if len(raw.encode("utf-8")) > MAX_OUTPUT_BYTES:
        raw = json.dumps(_error_envelope(ClientError("output_too_large")), ensure_ascii=False, separators=(",", ":"))
    print(raw)


def _configure_utf8_output() -> None:
    """The CLI emits UTF-8 JSON even when Windows redirects a legacy code page."""
    for stream in (sys.stdout, sys.stderr):
        reconfigure = getattr(stream, "reconfigure", None)
        if callable(reconfigure):
            reconfigure(encoding="utf-8", errors="strict", newline="\n")


def _common_connection_arguments(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--base-url", default=os.environ.get("COSMOEDGE_CONNECT_URL", DEFAULT_BASE_URL))
    parser.add_argument("--token-file", default=os.environ.get("COSMOEDGE_CONNECT_TOKEN_FILE", str(_default_token_file())))


def _build_parser() -> argparse.ArgumentParser:
    parser = _ArgumentParser(description="CosmoEdge inspection v2 client")
    commands = parser.add_subparsers(dest="command", required=True)

    capabilities = commands.add_parser("capabilities")
    _common_connection_arguments(capabilities)
    capabilities.add_argument("--timeout", type=float, default=5.0)

    inspect = commands.add_parser("inspect")
    _common_connection_arguments(inspect)
    inspect.add_argument("--instruction-file", required=True)
    inspect.add_argument("--context", action="append", default=[])
    inspect.add_argument("--output-dir", required=True)
    inspect.add_argument("--timeout", type=float, default=45.0)
    inspect.add_argument("--subject", default=None)
    inspect.add_argument("--region", default=None)
    inspect.add_argument("--observable", default=None)

    status = commands.add_parser("status")
    _common_connection_arguments(status)
    status.add_argument("--run-ref", required=True)
    status.add_argument("--timeout", type=float, default=10.0)

    result = commands.add_parser("result")
    _common_connection_arguments(result)
    result.add_argument("--run-ref", required=True)
    result.add_argument("--output-dir", required=True)
    result.add_argument("--timeout", type=float, default=10.0)

    feedback = commands.add_parser("feedback")
    _common_connection_arguments(feedback)
    feedback.add_argument("--run-ref", required=True)
    feedback.add_argument("--helpful", choices=("yes", "no"), required=True)
    feedback.add_argument("--comment", default="")
    feedback.add_argument("--timeout", type=float, default=10.0)
    return parser


def _reject_retired_cli(argv: Optional[Sequence[str]]) -> None:
    arguments = list(sys.argv[1:] if argv is None else argv)
    if any(argument in RETIRED_CLI_ARGUMENTS for argument in arguments):
        raise ClientError("skill_reload_required")


def main(argv: Optional[Sequence[str]] = None) -> int:
    _configure_utf8_output()
    arguments = list(sys.argv[1:] if argv is None else argv)
    if arguments and arguments[0] in {"session", "catalog", "summary", "connect", "deploy", "deployment", "capture", "observe", "observation", "confirm", "cancel", "stop", "recover-observation", "recover-deployment"}:
        from operations_client import main as operations_main
        return operations_main(arguments)
    try:
        _reject_retired_cli(argv)
        args = _build_parser().parse_args(argv)
        if args.timeout <= 0 or args.timeout > 120:
            raise ClientError("invalid_arguments")
        token = _load_token(Path(args.token_file))
        client = InspectionClient(args.base_url, token)
        if args.command == "capabilities":
            envelope = query_capabilities(client, args.timeout)
        elif args.command == "inspect":
            envelope = run_inspection(
                client,
                instruction=_load_private_instruction(Path(args.instruction_file)),
                context=args.context,
                output_dir=args.output_dir,
                timeout=args.timeout,
                temporary_intent=_parse_temporary_intent(args.subject, args.region, args.observable),
            )
        elif args.command == "status":
            envelope = query_run_status(client, args.run_ref, args.timeout)
        elif args.command == "result":
            envelope = get_inspection_result(
                client,
                run_ref=args.run_ref,
                output_dir=args.output_dir,
                timeout=args.timeout,
            )
        else:
            envelope = submit_feedback(client, args.run_ref, args.helpful == "yes", args.comment, args.timeout)
        exit_code = 0
    except InteractionNeeded as interaction:
        envelope = _interaction_envelope(interaction)
        exit_code = 2
    except RunPending as pending:
        envelope = _pending_envelope(pending)
        exit_code = 3
    except RunUnavailable as unavailable:
        envelope = _unavailable_envelope(unavailable)
        exit_code = 4
    except ClientError as error:
        envelope = _error_envelope(error)
        exit_code = 1
    except (KeyboardInterrupt, Exception):
        envelope = _error_envelope(ClientError("internal_error"))
        exit_code = 1
    captured_argv = list(sys.argv[1:] if argv is None else argv)
    _write_diagnostic(captured_argv, envelope)
    _print_envelope(envelope)
    return exit_code


if __name__ == "__main__":
    raise SystemExit(main())
