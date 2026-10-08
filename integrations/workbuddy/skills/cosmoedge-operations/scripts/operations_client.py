"""Paired CosmoEdge Connect client. One deadline; no replay of business writes."""
from __future__ import annotations
import argparse
import datetime as dt
import hashlib
import hmac
import http.client
import json
import math
import os
from pathlib import Path, PurePosixPath
import re
import socket
import stat
import sys
import tempfile
import threading
import time
import urllib.parse
import uuid
import cosmoedge_operations as transport
import local_files

PREFIX = "/operations/v1/"
COMMANDS = {"session", "catalog", "summary", "connect", "deploy", "deployment", "capture", "observe", "observation", "confirm", "cancel", "stop", "recover-observation", "recover-deployment"}
REFERENCE = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,127}\Z")
SESSION = re.compile(r"[0-9a-f]{32}\.[0-9]+\.[0-9a-f]{64}\Z")
MAX_JSON_BYTES = 512 * 1024
MAX_REPORT_BYTES = 256 * 1024
MAX_REPORT_PROVENANCE_BYTES = 4096
REPORT_FILE_NAME = "统计报告.md"
REPORT_PROVENANCE_NAME = "report-provenance.json"
HISTORY_CAPABILITY_BOUNDARY = "现有工具可查询指定时窗的留存告警，但不能追溯事件原因或过去启停；现在看图、部署、停用和当前状态查询也不能补证过去。"


class Parser(argparse.ArgumentParser):
    def error(self, message):
        raise transport.ClientError("invalid_arguments")


def strict_json(raw):
    def pairs(items):
        result = {}
        for key, value in items:
            if key in result:
                raise ValueError("duplicate JSON key")
            result[key] = value
        return result
    return json.loads(raw, object_pairs_hook=pairs,
                      parse_constant=lambda value: (_ for _ in ()).throw(ValueError("non-finite JSON value")))


def secure_read(path, limit, private=False, error_code="invalid_arguments"):
    """Pin the checked inode before reading; never follow a final-component link."""
    try:
        before = path.lstat()
        forbidden_mode = 0o077 if private else 0o022
        if not stat.S_ISREG(before.st_mode) or (not local_files.WINDOWS and before.st_mode & forbidden_mode) or before.st_size > limit:
            raise ValueError("unsafe file")
        if hasattr(os, "getuid") and before.st_uid != os.getuid():
            raise ValueError("foreign file")
        descriptor = local_files.open_read(path)
        with os.fdopen(descriptor, "rb") as stream:
            opened = os.fstat(stream.fileno())
            if (opened.st_dev, opened.st_ino, opened.st_mode, opened.st_uid) != (before.st_dev, before.st_ino, before.st_mode, before.st_uid):
                raise ValueError("changed file")
            raw = stream.read(limit + 1)
            after = os.fstat(stream.fileno())
            if local_files.WINDOWS:
                local_files.validate(path, descriptor=stream.fileno())
        final = path.lstat()
        identity = lambda value: (value.st_dev, value.st_ino, value.st_size, value.st_mtime_ns, value.st_ctime_ns)
        # On Windows Python lstat reports creation time in st_ctime while
        # fstat may report the metadata change time. Compare change times only
        # between the pinned descriptor's two observations on that platform.
        final_identity = lambda value: identity(value)[:-1] if local_files.WINDOWS else identity(value)
        if len(raw) > limit or identity(opened) != identity(after) or final_identity(after) != final_identity(final):
            raise ValueError("changed file")
        return raw
    except (OSError, ValueError):
        raise transport.ClientError(error_code) from None


def paired_path(root, relative):
    if not isinstance(relative, str):
        raise transport.ClientError("version_mismatch")
    parsed = PurePosixPath(relative)
    if parsed.is_absolute() or not relative or str(parsed) != relative or any(p in (".", "..") for p in parsed.parts):
        raise transport.ClientError("version_mismatch")
    path = root
    for part in parsed.parts:
        path = path / part
        if path.is_symlink() or (local_files.WINDOWS and path.lstat().st_file_attributes & 0x400):
            raise transport.ClientError("version_mismatch")
    return path


def operation_kind(command):
    if command in ("deploy", "deployment", "stop", "confirm", "cancel", "recover-deployment"):
        return "deployment"
    if command in ("capture", "observe", "observation", "recover-observation"):
        return "observation"
    return None


class Client:
    def __init__(self, base, token, session_ref="", deadline=None):
        self.base = transport._normalize_base_url(base)
        self.token = token
        self.session_ref = session_ref
        self.deadline = deadline if deadline is not None else time.monotonic() + 55
        self.paired_identity = None

    def remaining(self):
        value = self.deadline - time.monotonic()
        if value <= 0:
            raise TimeoutError("client deadline reached")
        return value

    def read(self, path, body=None, timeout=55, limit=MAX_JSON_BYTES):
        if not isinstance(path, str) or not re.fullmatch(r"/operations/v1/[A-Za-z0-9_./-]+", path) or any(part in (".", "..") for part in path.split("/")):
            raise transport.ClientError("invalid_arguments")
        # HTTPConnection goes directly to the normalized literal loopback endpoint:
        # no environment proxies, redirects, shell command, or ambient credentials.
        url = urllib.parse.urlsplit(self.base)
        end = min(self.deadline, time.monotonic() + timeout)
        connection = http.client.HTTPConnection(url.hostname, url.port or 80, timeout=min(timeout, self.remaining()))
        headers = {"Authorization": "Bearer " + self.token, "X-CosmoEdge-Session": self.session_ref}
        encoded = None
        if body is not None:
            headers["Content-Type"] = "application/json"
            encoded = json.dumps(body, ensure_ascii=False, allow_nan=False).encode("utf-8")
        deadline_timer = None
        try:
            connection.connect()
            active_socket = connection.sock
            def expire():
                try:
                    active_socket.shutdown(socket.SHUT_RDWR)
                except OSError:
                    pass
            deadline_timer = threading.Timer(max(0.001, end - time.monotonic()), expire)
            deadline_timer.daemon = True
            deadline_timer.start()
            connection.sock.settimeout(max(0.001, min(end - time.monotonic(), self.remaining())))
            connection.request("POST" if body is not None else "GET", path, body=encoded, headers=headers)
            response = connection.getresponse()
            raw = bytearray()
            while True:
                remaining = min(end - time.monotonic(), self.remaining())
                if remaining <= 0:
                    raise TimeoutError("request deadline reached")
                # read1 returns available bytes; re-arm an absolute remaining budget
                # between chunks so a trickling response cannot extend the deadline.
                if connection.sock is not None:
                    connection.sock.settimeout(remaining)
                chunk = response.read1(min(65536, limit + 1 - len(raw)))
                # Our deadline timer can end a blocked read with EOF instead of
                # a socket timeout. Do not treat that partial body as complete.
                if time.monotonic() >= end:
                    raise TimeoutError("request deadline reached")
                if not chunk:
                    break
                raw.extend(chunk)
                if len(raw) > limit:
                    raise transport.ClientError("invalid_response")
            return response.status, response.getheader("Content-Type", "").split(";", 1)[0].strip().lower(), bytes(raw)
        except http.client.HTTPException:
            # shutdown() can wake getresponse/read1 as RemoteDisconnected or a
            # parser error. It is the same timeout regardless of which thread
            # wins the race with the socket timeout.
            if time.monotonic() >= end:
                raise TimeoutError("request deadline reached") from None
            raise transport.ClientError("invalid_response") from None
        finally:
            if deadline_timer is not None:
                deadline_timer.cancel()
            connection.close()

    def request(self, path, body=None, timeout=55):
        status, mime, raw = self.read(path, body, timeout)
        try:
            data = strict_json(raw)
        except (ValueError, UnicodeError):
            raise transport.ClientError("invalid_response") from None
        if mime != "application/json" or not isinstance(data, dict) or not isinstance(data.get("ok"), bool):
            raise transport.ClientError("invalid_response")
        if 300 <= status < 400 or status < 200 or status >= 600 or (status >= 400 and data["ok"]):
            raise transport.ClientError("invalid_response")
        return data

    def verify_pairing(self, allow_unpaired_development=False):
        root = Path(__file__).resolve().parent.parent
        candidate_path = root / "candidate.json"
        if not candidate_path.exists() and not candidate_path.is_symlink():
            repository = root.parents[3] if len(root.parents) >= 4 else None
            expected_suffix = ("integrations", "workbuddy", "skills", "cosmoedge-operations")
            if allow_unpaired_development and tuple(root.parts[-4:]) == expected_suffix and repository and (repository / ".git").exists():
                return
            raise transport.ClientError("version_mismatch")
        try:
            candidate = strict_json(secure_read(candidate_path, 65536, error_code="version_mismatch"))
            if not isinstance(candidate, dict) or candidate.get("schemaVersion") != 1:
                raise ValueError("candidate schema")
            clients = candidate.get("clientFiles")
            if not isinstance(clients, dict) or not clients or set(clients) != {
                    p.relative_to(root).as_posix() for p in (root / "scripts").rglob("*.py")}:
                raise ValueError("client inventory")
            if not {"scripts/operations_client.py", "scripts/cosmoedge_operations.py"}.issubset(clients):
                raise ValueError("client inventory")
            for relative, expected in clients.items():
                if not isinstance(expected, str) or not re.fullmatch(r"[0-9a-f]{64}", expected):
                    raise ValueError("client digest")
                path = paired_path(root, relative)
                raw = secure_read(path, 4 * 1024 * 1024, error_code="version_mismatch")
                if not hmac.compare_digest(hashlib.sha256(raw).hexdigest(), expected):
                    raise ValueError("client digest")
            if not isinstance(candidate.get("modified"), bool) or not re.fullmatch(r"[0-9a-f]{40,64}", candidate.get("revision", "")):
                raise ValueError("source identity")
            if not isinstance(candidate.get("version"), str) or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]{0,79}", candidate["version"]):
                raise ValueError("candidate version")
            if not isinstance(candidate.get("platform"), str) or not re.fullmatch(r"[a-z0-9]+/[a-z0-9]+", candidate["platform"]):
                raise ValueError("candidate platform")
        except (ValueError, TypeError, OSError):
            raise transport.ClientError("version_mismatch") from None
        actual = self.request(PREFIX + "version")
        if actual.get("ok") is not True or actual.get("protocol") != "cosmoedge.operations.v1" or not isinstance(actual.get("version"), dict) or actual["version"].get("product") != "cosmoedge-connect":
            raise transport.ClientError("version_mismatch")
        for key in ("version", "revision", "modified", "platform"):
            if actual["version"].get(key) != candidate.get(key):
                raise transport.ClientError("version_mismatch")
        self.paired_identity = dict(product="cosmoedge-connect", **{
            key: candidate[key] for key in ("version", "revision", "modified", "platform")})

    def summary_report(self, result, source_name="", algorithm_name=""):
        """Prepare original report bytes; never claim native host delivery.

        Keep computed facts available to the host independently of preparing
        the original report. Neither a download nor this response claims delivery.
        """
        if result.get("ok") is not True:
            return result
        summary = result.get("summary", {})
        context = {key: summary[key] for key in (
            "window", "timeZone", "coverage",
            "sourceKindScope", "sourceKindBasis") if isinstance(summary, dict) and key in summary}
        context["filters"] = {"sourceName": source_name, "algorithmName": algorithm_name}
        compact = {key: value for key, value in result.items() if key not in (
            "summaryReport", "headline", "userMessage", "attachments",
            "attachmentFiles", "attachmentFailures", "clientInstruction")}
        compact.update(summaryContext=context, attachmentFiles=[],
                       historyCapabilityBoundary=HISTORY_CAPABILITY_BOUNDARY)
        delivery = {"state": "unavailable", "code": "report_metadata_unavailable"}
        headline = "已取得统计结果。"
        try:
            report, content = self.verified_summary_report(result)
            headline = report["headline"]
            context["filters"] = dict(report["filters"])
            delivery.update({key: report[key] for key in ("sha256", "sizeBytes", "contentType")})
            delivery["candidate"] = dict(self.paired_identity)
            path = save_summary_report(content, self.paired_identity)
            compact["attachmentFiles"] = [str(path)]
            delivery.update(state="ready", code="report_ready")
        except transport.ClientError as error:
            delivery["code"] = error.code
        delivery["userMessage"] = ("统计报告原件已准备，尚未交付。" if delivery["state"] == "ready"
                                   else "统计报告原件未能准备，本次未交付报告。")
        compact["userMessage"] = headline
        if delivery["state"] != "ready":
            compact["userMessage"] += "统计已取得，但报告文件暂时无法提供。"
        coverage = context.get("coverage")
        if result.get("partial") is True or not isinstance(coverage, dict) or coverage.get("retrievalComplete") is not True:
            compact["userMessage"] += "本次记录未读取完整。"
        compact["reportDelivery"] = delivery
        compact["clientInstruction"] = (
            "根据 summary、peak 和 summaryEvidence 回答用户所问的重点，可沿用 summaryContext 追问。"
            "数值与分组已由服务计算；只提示影响本次结论的数据缺失，不推断未提供的历史原因。"
            "通过 WorkBuddy 原生 present_files 交付 attachmentFiles 原路径，cwd 用当前任务目录。"
            "文件准备或交付失败不改变已有统计事实；原件重发复用原路径，不重新查询。"
        )
        return compact

    def verified_summary_report(self, result):
        report = result.get("summaryReport")
        if report is None:
            raise transport.ClientError("report_metadata_unavailable")
        message = result.get("userMessage")
        if (not isinstance(report, dict) or type(report.get("schemaVersion")) is not int
                or report["schemaVersion"] != 1 or report.get("contentType") != "text/markdown; charset=utf-8"
                or not isinstance(message, str) or not message
                or type(report.get("sizeBytes")) is not int or not 0 < report["sizeBytes"] <= MAX_REPORT_BYTES
                or not isinstance(report.get("sha256"), str) or not re.fullmatch(r"[0-9a-f]{64}", report["sha256"])
                or not isinstance(report.get("headline"), str) or not report["headline"]
                or len(report["headline"]) > 4096
                or not isinstance(report.get("filters"), dict)
                or set(report["filters"]) != {"sourceName", "algorithmName"}
                or any(not isinstance(value, str) for value in report["filters"].values())):
            raise transport.ClientError("report_metadata_invalid")
        try:
            content = message.encode("utf-8")
        except UnicodeError:
            raise transport.ClientError("report_metadata_invalid") from None
        if (len(content) != report["sizeBytes"]
                or not hmac.compare_digest(hashlib.sha256(content).hexdigest(), report["sha256"])):
            raise transport.ClientError("report_integrity_mismatch")
        if self.paired_identity is None:
            raise transport.ClientError("report_candidate_unverified")
        candidate = report.get("candidate")
        if not isinstance(candidate, dict) or any(
                type(candidate.get(key)) is not type(value) or candidate[key] != value
                for key, value in self.paired_identity.items()):
            raise transport.ClientError("report_candidate_mismatch")
        return report, content

    def attachments(self, result):
        attachments = result.get("attachments", [])
        if not isinstance(attachments, list):
            raise transport.ClientError("invalid_response")
        if not attachments:
            return result
        files, failures = [], []
        directory = local_files.private_tempdir(prefix="cosmoedge-evidence-")
        for index, item in enumerate(attachments[:8]):
            target = None
            try:
                if not isinstance(item, dict):
                    raise ValueError("media item")
                path = item["path"]
                if not isinstance(path, str) or not re.fullmatch(r"/operations/v1/media/[A-Za-z0-9][A-Za-z0-9._-]*", path):
                    raise ValueError("media path")
                mime = item["contentType"]
                if mime not in transport.MEDIA_TYPES:
                    raise ValueError("media type")
                extension, magic = transport.MEDIA_TYPES[mime]
                status, actual_mime, content = self.read(path, timeout=10, limit=transport.MAX_MEDIA_BYTES)
                if status != 200 or actual_mime != mime or not content.startswith(magic):
                    raise ValueError("media content")
                if not isinstance(item["sha256"], str) or not hmac.compare_digest(hashlib.sha256(content).hexdigest(), item["sha256"]):
                    raise ValueError("media digest")
                target = directory / ("现场图片-%02d" % (index + 1) + extension)
                descriptor = local_files.create_file(target)
                with os.fdopen(descriptor, "wb") as stream:
                    stream.write(content)
                    stream.flush()
                    os.fsync(stream.fileno())
                files.append(str(target))
            except (transport.ClientError, OSError, ValueError, KeyError, TypeError):
                if target and target.exists():
                    target.unlink()
                failures.append({"index": index + 1, "reason": "图片暂时无法取得"})
        if len(attachments) > 8:
            failures.append({"fromIndex": 9, "count": len(attachments) - 8, "reason": "本次最多获取8张图片，其余图片未下载"})
        result["attachmentFiles"] = files
        result["attachmentFailures"] = failures
        if files:
            # Download verification cannot establish delivery in the host UI.
            observation = result.get("observation", {})
            capture = isinstance(observation, dict) and observation.get("kind") == "capture"
            analysis = (
                "这是抓图结果。用 Read 实际读取原图后，结合用户问题进行多模态分析；"
                "直接描述可见内容，画面不足时说明看不清。"
                if capture else
                "这是盒端分析结果，保留 observation.answer、facts、limitations 的含义；"
                "宿主另行看图的意见要与盒端结果区分。"
            )
            result["clientInstruction"] = (
                "attachmentFiles 是已校验的原图。调用 WorkBuddy 原生 Read 读取，再用原生 present_files "
                "交付原路径（cwd 为当前任务目录）；按实际工具回执说明图片是否已展示。"
                + analysis + "来源及时间以 observation 为准。原图追问沿用同一操作，不重新抓图。"
            )
        else:
            result["clientInstruction"] = (
                "原图暂时无法取得。保留已有结果；无法实际读取图像时不作新的视觉判断。"
                "原图续取使用同一 observation，不重新抓图。"
            )
        if failures:
            result["partial"] = True
            original = result.get("userMessage", "")
            result["userMessage"] = (original if isinstance(original, str) else "") + "部分图片未能取得，已保留可用图片和文字结果。"
        if not files:
            directory.rmdir()
        return result


def save_summary_report(content, candidate):
    """Publish original bytes and provenance together before exposing readiness.

    Both final names are exclusive, with only complete fsynced files linked into
    the new private directory. No attachment path escapes until both readbacks
    match; a failure removes only files this invocation successfully created.
    """
    directory = None
    owned = set()
    try:
        provenance = dict(schemaVersion=1, kind="cosmoedge_summary_report", reportFile=REPORT_FILE_NAME,
                          sha256=hashlib.sha256(content).hexdigest(), sizeBytes=len(content),
                          contentType="text/markdown; charset=utf-8", candidate=dict(candidate))
        metadata = json.dumps(provenance, ensure_ascii=False, allow_nan=False, separators=(",", ":")).encode("utf-8")
        if not 0 < len(content) <= MAX_REPORT_BYTES or len(metadata) > MAX_REPORT_PROVENANCE_BYTES:
            raise ValueError("report bounds")
        directory = local_files.private_tempdir(prefix="cosmoedge-summary-")
        files = [(directory / ".report.tmp", directory / REPORT_FILE_NAME, content, MAX_REPORT_BYTES),
                 (directory / ".provenance.tmp", directory / REPORT_PROVENANCE_NAME, metadata, MAX_REPORT_PROVENANCE_BYTES)]
        for staging, _, raw, _ in files:
            descriptor = local_files.create_file(staging)
            owned.add(staging)
            with os.fdopen(descriptor, "wb") as stream:
                local_files.protect_descriptor(stream.fileno())
                stream.write(raw)
                stream.flush()
                os.fsync(stream.fileno())
        for staging, target, _, _ in files:
            # Exclusive publication: never replace a collided destination.
            local_files.publish_exclusive(staging, target)
            owned.add(target)
            if not local_files.WINDOWS:
                staging.unlink()
            owned.remove(staging)
        for _, target, raw, limit in files:
            if secure_read(target, limit, private=True, error_code="report_save_failed") != raw:
                raise transport.ClientError("report_save_failed")
            local_files.validate(target)
        local_files.sync_directory(directory, private=True)
        return directory / REPORT_FILE_NAME
    except (OSError, ValueError, TypeError, transport.ClientError):
        for path in owned:
            try:
                path.unlink()
            except OSError:
                pass
        if directory:
            try:
                directory.rmdir()
            except OSError:
                pass
        raise transport.ClientError("report_save_failed") from None


def save_deployment_receipt(result, candidate):
    """Retain the validated final receipt without changing the operation result."""
    directory, path, owned = None, None, False
    try:
        document = {"schemaVersion": 1, "kind": "cosmoedge_deployment_receipt",
                    "candidate": candidate, "receipt": result}
        raw = json.dumps(document, ensure_ascii=False, allow_nan=False,
                         separators=(",", ":")).encode("utf-8")
        limit = MAX_JSON_BYTES + 64 * 1024
        if len(raw) > limit:
            raise ValueError("receipt bounds")
        directory = local_files.private_tempdir(prefix="cosmoedge-deployment-")
        path = directory / "receipt.json"
        descriptor = local_files.create_file(path)
        owned = True
        with os.fdopen(descriptor, "wb") as stream:
            local_files.protect_descriptor(stream.fileno())
            stream.write(raw)
            stream.flush()
            os.fsync(stream.fileno())
        if secure_read(path, limit, private=True, error_code="details_save_failed") != raw:
            raise ValueError("receipt readback")
        local_files.validate(path)
        return {"state": "ready", "path": str(path), "sha256": hashlib.sha256(raw).hexdigest(), "sizeBytes": len(raw)}
    except (OSError, ValueError, TypeError, transport.ClientError):
        if owned:
            try:
                path.unlink()
            except OSError:
                pass
        if directory:
            try:
                directory.rmdir()
            except OSError:
                pass
        return {"state": "unavailable", "code": "details_save_failed"}


def deployment_output(result, candidate):
    """Compact only the final host output, after binding and bounded polling."""
    compact = {key: value for key, value in result.items()
               if key not in ("deployment", "proposal", "configurationRequirement", "deploymentEvidence")}

    def observed_time(value, key):
        raw = value.get(key) if isinstance(value, dict) else None
        try:
            parsed = dt.datetime.fromisoformat(raw.replace("Z", "+00:00"))
            return raw if parsed.tzinfo is not None and parsed.year > 1 else None
        except (AttributeError, ValueError, TypeError):
            return None

    status = result.get("deployment")
    if isinstance(status, dict):
        facts = {key: status[key] for key in ("state", "class") if key in status}
        target = status.get("target")
        if isinstance(target, dict):
            facts.update({key: target[key] for key in ("sourceName", "algorithmName") if key in target})
        original = status.get("originalVerification")
        for key, name in (("observedAt", "originalObservedAt"), ("sealedAt", "originalSealedAt")):
            stamp = observed_time(original, key)
            if stamp:
                facts[name] = stamp
        current_time = observed_time(status.get("current"), "observedAt")
        fresh = not result.get("unknown") and not result.get("currentReadUnavailable")
        facts["currentReadbackAvailable"] = bool(current_time and fresh)
        if current_time:
            facts["currentObservedAt" if fresh else "lastKnownObservedAt"] = current_time
        compact["deployment"] = facts
    for key in ("proposal", "configurationRequirement"):
        value = result.get(key)
        if isinstance(value, dict):
            fields = ("state", "sourceName", "algorithmName", "enabled", "expiresAt") if key == "proposal" else ("state", "sourceName", "algorithmName", "missing")
            compact[key] = {name: value[name] for name in fields if name in value}
    compact["deploymentDetails"] = save_deployment_receipt(result, candidate)
    return compact


def parser():
    p = Parser(add_help=True)
    p.add_argument("command", choices=sorted(COMMANDS))
    transport._common_connection_arguments(p)
    p.add_argument("--session-ref", default=None)
    p.add_argument("--request-file")
    p.add_argument("--source", default="")
    p.add_argument("--sources", nargs="+", help="summary: select these camera names together")
    p.add_argument("--source-ref", default="")
    p.add_argument("--algorithm", default="")
    p.add_argument("--start")
    p.add_argument("--end")
    p.add_argument("--time-zone", default="Asia/Shanghai")
    p.add_argument("--request-id")
    p.add_argument("--operation-ref")
    p.add_argument("--confirmation-token")
    p.add_argument("--question")
    p.add_argument("--subject")
    p.add_argument("--wait-seconds", type=float, default=None,
                   help="polling budget: new observe defaults to 0 seconds; other commands default to 45")
    p.add_argument("--timeout", type=float, default=55, help="total network, polling and attachment deadline (seconds)")
    p.add_argument("--allow-unpaired-development", action="store_true", help=argparse.SUPPRESS)
    return p


def date_value(raw, zone):
    from zoneinfo import ZoneInfo, ZoneInfoNotFoundError
    value = dt.datetime.fromisoformat(raw.replace("Z", "+00:00"))
    if value.tzinfo is None:
        try:
            timezone = ZoneInfo(zone)
        except ZoneInfoNotFoundError:
            # Windows may have no IANA database. China has used UTC+08 without
            # DST since 1992. Do not invent offsets for older dates or zones.
            if zone == "Asia/Shanghai" and value.year >= 1992:
                timezone = dt.timezone(dt.timedelta(hours=8))
            elif zone in ("UTC", "Etc/UTC"):
                timezone = dt.timezone.utc
            else:
                raise transport.ClientError("invalid_arguments") from None
        value = value.replace(tzinfo=timezone)
    return value.isoformat()


def apply_request_file(args):
    if not args.request_file:
        return
    try:
        raw = secure_read(Path(args.request_file), 16384, private=True)
        payload = strict_json(raw)
    except (ValueError, UnicodeError):
        raise transport.ClientError("invalid_arguments") from None
    mapping = {"sessionRef": "session_ref", "sourceName": "source", "sourceNames": "sources", "sourceRef": "source_ref", "algorithmName": "algorithm",
               "start": "start", "end": "end", "timeZone": "time_zone",
               "requestId": "request_id", "operationRef": "operation_ref", "confirmationToken": "confirmation_token",
               "question": "question", "subject": "subject", "waitSeconds": "wait_seconds",
               "operationKind": "_saved_operation_kind"}
    if not isinstance(payload, dict) or set(payload) - set(mapping):
        raise transport.ClientError("invalid_arguments")
    if "sourceNames" in payload and "sourceName" in payload:
        raise transport.ClientError("invalid_arguments")
    for key, value in payload.items():
        if key == "sourceNames":
            if not valid_source_names(value):
                raise transport.ClientError("invalid_arguments")
            continue
        if key == "waitSeconds":
            if type(value) not in (int, float) or not math.isfinite(value) or not 0 <= value <= 55:
                raise transport.ClientError("invalid_arguments")
            continue
        if not isinstance(value, str) or len(value) > 2000 or "\x00" in value:
            raise transport.ClientError("invalid_arguments")
    if "operationKind" in payload and payload["operationKind"] not in ("observation", "deployment"):
        raise transport.ClientError("invalid_arguments")
    # A saved recovery binding cannot be moved to another conversation or ID
    # through command-line overrides. The original request file stays authoritative.
    for key, name in (("sessionRef", "session_ref"), ("requestId", "request_id")):
        explicit = getattr(args, name)
        supplied = explicit is not None if name == "session_ref" else bool(explicit)
        if key in payload and supplied and explicit != payload[key]:
            raise transport.ClientError("request_binding_conflict")
    recovering = args.command.startswith("recover-")
    if recovering and (payload.get("operationKind") != operation_kind(args.command)
                       or not payload.get("sessionRef") or not payload.get("requestId")
                       or args.operation_ref or args.confirmation_token is not None):
        raise transport.ClientError("request_recovery_required")
    for key, value in payload.items():
        if recovering and key not in ("sessionRef", "requestId", "operationKind", "waitSeconds"):
            continue
        setattr(args, mapping[key], value)
    args._request_raw, args._request_payload = raw, payload


def persist_request(args):
    """Publish an immutable recovery binding before transport, not an ACK.

    A durable marker consumes this request file for submission even if the
    process dies before POST. Future invocations may only recover by request ID.
    The sibling flock serializes cooperating clients across atomic replacement;
    checked original bytes prevent overwriting a concurrently edited request.
    """
    if args.command not in ("deploy", "stop", "capture", "observe") or not args.request_file:
        return
    if "operationKind" in args._request_payload:
        raise transport.ClientError("request_recovery_required")
    path = Path(args.request_file).absolute()
    lock_fd, temporary = None, None
    try:
        lock_fd = local_files.create_file(str(path) + ".cosmoedge-connect.lock", existing=True)
        local_files.validate(str(path) + ".cosmoedge-connect.lock", descriptor=lock_fd)
        local_files.lock_exclusive(lock_fd)
        if secure_read(path, 16384, private=True) != args._request_raw:
            raise ValueError("changed request")
        payload = dict(args._request_payload, sessionRef=args.session_ref, requestId=args.request_id,
                       operationKind=operation_kind(args.command))
        raw = json.dumps(payload, ensure_ascii=False, allow_nan=False, separators=(",", ":")).encode("utf-8")
        if len(raw) > 16384:
            raise ValueError("request too large")
        descriptor, temporary = local_files.private_tempfile(prefix=".cosmoedge-request-", directory=path.parent)
        with os.fdopen(descriptor, "wb") as stream:
            local_files.protect_descriptor(stream.fileno())
            stream.write(raw)
            stream.flush()
            os.fsync(stream.fileno())
        if secure_read(path, 16384, private=True) != args._request_raw:
            raise ValueError("changed request")
        local_files.replace_durable(temporary, path)
        temporary = None
        local_files.sync_directory(path.parent)
    except (OSError, ValueError, transport.ClientError):
        raise transport.ClientError("request_persistence_failed") from None
    finally:
        if temporary is not None:
            os.unlink(temporary)
        if lock_fd is not None:
            os.close(lock_fd)


def valid_source_names(value):
    return (isinstance(value, list) and bool(value)
            and all(isinstance(name, str) and name.strip() and len(name) <= 2000 and "\x00" not in name
                    for name in value))


def validate_args(args):
    # Resolve only an omitted wait after JSON overrides have been applied.
    # A new observation exposes its real first receipt; read-only continuations
    # and other commands retain their existing bounded waiting behavior.
    if args.wait_seconds is None:
        args.wait_seconds = 0 if args.command == "observe" else 45
    if not math.isfinite(args.wait_seconds) or not 0 <= args.wait_seconds <= 55 or not math.isfinite(args.timeout) or not 0.05 <= args.timeout <= 60:
        raise transport.ClientError("invalid_arguments")
    if args.session_ref is None:
        if args.command not in ("session", "connect"):
            raise transport.ClientError("session_required")
        args.session_ref = ""
    elif not SESSION.fullmatch(args.session_ref):
        raise transport.ClientError("session_required")
    # Proposal creation and confirmation are separate commands. Reject the
    # mixed request before loading credentials or making even a pairing read;
    # never infer user confirmation or silently dispatch a different command.
    if args.command in ("deploy", "stop") and (args.operation_ref is not None or args.confirmation_token is not None):
        raise transport.ClientError("confirmation_command_required")
    if args.confirmation_token is not None:
        raise transport.ClientError("local_confirmation_required")
    for name in ("source", "algorithm", "question", "subject", "confirmation_token", "time_zone"):
        value = getattr(args, name)
        if value is not None and (not isinstance(value, str) or len(value) > 2000 or "\x00" in value):
            raise transport.ClientError("invalid_arguments")
    if args.sources is not None and (args.command != "summary" or args.source or not valid_source_names(args.sources)):
        raise transport.ClientError("invalid_arguments")
    if args.request_id and not REFERENCE.fullmatch(args.request_id):
        raise transport.ClientError("invalid_request_id")
    if args.operation_ref and not REFERENCE.fullmatch(args.operation_ref):
        raise transport.ClientError("invalid_arguments")
    if args.source_ref and (args.command not in ("capture", "observe") or not re.fullmatch(r"source_[0-9a-f]{24}", args.source_ref)):
        raise transport.ClientError("invalid_arguments")
    if args.command in ("deployment", "observation") and bool(args.operation_ref) == bool(args.request_id):
        raise transport.ClientError("query_reference_required")
    if args.command in ("confirm", "cancel") and (not args.operation_ref or args.request_id or args.source or args.algorithm or args.question or args.subject):
        raise transport.ClientError("invalid_arguments")
    if args.command.startswith("recover-") and (not args.request_file or not args.request_id):
        raise transport.ClientError("request_recovery_required")
    if args.command in ("deploy", "stop", "capture", "observe"):
        args.request_id = args.request_id or uuid.uuid4().hex
    if args.command == "observe" and (not args.question or not args.subject):
        raise transport.ClientError("invalid_arguments")
    if args.command == "summary":
        if not args.start or not args.end:
            raise transport.ClientError("invalid_arguments")
        try:
            args.start, args.end = date_value(args.start, args.time_zone), date_value(args.end, args.time_zone)
        except (ValueError, KeyError):
            raise transport.ClientError("invalid_arguments") from None


def execute(args, client):
    command = args.command
    if command == "session":
        return client.request(PREFIX + "session", {})
    if command == "catalog":
        return client.request(PREFIX + "catalog")
    if command == "connect":
        if not args.session_ref:
            # Pairing has already passed. Use this same client/deadline for both
            # requests, and retain the new conversation identity if opening fails.
            session_args = argparse.Namespace(**vars(args))
            session_args.command = "session"
            created = bind_result(client.request(PREFIX + "session", {}), session_args)
            if not created.get("ok"):
                return created
            args.session_ref = client.session_ref = created["sessionRef"]
            server_time = created.get("serverTime")
            if isinstance(server_time, str):
                try:
                    if dt.datetime.fromisoformat(server_time.replace("Z", "+00:00")).utcoffset() is not None:
                        args._connection_server_time = server_time
                except ValueError:
                    pass
        return client.request(PREFIX + "connection", {})
    if command == "summary":
        payload = {"start": args.start, "end": args.end, "timeZone": args.time_zone, "algorithmName": args.algorithm}
        payload.update({"sourceNames": args.sources} if args.sources is not None else {"sourceName": args.source})
        return client.request(PREFIX + "summary", payload)
    if command in ("deployment", "observation", "recover-deployment", "recover-observation"):
        suffix = args.operation_ref if args.operation_ref else "by-request/" + args.request_id
        return client.request(PREFIX + operation_kind(command) + "s/" + suffix)
    if command in ("deploy", "stop"):
        args._submitted = True
        return client.request(PREFIX + "deployments", {"requestId": args.request_id, "sourceName": args.source,
            "algorithmName": args.algorithm, "enabled": command == "deploy"})
    if command in ("confirm", "cancel"):
        args._submitted = True
        path = "deployments/review" if command == "confirm" else "deployments/cancel"
        return client.request(PREFIX + path, {"operationRef": args.operation_ref})
    if command in ("capture", "observe"):
        args._submitted = True
        payload = {"requestId": args.request_id, "sourceName": args.source,
            "question": args.question}
        if command == "observe":
            payload["subject"] = args.subject
        if args.source_ref:
            payload["sourceRef"] = args.source_ref
        return client.request(PREFIX + ("captures" if command == "capture" else "observations"), payload)
    raise transport.ClientError("invalid_arguments")


def bind_result(result, args):
    kind = operation_kind(args.command)
    for name, expected in (("requestId", args.request_id), ("operationRef", args.operation_ref)):
        actual = result.get(name)
        if actual is not None and (not isinstance(actual, str) or not REFERENCE.fullmatch(actual) or (expected and actual != expected)):
            raise transport.ClientError("invalid_response")
    if args.command == "session" and result.get("ok") and (not isinstance(result.get("sessionRef"), str) or not SESSION.fullmatch(result["sessionRef"])):
        raise transport.ClientError("invalid_response")
    if result.get("sessionRef") is not None and args.command != "session" and result["sessionRef"] != args.session_ref:
        raise transport.ClientError("invalid_response")
    if args.command == "connect" and result.get("ok") is True and (
            result.get("interactionRequired") is not True or result.get("pageState") != "dispatched"
            or result.get("supportedInteraction") != "connection_only"):
        raise transport.ClientError("invalid_response")
    pending_values = [result]
    while pending_values:
        value = pending_values.pop()
        if isinstance(value, dict):
            if "confirmationToken" in value or "confirmationReceipt" in value:
                raise transport.ClientError("invalid_response")
            pending_values.extend(value.values())
        elif isinstance(value, list):
            pending_values.extend(value)
    if any(key in result and not isinstance(result[key], bool) for key in ("pending", "partial", "interactionRequired", "pageOpened")):
        raise transport.ClientError("invalid_response")
    if args.command == "confirm" and result.get("pageOpened") is True and (
            result.get("ok") is not True or result.get("interactionRequired") is not True
            or result.get("confirmationMode") != "local_page"
            or result.get("supportedInteraction") != "deployment_confirmation"):
        raise transport.ClientError("invalid_response")
    path = result.get("pollPath")
    if path:
        prefix = PREFIX + (kind + "s/" if kind else "")
        ref = path[len(prefix):] if isinstance(path, str) and path.startswith(prefix) else ""
        if not kind or not REFERENCE.fullmatch(ref) or (result.get("operationRef") and result["operationRef"] != ref) or (args.operation_ref and args.operation_ref != ref):
            raise transport.ClientError("invalid_response")
        result["operationRef"] = ref
    if result.get("operationRef"):
        args.operation_ref = result["operationRef"]
    if args.request_id:
        result.setdefault("requestId", args.request_id)
    if args.session_ref:
        result.setdefault("sessionRef", args.session_ref)
    return result


def continuation(args):
    result = {}
    if not args:
        return result
    for field, name in (("requestId", "request_id"), ("operationRef", "operation_ref"), ("sessionRef", "session_ref")):
        value = getattr(args, name, None)
        if value:
            result[field] = value
    kind = operation_kind(args.command)
    if kind and (args.operation_ref or args.request_id):
        follow = {"command": kind, "sessionRef": args.session_ref}
        follow["operationRef" if args.operation_ref else "requestId"] = args.operation_ref or args.request_id
        result["continuation"] = follow
    return result


def awaiting_confirmation(result, args):
    return (args.command == "confirm" and result.get("ok") is True
            and result.get("interactionRequired") is True
            and result.get("supportedInteraction") == "deployment_confirmation"
            and bool(args.operation_ref))


def next_poll_path(result, args):
    if args.command == "cancel":
        return None
    if result.get("pending") and result.get("pollPath"):
        return result["pollPath"]
    if awaiting_confirmation(result, args):
        # Opening the page does not confirm it. Wait for the user's real click
        # by reading this same operation within the existing wait budget.
        return PREFIX + "deployments/" + args.operation_ref
    return None


def main(argv=None):
    transport._configure_utf8_output()
    args, result, last_result, client = None, None, None, None
    requested_command = next(iter(argv if argv is not None else sys.argv[1:]), None)
    started = time.monotonic()
    try:
        args = parser().parse_args(argv)
        args._submitted = False
        apply_request_file(args)
        validate_args(args)
        persist_request(args)
        client = Client(args.base_url, transport._load_token(Path(args.token_file)), args.session_ref, started + args.timeout)
        client.verify_pairing(args.allow_unpaired_development)
        result = bind_result(execute(args, client), args)
        last_result = dict(result)
        deadline = min(client.deadline, time.monotonic() + args.wait_seconds)
        # A cancellation receipt must survive even when the original operation
        # is still running; polling its status would replace the refusal.
        while (poll_path := next_poll_path(result, args)) is not None:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                break
            time.sleep(min(1, remaining))
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                break
            result = bind_result(client.request(poll_path, timeout=min(10, remaining)), args)
            if (operation_kind(args.command) == "deployment" and result.get("ok") is False
                    and not isinstance(result.get("deployment"), dict)):
                # A valid error envelope is not a new deployment observation.
                # Keep the original binding/receipt and stop polling this turn.
                error_code = result.get("code")
                result = dict(last_result or {})
                result.update({"ok": False, "unknown": True, "retryable": False,
                    "code": error_code if isinstance(error_code, str) and REFERENCE.fullmatch(error_code) else "deployment_unavailable",
                    "requestSubmitted": bool(args._submitted), "currentReadUnavailable": True,
                    "userMessage": "本次续查未能取得新的部署状态；已保留原操作及此前取得的事实，不能当作本次新回读。请仅续查原操作，不要重新提交。"})
                result.update(continuation(args))
                break
            last_result = dict(result)
        if args.command == "summary":
            result = client.summary_report(result, args.source or "、".join(args.sources or []), args.algorithm)
        elif not result.get("pending"):
            result = client.attachments(result)
        if result.get("pending") or awaiting_confirmation(result, args):
            result.update(continuation(args))
        code = 0
    except transport.ClientError as error:
        messages = {"session_required": "请先在本次对话开始新的查询。", "invalid_arguments": "请检查本次业务所需的信息与格式。",
                    "query_reference_required": "续查信息尚未整理完整，本次没有发出查询或新的业务请求。",
                    "confirmation_command_required": "确认操作的调用方式需要修正，本次没有发送部署、停止或确认请求。",
                    "local_confirmation_required": "确认只能在本机核对页由用户完成；本次未发送确认或设备变更请求。",
                    "request_persistence_failed": "未能安全保存本次续查标识，本次没有发送业务请求。请保留原请求文件检查，不要重建请求。",
                    "request_binding_conflict": "请求文件与本次对话或请求标识不一致，本次没有发送请求。",
                    "request_recovery_required": "请用原请求文件只读恢复查询，本次没有重新提交业务。",
                    "invalid_request_id": "本次请求标识格式不正确，本次没有发送业务请求。",
                    "version_mismatch": "服务与技能版本不匹配，请重新安装同一份配套候选。"}
        if requested_command == "summary":
            messages["invalid_arguments"] = "请明确查询的起止时间，并检查请求信息格式。"
        unknown = error.code == "invalid_response" and bool(args and (args._submitted or last_result or operation_kind(args.command)))
        result = dict(last_result or {}) if unknown else {}
        result.update({"ok": False, "code": error.code, "userMessage": messages.get(error.code, "当前结果暂时无法可靠读取，请续查原请求。")})
        if error.code == "query_reference_required":
            result["clientInstruction"] = "查询仅提供 operationRef 或 requestId 之一。有 operationRef 时只传 operationRef；仅首次响应丢失且没有 operationRef 时传原 requestId。保留本次 sessionRef，不重新提交业务。"
            result["requestSubmitted"] = False
        if error.code == "confirmation_command_required":
            result["clientInstruction"] = "deploy/stop 仅建立新提议，不接受 operationRef 或 confirmationToken。这是本地命令与字段不匹配，不表示跨会话冲突。已有本次对话提议时，confirm 的最小请求仅含 sessionRef、operationRef，用于打开本机核对页；必须由用户在该页明确确认，聊天回复不能代替点击。仅查状态时用 deployment 和原 operationRef，不重新 deploy/stop。"
            result["requestSubmitted"] = False
        if error.code == "local_confirmation_required":
            result["clientInstruction"] = "不要传入或索取 confirmationToken。仅用 confirm 和原 sessionRef、operationRef 打开本机核对页，由用户在页面确认；这次本地拒绝没有发出 HTTP。"
            result["requestSubmitted"] = False
        if error.code in ("request_persistence_failed", "request_binding_conflict", "request_recovery_required"):
            result["requestSubmitted"] = False
            result["clientInstruction"] = "保留原文件和其中的 sessionRef、requestId、operationKind；按业务类型用 recover-observation 或 recover-deployment --request-file 原路径，只读查询。查询不到不代表可以重新派发，不自动重试 POST。"
        if error.code == "invalid_request_id":
            result["clientInstruction"] = "requestId 必须是 1–128 个 ASCII 字符，以字母或数字开头，其余仅允许字母、数字、点、下划线、连字符。全新的 deploy/stop/capture/observe 请求可以省略此字段，由客户端生成。已经提交、结果未知或需要续查时，保留原返回的 requestId；有 operationRef 则只读查询该操作。不要把既有标识翻译、转写或换成新值重新提交。"
            result["requestSubmitted"] = False
        if unknown:
            result.update({"unknown": True, "retryable": False, "requestSubmitted": bool(args and args._submitted)})
            result.update(continuation(args))
        code = 0 if unknown else 1
    except (OSError, TimeoutError):
        result = dict(last_result or {})
        message = "本机服务暂时无法连接，请稍后继续查询。"
        if args and operation_kind(args.command):
            message = "暂时无法确认这次任务的结果，请续查原请求，暂勿再次提交。"
        result.update({"ok": False, "unknown": True, "code": "transport_unknown", "retryable": False,
                       "requestSubmitted": bool(args and args._submitted), "userMessage": message})
        result.update(continuation(args))
        code = 0
    except Exception:
        result = {"ok": False, "code": "invalid_response", "userMessage": "当前返回结果无法可靠读取，请稍后续查。"}
        if args:
            result.update(continuation(args))
        code = 1
    if args and args.command == "connect" and isinstance(args.session_ref, str) and SESSION.fullmatch(args.session_ref):
        result["sessionRef"] = args.session_ref
        if getattr(args, "_connection_server_time", None):
            result.setdefault("serverTime", args._connection_server_time)
    if args and operation_kind(args.command) == "deployment":
        result = deployment_output(result, client.paired_identity if client else None)
    print(json.dumps(result, ensure_ascii=False, separators=(",", ":")), flush=True)
    return code


if __name__ == "__main__":
    raise SystemExit(main())
