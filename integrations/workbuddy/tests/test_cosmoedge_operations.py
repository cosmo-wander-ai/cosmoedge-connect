import contextlib
import hashlib
import io
import json
import os
from pathlib import Path
import stat
import subprocess
import sys
import tempfile
import threading
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer


SCRIPT = (
    Path(__file__).resolve().parents[1]
    / "skills"
    / "cosmoedge-operations"
    / "scripts"
    / "cosmoedge_operations.py"
)
SKILL_ROOT = SCRIPT.parents[1]
sys.path.insert(0, str(SCRIPT.parent))
import local_files
# Reuse the canonical module: other suites may already hold its ClientError.
# Republishing a second module here breaks their real exception handlers.
import cosmoedge_operations as client


TOKEN = "0123456789abcdef" * 4  # gitleaks:allow -- Synthetic credential for an isolated local test fixture.
RUN_REF = "run-public-7"
MEDIA_REF = "media-public-9"
PNG = b"\x89PNG\r\n\x1a\nworkbuddy-fixture"


class Scenario:
    def __init__(self):
        self.calls = []
        self.polls = 0
        self.interaction_route = ""
        self.interaction_capability = "operator.onboarding"
        self.media_mode = "ok"
        self.unsafe_result = False
        self.raw_capabilities = None
        self.run_status = "progressive"
        self.result_not_ready = False


class FixtureService:
    def __init__(self, scenario):
        self.scenario = scenario
        scenario_ref = scenario

        class Handler(BaseHTTPRequestHandler):
            def log_message(self, *_args):
                return

            def _record(self, body=None):
                scenario_ref.calls.append({
                    "method": self.command,
                    "path": self.path,
                    "authorization": self.headers.get("Authorization"),
                    "idempotency": self.headers.get("Idempotency-Key"),
                    "body": body,
                })

            def _json(self, status, value):
                raw = json.dumps(value, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
                self.send_response(status)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(raw)))
                self.end_headers()
                self.wfile.write(raw)

            def _authorized(self):
                if self.headers.get("Authorization") == "Bearer " + TOKEN:
                    return True
                self._json(401, {"error": {"code": "unauthenticated", "message": "authentication is required"}})
                return False

            def _interaction(self):
                persistent = scenario_ref.interaction_capability == "operator.persistent_change"
                self._json(409, {
                    "error": {"code": "interaction_required", "message": "local interaction is required"},
                    "interactionRequired": {
                        "title": "需要在本机确认现场变更" if persistent else "需要先完成现场接入",
                        "message": "该变更只会生成待确认事项，请在本机管理页面核对并确认后执行。" if persistent else "请在本机管理页面完成现场连接后再试。",
                        "actionLabel": "打开本机管理页面",
                        "capability": scenario_ref.interaction_capability,
                        "handoffRef": "handoff-public-change" if persistent else "handoff-public-3",
                    },
                })

            def do_GET(self):
                if not self._authorized():
                    return
                self._record()
                if self.path == "/api/inspection/capabilities":
                    if scenario_ref.interaction_route == "capabilities":
                        self._interaction()
                        return
                    if scenario_ref.raw_capabilities is not None:
                        raw = scenario_ref.raw_capabilities
                        self.send_response(200)
                        self.send_header("Content-Type", "application/json")
                        self.send_header("Content-Length", str(len(raw)))
                        self.end_headers()
                        self.wfile.write(raw)
                        return
                    self._json(200, {
                        "contextLabel": "当前门店",
                        "capabilities": [{
                            "capabilityRef": "inspection.scene",
                            "title": "现场情况查看",
                            "description": "可按临时问题查看已接入区域",
                            "examples": ["看看入口现在是否拥堵", "检查货架通道是否畅通"],
                        }],
                    })
                    return
                if self.path == "/api/inspection/runs/" + RUN_REF:
                    scenario_ref.polls += 1
                    status = scenario_ref.run_status
                    if status == "progressive":
                        status = "working" if scenario_ref.polls == 1 else "ready"
                    messages = {
                        "accepted": "巡检请求已受理",
                        "working": "正在查看现场",
                        "ready": "现场查看已完成",
                        "unable": "这次现场查看未能完成",
                        "cancelled": "这次现场查看已取消",
                        "expired": "这次现场查看已过期",
                    }
                    self._json(200, {
                        "runRef": RUN_REF,
                        "status": status,
                        "message": messages[status],
                        "submittedAt": "2026-07-19T08:00:00Z",
                        "updatedAt": "2026-07-19T08:00:01Z",
                    })
                    return
                if self.path == "/api/inspection/runs/{}/result".format(RUN_REF):
                    if scenario_ref.result_not_ready:
                        self._json(409, {"error": {"code": "result_not_ready", "message": "inspection result is not ready"}})
                        return
                    summary = "详细内容位于 http://private.invalid" if scenario_ref.unsafe_result else "已完成所选区域的现场查看。"
                    self._json(200, {
                        "runRef": RUN_REF,
                        "summary": summary,
                        "sections": [{
                            "title": "北侧通道",
                            "conclusion": "当前通行基本顺畅",
                            "details": ["未发现明显阻挡"],
                            "evidence": [{
                                "mediaRef": MEDIA_REF,
                                "capability": "inspection.media.deliver",
                                "mediaType": "image/png",
                                "title": "北侧通道现场图片",
                            }],
                        }],
                        "limitations": ["画面外区域无法判断"],
                        "completedAt": "2026-07-19T08:00:02Z",
                    })
                    return
                if self.path == "/api/inspection/media/" + MEDIA_REF:
                    if scenario_ref.media_mode == "redirect":
                        self.send_response(302)
                        self.send_header("Location", "http://127.0.0.1:1/private")
                        self.end_headers()
                        return
                    content_type = "text/plain" if scenario_ref.media_mode == "type" else "image/png"
                    digest = hashlib.sha256(PNG).hexdigest()
                    if scenario_ref.media_mode == "hash":
                        digest = "0" * 64
                    self.send_response(200)
                    self.send_header("Content-Type", content_type)
                    self.send_header("Content-Length", str(len(PNG)))
                    self.send_header("X-Content-SHA256", digest)
                    self.end_headers()
                    self.wfile.write(PNG)
                    return
                self._json(404, {"error": {"code": "not_found", "message": "resource not found"}})

            def do_POST(self):
                if not self._authorized():
                    return
                length = int(self.headers.get("Content-Length", "0"))
                raw = self.rfile.read(length)
                try:
                    body = json.loads(raw.decode("utf-8"))
                except (UnicodeDecodeError, json.JSONDecodeError):
                    body = None
                self._record(body)
                if self.path == "/api/inspection/requests":
                    if scenario_ref.interaction_route == "request":
                        self._interaction()
                        return
                    self._json(201, {
                        "created": True,
                        "run": {
                            "runRef": RUN_REF,
                            "status": "accepted",
                            "message": "已经收到巡检要求",
                            "submittedAt": "2026-07-19T08:00:00Z",
                            "updatedAt": "2026-07-19T08:00:00Z",
                        },
                    })
                    return
                if self.path == "/api/inspection/runs/{}/feedback".format(RUN_REF):
                    self._json(201, {"created": True, "feedback": {"accepted": True}})
                    return
                self._json(404, {"error": {"code": "not_found", "message": "resource not found"}})

        self.server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)

    def __enter__(self):
        self.thread.start()
        return "http://127.0.0.1:{}".format(self.server.server_port)

    def __exit__(self, *_args):
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(timeout=5)


class InspectionClientTests(unittest.TestCase):
    def _files(self, root):
        token = Path(root) / "access.token"
        token.write_text(TOKEN + "\n", encoding="ascii")
        local_files.protect(token)
        instruction = Path(root) / "instruction.txt"
        instruction.write_text("请看看仓库北侧通道现在是否畅通", encoding="utf-8")
        local_files.protect(instruction)
        output = Path(root) / "output"
        return token, instruction, output

    def _main(self, arguments):
        stdout = io.StringIO()
        with contextlib.redirect_stdout(stdout):
            code = client.main(arguments)
        lines = stdout.getvalue().splitlines()
        self.assertEqual(len(lines), 1)
        return code, json.loads(lines[0])

    def test_capabilities_are_queried_from_bound_session(self):
        scenario = Scenario()
        with tempfile.TemporaryDirectory() as root, FixtureService(scenario) as base_url:
            token, _, _ = self._files(root)
            code, envelope = self._main([
                "capabilities", "--base-url", base_url, "--token-file", str(token)
            ])
        self.assertEqual(code, 0)
        self.assertTrue(envelope["ok"])
        self.assertIn("现场情况查看", envelope["userMessage"])
        self.assertIn("货架通道", envelope["userMessage"])
        self.assertEqual(scenario.calls[0]["path"], "/api/inspection/capabilities")
        self.assertEqual(scenario.calls[0]["authorization"], "Bearer " + TOKEN)
        self.assertNotIn("tenant", json.dumps(scenario.calls, ensure_ascii=False).lower())

    def test_capabilities_group_matching_business_descriptions_and_merge_examples(self):
        scenario = Scenario()
        scenario.raw_capabilities = json.dumps({
            "contextLabel": "当前门店",
            "capabilities": [
                {
                    "capabilityRef": "inspection.existing",
                    "title": "现场情况查看",
                    "description": "可按临时问题查看已接入区域",
                    "examples": ["看看入口现在是否拥堵", "检查货架通道是否畅通"],
                },
                {
                    "capabilityRef": "inspection.snapshot",
                    "title": "现场情况查看",
                    "description": "可按临时问题查看已接入区域",
                    "examples": ["检查货架通道是否畅通", "查看收银区是否需要关注"],
                },
                {
                    "capabilityRef": "inspection.clip",
                    "title": "现场情况查看",
                    "description": "可按临时问题查看已接入区域",
                    "examples": ["看看入口现在是否拥堵"],
                },
                {
                    "capabilityRef": "inspection.hybrid",
                    "title": "现场情况查看",
                    "description": "可按临时问题查看已接入区域",
                    "examples": [],
                },
            ],
        }, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
        with tempfile.TemporaryDirectory() as root, FixtureService(scenario) as base_url:
            token, _, _ = self._files(root)
            code, envelope = self._main([
                "capabilities", "--base-url", base_url, "--token-file", str(token)
            ])
        self.assertEqual(code, 0)
        self.assertTrue(envelope["ok"])
        message = envelope["userMessage"]
        self.assertEqual(message.count("- 现场情况查看：可按临时问题查看已接入区域"), 1)
        self.assertIn(
            "  例如：看看入口现在是否拥堵；检查货架通道是否畅通；查看收银区是否需要关注",
            message,
        )
        for reference in ("inspection.existing", "inspection.snapshot", "inspection.clip", "inspection.hybrid"):
            self.assertNotIn(reference, message)

    def test_capabilities_still_reject_duplicate_internal_references(self):
        scenario = Scenario()
        capability = {
            "capabilityRef": "inspection.scene",
            "title": "现场情况查看",
            "description": "可按临时问题查看已接入区域",
            "examples": ["看看入口现在是否拥堵"],
        }
        scenario.raw_capabilities = json.dumps({
            "contextLabel": "当前门店",
            "capabilities": [capability, dict(capability)],
        }, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
        with tempfile.TemporaryDirectory() as root, FixtureService(scenario) as base_url:
            token, _, _ = self._files(root)
            code, envelope = self._main([
                "capabilities", "--base-url", base_url, "--token-file", str(token)
            ])
        self.assertEqual(code, 1)
        self.assertFalse(envelope["ok"])

    def test_generic_inspection_returns_business_text_and_verified_attachment(self):
        scenario = Scenario()
        with tempfile.TemporaryDirectory() as root, FixtureService(scenario) as base_url:
            token, instruction, output = self._files(root)
            code, envelope = self._main([
                "inspect",
                "--base-url", base_url,
                "--token-file", str(token),
                "--instruction-file", str(instruction),
                "--context", "关注点=通道阻挡",
                "--output-dir", str(output),
                "--timeout", "5",
            ])
            self.assertEqual(code, 0)
            self.assertTrue(envelope["ok"])
            self.assertIn("未发现明显阻挡", envelope["userMessage"])
            self.assertIn("已附上本次巡检的现场图片", envelope["userMessage"])
            self.assertEqual(len(envelope["attachmentFiles"]), 1)
            attachment = Path(envelope["attachmentFiles"][0])
            self.assertEqual(attachment.read_bytes(), PNG)
            local_files.validate(attachment)
            self.assertNotIn(str(output), envelope["userMessage"])

        create = next(call for call in scenario.calls if call["path"] == "/api/inspection/requests")
        self.assertEqual(create["body"], {
            "instruction": "请看看仓库北侧通道现在是否畅通",
            "context": [{"name": "关注点", "value": "通道阻挡"}],
        })
        self.assertTrue(create["idempotency"].startswith("wb-"))
        serialized = json.dumps(create["body"], ensure_ascii=False).lower()
        for forbidden in ("tenant", "site", "channel", "template", "assignment", "camera", "device", "source"):
            self.assertNotIn(forbidden, serialized)
        visible = envelope["userMessage"].lower()
        for forbidden in (RUN_REF, MEDIA_REF, "accepted", "working", "ready", "inspection.media", "http://", "/api/"):
            self.assertNotIn(forbidden.lower(), visible)

    def test_group_readable_instruction_is_accepted(self):
        # Callers (e.g. the WorkBuddy harness) write the temp instruction under
        # the default umask, which leaves group/other read bits set (0644).
        # Those must be accepted; only writable bits fail closed.
        scenario = Scenario()
        with tempfile.TemporaryDirectory() as root, FixtureService(scenario) as base_url:
            token, instruction, output = self._files(root)
            os.chmod(instruction, 0o644)
            code, envelope = self._main([
                "inspect",
                "--base-url", base_url,
                "--token-file", str(token),
                "--instruction-file", str(instruction),
                "--output-dir", str(output),
                "--timeout", "5",
            ])
            self.assertEqual(code, 0)
            self.assertTrue(envelope["ok"])

    def test_private_instruction_trims_edge_whitespace_and_rejects_blank_content(self):
        scenario = Scenario()
        with tempfile.TemporaryDirectory() as root, FixtureService(scenario) as base_url:
            token, instruction, output = self._files(root)
            instruction.write_text(" \n请看看仓库北侧通道现在是否畅通\t\n", encoding="utf-8")
            code, envelope = self._main([
                "inspect", "--base-url", base_url, "--token-file", str(token),
                "--instruction-file", str(instruction), "--output-dir", str(output), "--timeout", "5",
            ])
            self.assertEqual(code, 0)
            self.assertTrue(envelope["ok"])
            create = next(call for call in scenario.calls if call["path"] == "/api/inspection/requests")
            self.assertEqual(create["body"]["instruction"], "请看看仓库北侧通道现在是否畅通")

            instruction.write_text(" \n\t ", encoding="utf-8")
            code, envelope = self._main([
                "inspect", "--base-url", base_url, "--token-file", str(token),
                "--instruction-file", str(instruction), "--output-dir", str(output), "--timeout", "5",
            ])
            self.assertEqual(code, 1)
            self.assertFalse(envelope["ok"])

    def test_interaction_required_preserves_only_trusted_handoff(self):
        scenario = Scenario()
        scenario.interaction_route = "request"
        with tempfile.TemporaryDirectory() as root, FixtureService(scenario) as base_url:
            token, instruction, output = self._files(root)
            code, envelope = self._main([
                "inspect", "--base-url", base_url, "--token-file", str(token),
                "--instruction-file", str(instruction), "--output-dir", str(output),
            ])
        self.assertEqual(code, 2)
        self.assertFalse(envelope["ok"])
        self.assertTrue(envelope["interactionRequired"])
        self.assertEqual(envelope["interaction"], {
            "actionLabel": "打开本机管理页面",
            "capability": "operator.onboarding",
            "handoffRef": "handoff-public-3",
        })
        self.assertIn("本机管理页面", envelope["userMessage"])
        self.assertNotIn("http", json.dumps(envelope, ensure_ascii=False).lower())

    def test_persistent_change_uses_its_distinct_trusted_local_action(self):
        scenario = Scenario()
        scenario.interaction_route = "request"
        scenario.interaction_capability = "operator.persistent_change"
        with tempfile.TemporaryDirectory() as root, FixtureService(scenario) as base_url:
            token, instruction, output = self._files(root)
            instruction.write_text("把入口巡检改为每天闭店后执行", encoding="utf-8")
            code, envelope = self._main([
                "inspect", "--base-url", base_url, "--token-file", str(token),
                "--instruction-file", str(instruction), "--output-dir", str(output),
            ])
        self.assertEqual(code, 2)
        self.assertFalse(envelope["ok"])
        self.assertEqual(envelope["interaction"], {
            "actionLabel": "打开本机管理页面",
            "capability": "operator.persistent_change",
            "handoffRef": "handoff-public-change",
        })
        self.assertIn("待确认", envelope["userMessage"])
        self.assertIn("本机管理页面", envelope["userMessage"])
        visible = envelope["userMessage"].lower()
        for forbidden in ("operator.", "handoff", "task-", "source-", "http", "/api/"):
            self.assertNotIn(forbidden, visible)

    def test_unrecognized_local_action_is_rejected(self):
        scenario = Scenario()
        scenario.interaction_route = "request"
        scenario.interaction_capability = "operator.unbounded_action"
        with tempfile.TemporaryDirectory() as root, FixtureService(scenario) as base_url:
            token, instruction, output = self._files(root)
            code, envelope = self._main([
                "inspect", "--base-url", base_url, "--token-file", str(token),
                "--instruction-file", str(instruction), "--output-dir", str(output),
            ])
        self.assertEqual(code, 1)
        self.assertFalse(envelope["ok"])
        self.assertNotIn("interactionRequired", envelope)
        self.assertNotIn("operator", envelope["userMessage"].lower())

    def test_pending_request_can_be_continued_through_status_and_result(self):
        scenario = Scenario()
        scenario.run_status = "working"
        with tempfile.TemporaryDirectory() as root, FixtureService(scenario) as base_url:
            token, instruction, output = self._files(root)
            code, pending = self._main([
                "inspect", "--base-url", base_url, "--token-file", str(token),
                "--instruction-file", str(instruction), "--output-dir", str(output), "--timeout", "1",
            ])
            self.assertEqual(code, 3)
            self.assertFalse(pending["ok"])
            self.assertTrue(pending["pending"])
            self.assertEqual(pending["runRef"], RUN_REF)
            self.assertIn("稍后继续查看", pending["userMessage"])
            self.assertNotIn(RUN_REF, pending["userMessage"])

            scenario.run_status = "ready"
            code, status = self._main([
                "status", "--base-url", base_url, "--token-file", str(token),
                "--run-ref", pending["runRef"],
            ])
            self.assertEqual(code, 0)
            self.assertTrue(status["ok"])
            self.assertTrue(status["resultAvailable"])
            self.assertEqual(status["userMessage"], "现场查看已完成")

            code, result = self._main([
                "result", "--base-url", base_url, "--token-file", str(token),
                "--run-ref", pending["runRef"], "--output-dir", str(output),
            ])
            self.assertEqual(code, 0)
            self.assertTrue(result["ok"])
            self.assertEqual(Path(result["attachmentFiles"][0]).read_bytes(), PNG)
            self.assertIn("未发现明显阻挡", result["userMessage"])
            self.assertNotIn(RUN_REF, result["userMessage"])

    def test_status_preserves_honest_chinese_terminal_message(self):
        expected = {
            "unable": "这次现场查看未能完成",
            "cancelled": "这次现场查看已取消",
            "expired": "这次现场查看已过期",
        }
        for run_status, message in expected.items():
            with self.subTest(run_status=run_status):
                scenario = Scenario()
                scenario.run_status = run_status
                with tempfile.TemporaryDirectory() as root, FixtureService(scenario) as base_url:
                    token, _, _ = self._files(root)
                    code, envelope = self._main([
                        "status", "--base-url", base_url, "--token-file", str(token), "--run-ref", RUN_REF,
                    ])
                self.assertEqual(code, 0)
                self.assertEqual(envelope["userMessage"], message)
                self.assertFalse(envelope["resultAvailable"])
                self.assertNotIn(run_status, envelope["userMessage"].lower())

    def test_result_not_ready_retains_only_internal_continuation(self):
        scenario = Scenario()
        scenario.result_not_ready = True
        with tempfile.TemporaryDirectory() as root, FixtureService(scenario) as base_url:
            token, _, output = self._files(root)
            code, envelope = self._main([
                "result", "--base-url", base_url, "--token-file", str(token),
                "--run-ref", RUN_REF, "--output-dir", str(output),
            ])
        self.assertEqual(code, 3)
        self.assertTrue(envelope["pending"])
        self.assertEqual(envelope["runRef"], RUN_REF)
        self.assertNotIn(RUN_REF, envelope["userMessage"])
        self.assertNotIn("result_not_ready", envelope["userMessage"])

    def test_feedback_is_idempotent_and_business_only(self):
        scenario = Scenario()
        with tempfile.TemporaryDirectory() as root, FixtureService(scenario) as base_url:
            token, _, _ = self._files(root)
            code, envelope = self._main([
                "feedback", "--base-url", base_url, "--token-file", str(token),
                "--run-ref", RUN_REF, "--helpful", "yes", "--comment", "结果有帮助",
            ])
        self.assertEqual(code, 0)
        self.assertEqual(envelope, {"ok": True, "userMessage": "已收到你的反馈，谢谢。"})
        call = scenario.calls[0]
        self.assertEqual(call["path"], "/api/inspection/runs/{}/feedback".format(RUN_REF))
        self.assertEqual(call["body"], {"helpful": True, "comment": "结果有帮助"})
        self.assertTrue(call["idempotency"].startswith("wb-feedback-"))

    def test_unsafe_result_text_never_reaches_chat(self):
        scenario = Scenario()
        scenario.unsafe_result = True
        with tempfile.TemporaryDirectory() as root, FixtureService(scenario) as base_url:
            token, instruction, output = self._files(root)
            code, envelope = self._main([
                "inspect", "--base-url", base_url, "--token-file", str(token),
                "--instruction-file", str(instruction), "--output-dir", str(output), "--timeout", "5",
            ])
        self.assertEqual(code, 1)
        self.assertFalse(envelope["ok"])
        self.assertNotIn("http", envelope["userMessage"].lower())
        self.assertNotIn("private", envelope["userMessage"].lower())

    def test_presentation_rejects_internal_and_technical_text(self):
        values = [
            "巡检状态 ready",
            "巡检还在pending",
            "服务返回result_not_ready",
            "巡检结论meets_rule不可展示",
            "内部运行引用 run-public-7",
            "图片引用 media-public-9",
            "请使用提示词重新分析",
            "模型回答为是",
            "模型判断现场整齐",
            "模型结论是没有问题",
            "结果保存在 /var/tmp/result.json",
            "设备编号：CAMERA-42",
            "设备 deviceId=CAMERA42",
            "现场地址是 192.168.1.20:554",
            "使用 RTSP 接入后再做 VLM 分析",
            "使用RTSP接入后再做VLM分析",
            "服务错误码 500",
        ]
        for value in values:
            with self.subTest(value=value):
                with self.assertRaises(client.ClientError):
                    client._presentation_text(value)

    def test_media_hash_type_and_redirect_are_rejected(self):
        for mode in ("hash", "type", "redirect"):
            with self.subTest(mode=mode):
                scenario = Scenario()
                scenario.media_mode = mode
                with tempfile.TemporaryDirectory() as root, FixtureService(scenario) as base_url:
                    token, instruction, output = self._files(root)
                    code, envelope = self._main([
                        "inspect", "--base-url", base_url, "--token-file", str(token),
                        "--instruction-file", str(instruction), "--output-dir", str(output), "--timeout", "5",
                    ])
                    self.assertEqual(code, 1)
                    self.assertFalse(envelope["ok"])
                    self.assertEqual(list(output.glob("*")), [])

    def test_duplicate_json_keys_are_rejected(self):
        scenario = Scenario()
        scenario.raw_capabilities = b'{"contextLabel":"A","contextLabel":"B","capabilities":[]}'
        with tempfile.TemporaryDirectory() as root, FixtureService(scenario) as base_url:
            token, _, _ = self._files(root)
            code, envelope = self._main(["capabilities", "--base-url", base_url, "--token-file", str(token)])
        self.assertEqual(code, 1)
        self.assertFalse(envelope["ok"])

    def test_non_loopback_and_insecure_local_files_fail_closed(self):
        with tempfile.TemporaryDirectory() as root:
            token, instruction, output = self._files(root)
            code, envelope = self._main([
                "capabilities", "--base-url", "http://192.0.2.10:37789", "--token-file", str(token)
            ])
            self.assertEqual(code, 1)
            self.assertFalse(envelope["ok"])

            if os.name == 'nt':
                subprocess.run(['icacls', str(token), '/grant', '*S-1-1-0:(R)'], check=True, capture_output=True)
            else:
                os.chmod(token, 0o644)
            code, envelope = self._main(["capabilities", "--token-file", str(token)])
            self.assertEqual(code, 1)
            self.assertIn("本机", envelope["userMessage"])

            local_files.protect(token)
            # Group/other WRITABLE instruction is a tampering risk and must
            # still fail closed (read bits alone are tolerated; see the
            # accepts-group-readable test below).
            if os.name == 'nt':
                subprocess.run(['icacls', str(instruction), '/grant', '*S-1-1-0:(W)'], check=True, capture_output=True)
            else:
                os.chmod(instruction, 0o666)
            code, envelope = self._main([
                "inspect", "--token-file", str(token), "--instruction-file", str(instruction),
                "--output-dir", str(output),
            ])
            self.assertEqual(code, 1)
            self.assertFalse(envelope["ok"])

    def test_skill_sources_have_no_retired_fixed_business_contract(self):
        sources = [
            (SKILL_ROOT / "SKILL.md").read_text(encoding="utf-8"),
            (SKILL_ROOT / "references" / "api-contract.md").read_text(encoding="utf-8"),
            SCRIPT.read_text(encoding="utf-8"),
        ]
        joined = "\n".join(sources).lower()
        retired_terms = [
            "dining-" + "east", "dining-" + "west", "visible-" + "hygiene", "synthetic" + "_mock",
            "/api/inspection-" + "runs", "/api/inspection-" + "templates", "/api/" + "mock-inspection-runs",
        ]
        for term in retired_terms:
            self.assertNotIn(term, joined)
        self.assertNotIn("tenant" + "_id", joined)
        self.assertNotIn("site" + "_id", joined)
        self.assertNotIn("template" + "_id", joined)

    def test_retired_cli_requests_skill_reload_without_contacting_service(self):
        for arguments in (
            ["check"],
            ["inspect", "--area", "all", "--focus", "hygiene"],
        ):
            with self.subTest(arguments=arguments):
                code, envelope = self._main(arguments)
                self.assertEqual(code, 1)
                self.assertFalse(envelope["ok"])
                self.assertTrue(envelope["skillReloadRequired"])
                self.assertEqual(
                    envelope["userMessage"],
                    "巡检功能已更新，本次没有执行。请重新发送刚才的巡检要求。",
                )
                self.assertNotIn("区域和关注的问题", envelope["userMessage"])

    def test_installed_skill_links_to_its_packaged_tool_contract(self):
        skill = (SKILL_ROOT / "SKILL.md").read_text(encoding="utf-8")
        contract_path = SKILL_ROOT / "references" / "api-contract.md"
        self.assertTrue(contract_path.is_file())
        self.assertIn("references/api-contract.md", skill)
        self.assertIn("scripts/cosmoedge-operations", skill)
        self.assertIn("--request-file", skill)
        # Command/field handling is covered by real-process tests. Wording and
        # whether operators can complete a task belong to host acceptance.
        self.assertNotIn("--instruction-file", skill)

    def test_structured_result_extracts_yes_answer_and_question_from_details(self):
        structured = client._derive_structured_result(
            sections=[{
                "title": "当前区域 · 现场情况",
                "conclusion": "现场可见情况",
                "details": ['针对“货物有没有随意堆放”，本次查看得到肯定结果'],
                "evidence": [],
            }],
            limitations=[],
        )
        self.assertEqual(structured["answer"], "yes")
        self.assertEqual(structured["question"], "货物有没有随意堆放")
        self.assertEqual(structured["region"], "当前区域")
        self.assertEqual(structured["subject"], "现场情况")
        self.assertEqual(len(structured["facts"]), 1)
        self.assertEqual(len(structured["limitations"]), 0)

    def test_structured_result_extracts_no_answer_and_question_from_limitations(self):
        structured = client._derive_structured_result(
            sections=[{
                "title": "西侧就餐区 · 桌椅",
                "conclusion": "现场可见情况",
                "details": [],
                "evidence": [],
            }],
            limitations=['当前画面不足以肯定回答“桌椅摆放是否整齐”'],
        )
        self.assertEqual(structured["answer"], "no")
        self.assertEqual(structured["question"], "桌椅摆放是否整齐")
        self.assertEqual(structured["region"], "西侧就餐区")
        self.assertEqual(structured["subject"], "桌椅")
        self.assertEqual(len(structured["facts"]), 0)
        self.assertEqual(len(structured["limitations"]), 1)

    def test_structured_result_answer_kind_unable_when_no_details_or_limitations(self):
        structured = client._derive_structured_result(
            sections=[{
                "title": "当前区域",
                "conclusion": "现场可见情况",
                "details": [],
                "evidence": [],
            }],
            limitations=[],
        )
        self.assertEqual(structured["answer"], "unable")
        self.assertEqual(structured["question"], "")

    def test_structured_result_question_extracted_from_detail_over_limitation(self):
        structured = client._derive_structured_result(
            sections=[{
                "title": "走廊 · 地面",
                "conclusion": "现场可见情况",
                "details": ['针对“地面有没有水渍”，本次查看得到肯定结果'],
                "evidence": [],
            }],
            limitations=['当前画面不足以肯定回答“不应被提取”'],
        )
        self.assertEqual(structured["answer"], "yes")
        self.assertEqual(structured["question"], "地面有没有水渍")

    def test_structured_result_question_not_extracted_from_non_matching_text(self):
        structured = client._derive_structured_result(
            sections=[{
                "title": "北侧通道",
                "conclusion": "当前通行基本顺畅",
                "details": ["未发现明显阻挡"],
                "evidence": [],
            }],
            limitations=["画面外区域无法判断"],
        )
        self.assertEqual(structured["answer"], "yes")
        self.assertEqual(structured["question"], "")
        self.assertEqual(structured["region"], "")
        self.assertEqual(structured["subject"], "")


    def test_structured_result_uses_api_answer_when_provided(self):
        """When api_answer and api_question are provided, regex extraction is skipped."""
        structured = client._derive_structured_result(
            sections=[{
                "title": "当前区域 · 现场情况",
                "conclusion": "现场可见情况",
                "details": [],  # No detail — regex would fail
                "evidence": [],
            }],
            limitations=[],
            api_answer="yes",
            api_question="货物有没有随意堆放",
        )
        self.assertEqual(structured["answer"], "yes")
        self.assertEqual(structured["question"], "货物有没有随意堆放")

    def test_structured_result_falls_back_to_regex_when_api_answer_empty(self):
        """When api_answer is empty, falls back to regex extraction."""
        structured = client._derive_structured_result(
            sections=[{
                "title": "当前区域 · 现场情况",
                "conclusion": "现场可见情况",
                "details": ['针对“货物有没有随意堆放”，本次查看得到肯定结果'],
                "evidence": [],
            }],
            limitations=[],
            api_answer="",
            api_question="",
        )
        self.assertEqual(structured["answer"], "yes")
        self.assertEqual(structured["question"], "货物有没有随意堆放")

    def test_result_message_drops_machine_formatting(self):
        """Reformatted userMessage drops machine headers and bullet formatting."""
        message = client._result_message(
            "本次现场查看得到肯定结果",
            [{
                "title": "当前区域 · 现场情况",
                "conclusion": "现场可见情况",
                "details": ['针对"货物有没有随意堆放"，本次查看得到肯定结果'],
                "evidence": [],
            }],
            ["画面外区域无法判断"],
            1,
        )
        self.assertNotIn("巡检结果", message)
        self.assertNotIn("需要说明", message)


if __name__ == "__main__":
    unittest.main()
