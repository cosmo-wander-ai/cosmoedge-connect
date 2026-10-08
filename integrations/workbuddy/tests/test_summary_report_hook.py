import copy
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

if os.name == 'nt':
    raise unittest.SkipTest('POSIX macOS packaging contract; native Windows suites run separately')


MARKET = Path(__file__).resolve().parents[1] / 'plugins/summary-report-guard'
PLUGIN = MARKET / 'plugins/cosmoedge-summary-report-guard'
SCRIPT = PLUGIN / 'scripts/post_read.py'
spec = importlib.util.spec_from_file_location('summary_post_read', SCRIPT)
hook = importlib.util.module_from_spec(spec)
spec.loader.exec_module(hook)
CANDIDATE = dict(product='cosmoedge-connect', version='synthetic-v1', revision='a' * 40,
                 modified=False, platform='darwin/arm64')
BODY = '# Synthetic report\n\nORIGINAL_BODY_CANARY\n\nalpha: 7; beta: 5\n'


class SummaryReadHookTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix='summary-hook-unit-')
        self.root = Path(self.tmp.name)
        self.directory = self.root / 'cosmoedge-summary-ab12_cd3'
        self.directory.mkdir(mode=0o700)
        self.report = self.directory / hook.REPORT_FILE
        self.metadata = self.directory / hook.PROVENANCE_FILE
        self.expected = self.root / 'candidate.json'
        self.write_private(self.report, BODY.encode())
        self.provenance = dict(schemaVersion=1, kind='cosmoedge_summary_report', reportFile=hook.REPORT_FILE,
            sha256=hashlib.sha256(BODY.encode()).hexdigest(), sizeBytes=len(BODY.encode()),
            contentType=hook.CONTENT_TYPE, candidate=copy.deepcopy(CANDIDATE))
        self.write_metadata()
        self.write_private(self.expected, json.dumps(dict(schemaVersion=1, candidate=CANDIDATE)).encode())
        self.payload = dict(session_id='synthetic-only', hook_event_name='PostToolUse', tool_name='Read',
            tool_input={'file_path': str(self.report)},
            tool_response={'type': 'text', 'text': '     1→' + BODY})

    def tearDown(self):
        self.tmp.cleanup()

    def write_private(self, path, data):
        path.write_bytes(data)
        path.chmod(0o600)

    def write_metadata(self):
        self.write_private(self.metadata, json.dumps(self.provenance, ensure_ascii=False).encode())

    def invoke(self, payload=None):
        return hook.project(self.payload if payload is None else payload, (str(self.root),), self.expected)

    def unavailable(self):
        self.assertEqual(self.invoke(), hook.replacement(hook.UNAVAILABLE))

    def test_actual_native_read_shape_projects_only_delivery_path_and_keeps_files(self):
        before = (self.report.read_bytes(), self.metadata.read_bytes())
        result = self.invoke()
        text = result['hookSpecificOutput']['updatedToolOutput']
        self.assertIn(str(self.report), text)
        self.assertIn('尚未交付', text)
        self.assertIn('present_files', text)
        self.assertNotIn('ORIGINAL_BODY_CANARY', text)
        self.assertNotIn('alpha', text)
        self.assertEqual((self.report.read_bytes(), self.metadata.read_bytes()), before)
        for response in [BODY, [{'type': 'text', 'text': BODY}], {'content': BODY}]:
            self.payload['tool_response'] = response
            self.assertEqual(self.invoke(), result)

    def test_non_target_reads_and_other_tools_are_untouched(self):
        for path in [str(self.root / 'notes.md'), str(self.directory / 'another.md'),
                     '/outside/cosmoedge-summary-ab12_cd3/' + hook.REPORT_FILE,
                     str(self.root / 'nested' / self.directory.name / hook.REPORT_FILE)]:
            payload = copy.deepcopy(self.payload)
            payload['tool_input']['file_path'] = path
            self.assertIsNone(self.invoke(payload))
        for event, name in [('PreToolUse', 'Read'), ('PostToolUse', 'Bash'), ('PostToolUse', 'present_files')]:
            payload = dict(self.payload, hook_event_name=event, tool_name=name)
            self.assertIsNone(self.invoke(payload))

    def test_missing_old_metadata_or_report_and_bad_json_never_return_body(self):
        self.metadata.unlink()
        self.unavailable()
        self.write_private(self.metadata, b'{bad json')
        self.unavailable()
        self.write_metadata()
        self.report.unlink()
        self.unavailable()

    def test_replaced_or_corrupted_report_fails_integrity(self):
        replacement = self.directory / 'new-report'
        self.write_private(replacement, b'REPLACED_BODY_CANARY')
        os.replace(replacement, self.report)
        self.unavailable()

    def test_candidate_requires_valid_metadata_and_exact_paired_identity(self):
        for key, value in [('product', 'other'), ('version', 'synthetic-v2'), ('revision', 'b' * 40),
                           ('modified', True), ('modified', 0), ('platform', 'linux/amd64')]:
            with self.subTest(key=key, value=value):
                self.provenance['candidate'] = dict(CANDIDATE, **{key: value})
                self.write_metadata()
                self.unavailable()
        self.provenance['candidate'] = dict(CANDIDATE, unexpected='not accepted')
        self.write_metadata()
        self.unavailable()
        self.provenance['candidate'] = dict(CANDIDATE)
        self.write_metadata()
        self.expected.unlink()
        self.unavailable()

    def test_strict_provenance_types_keys_and_duplicate_json(self):
        original = copy.deepcopy(self.provenance)
        for key, value in [('schemaVersion', True), ('sizeBytes', True), ('sizeBytes', 0),
                           ('sizeBytes', hook.MAX_REPORT_BYTES + 1), ('sha256', 'A' * 64),
                           ('kind', 'other'), ('contentType', 'text/plain'), ('reportFile', '../other')]:
            self.provenance = dict(original, **{key: value})
            self.write_metadata()
            self.unavailable()
        self.provenance = dict(original, extra='not allowed')
        self.write_metadata()
        self.unavailable()
        self.write_private(self.metadata, ('{"schemaVersion":1,' + json.dumps(original)[1:]).encode())
        self.unavailable()

    def test_private_permissions_and_owner_are_required(self):
        for path, bad_mode, normal_mode in [(self.directory, 0o755, 0o700),
                                           (self.report, 0o644, 0o600), (self.metadata, 0o644, 0o600)]:
            path.chmod(bad_mode)
            self.unavailable()
            path.chmod(normal_mode)
        with patch.object(hook.os, 'getuid', return_value=os.getuid() + 1):
            self.unavailable()

    def test_symlink_report_metadata_parent_and_candidate_are_rejected(self):
        for path in [self.report, self.metadata, self.expected]:
            held = path.with_name(path.name + '.held')
            path.rename(held)
            path.symlink_to(held.name)
            self.unavailable()
            path.unlink()
            held.rename(path)
        held = self.root / 'held-directory'
        self.directory.rename(held)
        self.directory.symlink_to(held.name)
        self.unavailable()

    def test_file_size_and_utf8_contract(self):
        for body in [b'x' * (hook.MAX_REPORT_BYTES + 1), b'\xffnot-utf8']:
            self.write_private(self.report, body)
            self.provenance.update(sha256=hashlib.sha256(body).hexdigest(), sizeBytes=len(body))
            self.write_metadata()
            self.unavailable()
        self.write_private(self.metadata, b' ' * (hook.MAX_METADATA_BYTES + 1))
        self.unavailable()

    def test_swap_during_descriptor_read_is_detected(self):
        original_read = hook.os.read
        replaced = False
        def swapping_read(fd, length):
            nonlocal replaced
            data = original_read(fd, length)
            if b'ORIGINAL_BODY_CANARY' in data and not replaced:
                replaced = True
                other = self.directory / 'changed'
                self.write_private(other, b'OTHER_BODY')
                os.replace(other, self.report)
            return data
        with patch.object(hook.os, 'read', side_effect=swapping_read):
            self.unavailable()
        self.assertTrue(replaced)

    def test_bounded_invalid_native_envelope_does_not_reveal_target_body(self):
        raw = json.dumps(self.payload, ensure_ascii=False).encode()
        self.assertEqual(hook.process_bytes(raw, (str(self.root),), self.expected), self.invoke())
        header = raw.split(b'"tool_response"', 1)[0] + b'"tool_response":'
        for damaged in [header + b'"unterminated', header + b'"' + b'X' * hook.MAX_HOOK_INPUT_BYTES]:
            self.assertEqual(hook.process_bytes(damaged, (str(self.root),), self.expected), hook.replacement(hook.UNAVAILABLE))
        self.assertIsNone(hook.process_bytes(b'{bad', (str(self.root),), self.expected))

    def test_package_declares_only_post_read_and_matching_local_market(self):
        hooks = json.loads((PLUGIN / 'hooks/hooks.json').read_text())['hooks']
        self.assertEqual(set(hooks), {'PostToolUse'})
        self.assertEqual(hooks['PostToolUse'][0]['matcher'], '^Read$')
        self.assertEqual(hooks['PostToolUse'][0]['hooks'][0]['type'], 'command')
        self.assertEqual(hooks['PostToolUse'][0]['hooks'][0]['command'],
                         '/usr/bin/python3 "${CODEBUDDY_PLUGIN_ROOT}/scripts/post_read.py"')
        market = json.loads((MARKET / '.codebuddy-plugin/marketplace.json').read_text())
        self.assertEqual(market['plugins'][0]['source'], './plugins/cosmoedge-summary-report-guard')
        self.assertFalse((PLUGIN / 'candidate.json').exists())  # Injected only by paired build.

    def test_main_with_real_standard_temp_anchor_is_silent_for_other_reads(self):
        with tempfile.TemporaryDirectory(prefix='cosmoedge-summary-') as name:
            report_dir = Path(name)
            report = report_dir / hook.REPORT_FILE
            self.write_private(report, BODY.encode())
            self.write_private(report_dir / hook.PROVENANCE_FILE, json.dumps(self.provenance).encode())
            scripts = self.root / 'plugin/scripts'
            scripts.mkdir(parents=True)
            shutil.copyfile(SCRIPT, scripts / 'post_read.py')
            shutil.copyfile(self.expected, scripts.parent / 'candidate.json')
            payload = copy.deepcopy(self.payload)
            payload['tool_input']['file_path'] = str(report)
            run = lambda p: subprocess.run([sys.executable, str(scripts / 'post_read.py')],
                input=json.dumps(p), text=True, capture_output=True, timeout=3, check=True)
            result = run(payload)
            self.assertIn(str(report), json.loads(result.stdout)['hookSpecificOutput']['updatedToolOutput'])
            self.assertNotIn('ORIGINAL_BODY_CANARY', result.stdout)
            self.assertEqual(result.stderr, '')
            payload['tool_input']['file_path'] = str(self.root / 'ordinary-notes.md')
            result = run(payload)
            self.assertEqual((result.stdout, result.stderr), ('', ''))


if __name__ == '__main__':
    unittest.main()
