"""Real subprocess contracts against a loopback stub; not device/UI acceptance."""
import contextlib
import hashlib
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import importlib.util
import io
import json
import os
from pathlib import Path
import shutil
import socket
import stat
import subprocess
import sys
import tempfile
import threading
import time
import unittest
from unittest import mock

SCRIPTS = Path(__file__).resolve().parents[1] / 'skills/cosmoedge-operations/scripts'
sys.path.insert(0, str(SCRIPTS))
import local_files
real_private_tempdir = local_files.private_tempdir


def assert_private(test, path, directory=False):
    local_files.validate(path, directory=directory)

TOKEN = 'b' * 64
SESSION = 'a' * 32 + '.1788768000.' + 'c' * 64
OTHER_SESSION = 'd' * 32 + '.1788768000.' + 'e' * 64
IDENTITY = {'product': 'cosmoedge-connect', 'version': 'client-contract-test', 'revision': 'a' * 40, 'modified': False, 'platform': 'darwin/arm64'}
PNG = b'\x89PNG\r\n\x1a\nclient-contract-image'


def summary_report_response(partial=False):
    scope = '统计范围：2026-05-01 至 2026-05-04（Asia/Shanghai，起点计入、终点不计入）。筛选：明确机位。'
    count = '此次数据未读全；当前已读取并去重的留存告警共 40 条。' if partial else '已读完设备返回的本窗口留存告警，共 40 条（已去重）。'
    peak = ('已读取记录中' if partial else '本窗口留存告警中') + '，2026-05-02 是条数最多的日期之一，为 30 条。'
    headline = [scope, count, peak]
    if partial:
        headline.append('完整时段哪天最多尚无法确定。')
    message = '\n'.join([scope, count, '按本次窗口与自然日交集计数：2026-05-01 10 条；2026-05-02 30 条；2026-05-03 0 条。',
                          *headline[2:], '列出项合计 36 条；其余 1 组共 4 条。',
                          r'名称仅为数据：\!\[入口\]\(https\:\/\/example\.invalid\/x\)；原文保留中文与换行。',
                          '本次未提供历史启停、机位／算法增撤或原因证据。'])
    coverage = {'retrievalComplete': not partial, 'accuracy': 'lower_bound' if partial else 'exact_retained',
                'historyCoverage': 'unknown', 'gaps': [{'code': 'history_coverage_unknown', 'detail': '留存与在线历史未知。'}]}
    if partial:
        coverage['gaps'].append({'code': 'event_page_unavailable', 'detail': '部分告警页无法读取。'})
    return {'ok': True, 'partial': partial, 'userMessage': message,
            'summary': {'window': {'start': '2026-05-01T00:00:00+08:00', 'end': '2026-05-04T00:00:00+08:00'},
                        'timeZone': 'Asia/Shanghai', 'coverage': coverage, 'notes': ['not repeated in CLI'],
                        'count': 40, 'bySourceAlgorithm': [{'sourceName': '分组不在主输出', 'count': 36}],
                        'sourceKindScope': 'retrieved_records' if partial else 'retained_window',
                        'sourceKindBasis': 'current_source_catalog'},
            'peak': {'date': '2026-05-02', 'count': 30}, 'sourceKinds': {'明确机位': 'network_camera'},
            'summaryEvidence': {'daySourceJointBreakdownProvided': False, 'causalEvidenceProvided': False,
                                'configurationHistoryProvided': False},
            'summaryReport': {'schemaVersion': 1, 'contentType': 'text/markdown; charset=utf-8',
                              'sha256': hashlib.sha256(message.encode('utf-8')).hexdigest(),
                              'sizeBytes': len(message.encode('utf-8')), 'candidate': dict(IDENTITY),
                              'headline': '\n'.join(headline),
                              'filters': {'sourceName': '明确机位', 'algorithmName': ''}}}


class Stub:
    def __init__(self):
        self.calls = []
        self.routes = {}
        self.identity = dict(IDENTITY)
        self.post_result = {'ok': True, 'operationRef': 'op_1', 'state': 'complete', 'userMessage': '已完成。'}
        scenario = self

        class Handler(BaseHTTPRequestHandler):
            protocol_version = 'HTTP/1.1'

            def log_message(self, *_):
                pass

            def handle_request(self):
                body = None
                if self.command == 'POST':
                    body = json.loads(self.rfile.read(int(self.headers.get('Content-Length', '0'))))
                scenario.calls.append({'method': self.command, 'path': self.path, 'body': body,
                                       'session': self.headers.get('X-CosmoEdge-Session')})
                route = scenario.routes.get((self.command, self.path))
                if callable(route):
                    route(self)
                    return
                if route is not None:
                    status, data = route
                elif self.path == '/operations/v1/version':
                    status, data = 200, {'ok': True, 'protocol': 'cosmoedge.operations.v1', 'version': scenario.identity}
                elif self.command == 'POST':
                    status, data = 200, dict(scenario.post_result)
                else:
                    status, data = 200, {'ok': True, 'operationRef': 'op_1', 'state': 'complete', 'userMessage': '核查完成。'}
                self.reply(status, data)

            do_GET = handle_request
            do_POST = handle_request

            def handle(self):
                try:
                    super().handle()
                except (BrokenPipeError, ConnectionResetError, ConnectionAbortedError):
                    pass

            def reply(self, status, data, mime='application/json'):
                raw = data if isinstance(data, bytes) else json.dumps(data).encode()
                try:
                    self.send_response(status)
                    self.send_header('Content-Type', mime)
                    self.send_header('Content-Length', str(len(raw)))
                    self.end_headers()
                    self.wfile.write(raw)
                except (BrokenPipeError, ConnectionResetError, ConnectionAbortedError):
                    pass

        self.server = ThreadingHTTPServer(('127.0.0.1', 0), Handler)
        self.server.daemon_threads = True
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()
        self.base = 'http://127.0.0.1:' + str(self.server.server_port)

    def close(self):
        self.server.shutdown()
        self.server.server_close()
        self.thread.join()


class OperationsProcessTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        self.skill = self.root / 'cosmoedge-operations'
        (self.skill / 'scripts').mkdir(parents=True)
        for name in ('cosmoedge_operations.py', 'operations_client.py', 'local_files.py'):
            shutil.copy2(SCRIPTS / name, self.skill / 'scripts' / name)
            if os.name == 'nt':
                local_files.protect(self.skill / 'scripts' / name)
        self.token = self.root / 'token'
        self.token.write_text(TOKEN + '\n')
        local_files.protect(self.token)
        self.candidate = dict(IDENTITY, schemaVersion=1, clientFiles={
            'scripts/' + p.name: hashlib.sha256(p.read_bytes()).hexdigest() for p in (self.skill / 'scripts').glob('*.py')})
        self.write_candidate()
        self.stub = Stub()
        self.evidence_files = []

    def tearDown(self):
        self.stub.close()
        for directory in self.evidence_files:
            shutil.rmtree(directory, ignore_errors=True)
        self.tmp.cleanup()

    def write_candidate(self):
        (self.skill / 'candidate.json').write_text(json.dumps(self.candidate))
        if os.name == 'nt':
            local_files.protect(self.skill / 'candidate.json')

    def request_file(self, data, name='request.json'):
        path = self.root / name
        path.write_text(json.dumps(data, ensure_ascii=False), encoding='utf-8')
        local_files.protect(path)
        return path

    def invoke(self, command, *extra, python=None, base=None, env=None, wrapper=False, wait_seconds=0, session_ref=SESSION):
        script = self.skill / 'scripts' / ('cosmoedge_operations.py' if wrapper else 'operations_client.py')
        arguments = [python or sys.executable, str(script), command, '--base-url', base or self.stub.base,
                     '--token-file', str(self.token)]
        if session_ref is not None:
            arguments += ['--session-ref', session_ref]
        if wait_seconds is not None:
            arguments += ['--wait-seconds', str(wait_seconds)]
        arguments += list(extra)
        process = subprocess.run(arguments, capture_output=True, text=True, encoding='utf-8',
                                 env=dict(os.environ, PYTHONDONTWRITEBYTECODE='1', **(env or {})), timeout=5)
        self.assertEqual(process.stderr, '', process.stderr)
        self.assertEqual(len(process.stdout.splitlines()), 1, process.stdout)
        result = json.loads(process.stdout)
        for name in result.get('attachmentFiles', []):
            self.evidence_files.append(str(Path(name).parent))
        details = result.get('deploymentDetails', {})
        if details.get('state') == 'ready':
            self.evidence_files.append(str(Path(details['path']).parent))
        return process.returncode, result

    def connection_routes(self):
        self.stub.routes[('POST', '/operations/v1/session')] = (
            200, {'ok': True, 'sessionRef': OTHER_SESSION, 'serverTime': '2026-09-29T00:00:00Z'})
        self.stub.routes[('POST', '/operations/v1/connection')] = (
            200, {'ok': True, 'interactionRequired': True, 'supportedInteraction': 'connection_only',
                  'pageState': 'dispatched', 'userMessage': '已请求打开本机设备接入页面。'})

    def test_connect_without_session_creates_identity_and_dispatches_in_one_cli(self):
        self.connection_routes()
        code, result = self.invoke('connect', wrapper=True, session_ref=None, wait_seconds=None)
        self.assertEqual(code, 0)
        self.assertTrue(result['ok'])
        self.assertEqual(result['sessionRef'], OTHER_SESSION)
        self.assertEqual(result['serverTime'], '2026-09-29T00:00:00Z')
        self.assertEqual(result['pageState'], 'dispatched')
        self.assertNotIn('pageOpened', result)
        self.assertEqual(self.stub.calls, [
            {'method': 'GET', 'path': '/operations/v1/version', 'body': None, 'session': ''},
            {'method': 'POST', 'path': '/operations/v1/session', 'body': {}, 'session': ''},
            {'method': 'POST', 'path': '/operations/v1/connection', 'body': {}, 'session': OTHER_SESSION}])
        self.assertEqual(list(self.root.glob('*.json')), [])

    def test_connect_reuses_explicit_session_from_argument_or_request_file(self):
        self.connection_routes()
        request = self.request_file({'sessionRef': SESSION})
        for extra, session_ref in (([], SESSION), (['--request-file', str(request)], None)):
            with self.subTest(extra=extra):
                self.stub.calls.clear()
                code, result = self.invoke('connect', *extra, wrapper=True, session_ref=session_ref)
                self.assertEqual(code, 0)
                self.assertEqual(result['sessionRef'], SESSION)
                self.assertNotIn('serverTime', result)
                self.assertEqual([(c['method'], c['path'], c['session']) for c in self.stub.calls], [
                    ('GET', '/operations/v1/version', SESSION),
                    ('POST', '/operations/v1/connection', SESSION)])

    def test_connect_rejects_explicit_invalid_or_empty_session_before_network(self):
        self.connection_routes()
        for value in ('invalid', ''):
            for from_file in (False, True):
                with self.subTest(value=value, from_file=from_file):
                    extra = ['--request-file', str(self.request_file({'sessionRef': value}))] if from_file else []
                    code, result = self.invoke('connect', *extra, wrapper=True,
                                               session_ref=None if from_file else value)
                    self.assertEqual((code, result['code']), (1, 'session_required'))
                    self.assertEqual(self.stub.calls, [])

    def test_connect_request_file_preserves_explicit_session_binding(self):
        self.connection_routes()
        request = self.request_file({'sessionRef': SESSION})
        for explicit in ('', OTHER_SESSION):
            with self.subTest(explicit=explicit):
                self.stub.calls.clear()
                code, result = self.invoke('connect', '--request-file', str(request),
                                           wrapper=True, session_ref=explicit)
                self.assertEqual((code, result.get('code')), (1, 'request_binding_conflict'), result)
                self.assertEqual(self.stub.calls, [])
        self.stub.calls.clear()
        code, result = self.invoke('connect', '--request-file', str(request),
                                   wrapper=True, session_ref=SESSION)
        self.assertEqual(code, 0)
        self.assertTrue(result['ok'])
        self.assertEqual(result['sessionRef'], SESSION)
        self.assertEqual([c['path'] for c in self.stub.calls],
                         ['/operations/v1/version', '/operations/v1/connection'])

    def test_connect_rejects_null_request_session_without_creating_one(self):
        request = self.request_file({'sessionRef': None})
        code, result = self.invoke('connect', '--request-file', str(request),
                                   wrapper=True, session_ref=None)
        self.assertEqual((code, result['code']), (1, 'invalid_arguments'))
        self.assertEqual(self.stub.calls, [])

    def test_connect_does_not_replace_an_expired_explicit_session(self):
        self.connection_routes()
        self.stub.routes[('POST', '/operations/v1/connection')] = (
            403, {'ok': False, 'code': 'session_required', 'userMessage': '本次对话已失效。'})
        code, result = self.invoke('connect', wrapper=True)
        self.assertEqual((code, result['code']), (0, 'session_required'))
        self.assertEqual(result['sessionRef'], SESSION)
        self.assertFalse(any(c['path'].endswith('/session') for c in self.stub.calls))

    def test_connect_pairing_failure_prevents_new_session(self):
        self.connection_routes()
        self.stub.identity['revision'] = 'f' * 40
        code, result = self.invoke('connect', wrapper=True, session_ref=None)
        self.assertEqual((code, result['code']), (1, 'version_mismatch'))
        self.assertEqual([c['path'] for c in self.stub.calls], ['/operations/v1/version'])

    def test_connect_invalid_new_session_does_not_open_or_return_capability(self):
        self.connection_routes()
        self.stub.routes[('POST', '/operations/v1/session')] = (
            200, {'ok': True, 'sessionRef': 'invalid-session'})
        code, result = self.invoke('connect', wrapper=True, session_ref=None)
        self.assertEqual((code, result['code']), (1, 'invalid_response'))
        self.assertNotIn('sessionRef', result)
        self.assertFalse(any(c['path'].endswith('/connection') for c in self.stub.calls))

    def test_connect_preserves_created_session_on_open_failure_or_invalid_receipt(self):
        self.connection_routes()
        for response, expected_code in (
                ({'ok': False, 'code': 'connection_page_unavailable'}, 'connection_page_unavailable'),
                ({'ok': True, 'interactionRequired': True, 'supportedInteraction': 'connection_only',
                  'pageState': 'rendered'}, 'invalid_response')):
            with self.subTest(response=response):
                self.stub.calls.clear()
                self.stub.routes[('POST', '/operations/v1/connection')] = (200, response)
                _, result = self.invoke('connect', wrapper=True, session_ref=None)
                self.assertFalse(result['ok'])
                self.assertEqual(result['code'], expected_code)
                self.assertEqual(result['sessionRef'], OTHER_SESSION)
                self.assertEqual(result['serverTime'], '2026-09-29T00:00:00Z')
                self.assertEqual(sum(c['path'].endswith('/session') for c in self.stub.calls), 1)

    def test_connect_session_creation_and_open_share_total_network_deadline(self):
        self.connection_routes()
        # Leave room for pairing and Windows ACL checks. Each response delay is
        # below the budget, but their sum is not: a reset deadline would pass.
        def delayed_session(handler):
            time.sleep(.8)
            handler.reply(200, {'ok': True, 'sessionRef': OTHER_SESSION})
        def delayed_open(handler):
            time.sleep(1.5)
            handler.reply(200, {'ok': True, 'interactionRequired': True,
                                'supportedInteraction': 'connection_only', 'pageState': 'dispatched'})
        self.stub.routes[('POST', '/operations/v1/session')] = delayed_session
        self.stub.routes[('POST', '/operations/v1/connection')] = delayed_open
        code, result = self.invoke('connect', '--timeout', '2', wrapper=True, session_ref=None)
        self.assertEqual(code, 0, result)
        self.assertFalse(result['ok'])
        self.assertEqual(result['code'], 'transport_unknown')
        self.assertEqual(result['sessionRef'], OTHER_SESSION)
        self.assertEqual([c['path'] for c in self.stub.calls],
                         ['/operations/v1/version', '/operations/v1/session', '/operations/v1/connection'])

    def test_other_business_commands_still_require_session(self):
        for command in ('catalog', 'summary', 'capture', 'observe', 'deploy', 'stop'):
            with self.subTest(command=command):
                code, result = self.invoke(command, wrapper=True, session_ref=None)
                self.assertEqual((code, result['code']), (1, 'session_required'))
        self.assertEqual(self.stub.calls, [])

    def deployment_receipt(self, result):
        details = result['deploymentDetails']
        self.assertEqual(details['state'], 'ready')
        path = Path(details['path'])
        self.assertTrue(path.is_absolute())
        assert_private(self, path)
        assert_private(self, path.parent, directory=True)
        raw = path.read_bytes()
        self.assertEqual(len(raw), details['sizeBytes'])
        self.assertEqual(hashlib.sha256(raw).hexdigest(), details['sha256'])
        document = json.loads(raw)
        self.assertEqual(document['schemaVersion'], 1)
        self.assertEqual(document['kind'], 'cosmoedge_deployment_receipt')
        self.assertEqual(document['candidate'], IDENTITY)
        self.assertNotIn(str(path), result.get('attachmentFiles', []))
        return document['receipt']

    def test_catalog_preserves_server_totals_in_real_cli_output(self):
        catalog = {
            'ok': True,
            'sources': [{'name': '入口', 'kind': 'network_camera'},
                        {'name': '测试视频', 'kind': 'test_video'},
                        {'name': 'USB', 'kind': 'usb_camera'},
                        {'name': '扩展来源', 'kind': 'future_source'}],
            'algorithms': [{'name': '安全帽'}],
            'tasks': [{'runtime': 'running'}, {'runtime': 'stopped'},
                      {'runtime': 'unknown'}],
            'totals': {'sourceCount': 4,
                       'sourcesByKind': {'network_camera': 1, 'test_video': 1,
                                         'usb_camera': 1, 'unknown': 1},
                       'algorithmCount': 1, 'taskCount': 3,
                       'runningTaskCount': 1, 'stoppedTaskCount': 1,
                       'unknownRuntimeTaskCount': 1},
        }
        self.stub.routes[('GET', '/operations/v1/catalog')] = (200, catalog)
        code, result = self.invoke('catalog', wrapper=True)
        self.assertEqual(code, 0)
        self.assertEqual(result, dict(catalog, sessionRef=SESSION))
        self.assertEqual([(call['method'], call['path']) for call in self.stub.calls],
                         [('GET', '/operations/v1/version'),
                          ('GET', '/operations/v1/catalog')])

    def test_request_file_is_opaque_data_and_wrapper_is_real_process(self):
        marker = self.root / 'must-not-exist'
        question = '现在有没有人？ $(touch ' + str(marker) + ') `touch ' + str(marker) + '` ; echo leaked'
        path = self.request_file({'sourceName': '前厅', 'subject': '人员', 'question': question, 'requestId': 'request_opaque'})
        code, result = self.invoke('observe', '--request-file', str(path), wrapper=True,
                                   env={'PYTHONIOENCODING': 'cp1252:strict', 'PYTHONUTF8': '0'})
        self.assertEqual(code, 0)
        self.assertTrue(result['ok'])
        self.assertEqual(result['userMessage'], '已完成。')
        self.assertFalse(marker.exists())
        posts = [c for c in self.stub.calls if c['method'] == 'POST']
        self.assertEqual(len(posts), 1)
        self.assertEqual(posts[0]['body']['question'], question)
        self.assertEqual(posts[0]['body']['requestId'], 'request_opaque')
        self.assertEqual(posts[0]['session'], SESSION)

    def test_summary_rejects_days_in_cli_and_request_file_before_network(self):
        for extra in [('--days', '7'), ('--days=7',),
                      ('--days', '7', '--start', '2026-08-31', '--end', '2026-09-07')]:
            with self.subTest(arguments=extra):
                code, result = self.invoke('summary', *extra, wrapper=True)
                self.assertEqual((code, result['code']), (1, 'invalid_arguments'))
                self.assertIn('起止时间', result['userMessage'])
        for data in ({'days': 7}, {'days': 7, 'start': '2026-08-31', 'end': '2026-09-07'}):
            with self.subTest(request=data):
                path = self.request_file(data)
                code, result = self.invoke('summary', '--request-file', str(path), wrapper=True)
                self.assertEqual((code, result['code']), (1, 'invalid_arguments'))
        self.assertEqual(self.stub.calls, [])

    def test_summary_requires_both_window_boundaries_before_network(self):
        for data in ({}, {'start': '2026-08-31'}, {'end': '2026-09-07'},
                     {'start': '', 'end': '2026-09-07'}, {'start': '2026-08-31', 'end': ''}):
            with self.subTest(request=data):
                path = self.request_file(data)
                code, result = self.invoke('summary', '--request-file', str(path), wrapper=True)
                self.assertEqual((code, result['code']), (1, 'invalid_arguments'))
                self.assertIn('起止时间', result['userMessage'])
        for extra in (('--start', '2026-08-31'), ('--end', '2026-09-07')):
            code, result = self.invoke('summary', *extra, wrapper=True)
            self.assertEqual((code, result['code']), (1, 'invalid_arguments'))
        self.assertEqual(self.stub.calls, [])

    def test_summary_preserves_shanghai_full_day_half_open_window(self):
        # August 31 through September 6 inclusive uses September 7 midnight as
        # the exclusive boundary. The client must not replace it with now-7d.
        for start, end in [('2026-08-31', '2026-09-07'),
                           ('2026-08-31T00:00:00+08:00', '2026-09-07T00:00:00+08:00')]:
            with self.subTest(start=start):
                path = self.request_file({'start': start, 'end': end, 'timeZone': 'Asia/Shanghai',
                                          'sourceName': '大厅', 'algorithmName': '人员检测'})
                code, result = self.invoke('summary', '--request-file', str(path), wrapper=True)
                self.assertEqual(code, 0)
                self.assertTrue(result['ok'])
        posts = [call for call in self.stub.calls if call['method'] == 'POST']
        self.assertEqual(len(posts), 2)
        for call in posts:
            self.assertEqual(call['path'], '/operations/v1/summary')
            self.assertEqual(call['body'], {'start': '2026-08-31T00:00:00+08:00',
                                           'end': '2026-09-07T00:00:00+08:00', 'timeZone': 'Asia/Shanghai',
                                           'sourceName': '大厅', 'algorithmName': '人员检测'})
            self.assertEqual(call['session'], SESSION)

    def test_python39_real_interpreter(self):
        interpreter = '/usr/bin/python3'
        if not Path(interpreter).is_file():
            self.skipTest('macOS Python interpreter unavailable')
        version = subprocess.check_output([interpreter, '-c', 'import sys; print(sys.version_info[:2])'], text=True).strip()
        if tuple(map(int, version.strip('()').split(', '))) != (3, 9):
            self.skipTest('the installed system interpreter is not Python 3.9')
        code, result = self.invoke('catalog', python=interpreter)
        self.assertEqual(code, 0)
        self.assertTrue(result['ok'])

    def test_summary_camera_group_stays_one_query_without_inferred_algorithm(self):
        original = summary_report_response()
        original['summaryReport']['filters'] = {'sourceName': '一楼、二楼', 'algorithmName': ''}
        self.stub.routes[('POST', '/operations/v1/summary')] = (200, original)
        path = self.request_file({'start': '2026-05-01', 'end': '2026-05-04',
                                  'sourceNames': ['一楼', '二楼']})
        code, result = self.invoke('summary', '--request-file', str(path), wrapper=True)
        self.assertEqual(code, 0)
        posts = [call for call in self.stub.calls if call['method'] == 'POST']
        self.assertEqual(len(posts), 1)
        self.assertEqual(posts[0]['body']['sourceNames'], ['一楼', '二楼'])
        self.assertNotIn('sourceName', posts[0]['body'])
        self.assertEqual(posts[0]['body']['algorithmName'], '')
        self.assertEqual(result['summaryContext']['filters'], original['summaryReport']['filters'])
        self.assertEqual(Path(result['attachmentFiles'][0]).read_text(encoding='utf-8'), original['userMessage'])

    def test_invalid_camera_groups_cannot_become_unfiltered_requests_or_deployments(self):
        for names in ([], '', '一楼', None, [None], [''], ['  '], ['一楼', 2]):
            with self.subTest(names=names):
                path = self.request_file({'start': '2026-05-01', 'end': '2026-05-04', 'sourceNames': names})
                code, result = self.invoke('summary', '--request-file', str(path), wrapper=True)
                self.assertEqual((code, result['code']), (1, 'invalid_arguments'))
        for command, data in (
                ('summary', {'start': '2026-05-01', 'end': '2026-05-04', 'sourceName': '一楼'}),
                ('deploy', {'sourceName': '一楼', 'algorithmName': '人员检测'})):
            path = self.request_file(dict(data, sourceNames=['二楼']))
            code, result = self.invoke(command, '--request-file', str(path), wrapper=True)
            self.assertEqual((code, result['code']), (1, 'invalid_arguments'))
        self.assertEqual(self.stub.calls, [])

    def test_summary_delivers_exact_original_and_computed_facts_without_catalog(self):
        original = summary_report_response(partial=True)
        self.stub.routes[('POST', '/operations/v1/summary')] = (200, original)
        path = self.request_file({'start': '2026-05-01', 'end': '2026-05-04',
                                  'timeZone': 'Asia/Shanghai', 'sourceName': ' 明确机位 '})
        code, result = self.invoke('summary', '--request-file', str(path), wrapper=True)
        self.assertEqual(code, 0)
        self.assertTrue(result['ok'])
        self.assertTrue(result['partial'])
        self.assertIn(original['summaryReport']['headline'], result['userMessage'])
        self.assertIn('本次记录未读取完整', result['userMessage'])
        self.assertEqual(result['summary'], original['summary'])
        self.assertEqual(result['peak'], original['peak'])
        self.assertNotIn('summaryReport', result)
        self.assertEqual(result['summaryEvidence'], original['summaryEvidence'])
        for key in ('window', 'timeZone', 'coverage', 'sourceKindScope', 'sourceKindBasis'):
            self.assertEqual(result['summaryContext'][key], original['summary'][key])
        self.assertEqual(result['summaryContext']['filters'], original['summaryReport']['filters'])
        self.assertEqual(result['reportDelivery']['state'], 'ready')
        self.assertIn('尚未交付', result['reportDelivery']['userMessage'])
        self.assertEqual(result['reportDelivery']['candidate'], IDENTITY)
        report_file = Path(result['attachmentFiles'][0])
        self.assertTrue(report_file.is_absolute())
        self.assertEqual(report_file.name, '统计报告.md')
        self.assertEqual(report_file.read_bytes(), original['userMessage'].encode('utf-8'))
        assert_private(self, report_file)
        assert_private(self, report_file.parent, directory=True)
        provenance_path = report_file.parent / 'report-provenance.json'
        provenance = json.loads(provenance_path.read_bytes())
        self.assertEqual(provenance, {'schemaVersion': 1, 'kind': 'cosmoedge_summary_report',
                                     'reportFile': '统计报告.md', 'sha256': hashlib.sha256(report_file.read_bytes()).hexdigest(),
                                     'sizeBytes': len(report_file.read_bytes()), 'contentType': 'text/markdown; charset=utf-8',
                                     'candidate': IDENTITY})
        assert_private(self, provenance_path)
        self.assertEqual(set(report_file.parent.iterdir()), {report_file, provenance_path})
        self.assertEqual(result['attachmentFiles'], [str(report_file)])
        self.assertEqual([(c['method'], c['path']) for c in self.stub.calls],
                         [('GET', '/operations/v1/version'), ('POST', '/operations/v1/summary')])

    def test_summary_report_rejects_changed_response_candidate_without_new_request(self):
        original = summary_report_response()
        original['summaryReport']['candidate']['revision'] = 'f' * 40
        self.stub.routes[('POST', '/operations/v1/summary')] = (200, original)
        code, result = self.invoke('summary', '--start', '2026-05-01', '--end', '2026-05-04')
        self.assertEqual(code, 0)
        self.assertEqual(result['reportDelivery']['code'], 'report_candidate_mismatch')
        self.assertTrue(result['ok'])
        self.assertFalse(result['partial'])
        self.assertEqual(result['attachmentFiles'], [])
        self.assertEqual(result['summaryContext']['coverage'], original['summary']['coverage'])
        self.assertEqual(len(self.stub.calls), 2)

    def test_summary_business_error_keeps_original_failure_and_does_not_prepare_report(self):
        original = {'ok': False, 'code': 'source_ambiguous_or_missing',
                    'partial': True, 'userMessage': '请明确机位名称。'}
        self.stub.routes[('POST', '/operations/v1/summary')] = (409, original)
        code, result = self.invoke('summary', '--start', '2026-05-01', '--end', '2026-05-04')
        self.assertEqual(code, 0)
        for key, value in original.items():
            self.assertEqual(result[key], value)
        self.assertNotIn('reportDelivery', result)
        self.assertNotIn('attachmentFiles', result)
        self.assertEqual(len(self.stub.calls), 2)

    def test_selected_observation_source_ref_is_preserved(self):
        selected = 'source_' + '7' * 24
        path = self.request_file({'sourceName': '同名机位', 'sourceRef': selected,
                                  'subject': '人员', 'question': '现在有人吗？'})
        code, result = self.invoke('observe', '--request-file', str(path))
        self.assertEqual(code, 0)
        posts = [c for c in self.stub.calls if c['method'] == 'POST']
        self.assertEqual(len(posts), 1)
        self.assertEqual(posts[0]['body']['sourceRef'], selected)

    def test_deploy_stop_cannot_carry_confirmation_fields_before_any_transport(self):
        # The real D4 misuse must fail locally, with or without source/algorithm.
        # Removing the token also proves validation precedes credential loading.
        self.token.unlink()
        for command in ('deploy', 'stop'):
            for fields in ({'operationRef': 'op_1', 'confirmationToken': 'private_confirmation'},
                           {'operationRef': 'op_1'}, {'confirmationToken': 'private_confirmation'},
                           {'operationRef': '', 'confirmationToken': ''}):
                with self.subTest(command=command, fields=list(fields)):
                    path = self.request_file(dict(fields, sourceName='入口', algorithmName='目录算法'))
                    code, result = self.invoke(command, '--request-file', str(path), wrapper=True)
                    self.assertEqual((code, result['code']), (1, 'confirmation_command_required'))
                    self.assertFalse(result['requestSubmitted'])
                    self.assertIn('用户在该页明确确认', result['clientInstruction'])
                    self.assertIn('confirm', result['clientInstruction'])
                    self.assertIn('deployment', result['clientInstruction'])
                    self.assertNotIn('起止时间', result['userMessage'])
                    self.assertNotIn('private_confirmation', json.dumps(result))
                    self.assertNotIn('continuation', result)
        code, result = self.invoke('deploy', '--operation-ref', 'op_1',
                                   '--confirmation-token', 'private_confirmation')
        self.assertEqual((code, result['code']), (1, 'confirmation_command_required'))
        self.assertFalse(result['requestSubmitted'])
        self.assertEqual(self.stub.calls, [])

    def test_non_ascii_request_ids_have_precise_local_error_and_are_not_rewritten(self):
        for command, request_id in (('deploy', '轨道部署'), ('stop', 'request_é'),
                                    ('observe', 'Ａ123'), ('deployment', '原请求')):
            with self.subTest(command=command):
                path = self.request_file({'requestId': request_id, 'sourceName': '入口',
                                          'algorithmName': '目录算法', 'subject': '人员', 'question': '是否有人'})
                code, result = self.invoke(command, '--request-file', str(path), wrapper=True)
                self.assertEqual((code, result['code']), (1, 'invalid_request_id'))
                self.assertFalse(result['requestSubmitted'])
                self.assertIn('ASCII', result['clientInstruction'])
                self.assertIn('省略', result['clientInstruction'])
                self.assertIn('结果未知', result['clientInstruction'])
                self.assertNotIn('起止时间', result['userMessage'])
                self.assertNotIn('requestId', result)
                self.assertNotIn('continuation', result)
        self.assertEqual(self.stub.calls, [])

    def test_fresh_requests_persist_id_and_review_only_opens_local_page(self):
        for command in ('deploy', 'stop', 'observe'):
            path = self.request_file({'sourceName': '入口', 'algorithmName': '目录算法',
                                      'subject': '人员', 'question': '是否有人'})
            code, result = self.invoke(command, '--request-file', str(path), wrapper=True)
            self.assertEqual(code, 0)
            self.assertRegex(result['requestId'], r'^[0-9a-f]{32}$')
            self.assertEqual(self.stub.calls[-1]['body']['requestId'], result['requestId'])
            saved = json.loads(path.read_bytes())
            self.assertEqual(saved['requestId'], result['requestId'])
            self.assertEqual(saved['sessionRef'], SESSION)
            self.assertEqual(saved['operationKind'], 'observation' if command == 'observe' else 'deployment')
            self.assertNotIn('operationKind', self.stub.calls[-1]['body'])
            assert_private(self, path)
        before = len(self.stub.calls)
        self.stub.post_result = {'ok': True, 'operationRef': 'op_1', 'interactionRequired': True,
                                'confirmationMode': 'local_page', 'supportedInteraction': 'deployment_confirmation',
                                'pageOpened': True}
        path = self.request_file({'sessionRef': SESSION, 'operationRef': 'op_1'})
        code, result = self.invoke('confirm', '--request-file', str(path), wrapper=True)
        self.assertEqual(code, 0)
        self.assertTrue(result['ok'])
        calls = self.stub.calls[before:]
        self.assertEqual([(c['method'], c['path']) for c in calls],
                         [('GET', '/operations/v1/version'), ('POST', '/operations/v1/deployments/review')])
        self.assertEqual(calls[1]['body'], {'operationRef': 'op_1'})
        self.assertTrue(result['pageOpened'])
        self.assertTrue(result['interactionRequired'])
        self.assertEqual(result['confirmationMode'], 'local_page')
        self.assertNotIn('confirmationToken', result)

    def test_proposal_scope_survives_cli_without_poll_or_confirmation(self):
        scope = {'resultScope': 'proposal_only', 'targetScope': 'original_proposal',
                 'currentScope': 'not_provided', 'currentReadbackProvided': False}
        message = '本回执仅说明该提议尚未派发；未提供当前设备状态回读，不能据此认定设备仍与上次一致。'
        for command in ('deploy', 'deployment', 'confirm'):
            with self.subTest(command=command):
                response = {'ok': True, 'operationRef': 'op_1', 'interactionRequired': True,
                            'confirmationMode': 'local_page', 'supportedInteraction': 'deployment_confirmation',
                            'deploymentEvidence': dict(scope), 'userMessage': message}
                if command == 'confirm':
                    response['pageOpened'] = True
                else:
                    response.update({'proposalCreated': True, 'proposal': {'state': 'proposed', 'enabled': False}})
                method = 'GET' if command == 'deployment' else 'POST'
                route = {'deploy': '/operations/v1/deployments',
                         'deployment': '/operations/v1/deployments/op_1',
                         'confirm': '/operations/v1/deployments/review'}[command]
                self.stub.routes[(method, route)] = (200, response)
                body = {'sourceName': '入口', 'algorithmName': '目录算法'} if command == 'deploy' else {'operationRef': 'op_1'}
                path = self.request_file(body)
                before = len(self.stub.calls)
                code, result = self.invoke(command, '--request-file', str(path), wrapper=True)
                self.assertEqual(code, 0)
                self.assertEqual(self.deployment_receipt(result)['deploymentEvidence'], scope)
                self.assertNotIn('deploymentEvidence', result)
                if command != 'confirm':
                    self.assertIs(result['proposal']['enabled'], False)
                self.assertEqual(result['userMessage'], message)
                self.assertNotIn('current', result)
                self.assertNotIn('deployment', result)
                self.assertNotIn('confirmationToken', result)
                self.assertNotIn('confirmationReceipt', result)
                self.assertEqual([(c['method'], c['path']) for c in self.stub.calls[before:]],
                                 [('GET', '/operations/v1/version'), (method, route)])

    def test_dispatch_write_accounting_survives_read_only_cli(self):
        for outcome, state, writes in [('accepted', 'completed', 0), ('accepted', 'completed', 1),
                                       ('known_failed', 'blocked', 0), ('outcome_unknown', 'unknown', 1)]:
            with self.subTest(outcome=outcome, writes=writes):
                message = '设备写入计数包含启停开关写入，并非仅指参数重写，也不等于网络请求次数。'
                response = {'ok': state == 'completed', 'operationRef': 'op_1', 'pending': False,
                            'deployment': {'state': state, 'class': state, 'dispatchOutcome': outcome,
                                           'dispatches': 1, 'deviceWrites': writes},
                            'deploymentEvidence': {'counterScope': 'operation_lifetime',
                                                   'deviceWriteScope': 'configuration_and_enable_switch_accounting'},
                            'userMessage': message}
                self.stub.routes[('GET', '/operations/v1/deployments/op_1')] = (200, response)
                path = self.request_file({'operationRef': 'op_1'})
                before = len(self.stub.calls)
                code, result = self.invoke('deployment', '--request-file', str(path), wrapper=True)
                self.assertEqual(code, 0)
                receipt = self.deployment_receipt(result)
                self.assertEqual(receipt['deployment'], response['deployment'])
                self.assertEqual(receipt['deploymentEvidence'], response['deploymentEvidence'])
                self.assertEqual(result['deployment'], {'state': state, 'class': state, 'currentReadbackAvailable': False})
                self.assertNotIn('deploymentEvidence', result)
                self.assertNotIn('clientInstruction', result)
                self.assertEqual(result['userMessage'], message)
                self.assertEqual(result['ok'], response['ok'])
                self.assertEqual([(c['method'], c['path']) for c in self.stub.calls[before:]],
                                 [('GET', '/operations/v1/version'), ('GET', '/operations/v1/deployments/op_1')])

    def test_deployment_stdout_keeps_business_and_time_facts_with_private_full_receipt(self):
        original = {'exists': True, 'enabled': 0, 'configurationMatch': True, 'runtime': 'stopped',
                    'observedAt': '2026-09-10T10:00:00Z', 'sealedAt': '2026-09-10T10:00:01Z'}
        current = {'exists': True, 'enabled': 1, 'configurationMatch': True, 'runtime': 'processing',
                   'observedAt': '2026-09-10T10:05:00Z',
                   'progress': [{'nodeId': 'node_internal', 'before': 40, 'after': 60}]}
        message = '设备资源不足，这次启用未完成。入口的人员检测目前正在运行。'
        response = {'ok': False, 'pending': False, 'operationRef': 'op_1',
                    'pollPath': '/operations/v1/deployments/op_1', 'userMessage': message,
                    'deployment': {'state': 'blocked', 'class': 'failed', 'reason': 'deployment_rejected',
                                   'dispatches': 1, 'deviceWrites': 0, 'dispatchOutcome': 'known_failed',
                                   'diagnostic': {'operation': 'task_switch', 'msgCode': '8'},
                                   'target': {'state': 'proposed', 'sourceName': '入口', 'algorithmName': '人员检测',
                                              'enabled': True, 'configurationKind': 'existing_binding',
                                              'expiresAt': '2026-09-10T09:59:00Z'},
                                   'originalVerification': original, 'current': current},
                    'deploymentEvidence': {'counterScope': 'operation_lifetime'}}
        self.stub.routes[('GET', '/operations/v1/deployments/op_1')] = (200, response)
        code, result = self.invoke('deployment', '--operation-ref', 'op_1', wrapper=True)
        self.assertEqual(code, 0)
        self.assertFalse(result['ok'])
        self.assertEqual(result['userMessage'], message)
        self.assertEqual(result['deployment'], {
            'state': 'blocked', 'class': 'failed', 'sourceName': '入口', 'algorithmName': '人员检测',
            'currentReadbackAvailable': True, 'currentObservedAt': current['observedAt'],
            'originalObservedAt': original['observedAt'], 'originalSealedAt': original['sealedAt']})
        for omitted in ('enabled', 'configurationMatch', 'msgCode', 'dispatches', 'deviceWrites', 'progress', 'configurationKind'):
            self.assertNotIn(omitted, json.dumps(result))
        receipt = self.deployment_receipt(result)
        for key, value in response.items():
            self.assertEqual(receipt[key], value, key)
        self.assertEqual(receipt['sessionRef'], SESSION)
        self.assertEqual(receipt['operationRef'], 'op_1')
        self.assertFalse([c for c in self.stub.calls if c['method'] == 'POST'])

    def test_deployment_without_current_does_not_borrow_original_time(self):
        self.stub.routes[('GET', '/operations/v1/deployments/op_1')] = (200, {
            'ok': True, 'operationRef': 'op_1', 'userMessage': '此前已确认运行。暂时没取到最新状态。',
            'deployment': {'state': 'completed', 'class': 'completed',
                           'originalVerification': {'observedAt': '2026-09-10T10:00:00Z',
                                                    'sealedAt': '2026-09-10T10:00:01Z'}}})
        code, result = self.invoke('deployment', '--operation-ref', 'op_1')
        self.assertEqual(code, 0)
        self.assertFalse(result['deployment']['currentReadbackAvailable'])
        self.assertNotIn('currentObservedAt', result['deployment'])
        self.assertNotIn('lastKnownObservedAt', result['deployment'])
        self.assertEqual(result['deployment']['originalObservedAt'], '2026-09-10T10:00:00Z')
        self.deployment_receipt(result)

    def test_configuration_requirement_preserves_missing_inputs_without_an_editor(self):
        response = {'ok': False, 'interactionRequired': False, 'proposalCreated': False,
                    'supportedInteraction': 'none', 'userMessage': '还需要明确区域，当前入口没有配置页面。',
                    'configurationRequirement': {'state': 'needs_input', 'sourceName': '入口',
                                                 'algorithmName': '区域检测', 'enabled': True,
                                                 'missing': ['algorithmRegion 必须明确']}}
        self.stub.post_result = response
        code, result = self.invoke('deploy', '--source', '入口', '--algorithm', '区域检测')
        self.assertEqual(code, 0)
        self.assertFalse(result['interactionRequired'])
        self.assertFalse(result['proposalCreated'])
        self.assertEqual(result['supportedInteraction'], 'none')
        self.assertEqual(result['configurationRequirement']['missing'], ['algorithmRegion 必须明确'])
        self.assertNotIn('proposal', result)
        self.assertEqual(self.deployment_receipt(result)['configurationRequirement'], response['configurationRequirement'])
        self.assertEqual([c['path'] for c in self.stub.calls if c['method'] == 'POST'], ['/operations/v1/deployments'])

    def test_deployment_receipt_save_failure_preserves_success_and_original_query(self):
        # Fault only this child's optional detail writer, after real HTTP I/O.
        hooks = self.root / 'test-hooks'
        hooks.mkdir()
        (hooks / 'sitecustomize.py').write_text(
            "import sys\n"
            "sys.path.insert(0, " + repr(str(self.skill / 'scripts')) + ")\n"
            "import local_files\n"
            "original = local_files.private_tempdir\n"
            "def unavailable(*args, **kwargs):\n"
            "    if kwargs.get('prefix') == 'cosmoedge-deployment-':\n"
            "        raise OSError('test detail storage unavailable')\n"
            "    return original(*args, **kwargs)\n"
            "local_files.private_tempdir = unavailable\n")
        response = {'ok': True, 'pending': False, 'operationRef': 'op_1', 'userMessage': '入口的人员检测目前正在运行。',
                    'deployment': {'state': 'completed', 'class': 'completed', 'dispatches': 1, 'deviceWrites': 1}}
        self.stub.post_result = response
        code, result = self.invoke('confirm', '--operation-ref', 'op_1', env={'PYTHONPATH': str(hooks)})
        self.assertEqual(code, 0)
        self.assertTrue(result['ok'])
        self.assertEqual(result['userMessage'], response['userMessage'])
        self.assertEqual(result['deployment']['state'], 'completed')
        self.assertEqual(result['deploymentDetails'], {'state': 'unavailable', 'code': 'details_save_failed'})
        self.assertEqual(result['operationRef'], 'op_1')
        self.assertEqual(result['sessionRef'], SESSION)
        self.assertEqual([c['path'] for c in self.stub.calls if c['method'] == 'POST'],
                         ['/operations/v1/deployments/review'])
        self.stub.routes[('GET', '/operations/v1/deployments/op_1')] = (200, response)
        code, followup = self.invoke('deployment', '--operation-ref', result['operationRef'])
        self.assertEqual(code, 0)
        self.assertEqual(self.deployment_receipt(followup)['deployment'], response['deployment'])
        self.assertEqual(len([c for c in self.stub.calls if c['method'] == 'POST']), 1)

    def test_non_summary_argument_errors_do_not_request_a_date_window(self):
        code, result = self.invoke('confirm')
        self.assertEqual((code, result['code']), (1, 'invalid_arguments'))
        self.assertNotIn('起止时间', result['userMessage'])
        self.assertEqual(self.stub.calls, [])

    def test_unusable_source_ref_is_rejected_before_network(self):
        for command, value in [('observe', 'guessed_source'), ('deploy', 'source_' + '7' * 24)]:
            code, result = self.invoke(command, '--source-ref', value,
                                       '--subject', '人员', '--question', '有人吗？')
            self.assertNotEqual(code, 0)
            self.assertEqual(result['code'], 'invalid_arguments')
        self.assertEqual(self.stub.calls, [])

    def test_pairing_version_or_source_mismatch_prevents_business_post(self):
        self.stub.identity['revision'] = 'f' * 40
        code, result = self.invoke('deploy', '--source', '入口', '--algorithm', '安全帽')
        self.assertEqual(code, 1)
        self.assertEqual(result['code'], 'version_mismatch')
        self.assertEqual([c['path'] for c in self.stub.calls], ['/operations/v1/version'])

    def test_pairing_client_digest_and_missing_candidate_prevent_network(self):
        with (self.skill / 'scripts/cosmoedge_operations.py').open('a') as stream:
            stream.write('\n# drift\n')
        code, result = self.invoke('catalog')
        self.assertEqual((code, result['code']), (1, 'version_mismatch'))
        self.assertEqual(self.stub.calls, [])
        (self.skill / 'candidate.json').unlink()
        code, result = self.invoke('catalog', '--allow-unpaired-development')
        self.assertEqual((code, result['code']), (1, 'version_mismatch'))
        self.assertEqual(self.stub.calls, [])

    def test_development_bypass_requires_explicit_flag_and_actual_repo_path(self):
        if (SCRIPTS.parent / 'candidate.json').exists():
            self.skipTest('source tree carries a candidate; missing-manifest bypass does not apply')
        arguments = [sys.executable, str(SCRIPTS / 'operations_client.py'), 'catalog', '--base-url', self.stub.base,
                     '--token-file', str(self.token), '--session-ref', SESSION, '--wait-seconds', '0']
        process = subprocess.run(arguments, capture_output=True, text=True, encoding='utf-8', timeout=5)
        self.assertEqual(json.loads(process.stdout)['code'], 'version_mismatch')
        process = subprocess.run(arguments + ['--allow-unpaired-development'], capture_output=True, text=True, encoding='utf-8', timeout=5)
        self.assertEqual(process.returncode, 0, process.stdout)
        self.assertTrue(json.loads(process.stdout)['ok'])
        self.assertEqual([call['path'] for call in self.stub.calls], ['/operations/v1/catalog'])

    def test_pairing_parent_symlink_or_traversal_rejects(self):
        extra = self.root / 'extra'
        extra.mkdir()
        (extra / 'helper.py').write_text('# helper\n')
        try:
            (self.skill / 'scripts/linked').symlink_to(extra, target_is_directory=True)
        except OSError as error:
            if getattr(error, 'winerror', None) == 1314:
                self.skipTest('Windows account cannot create symbolic links')
            raise
        self.candidate['clientFiles']['scripts/linked/helper.py'] = hashlib.sha256((extra / 'helper.py').read_bytes()).hexdigest()
        self.write_candidate()
        code, result = self.invoke('catalog')
        self.assertEqual((code, result['code']), (1, 'version_mismatch'))
        (self.skill / 'scripts/linked').unlink()
        del self.candidate['clientFiles']['scripts/linked/helper.py']
        self.candidate['clientFiles']['scripts/../../outside.py'] = 'a' * 64
        self.write_candidate()
        code, result = self.invoke('catalog')
        self.assertEqual((code, result['code']), (1, 'version_mismatch'))
        self.assertEqual(self.stub.calls, [])

    def test_request_file_symlink_permissions_duplicate_keys_nul_and_unknown_keys(self):
        path = self.request_file({'sourceName': '前厅'})
        alias = self.root / 'alias.json'
        try:
            alias.symlink_to(path)
        except OSError as error:
            if getattr(error, 'winerror', None) == 1314:
                self.skipTest('Windows account cannot create symbolic links')
            raise
        cases = [(alias, None), (path, {'sourceName': '前厅\x00坏'}), (path, {'command': 'stop'}), (path, {'days': True})]
        for target, data in cases:
            if data is not None:
                path.write_text(json.dumps(data))
            code, result = self.invoke('deploy', '--request-file', str(target))
            self.assertEqual((code, result['code']), (1, 'invalid_arguments'))
        path.write_text('{"sourceName":"前厅","sourceName":"后门"}', encoding='utf-8')
        code, result = self.invoke('deploy', '--request-file', str(path))
        self.assertEqual((code, result['code']), (1, 'invalid_arguments'))
        path.write_text('{}')
        if os.name == 'nt':
            subprocess.run(['icacls', str(path), '/grant', '*S-1-1-0:(R)'], check=True, capture_output=True)
        else:
            path.chmod(0o644)
        code, result = self.invoke('deploy', '--request-file', str(path))
        self.assertEqual((code, result['code']), (1, 'invalid_arguments'))
        self.assertEqual(self.stub.calls, [])

    def test_cancel_uses_original_proposal_without_new_request_or_confirmation_token(self):
        self.stub.routes[('POST', '/operations/v1/deployments/cancel')] = (200, {
            'ok': True, 'cancelled': True, 'operationRef': 'op_1', 'userMessage': '已取消。'})
        path = self.request_file({'sessionRef': SESSION, 'operationRef': 'op_1'})
        before = path.read_bytes()
        code, result = self.invoke('cancel', '--request-file', str(path), wrapper=True)
        self.assertEqual(code, 0)
        self.assertTrue(result['cancelled'])
        self.assertNotIn('requestId', result)
        self.assertEqual(path.read_bytes(), before)
        posts = [call for call in self.stub.calls if call['method'] == 'POST']
        self.assertEqual(posts, [{'method': 'POST', 'path': '/operations/v1/deployments/cancel',
                                 'body': {'operationRef': 'op_1'}, 'session': SESSION}])

    def test_cancel_preserves_rejection_while_original_operation_is_pending_without_polling(self):
        rejection = {'ok': False, 'cancelled': False, 'code': 'deployment_not_cancellable',
                     'pending': True, 'operationRef': 'op_1',
                     'pollPath': '/operations/v1/deployments/op_1',
                     'deployment': {'state': 'dispatching'},
                     'userMessage': '这次操作已确认或结束，不能再作为待办取消。'}
        self.stub.routes[('POST', '/operations/v1/deployments/cancel')] = (409, rejection)
        self.stub.routes[('GET', '/operations/v1/deployments/op_1')] = (200, {
            'ok': True, 'pending': False, 'operationRef': 'op_1',
            'deployment': {'state': 'completed'}, 'userMessage': '目前正在运行。'})
        path = self.request_file({'sessionRef': SESSION, 'operationRef': 'op_1'})
        code, result = self.invoke('cancel', '--request-file', str(path), wrapper=True, wait_seconds=None)
        self.assertEqual(code, 0)
        receipt = self.deployment_receipt(result)
        for key, value in rejection.items():
            self.assertEqual(receipt.get(key), value, key)
            if key != 'deployment':
                self.assertEqual(result.get(key), value, key)
        self.assertEqual(result['deployment']['state'], 'dispatching')
        self.assertEqual(result['continuation'], {'command': 'deployment', 'sessionRef': SESSION, 'operationRef': 'op_1'})
        self.assertEqual([(call['method'], call['path']) for call in self.stub.calls], [
            ('GET', '/operations/v1/version'), ('POST', '/operations/v1/deployments/cancel')])

    def test_capture_uses_separate_endpoint_and_recovers_without_new_submission(self):
        self.stub.post_result = {'ok': True, 'pending': True, 'operationRef': 'op_1',
                                'pollPath': '/operations/v1/observations/op_1'}
        path = self.request_file({'sourceName': '入口', 'question': '这张图里有什么', 'waitSeconds': 0})
        code, result = self.invoke('capture', '--request-file', str(path), wrapper=True)
        self.assertEqual(code, 0)
        self.assertTrue(result['pending'])
        saved = json.loads(path.read_bytes())
        self.assertEqual(saved['operationKind'], 'observation')
        posts = [call for call in self.stub.calls if call['method'] == 'POST']
        self.assertEqual(len(posts), 1)
        self.assertEqual(posts[0]['path'], '/operations/v1/captures')
        self.assertNotIn('subject', posts[0]['body'])
        self.assertEqual(posts[0]['body']['question'], '这张图里有什么')
        code, recovered = self.invoke('recover-observation', '--request-file', str(path), wrapper=True)
        self.assertEqual(code, 0)
        self.assertEqual(recovered['requestId'], saved['requestId'])
        self.assertEqual(self.stub.calls[-1]['path'], '/operations/v1/observations/by-request/' + saved['requestId'])
        self.assertEqual(len([call for call in self.stub.calls if call['method'] == 'POST']), 1)
        code, rejected = self.invoke('capture', '--request-file', str(path), wrapper=True)
        self.assertEqual(rejected['code'], 'request_recovery_required')
        self.assertEqual(len([call for call in self.stub.calls if call['method'] == 'POST']), 1)

    def test_capture_delivers_original_without_inventing_an_edge_answer(self):
        item = {'path': '/operations/v1/media/capture-original', 'contentType': 'image/png',
                'sha256': hashlib.sha256(PNG).hexdigest()}
        observation = {'kind': 'capture', 'analysisSource': 'none', 'status': 'captured',
                       'sourceName': '新机位', 'sourceKind': 'test_video', 'frameTimeKnown': False,
                       'observedAt': '2026-09-10T10:00:00Z', 'timeMeaning': 'image_retrieved_at'}
        self.stub.post_result = {'ok': True, 'operationRef': 'op_1', 'observation': observation, 'attachments': [item]}
        self.stub.routes[('GET', item['path'])] = lambda handler: handler.reply(200, PNG, 'image/png')
        code, result = self.invoke('capture', '--source', '新机位', wrapper=True)
        self.assertEqual(code, 0)
        self.assertEqual(result['observation'], observation)
        self.assertNotIn('answer', result['observation'])
        self.assertEqual(Path(result['attachmentFiles'][0]).read_bytes(), PNG)
        self.assertEqual([call['path'] for call in self.stub.calls if call['method'] == 'POST'], ['/operations/v1/captures'])

    def test_pending_deadline_retains_reference_without_resubmission(self):
        pending = {'ok': True, 'pending': True, 'operationRef': 'op_1',
                   'pollPath': '/operations/v1/observations/op_1', 'userMessage': '正在查看。'}
        submitted_at = []

        def submit(handler):
            submitted_at.append(time.monotonic())
            handler.reply(200, pending)

        self.stub.routes[('POST', '/operations/v1/observations')] = submit
        # The operation remains pending throughout this turn, including if a
        # platform timer wakes just before the polling budget expires.
        self.stub.routes[('GET', '/operations/v1/observations/op_1')] = (200, pending)
        code, result = self.invoke('observe', '--source', '入口', '--subject', '人员',
                                   '--question', '现在有没有人', '--wait-seconds', '0.15')
        self.assertEqual(len(submitted_at), 1, result)
        # Bound the business wait rather than interpreter startup or pairing.
        self.assertLess(time.monotonic() - submitted_at[0], 1.2)
        self.assertEqual(code, 0)
        self.assertTrue(result.get('pending'), result)
        self.assertEqual(result['continuation']['operationRef'], 'op_1')
        self.assertRegex(result['requestId'], r'^[0-9a-f]{32}$')
        self.assertEqual(len([c for c in self.stub.calls if c['method'] == 'POST']), 1)
        self.stub.routes[('GET', '/operations/v1/observations/op_1')] = (200, {
            'ok': True, 'operationRef': 'op_1', 'state': 'complete', 'userMessage': '核查完成。'})
        code, follow = self.invoke('observation', '--operation-ref', result['operationRef'])
        self.assertEqual(code, 0)
        self.assertEqual(follow['state'], 'complete')
        self.assertEqual(follow['operationRef'], result['operationRef'])
        self.assertEqual(len([c for c in self.stub.calls if c['method'] == 'POST']), 1)

    def test_json_zero_wait_returns_actual_pending_without_poll_or_media_read(self):
        self.stub.post_result = {'ok': True, 'pending': True, 'operationRef': 'op_1',
            'pollPath': '/operations/v1/observations/op_1',
            'attachments': [{'path': '/operations/v1/media/not-yet-needed', 'contentType': 'image/png',
                             'sha256': hashlib.sha256(PNG).hexdigest()}]}
        path = self.request_file({'sessionRef': SESSION, 'sourceName': '入口', 'subject': '人员',
                                  'question': '现在有没有人', 'waitSeconds': 0})
        start = time.monotonic()
        # The JSON zero overrides this deliberately longer CLI wait.
        code, result = self.invoke('observe', '--request-file', str(path), '--wait-seconds', '3')
        self.assertLess(time.monotonic() - start, 1.5)
        self.assertEqual(code, 0)
        self.assertTrue(result['pending'])
        self.assertEqual(result['continuation']['operationRef'], 'op_1')
        self.assertNotIn('attachmentFiles', result)
        self.assertEqual([(c['method'], c['path']) for c in self.stub.calls],
                         [('GET', '/operations/v1/version'), ('POST', '/operations/v1/observations')])
        saved = json.loads(path.read_bytes())
        self.assertEqual(saved['waitSeconds'], 0)
        self.assertEqual(saved['requestId'], result['requestId'])
        self.assertNotIn('waitSeconds', self.stub.calls[-1]['body'])

    def test_default_observe_exposes_pending_without_poll_or_old_attachment_download(self):
        self.stub.post_result = {'ok': True, 'pending': True, 'operationRef': 'op_1',
            'pollPath': '/operations/v1/observations/op_1',
            'attachments': [{'path': '/operations/v1/media/old-image', 'contentType': 'image/png',
                             'sha256': hashlib.sha256(PNG).hexdigest()}]}
        for use_file in (False, True):
            with self.subTest(request_file=use_file):
                self.stub.calls.clear()
                if use_file:
                    path = self.request_file({'sourceName': '入口', 'subject': '人员', 'question': '有人吗'})
                    extra = ('--request-file', str(path))
                else:
                    extra = ('--source', '入口', '--subject', '人员', '--question', '有人吗')
                code, result = self.invoke('observe', *extra, wrapper=True, wait_seconds=None)
                self.assertEqual(code, 0)
                self.assertTrue(result['pending'])
                self.assertEqual(result['operationRef'], 'op_1')
                self.assertEqual(result['continuation'],
                                 {'command': 'observation', 'sessionRef': SESSION, 'operationRef': 'op_1'})
                self.assertNotIn('attachmentFiles', result)
                self.assertEqual([(c['method'], c['path']) for c in self.stub.calls],
                                 [('GET', '/operations/v1/version'), ('POST', '/operations/v1/observations')])
                self.assertNotIn('waitSeconds', self.stub.calls[-1]['body'])
                if use_file:
                    saved = json.loads(path.read_bytes())
                    self.assertEqual(saved['requestId'], result['requestId'])
                    self.assertEqual(saved['operationKind'], 'observation')
                    self.assertNotIn('waitSeconds', saved)

    def test_default_observe_terminal_still_delivers_original_without_polling(self):
        item = {'path': '/operations/v1/media/original', 'contentType': 'image/png',
                'sha256': hashlib.sha256(PNG).hexdigest()}
        self.stub.post_result = {'ok': True, 'pending': False, 'operationRef': 'op_1',
            'pollPath': '/operations/v1/observations/op_1', 'attachments': [item]}
        self.stub.routes[('GET', item['path'])] = lambda handler: handler.reply(200, PNG, 'image/png')
        code, result = self.invoke('observe', '--subject', '人员', '--question', '有人吗',
                                   wrapper=True, wait_seconds=None)
        self.assertEqual(code, 0)
        self.assertFalse(result['pending'])
        self.assertEqual(len(result['attachmentFiles']), 1)
        self.assertEqual(Path(result['attachmentFiles'][0]).read_bytes(), PNG)
        self.assertEqual(result['attachmentFailures'], [])
        self.assertEqual([(c['method'], c['path']) for c in self.stub.calls],
                         [('GET', '/operations/v1/version'), ('POST', '/operations/v1/observations'),
                          ('GET', item['path'])])

    def test_explicit_observe_wait_still_polls_and_json_overrides_cli_zero(self):
        self.stub.post_result = {'ok': True, 'pending': True, 'operationRef': 'op_1',
                                'pollPath': '/operations/v1/observations/op_1'}
        for json_wait in (False, True):
            with self.subTest(json_wait=json_wait):
                self.stub.calls.clear()
                if json_wait:
                    path = self.request_file({'subject': '人员', 'question': '有人吗', 'waitSeconds': 1.3})
                    extra = ('--request-file', str(path), '--wait-seconds', '0')
                else:
                    extra = ('--subject', '人员', '--question', '有人吗', '--wait-seconds', '1.3')
                code, result = self.invoke('observe', *extra, wrapper=True, wait_seconds=None)
                self.assertEqual(code, 0)
                self.assertFalse(result.get('pending', False))
                self.assertEqual(result['state'], 'complete')
                self.assertEqual([(c['method'], c['path']) for c in self.stub.calls],
                                 [('GET', '/operations/v1/version'), ('POST', '/operations/v1/observations'),
                                  ('GET', '/operations/v1/observations/op_1')])

    def test_other_commands_keep_default_polling_and_recovery_is_read_only(self):
        for command in ('deploy', 'stop', 'deployment', 'observation', 'recover-deployment', 'recover-observation'):
            with self.subTest(command=command):
                self.stub.calls.clear()
                self.stub.routes.clear()
                kind = 'observation' if 'observation' in command else 'deployment'
                poll_path = '/operations/v1/' + kind + 's/op_1'
                pending = {'ok': True, 'pending': True, 'operationRef': 'op_1', 'pollPath': poll_path}
                terminal = {'ok': True, 'pending': False, 'operationRef': 'op_1', 'state': 'complete'}
                self.stub.post_result = pending
                if command.startswith('recover-'):
                    path = self.request_file({'sessionRef': SESSION, 'requestId': 'original_request',
                                              'operationKind': kind}, name=command + '.json')
                    before = path.read_bytes()
                    extra = ('--request-file', str(path))
                    initial_method, initial_path = 'GET', '/operations/v1/' + kind + 's/by-request/original_request'
                    self.stub.routes[('GET', initial_path)] = (200, pending)
                    self.stub.routes[('GET', poll_path)] = (200, terminal)
                elif command in ('deployment', 'observation'):
                    extra = ('--operation-ref', 'op_1')
                    initial_method, initial_path = 'GET', poll_path
                    replies = iter([pending, terminal])
                    self.stub.routes[('GET', poll_path)] = lambda handler: handler.reply(200, next(replies))
                else:
                    extra = ()
                    initial_method, initial_path = 'POST', '/operations/v1/deployments'
                    self.stub.routes[('GET', poll_path)] = (200, terminal)
                code, result = self.invoke(command, *extra, wrapper=True, wait_seconds=None)
                self.assertEqual(code, 0)
                self.assertFalse(result['pending'])
                self.assertEqual(result['state'], 'complete')
                self.assertEqual([(c['method'], c['path']) for c in self.stub.calls],
                                 [('GET', '/operations/v1/version'), (initial_method, initial_path), ('GET', poll_path)])
                self.assertTrue(all(c['session'] == SESSION for c in self.stub.calls))
                if command.startswith('recover-'):
                    self.assertEqual(path.read_bytes(), before)

    def test_json_wait_validation_and_fast_terminal_do_not_invent_pending(self):
        for wait in (True, '0', -1, 56, None):
            path = self.request_file({'subject': '人员', 'question': '有人吗', 'waitSeconds': wait})
            code, result = self.invoke('observe', '--request-file', str(path))
            self.assertEqual((code, result['code']), (1, 'invalid_arguments'))
        self.assertEqual(self.stub.calls, [])
        path = self.request_file({'subject': '人员', 'question': '有人吗', 'waitSeconds': 0})
        code, result = self.invoke('observe', '--request-file', str(path))
        self.assertEqual(code, 0)
        self.assertEqual(result['state'], 'complete')
        self.assertFalse(result.get('pending', False))

    def test_killed_submit_recovers_durable_same_session_request_with_get_only(self):
        admitted, release = threading.Event(), threading.Event()
        captured = {}
        def hold_ack(handler):
            captured.update(self.stub.calls[-1]['body'])
            admitted.set()
            release.wait(4)
            handler.reply(200, {'ok': True, 'pending': True, 'operationRef': 'op_1',
                                'requestId': captured['requestId'], 'pollPath': '/operations/v1/observations/op_1'})
        self.stub.routes[('POST', '/operations/v1/observations')] = hold_ack
        original = {'sourceName': '入口', 'subject': '人员', 'question': '现在有人吗？', 'waitSeconds': 0}
        path = self.request_file(original)
        script = self.skill / 'scripts/cosmoedge_operations.py'
        process = subprocess.Popen([sys.executable, str(script), 'observe', '--base-url', self.stub.base,
                                    '--token-file', str(self.token), '--session-ref', SESSION,
                                    '--request-file', str(path)], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        try:
            self.assertTrue(admitted.wait(2), 'the stub never durably admitted the single POST')
            saved_raw = path.read_bytes()
            saved = json.loads(saved_raw)
            self.assertEqual(saved, dict(original, requestId=captured['requestId'], sessionRef=SESSION,
                                         operationKind='observation'))
            process.kill()
            stdout, stderr = process.communicate(timeout=2)
            self.assertEqual(stdout, b'')
            self.assertEqual(stderr, b'')
        finally:
            release.set()
            if process.poll() is None:
                process.kill()
                process.communicate(timeout=2)
        self.stub.routes[('GET', '/operations/v1/observations/by-request/' + saved['requestId'])] = (200, {
            'ok': True, 'pending': True, 'operationRef': 'op_1', 'requestId': saved['requestId'],
            'pollPath': '/operations/v1/observations/op_1'})
        code, result = self.invoke('recover-observation', '--request-file', str(path), wrapper=True)
        self.assertEqual(code, 0)
        self.assertTrue(result['pending'])
        self.assertEqual(result['operationRef'], 'op_1')
        self.assertEqual(result['requestId'], saved['requestId'])
        self.assertEqual(path.read_bytes(), saved_raw)
        self.assertEqual(self.stub.calls[-1]['session'], SESSION)
        self.assertEqual(self.stub.calls[-1]['method'], 'GET')
        count = len(self.stub.calls)
        code, result = self.invoke('observe', '--request-file', str(path))
        self.assertEqual((code, result['code']), (1, 'request_recovery_required'))
        self.assertFalse(result['requestSubmitted'])
        self.assertEqual(len(self.stub.calls), count)
        self.assertEqual(len([c for c in self.stub.calls if c['method'] == 'POST']), 1)

    def test_recovery_kind_session_and_missing_record_fail_closed(self):
        saved = {'sessionRef': SESSION, 'requestId': 'original_id', 'operationKind': 'observation',
                 'sourceName': '入口', 'subject': '人员', 'question': '有人吗？'}
        path = self.request_file(saved)
        for command, extra in [('recover-deployment', []),
                               ('recover-observation', ['--session-ref', OTHER_SESSION]),
                               ('recover-observation', ['--request-id', 'replacement_id'])]:
            code, result = self.invoke(command, '--request-file', str(path), *extra, wrapper=True)
            self.assertEqual(code, 1)
            self.assertIn(result['code'], ('request_recovery_required', 'request_binding_conflict'))
        path = self.request_file({'sessionRef': SESSION, 'sourceName': '入口'})
        code, result = self.invoke('recover-observation', '--request-file', str(path))
        self.assertEqual((code, result['code']), (1, 'request_recovery_required'))
        self.assertEqual(self.stub.calls, [])
        self.assertNotIn('requestId', json.loads(path.read_bytes()))

    def test_recovery_not_found_is_not_automatic_resubmission(self):
        path = self.request_file({'sessionRef': SESSION, 'requestId': 'prepared_but_not_sent',
                                  'operationKind': 'deployment'})
        before = path.read_bytes()
        self.stub.routes[('GET', '/operations/v1/deployments/by-request/prepared_but_not_sent')] = (404, {
            'ok': False, 'code': 'operation_not_found'})
        code, result = self.invoke('recover-deployment', '--request-file', str(path), wrapper=True)
        self.assertEqual(code, 0)
        self.assertFalse(result['ok'])
        self.assertEqual(result['code'], 'operation_not_found')
        self.assertFalse(result.get('pending', False))
        self.assertTrue(all(c['method'] == 'GET' for c in self.stub.calls))
        self.assertEqual(path.read_bytes(), before)

    def test_busy_recovery_lock_blocks_before_any_http(self):
        path = self.request_file({'subject': '人员', 'question': '有人吗？'})
        before = path.read_bytes()
        with os.fdopen(local_files.create_file(str(path) + '.cosmoedge-connect.lock'), 'w') as lock:
            local_files.lock_exclusive(lock.fileno())
            code, result = self.invoke('observe', '--request-file', str(path))
        self.assertEqual((code, result['code']), (1, 'request_persistence_failed'))
        self.assertFalse(result['requestSubmitted'])
        self.assertEqual(path.read_bytes(), before)
        self.assertEqual(self.stub.calls, [])

    def test_query_reference_error_can_be_corrected_without_business_resubmission(self):
        for command in ('deployment', 'observation'):
            for references in ({}, {'operationRef': 'op_1', 'requestId': 'request_1'}):
                with self.subTest(command=command, references=references):
                    self.stub.calls.clear()
                    path = self.request_file(references)
                    code, result = self.invoke(command, '--request-file', str(path), wrapper=True)
                    self.assertEqual((code, result['code']), (1, 'query_reference_required'))
                    self.assertFalse(result['requestSubmitted'])
                    self.assertIn('operationRef 或 requestId 之一', result['clientInstruction'])
                    self.assertEqual(self.stub.calls, [])
                    # The caller corrects the query file; the client never silently
                    # chooses a reference or submits a replacement business action.
                    path = self.request_file({'operationRef': 'op_1'})
                    code, follow = self.invoke(command, '--request-file', str(path), wrapper=True)
                    self.assertEqual(code, 0)
                    self.assertTrue(follow['ok'])
                    self.assertEqual(follow['operationRef'], 'op_1')
                    self.assertEqual([c['path'] for c in self.stub.calls],
                                     ['/operations/v1/version', '/operations/v1/' + command + 's/op_1'])
                    self.assertTrue(all(c['method'] == 'GET' for c in self.stub.calls))

    def test_first_post_timeout_has_generated_request_id_and_read_only_continuation(self):
        def delay(handler):
            time.sleep(0.5)
            handler.reply(200, {'ok': True, 'operationRef': 'op_1'})
        self.stub.routes[('POST', '/operations/v1/deployments')] = delay
        start = time.monotonic()
        code, result = self.invoke('deploy', '--source', '入口', '--algorithm', '人员', '--timeout', '0.2')
        self.assertLess(time.monotonic() - start, 0.9)
        self.assertEqual(code, 0)
        self.assertTrue(result['unknown'])
        self.assertTrue(result['requestSubmitted'])
        self.assertRegex(result['requestId'], r'^[0-9a-f]{32}$')
        self.assertEqual(result['continuation']['requestId'], result['requestId'])
        self.assertEqual(len([c for c in self.stub.calls if c['method'] == 'POST']), 1)
        code, follow = self.invoke('deployment', '--request-id', result['requestId'])
        self.assertEqual(code, 0)
        self.assertEqual(self.stub.calls[-1]['path'], '/operations/v1/deployments/by-request/' + result['requestId'])
        self.assertEqual(len([c for c in self.stub.calls if c['method'] == 'POST']), 1)

    def test_no_service_returns_unknown_and_request_reference(self):
        with contextlib.closing(socket.socket()) as sock:
            sock.bind(('127.0.0.1', 0))
            base = 'http://127.0.0.1:' + str(sock.getsockname()[1])
        code, result = self.invoke('deploy', '--request-id', 'known_request', '--timeout', '0.2', base=base)
        self.assertEqual(code, 0)
        self.assertTrue(result['unknown'])
        self.assertFalse(result['requestSubmitted'])
        self.assertEqual(result['requestId'], 'known_request')
        self.assertEqual(result['continuation']['command'], 'deployment')

    def test_legacy_token_rejected_before_loading_credentials_or_http(self):
        self.token.unlink()
        for extra in [('--operation-ref', 'op_1', '--confirmation-token', 'private_confirmation'),
                      ('--request-file', str(self.request_file({'sessionRef': SESSION, 'operationRef': 'op_1',
                                                                'confirmationToken': 'private_confirmation'})))]:
            code, result = self.invoke('confirm', *extra, wrapper=True)
            self.assertEqual((code, result['code']), (1, 'local_confirmation_required'))
            self.assertFalse(result['requestSubmitted'])
            self.assertNotIn('private_confirmation', json.dumps(result))
        self.assertEqual(self.stub.calls, [])

    def test_review_of_existing_dispatch_preserves_original_terminal_counts(self):
        self.stub.post_result = {'ok': False, 'pending': False, 'operationRef': 'op_1',
            'deployment': {'state': 'blocked', 'reason': 'deployment_rejected', 'dispatches': 1, 'deviceWrites': 0}}
        code, result = self.invoke('confirm', '--operation-ref', 'op_1', '--wait-seconds', '2')
        self.assertEqual(code, 0)
        self.assertEqual(self.deployment_receipt(result)['deployment']['dispatches'], 1)
        self.assertEqual(result['deployment']['state'], 'blocked')
        self.assertFalse(result.get('unknown', False))
        self.assertFalse(result['pending'])
        self.assertNotIn('dispatches', result['deployment'])
        self.assertNotIn('clientInstruction', result)
        self.assertNotIn('pageOpened', result)
        posts = [c for c in self.stub.calls if c['method'] == 'POST']
        self.assertEqual([c['path'] for c in posts], ['/operations/v1/deployments/review'])
        self.assertEqual(posts[0]['body'], {'operationRef': 'op_1'})

    def test_review_open_failure_keeps_proposal_and_does_not_retry(self):
        self.stub.routes[('POST', '/operations/v1/deployments/review')] = (503, {
            'ok': False, 'code': 'local_review_unavailable', 'operationRef': 'op_1',
            'confirmationMode': 'local_page', 'pageOpened': False})
        code, result = self.invoke('confirm', '--operation-ref', 'op_1')
        self.assertEqual(code, 0)
        self.assertFalse(result['ok'])
        self.assertFalse(result['pageOpened'])
        self.assertEqual(result['operationRef'], 'op_1')
        self.assertEqual(result['code'], 'local_review_unavailable')
        self.assertEqual(len([c for c in self.stub.calls if c['method'] == 'POST']), 1)

    def test_review_waits_for_real_confirmation_then_same_operation_completion(self):
        opened = {'ok': True, 'interactionRequired': True, 'operationRef': 'op_1',
                  'confirmationMode': 'local_page', 'supportedInteraction': 'deployment_confirmation',
                  'pageOpened': True}
        self.stub.post_result = opened
        proposed = dict(opened, proposal={'state': 'proposed'})
        proposed.pop('pageOpened')
        queued = {'ok': True, 'pending': True, 'operationRef': 'op_1',
                  'pollPath': '/operations/v1/deployments/op_1', 'deployment': {'state': 'queued'}}
        completed = {'ok': True, 'pending': False, 'operationRef': 'op_1',
                     'deployment': {'state': 'completed', 'dispatches': 1, 'deviceWrites': 1}}
        replies = iter((proposed, queued, completed))
        self.stub.routes[('GET', '/operations/v1/deployments/op_1')] = lambda h: h.reply(200, next(replies))
        code, result = self.invoke('confirm', '--operation-ref', 'op_1', wrapper=True, wait_seconds=None)
        self.assertEqual(code, 0)
        self.assertEqual(self.deployment_receipt(result)['deployment'], completed['deployment'])
        self.assertEqual(result['deployment']['state'], 'completed')
        self.assertFalse(result['pending'])
        self.assertEqual([(c['method'], c['path']) for c in self.stub.calls], [
            ('GET', '/operations/v1/version'), ('POST', '/operations/v1/deployments/review'),
            *[('GET', '/operations/v1/deployments/op_1')] * 3])
        self.assertEqual(self.stub.calls[1]['body'], {'operationRef': 'op_1'})

    def test_review_wait_budget_keeps_unconfirmed_proposal_and_read_only_continuation(self):
        opened = {'ok': True, 'interactionRequired': True, 'operationRef': 'op_1',
                  'confirmationMode': 'local_page', 'supportedInteraction': 'deployment_confirmation',
                  'pageOpened': True}
        self.stub.post_result = opened
        proposed = dict(opened, proposal={'state': 'proposed'})
        proposed.pop('pageOpened')
        self.stub.routes[('GET', '/operations/v1/deployments/op_1')] = (200, proposed)
        code, result = self.invoke('confirm', '--operation-ref', 'op_1', '--wait-seconds', '1.3')
        self.assertEqual(code, 0)
        self.assertTrue(result['interactionRequired'])
        self.assertEqual(result['proposal']['state'], 'proposed')
        self.assertFalse(result.get('pending', False))
        self.assertEqual(result['continuation'],
                         {'command': 'deployment', 'sessionRef': SESSION, 'operationRef': 'op_1'})
        self.assertEqual([c['path'] for c in self.stub.calls if c['method'] == 'POST'],
                         ['/operations/v1/deployments/review'])
        self.stub.calls.clear()
        code, result = self.invoke('confirm', '--operation-ref', 'op_1')
        self.assertEqual(code, 0)
        self.assertTrue(result['pageOpened'])
        self.assertEqual(len(self.stub.calls), 2)  # Explicit zero wait opens the page only.

    def test_legacy_receipt_or_inconsistent_open_is_unknown_not_success(self):
        for invalid in [
            {'confirmationReceipt': {'disposition': 'accepted', 'newConfirmationAccepted': True}},
            {'confirmationToken': 'private_token'},
            {'proposal': {'confirmationToken': 'private_token'}},
            {'pageOpened': True, 'interactionRequired': False, 'confirmationMode': 'local_page'},
            {'pageOpened': 'true'},
        ]:
            with self.subTest(fields=list(invalid)):
                self.stub.post_result = dict(ok=True, operationRef='op_1', **invalid)
                code, result = self.invoke('confirm', '--operation-ref', 'op_1')
                self.assertEqual(code, 0)
                self.assertTrue(result['unknown'])
                self.assertEqual(result['code'], 'invalid_response')
                self.assertNotIn('confirmationReceipt', result)
                self.assertNotIn('confirmationToken', result)
                self.assertNotIn('private_token', json.dumps(result))

    def test_review_timeout_keeps_operation_and_does_not_retry_post(self):
        def drop(handler):
            handler.connection.shutdown(socket.SHUT_RDWR)
            handler.connection.close()
        self.stub.routes[('POST', '/operations/v1/deployments/review')] = drop
        code, result = self.invoke('confirm', '--operation-ref', 'op_1')
        self.assertEqual(code, 0)
        self.assertTrue(result['unknown'])
        self.assertEqual(result['operationRef'], 'op_1')
        self.assertEqual(result['continuation']['command'], 'deployment')
        self.assertEqual(len([c for c in self.stub.calls if c['method'] == 'POST']), 1)
        self.assertNotIn('confirmationToken', result)
        self.assertNotIn('confirmationReceipt', result)
        self.assertNotIn('newConfirmationAccepted', json.dumps(result))

    def test_prior_deployment_facts_remain_unknown_after_transport_poll_failure(self):
        prior = {'state': 'queued', 'dispatches': 0, 'deviceWrites': 0}
        self.stub.post_result = {'ok': True, 'pending': True, 'operationRef': 'op_1',
            'pollPath': '/operations/v1/deployments/op_1', 'deployment': prior}
        def drop(handler):
            handler.connection.shutdown(socket.SHUT_RDWR)
            handler.connection.close()
        self.stub.routes[('GET', '/operations/v1/deployments/op_1')] = drop
        code, result = self.invoke('confirm', '--operation-ref', 'op_1',
                                  '--wait-seconds', '1.3', '--timeout', '1.7')
        self.assertEqual(code, 0)
        self.assertFalse(result['ok'])
        self.assertTrue(result['unknown'])
        self.assertFalse(result['retryable'])
        self.assertEqual(result['operationRef'], 'op_1')
        self.assertEqual(result['continuation'],
                         {'command': 'deployment', 'sessionRef': SESSION, 'operationRef': 'op_1'})
        self.assertEqual(self.deployment_receipt(result)['deployment'], prior)
        self.assertEqual(result['deployment'], {'state': 'queued', 'currentReadbackAvailable': False})
        self.assertNotIn('clientInstruction', result)
        posts = [c for c in self.stub.calls if c['method'] == 'POST']
        self.assertEqual([c['path'] for c in posts], ['/operations/v1/deployments/review'])
        self.assertEqual(len([c for c in self.stub.calls if c['path'] == '/operations/v1/deployments/op_1']), 1)

    def test_prior_deployment_facts_survive_json_503_poll(self):
        prior = {'state': 'queued', 'dispatches': 0, 'deviceWrites': 0,
                 'current': {'observedAt': '2020-01-01T00:00:00Z', 'runtime': 'stopped'}}
        self.stub.post_result = {'ok': True, 'pending': True, 'operationRef': 'op_1',
            'pollPath': '/operations/v1/deployments/op_1', 'deployment': prior}
        self.stub.routes[('GET', '/operations/v1/deployments/op_1')] = (503, {
            'ok': False, 'code': 'deployment_unavailable', 'userMessage': '本次读取不可用。'})
        code, result = self.invoke('confirm', '--operation-ref', 'op_1',
                                  '--wait-seconds', '1.3', '--timeout', '1.7', wrapper=True)
        self.assertEqual(code, 0)
        self.assertFalse(result['ok'])
        self.assertTrue(result['unknown'])
        self.assertFalse(result['retryable'])
        self.assertTrue(result['currentReadUnavailable'])
        self.assertEqual(result['code'], 'deployment_unavailable')
        self.assertEqual(result['operationRef'], 'op_1')
        self.assertEqual(self.deployment_receipt(result)['deployment'], prior)
        self.assertEqual(result['deployment'], {'state': 'queued', 'currentReadbackAvailable': False,
                                               'lastKnownObservedAt': '2020-01-01T00:00:00Z'})
        self.assertEqual(result['continuation'],
                         {'command': 'deployment', 'sessionRef': SESSION, 'operationRef': 'op_1'})
        self.assertIn('不能当作本次新回读', result['userMessage'])
        self.assertNotIn('clientInstruction', result)
        self.assertEqual([c['path'] for c in self.stub.calls if c['method'] == 'POST'],
                         ['/operations/v1/deployments/review'])
        self.assertEqual(len([c for c in self.stub.calls if c['path'] == '/operations/v1/deployments/op_1']), 1)

    def test_repeat_transport_uses_same_supplied_request_id(self):
        for _ in range(2):
            code, _result = self.invoke('deploy', '--request-id', 'same_logical_request')
            self.assertEqual(code, 0)
        bodies = [c['body'] for c in self.stub.calls if c['method'] == 'POST']
        self.assertEqual(len(bodies), 2)
        self.assertEqual(bodies[0], bodies[1])
        self.assertEqual(bodies[0]['requestId'], 'same_logical_request')
        # Device-write deduplication belongs to the service; this test proves the
        # two explicit process calls retain one logical invocation identity only.

    def test_poll_failure_preserves_accepted_operation(self):
        self.stub.post_result = {'ok': True, 'pending': True, 'operationRef': 'op_1', 'pollPath': '/operations/v1/deployments/op_1'}
        def drop(handler):
            handler.connection.shutdown(socket.SHUT_RDWR)
            handler.connection.close()
        self.stub.routes[('GET', '/operations/v1/deployments/op_1')] = drop
        code, result = self.invoke('deploy', '--request-id', 'request_poll', '--wait-seconds', '1.3', '--timeout', '1.7')
        self.assertEqual(code, 0)
        self.assertTrue(result['unknown'])
        self.assertEqual(result['operationRef'], 'op_1')
        self.assertEqual(result['requestId'], 'request_poll')
        self.assertEqual(len([c for c in self.stub.calls if c['method'] == 'POST']), 1)

    def test_wrong_poll_type_or_operation_never_followed(self):
        self.stub.post_result = {'ok': True, 'pending': True, 'operationRef': 'op_1', 'pollPath': '/operations/v1/observations/op_2'}
        code, result = self.invoke('deploy', '--wait-seconds', '0.2')
        self.assertEqual(code, 0)
        self.assertTrue(result['unknown'])
        self.assertEqual(result['code'], 'invalid_response')
        self.assertEqual(len(self.stub.calls), 2)

    def test_cross_session_response_is_rejected(self):
        self.stub.post_result['sessionRef'] = OTHER_SESSION
        code, result = self.invoke('deploy', '--request-id', 'own_request')
        self.assertEqual(code, 0)
        self.assertEqual(result['code'], 'invalid_response')
        self.assertEqual(result['sessionRef'], SESSION)
        self.assertNotIn(OTHER_SESSION, json.dumps(result))

    def test_partial_media_preserves_good_picture_and_facts(self):
        good = {'path': '/operations/v1/media/good', 'contentType': 'image/png', 'sha256': hashlib.sha256(PNG).hexdigest()}
        self.stub.post_result.update({'userMessage': '画面中可见一人。', 'facts': ['一人'], 'attachments': [good, dict(good, path='/operations/v1/media/bad')]})
        self.stub.routes[('GET', good['path'])] = lambda handler: handler.reply(200, PNG, 'image/png')
        self.stub.routes[('GET', '/operations/v1/media/bad')] = (404, {'ok': False})
        code, result = self.invoke('observe', '--subject', '人员', '--question', '有没有人')
        self.assertEqual(code, 0)
        self.assertTrue(result['ok'])
        self.assertTrue(result['partial'])
        self.assertEqual(result['facts'], ['一人'])
        self.assertIn('画面中可见一人。', result['userMessage'])
        self.assertEqual(len(result['attachmentFiles']), 1)
        path = Path(result['attachmentFiles'][0])
        self.assertEqual(path.read_bytes(), PNG)
        assert_private(self, path)
        assert_private(self, path.parent, directory=True)
        self.assertEqual(result['attachmentFailures'][0]['index'], 2)

    def test_verified_original_handoff_preserves_every_typed_answer(self):
        # Synthetic media and answers exercise the client-to-host boundary.
        # Native Read/present_files execution remains real-host acceptance.
        item = {'path': '/operations/v1/media/synthetic', 'contentType': 'image/png', 'sha256': hashlib.sha256(PNG).hexdigest()}
        self.stub.routes[('GET', item['path'])] = lambda handler: handler.reply(200, PNG, 'image/png')
        for answer in ('yes', 'no', 'unable'):
            with self.subTest(answer=answer):
                observation = {
                    'answer': answer, 'question': '是否可见测试标记？', 'sourceName': '合成机位',
                    'facts': ['合成事实'], 'limitations': ['仅供契约测试'],
                    'observedAt': '2025-01-02T03:04:05Z', 'timeMeaning': 'image_retrieved_at',
                }
                self.stub.post_result = {'ok': True, 'operationRef': 'op_1', 'observation': observation, 'attachments': [item]}
                self.stub.calls.clear()
                code, result = self.invoke('observe', '--subject', '测试标记', '--question', observation['question'])
                self.assertEqual(code, 0)
                self.assertEqual(result['observation'], observation)
                self.assertEqual(len(result['attachmentFiles']), 1)
                original = Path(result['attachmentFiles'][0])
                self.assertTrue(original.is_absolute())
                self.assertEqual(hashlib.sha256(original.read_bytes()).hexdigest(), item['sha256'])
                self.assertEqual(result['attachmentFailures'], [])
                self.assertEqual([call['path'] for call in self.stub.calls if call['method'] == 'POST'], ['/operations/v1/observations'])
                instruction = result['clientInstruction']

    def test_original_image_followup_uses_read_only_operation_and_same_bytes(self):
        item = {'path': '/operations/v1/media/synthetic-original', 'contentType': 'image/png', 'sha256': hashlib.sha256(PNG).hexdigest()}
        observation = {
            'answer': 'unable', 'question': '是否可见测试标记？', 'sourceName': '合成机位',
            'facts': [], 'limitations': ['合成案例细节不足'],
            'observedAt': '2025-01-02T03:04:05Z', 'timeMeaning': 'image_retrieved_at',
        }
        self.stub.routes[('GET', '/operations/v1/observations/op_1')] = (200, {
            'ok': True, 'operationRef': 'op_1', 'observation': observation, 'attachments': [item],
        })
        self.stub.routes[('GET', item['path'])] = lambda handler: handler.reply(200, PNG, 'image/png')
        code, result = self.invoke('observation', '--operation-ref', 'op_1')
        self.assertEqual(code, 0)
        self.assertEqual(result['operationRef'], 'op_1')
        self.assertEqual(result['observation'], observation)
        self.assertEqual(Path(result['attachmentFiles'][0]).read_bytes(), PNG)
        self.assertEqual([call['method'] for call in self.stub.calls], ['GET', 'GET', 'GET'])
        self.assertEqual(self.stub.calls[1]['path'], '/operations/v1/observations/op_1')

    def test_missing_original_retains_typed_result_without_delivery_claim_or_resubmit(self):
        item = {'path': '/operations/v1/media/missing', 'contentType': 'image/png', 'sha256': hashlib.sha256(PNG).hexdigest()}
        observation = {'answer': 'unable', 'facts': [], 'limitations': ['合成案例细节不足']}
        self.stub.routes[('GET', '/operations/v1/observations/op_1')] = (200, {
            'ok': True, 'operationRef': 'op_1', 'observation': observation, 'attachments': [item],
        })
        self.stub.routes[('GET', item['path'])] = (404, {'ok': False})
        code, result = self.invoke('observation', '--operation-ref', 'op_1')
        self.assertEqual(code, 0)
        self.assertEqual(result['observation'], observation)
        self.assertEqual(result['attachmentFiles'], [])
        self.assertEqual(result['attachmentFailures'], [{'index': 1, 'reason': '图片暂时无法取得'}])
        self.assertFalse(any(call['method'] == 'POST' for call in self.stub.calls))

    def test_media_excess_and_deadline_are_explicit_partial_failures(self):
        item = {'path': '/operations/v1/media/slow', 'contentType': 'image/png', 'sha256': hashlib.sha256(PNG).hexdigest()}
        self.stub.post_result['attachments'] = [dict(item) for _ in range(10)]
        def slow(handler):
            time.sleep(0.5)
            handler.reply(200, PNG, 'image/png')
        self.stub.routes[('GET', item['path'])] = slow
        start = time.monotonic()
        code, result = self.invoke('observe', '--subject', '人员', '--question', '有没有人', '--timeout', '0.2')
        self.assertLess(time.monotonic() - start, 0.9)
        self.assertEqual(code, 0)
        self.assertTrue(result['partial'])
        self.assertEqual(result['attachmentFiles'], [])
        self.assertEqual(result['attachmentFailures'][-1]['count'], 2)
        self.assertEqual(len([c for c in self.stub.calls if '/media/' in c['path']]), 1)

    def test_absolute_deadline_interrupts_trickling_response_headers(self):
        def trickle(handler):
            try:
                for value in b'HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n':
                    handler.connection.sendall(bytes([value]))
                    time.sleep(0.05)
            except (BrokenPipeError, ConnectionResetError):
                pass
        self.stub.routes[('POST', '/operations/v1/deployments')] = trickle
        start = time.monotonic()
        code, result = self.invoke('deploy', '--request-id', 'trickle_request', '--timeout', '0.2')
        self.assertLess(time.monotonic() - start, 0.9)
        self.assertEqual(code, 0)
        self.assertTrue(result['unknown'])
        self.assertTrue(result['requestSubmitted'])
        self.assertEqual(result['requestId'], 'trickle_request')

    def test_query_invalid_response_preserves_reference(self):
        self.stub.routes[('GET', '/operations/v1/observations/op_1')] = (200, b'not-json')
        code, result = self.invoke('observation', '--operation-ref', 'op_1')
        self.assertEqual(code, 0)
        self.assertTrue(result['unknown'])
        self.assertEqual(result['continuation']['operationRef'], 'op_1')

    def test_session_requires_valid_returned_capability(self):
        self.stub.post_result = {'ok': True, 'sessionRef': 'invalid-session'}
        code, result = self.invoke('session')
        self.assertEqual((code, result['code']), (1, 'invalid_response'))
        self.stub.post_result = {'ok': True, 'sessionRef': OTHER_SESSION}
        code, result = self.invoke('session')
        self.assertEqual(code, 0)
        self.assertEqual(result['sessionRef'], OTHER_SESSION)

    def test_environment_proxy_is_not_used(self):
        code, result = self.invoke('catalog', env={'HTTP_PROXY': 'http://127.0.0.1:1', 'http_proxy': 'http://127.0.0.1:1', 'NO_PROXY': '', 'no_proxy': ''})
        self.assertEqual(code, 0)
        self.assertTrue(result['ok'])
        self.assertEqual(len(self.stub.calls), 2)

    def test_nan_timeout_rejected_before_network(self):
        code, result = self.invoke('catalog', '--timeout', 'nan')
        self.assertEqual((code, result['code']), (1, 'invalid_arguments'))
        self.assertEqual(self.stub.calls, [])


class TransportDeadlineTests(unittest.TestCase):
    """Exercise both socket-expiry outcomes without racing operating-system timers."""

    @classmethod
    def setUpClass(cls):
        spec = importlib.util.spec_from_file_location('operations_deadline_test', SCRIPTS / 'operations_client.py')
        cls.module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(cls.module)

    def test_deadline_socket_shutdown_is_a_timeout_not_invalid_response(self):
        # A socket timeout and our deadline timer can wake the read in either
        # order. The timer path can surface as any HTTP parser exception.
        for deadline, timeout, end in ((102, 55, 102), (110, 1, 101)):
            for error in (self.module.http.client.RemoteDisconnected('closed'),
                          self.module.http.client.BadStatusLine('partial header')):
                with self.subTest(deadline=deadline, timeout=timeout, error=type(error).__name__):
                    clock = [100]
                    connection = mock.Mock()
                    with mock.patch.object(self.module.time, 'monotonic', side_effect=lambda: clock[0]), \
                         mock.patch.object(self.module.threading, 'Timer') as timer, \
                         mock.patch.object(self.module.http.client, 'HTTPConnection', return_value=connection):
                        def interrupted():
                            clock[0] = end
                            timer.call_args.args[1]()
                            raise error
                        connection.getresponse.side_effect = interrupted
                        client = self.module.Client('http://127.0.0.1:1', TOKEN, deadline=deadline)
                        with self.assertRaises(TimeoutError):
                            client.read('/operations/v1/connection', {}, timeout=timeout)
                    connection.sock.shutdown.assert_called_once_with(socket.SHUT_RDWR)
                    timer.return_value.cancel.assert_called_once()
                    connection.close.assert_called_once()

    def test_deadline_eof_does_not_return_an_incomplete_response_as_success(self):
        clock = [100]
        connection = mock.Mock()
        response = connection.getresponse.return_value
        response.status = 200
        response.getheader.return_value = 'application/json'
        response.read1.return_value = b'{"ok":true}'
        with mock.patch.object(self.module.time, 'monotonic', side_effect=lambda: clock[0]), \
             mock.patch.object(self.module.threading, 'Timer') as timer, \
             mock.patch.object(self.module.http.client, 'HTTPConnection', return_value=connection):
            def read_chunk(_):
                if response.read1.call_count == 1:
                    return b'{"ok":true}'
                # A peer can finish the JSON value but stall the HTTP body.
                # Socket shutdown then yields EOF rather than an exception.
                clock[0] = 102
                timer.call_args.args[1]()
                return b''
            response.read1.side_effect = read_chunk
            client = self.module.Client('http://127.0.0.1:1', TOKEN, deadline=102)
            with self.assertRaises(TimeoutError):
                client.request('/operations/v1/connection', {})
        connection.close.assert_called_once()

    def test_http_error_before_deadline_is_still_invalid_response(self):
        connection = mock.Mock()
        connection.getresponse.side_effect = self.module.http.client.BadStatusLine('not HTTP')
        with mock.patch.object(self.module.time, 'monotonic', return_value=100), \
             mock.patch.object(self.module.threading, 'Timer'), \
             mock.patch.object(self.module.http.client, 'HTTPConnection', return_value=connection):
            client = self.module.Client('http://127.0.0.1:1', TOKEN, deadline=102)
            with self.assertRaises(self.module.transport.ClientError) as raised:
                client.read('/operations/v1/connection', {})
        self.assertEqual(raised.exception.code, 'invalid_response')
        connection.close.assert_called_once()


class SummaryReportFileTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        sys.path.insert(0, str(SCRIPTS))
        try:
            spec = importlib.util.spec_from_file_location('operations_report_test', SCRIPTS / 'operations_client.py')
            cls.module = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(cls.module)
        finally:
            sys.path.pop(0)

    def setUp(self):
        self.client = self.module.Client('http://127.0.0.1:1', TOKEN)
        self.client.paired_identity = dict(IDENTITY)

    def test_invalid_integrity_and_provenance_never_create_a_file(self):
        mutations = [
            ('report_metadata_unavailable', lambda r: r.pop('summaryReport')),
            ('report_integrity_mismatch', lambda r: r['summaryReport'].update(sha256='0' * 64)),
            ('report_integrity_mismatch', lambda r: r['summaryReport'].update(sizeBytes=len(r['userMessage']))),
            ('report_integrity_mismatch', lambda r: r.update(userMessage=r['userMessage'] + '篡改')),
            ('report_metadata_invalid', lambda r: r['summaryReport'].update(sizeBytes=True)),
            ('report_metadata_invalid', lambda r: r['summaryReport'].update(sizeBytes=self.module.MAX_REPORT_BYTES + 1)),
            ('report_metadata_invalid', lambda r: r['summaryReport'].update(contentType='text/html')),
            ('report_metadata_invalid', lambda r: r['summaryReport'].update(headline=42)),
            ('report_metadata_invalid', lambda r: r['summaryReport'].update(filters={'sourceName': 5, 'algorithmName': ''})),
            ('report_candidate_mismatch', lambda r: r['summaryReport']['candidate'].update(modified=0)),
            ('report_candidate_mismatch', lambda r: r['summaryReport']['candidate'].update(platform='linux/amd64')),
        ]
        for code, mutate in mutations:
            with self.subTest(code=code, mutate=mutate):
                original = summary_report_response(partial=True)
                mutate(original)
                before = json.dumps(original, ensure_ascii=False)
                with mock.patch.object(self.module, 'save_summary_report') as save:
                    result = self.client.summary_report(original, '请求机位', '请求算法')
                save.assert_not_called()
                self.assertEqual(result['reportDelivery']['code'], code)
                self.assertEqual(result['attachmentFiles'], [])
                self.assertTrue(result['ok'])
                self.assertTrue(result['partial'])
                self.assertNotRegex(result['userMessage'], r'\d')
                self.assertNotIn(original['userMessage'], json.dumps(result, ensure_ascii=False))
                self.assertIn('本次记录未读取完整', result['userMessage'])
                self.assertEqual(result['summaryContext']['coverage'], original['summary']['coverage'])
                self.assertEqual(result['summaryContext']['filters'], {'sourceName': '请求机位', 'algorithmName': '请求算法'})
                self.assertEqual(json.dumps(original, ensure_ascii=False), before)
        self.client.paired_identity = None
        with mock.patch.object(self.module, 'save_summary_report') as save:
            result = self.client.summary_report(summary_report_response())
        save.assert_not_called()
        self.assertEqual(result['reportDelivery']['code'], 'report_candidate_unverified')

    def test_save_failure_keeps_computed_facts_and_original_coverage(self):
        for partial in (False, True):
            original = summary_report_response(partial)
            original['code'] = 'existing_response_code'
            before = json.dumps(original, ensure_ascii=False)
            with mock.patch.object(self.module, 'save_summary_report',
                                   side_effect=self.module.transport.ClientError('report_save_failed')):
                result = self.client.summary_report(original)
            self.assertIn('报告文件暂时无法提供', result['userMessage'])
            self.assertIn(original['summaryReport']['headline'], result['userMessage'])
            self.assertEqual(result['summary'], original['summary'])
            self.assertEqual('本次记录未读取完整' in result['userMessage'], partial)
            self.assertEqual(result['partial'], partial)
            self.assertTrue(result['ok'])
            self.assertEqual(result['code'], 'existing_response_code')
            self.assertEqual(result['summaryContext']['coverage'], original['summary']['coverage'])
            self.assertEqual(result['reportDelivery']['code'], 'report_save_failed')
            self.assertEqual(result['reportDelivery']['sha256'], original['summaryReport']['sha256'])
            self.assertEqual(result['attachmentFiles'], [])
            self.assertEqual(json.dumps(original, ensure_ascii=False), before)

    def test_delivery_projection_preserves_stats_and_marks_any_incomplete_coverage(self):
        for partial, complete in ((False, True), (True, True), (False, False), (False, None)):
            with self.subTest(partial=partial, complete=complete):
                original = summary_report_response(partial)
                original['summary']['coverage']['retrievalComplete'] = complete
                original['code'] = 'existing_code'
                original['errors'] = [{'code': 'existing_error', 'message': '原错误保留'}]
                original['headline'] = original['summaryReport']['headline']
                with mock.patch.object(self.module, 'save_summary_report', return_value=Path('/unused/统计报告.md')):
                    result = self.client.summary_report(original)
                self.assertEqual(result['ok'], original['ok'])
                self.assertEqual(result['partial'], partial)
                self.assertEqual(result['code'], original['code'])
                self.assertEqual(result['errors'], original['errors'])
                self.assertEqual(result['summaryContext']['coverage'], original['summary']['coverage'])
                self.assertEqual(result['summaryContext']['window'], original['summary']['window'])
                self.assertEqual(result['summaryContext']['timeZone'], original['summary']['timeZone'])
                self.assertEqual(result['summaryContext']['filters'], original['summaryReport']['filters'])
                self.assertEqual(result['historyCapabilityBoundary'], self.module.HISTORY_CAPABILITY_BOUNDARY)
                self.assertEqual('本次记录未读取完整' in result['userMessage'], partial or complete is not True)
                self.assertIn(original['summaryReport']['headline'], result['userMessage'])
                self.assertEqual(result['summary'], original['summary'])
                self.assertEqual(result['peak'], original['peak'])
                self.assertNotIn('summaryReport', result)

    def test_zero_record_count_is_answerable_and_original_retains_limits(self):
        original = summary_report_response()
        message = '\n'.join([original['userMessage'].split('\n')[0],
                             '本窗口已读取并去重的留存告警共 0 条。',
                             '零告警不证明设备正常、安全或没有发生事件。'])
        original['userMessage'] = message
        original['summary']['count'] = 0
        original['summaryReport'].update(headline='\n'.join(message.split('\n')[:2]),
                                         sha256=hashlib.sha256(message.encode('utf-8')).hexdigest(),
                                         sizeBytes=len(message.encode('utf-8')))
        real_mkdtemp = tempfile.mkdtemp
        with tempfile.TemporaryDirectory() as root, \
                mock.patch.object(self.module.local_files, 'private_tempdir', side_effect=lambda prefix: real_private_tempdir(prefix=prefix, directory=root)):
            result = self.client.summary_report(original)
            self.assertEqual(result['reportDelivery']['state'], 'ready')
            report = Path(result['attachmentFiles'][0])
            self.assertEqual(report.read_bytes(), message.encode('utf-8'))
            self.assertNotIn('零告警', result['userMessage'])
            self.assertEqual(result['summary']['count'], 0)
            self.assertNotIn('不能视为完整统计', result['userMessage'])

    @unittest.skipIf(os.name == "nt", "POSIX syscall contract; native Windows counterparts run separately")
    def test_atomic_publication_happens_only_after_complete_fsync(self):
        content = '统计原件\n原始中文不加 BOM 或尾换行。'.encode('utf-8')
        real_mkdtemp, real_fsync = tempfile.mkdtemp, os.fsync
        with tempfile.TemporaryDirectory() as root:
            seen = []
            def fsync(descriptor):
                directory = next(Path(root).iterdir())
                if stat.S_ISDIR(os.fstat(descriptor).st_mode):
                    self.assertEqual(len(seen), 2)
                    self.assertEqual((directory / '统计报告.md').read_bytes(), content)
                    metadata = json.loads((directory / 'report-provenance.json').read_bytes())
                    self.assertEqual(metadata['sha256'], hashlib.sha256(content).hexdigest())
                    self.assertEqual(metadata['sizeBytes'], len(content))
                    self.assertEqual(metadata['candidate'], IDENTITY)
                    self.assertEqual(stat.S_IMODE(os.fstat(descriptor).st_mode), 0o700)
                else:
                    self.assertFalse((directory / '统计报告.md').exists())
                    self.assertFalse((directory / 'report-provenance.json').exists())
                    self.assertEqual((directory / '.report.tmp').read_bytes(), content)
                    self.assertEqual(stat.S_IMODE(os.fstat(descriptor).st_mode), 0o600)
                seen.append(True)
                return real_fsync(descriptor)
            with mock.patch.object(self.module.local_files, 'private_tempdir', side_effect=lambda prefix: real_private_tempdir(prefix=prefix, directory=root)), \
                    mock.patch.object(self.module.os, 'fsync', side_effect=fsync):
                path = self.module.save_summary_report(content, IDENTITY)
            self.assertEqual(seen, [True, True, True])
            self.assertEqual(path.read_bytes(), content)
            self.assertEqual(set(path.parent.iterdir()), {path, path.parent / 'report-provenance.json'})
            assert_private(self, path)
            assert_private(self, path.parent, directory=True)

    def test_io_failure_removes_owned_partial_file_without_publishing(self):
        real_mkdtemp = tempfile.mkdtemp
        with tempfile.TemporaryDirectory() as root:
            with mock.patch.object(self.module.local_files, 'private_tempdir', side_effect=lambda prefix: real_private_tempdir(prefix=prefix, directory=root)), \
                    mock.patch.object(self.module.os, 'fsync', side_effect=OSError('synthetic storage failure')):
                with self.assertRaises(self.module.transport.ClientError) as error:
                    self.module.save_summary_report(b'original report', IDENTITY)
            self.assertEqual(error.exception.code, 'report_save_failed')
            self.assertEqual(list(Path(root).iterdir()), [])

    def test_post_link_unlink_failure_removes_owned_final_report(self):
        # Exercise POSIX publication on both hosts: native private files are
        # already complete before switching only the publication phase to
        # actual hard links. An unlink failure must remove the final name too.
        for failure_name in ('.report.tmp', '.provenance.tmp'):
            with self.subTest(staging=failure_name), tempfile.TemporaryDirectory() as root, contextlib.ExitStack() as stack:
                real_publish = self.module.local_files.publish_exclusive
                real_unlink = Path.unlink
                switched, failed = False, False

                def publish(source, target):
                    nonlocal switched
                    if not switched:
                        stack.enter_context(mock.patch.object(self.module.local_files, 'WINDOWS', False))
                        switched = True
                    real_publish(source, target)

                def unlink(path, *args, **kwargs):
                    nonlocal failed
                    if path.name == failure_name and not failed:
                        failed = True
                        raise OSError('synthetic unlink failure after successful publication')
                    return real_unlink(path, *args, **kwargs)

                stack.enter_context(mock.patch.object(self.module.local_files, 'private_tempdir',
                    side_effect=lambda prefix: real_private_tempdir(prefix=prefix, directory=root)))
                stack.enter_context(mock.patch.object(self.module.local_files, 'publish_exclusive', side_effect=publish))
                stack.enter_context(mock.patch.object(Path, 'unlink', side_effect=unlink, autospec=True))
                with self.assertRaises(self.module.transport.ClientError) as error:
                    self.module.save_summary_report(b'synthetic original report', IDENTITY)
                self.assertEqual(error.exception.code, 'report_save_failed')
                self.assertTrue(failed)
                self.assertEqual(list(Path(root).iterdir()), [])

    @unittest.skipIf(os.name == "nt", "POSIX syscall contract; native Windows counterparts run separately")
    def test_provenance_write_or_directory_sync_failure_never_exposes_attachment(self):
        real_mkdtemp, real_fsync = tempfile.mkdtemp, os.fsync
        for failure_at in (2, 3):
            with self.subTest(failure_at=failure_at), tempfile.TemporaryDirectory() as root:
                calls = []
                def fsync(descriptor):
                    calls.append(True)
                    if len(calls) == failure_at:
                        raise OSError('synthetic provenance/directory failure')
                    return real_fsync(descriptor)
                original = summary_report_response(partial=True)
                with mock.patch.object(self.module.local_files, 'private_tempdir', side_effect=lambda prefix: real_private_tempdir(prefix=prefix, directory=root)), \
                        mock.patch.object(self.module.os, 'fsync', side_effect=fsync):
                    result = self.client.summary_report(original)
                self.assertEqual(result['attachmentFiles'], [])
                self.assertEqual(result['reportDelivery']['state'], 'unavailable')
                self.assertEqual(result['reportDelivery']['code'], 'report_save_failed')
                self.assertTrue(result['ok'])
                self.assertTrue(result['partial'])
                self.assertEqual(result['summaryContext']['coverage'], original['summary']['coverage'])
                self.assertEqual(list(Path(root).iterdir()), [])

    def test_provenance_readback_corruption_removes_pair_and_never_exposes_attachment(self):
        real_mkdtemp, real_read = tempfile.mkdtemp, self.module.secure_read
        with tempfile.TemporaryDirectory() as root:
            def corrupt(path, *args, **kwargs):
                if path.name == 'report-provenance.json':
                    path.write_bytes(b'{"changed":true}')
                return real_read(path, *args, **kwargs)
            with mock.patch.object(self.module.local_files, 'private_tempdir', side_effect=lambda prefix: real_private_tempdir(prefix=prefix, directory=root)), \
                    mock.patch.object(self.module, 'secure_read', side_effect=corrupt):
                result = self.client.summary_report(summary_report_response())
            self.assertEqual(result['attachmentFiles'], [])
            self.assertEqual(result['reportDelivery']['code'], 'report_save_failed')
            self.assertTrue(result['ok'])
            self.assertFalse(result['partial'])
            self.assertEqual(list(Path(root).iterdir()), [])

    @unittest.skipIf(os.name == "nt", "POSIX syscall contract; native Windows counterparts run separately")
    def test_final_path_collision_is_not_overwritten_or_deleted(self):
        real_mkdtemp, real_link = tempfile.mkdtemp, os.link
        for name in ('统计报告.md', 'report-provenance.json'):
            with self.subTest(name=name), tempfile.TemporaryDirectory() as root:
                def collide(source, destination, **kwargs):
                    if Path(destination).name == name:
                        Path(destination).write_bytes(b'preexisting file')
                        raise FileExistsError('synthetic collision')
                    return real_link(source, destination, **kwargs)
                with mock.patch.object(self.module.local_files, 'private_tempdir', side_effect=lambda prefix: real_private_tempdir(prefix=prefix, directory=root)), \
                        mock.patch.object(self.module.os, 'link', side_effect=collide):
                    with self.assertRaises(self.module.transport.ClientError) as error:
                        self.module.save_summary_report(b'original report', IDENTITY)
                self.assertEqual(error.exception.code, 'report_save_failed')
                directory = next(Path(root).iterdir())
                self.assertEqual(list(directory.iterdir()), [directory / name])
                self.assertEqual((directory / name).read_bytes(), b'preexisting file')


class FileRaceTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        sys.path.insert(0, str(SCRIPTS))
        try:
            spec = importlib.util.spec_from_file_location('operations_race_test', SCRIPTS / 'operations_client.py')
            cls.module = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(cls.module)
        finally:
            sys.path.pop(0)

    @unittest.skipIf(os.name == "nt", "POSIX syscall contract; native Windows counterparts run separately")
    def test_replaced_file_between_lstat_and_open_is_rejected(self):
        # Deterministically exercise inode pinning; business contracts above run
        # actual child processes rather than importing main().
        module = self.module
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / 'input.json'
            path.write_text('{"sourceName":"first"}')
            local_files.protect(path)
            replacement = Path(temp) / 'replacement.json'
            replacement.write_text('{"sourceName":"other"}')
            local_files.protect(replacement)
            real_open = os.open
            def swapped(*args, **kwargs):
                os.replace(replacement, path)
                return real_open(*args, **kwargs)
            with mock.patch.object(module.os, 'open', side_effect=swapped):
                with self.assertRaises(module.transport.ClientError):
                    module.secure_read(path, 16384, private=True)

    @unittest.skipIf(os.name == "nt", "POSIX syscall contract; native Windows counterparts run separately")
    def test_request_file_fsync_failures_prevent_all_transport(self):
        for failure_at in (1, 2):
            with self.subTest(failure_at=failure_at), tempfile.TemporaryDirectory() as temp:
                path = Path(temp) / 'input.json'
                original = json.dumps({'sessionRef': SESSION, 'subject': '人员', 'question': '现在有人吗？'})
                path.write_text(original)
                local_files.protect(path)
                calls = []
                real_fsync = os.fsync
                def fail(descriptor):
                    calls.append(stat.S_IMODE(os.fstat(descriptor).st_mode))
                    if len(calls) == failure_at:
                        raise OSError('private filesystem error must not leak')
                    return real_fsync(descriptor)
                output = io.StringIO()
                with mock.patch.object(self.module.os, 'fsync', side_effect=fail), \
                     mock.patch.object(self.module, 'Client') as client, \
                     mock.patch.object(self.module.transport, '_load_token') as token, \
                     contextlib.redirect_stdout(output):
                    code = self.module.main(['observe', '--request-file', str(path)])
                result = json.loads(output.getvalue())
                self.assertEqual((code, result['code']), (1, 'request_persistence_failed'))
                self.assertFalse(result['requestSubmitted'])
                self.assertNotIn('private filesystem', output.getvalue())
                client.assert_not_called()
                token.assert_not_called()
                self.assertEqual(list(Path(temp).glob('.cosmoedge-request-*')), [])
                assert_private(self, path)
                if failure_at == 1:
                    self.assertEqual(path.read_text(), original)
                else:
                    saved = json.loads(path.read_text())
                    self.assertEqual(saved['operationKind'], 'observation')
                    self.assertEqual(saved['sessionRef'], SESSION)
                    self.assertRegex(saved['requestId'], r'^[0-9a-f]{32}$')

    def test_concurrently_edited_request_is_not_overwritten_or_submitted(self):
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / 'input.json'
            path.write_text(json.dumps({'sessionRef': SESSION, 'subject': '人员', 'question': '原问题'}))
            local_files.protect(path)
            changed = json.dumps({'sessionRef': SESSION, 'subject': '人员', 'question': '用户已改的问题'})
            real_read = self.module.secure_read
            reads = []
            def edit_before_replace(*args, **kwargs):
                reads.append(True)
                if len(reads) == 3:
                    path.write_text(changed)
                return real_read(*args, **kwargs)
            output = io.StringIO()
            with mock.patch.object(self.module, 'secure_read', side_effect=edit_before_replace), \
                 mock.patch.object(self.module, 'Client') as client, contextlib.redirect_stdout(output):
                code = self.module.main(['observe', '--request-file', str(path)])
            self.assertEqual((code, json.loads(output.getvalue())['code']), (1, 'request_persistence_failed'))
            client.assert_not_called()
            self.assertEqual(path.read_text(), changed)
            self.assertEqual(list(Path(temp).glob('.cosmoedge-request-*')), [])


if __name__ == '__main__':
    unittest.main()
