import importlib.util
import hashlib
import io
import json
import os
from pathlib import Path
import platform
import plistlib
import shutil
import stat
import struct
import sys
import tempfile
import unittest
from unittest import mock

if os.name == 'nt':
    raise unittest.SkipTest('POSIX macOS packaging contract; native Windows suites run separately')


MODULE = Path(__file__).resolve().parents[1] / 'paired_installer.py'
spec = importlib.util.spec_from_file_location('paired_installer', MODULE)
installer = importlib.util.module_from_spec(spec)
spec.loader.exec_module(installer)


class FakeHost:
    def __init__(self):
        self.loaded = {}
        self.listener_pids = set()
        self.alive_pids = set()
        self.next_pid = 100
        self.fail_next_start = False
        self.stuck = False
        self.events = []
        self.verifications = []
        self.identity = None
        self.fail_next_registration = False
        self.fail_signature = False

    def job(self, label):
        return self.loaded.get(label)

    def listeners(self):
        return set(self.listener_pids)

    def alive(self, pid):
        return pid in self.alive_pids

    def stop(self, label):
        self.events.append(('stop', label))
        job = self.loaded.pop(label, None)
        if job and not self.stuck:
            self.alive_pids.discard(job['pid'])
            self.listener_pids.discard(job['pid'])

    def start(self, plist):
        self.events.append(('start', str(plist)))
        if self.listener_pids:
            raise AssertionError('overlapping service start')
        if self.fail_next_start:
            self.fail_next_start = False
            raise installer.InstallError('simulated startup failure')
        label = plistlib.loads(plist.read_bytes())['Label']
        self.next_pid += 1
        self.loaded[label] = {'pid': self.next_pid, 'program': plistlib.loads(plist.read_bytes())['ProgramArguments'][0]}
        self.listener_pids.add(self.next_pid)
        self.alive_pids.add(self.next_pid)

    def version(self, service):
        return self.identity

    def ready(self, token, identity, protocol):
        return True

    def verify_app(self, path, app):
        # Read-only identity checks are separate from start/stop/register mutations.
        self.verifications.append(('verify_app', str(path)))
        if self.fail_signature:
            raise installer.InstallError('simulated invalid signature')

    def register_app(self, path):
        self.events.append(('register_app', str(path)))
        if self.fail_next_registration:
            self.fail_next_registration = False
            raise installer.InstallError('simulated registration failure')


class InstallationTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.base = Path(self.tmp.name)
        self.home = self.base / 'user'
        self.home.mkdir()
        self.host = FakeHost()
        self.inst = installer.Installer(self.home, self.host, timeout=0.01, ready_timeout=0.05)
        self.inst.prepare()

    def tearDown(self):
        self.tmp.cleanup()

    def bundle(self, version='v1'):
        root = self.base / version
        (root / installer.APP_SERVICE).parent.mkdir(parents=True)
        (root / 'payload/skill/scripts').mkdir(parents=True)
        (root / installer.APP_SERVICE).write_bytes(b'candidate-service-' + version.encode())
        (root / installer.CLIENT).write_text('print(' + repr(version) + ')\n')
        (root / installer.SKILL).write_text('---\nname: cosmoedge-operations\n---\n' + version)
        shutil.copy2(MODULE.parent / 'cosmoedge-operations', root / 'payload/skill/scripts/cosmoedge-operations')
        app = root / installer.APP_PAYLOAD
        info = {'CFBundleIdentifier': 'com.cosmoedge.connect.development', 'CFBundleExecutable': 'cosmoedge-connect',
                'CFBundlePackageType': 'APPL', 'LSUIElement': True, 'NSLocalNetworkUsageDescription': '连接用户选定的边缘设备。'}
        (app / 'Contents/Info.plist').write_bytes(plistlib.dumps(info))
        (app / 'Contents/_CodeSignature').mkdir()
        (app / 'Contents/_CodeSignature/CodeResources').write_bytes(b'isolated-fake-signature-' + version.encode())
        source = root / 'source-files.json'
        source.write_text('[]\n')
        files = [{'path': p.relative_to(root).as_posix(), 'sha256': installer.sha256(p), 'size': p.stat().st_size,
                  'executable': p.name in ('cosmoedge-connect', 'cosmoedge-operations'),
                  'role': 'service' if p.name == 'cosmoedge-connect' else 'client' if p.name == 'cosmoedge_operations.py' else 'skill'}
                 for p in sorted((root / 'payload').rglob('*')) if p.is_file()]
        platform_name = 'darwin/' + ('arm64' if platform.machine() == 'arm64' else 'amd64')
        manifest = {'schemaVersion': 1, 'product': 'cosmoedge-connect', 'version': version, 'platform': platform_name,
                    'service': {'entrypoint': './cmd/cosmoedge-connect', 'healthProtocol': 'cosmoedge.operations.v1',
                        'executablePath': installer.APP_SERVICE, 'macOSApp': {
                            'payloadPath': installer.APP_PAYLOAD, 'bundleIdentifier': info['CFBundleIdentifier'],
                            'signing': 'development-adhoc', 'teamIdentifier': None, 'buildUUID': 'AAAAAAAA-BBBB-CCCC-DDDD-EEEEEEEEEEEE'}},
                    'source': {'revision': 'a' * 40, 'tree': 'b' * 40, 'modified': False,
                               'inventorySHA256': installer.sha256(source)}, 'files': files}
        (root / 'manifest.json').write_text(json.dumps(manifest))
        self.host.identity = {'product': 'cosmoedge-connect', 'version': version, 'revision': 'a' * 40, 'modified': False, 'platform': platform_name}
        return root

    def install(self, bundle):
        with self.inst.locked():
            return self.inst.install(bundle)

    def mcp_bundle(self, version):
        root = self.bundle(version)
        manifest = json.loads((root / 'manifest.json').read_text())
        directory = root / 'payload/mcp'
        directory.mkdir()
        (directory / 'cosmoedge-mcp').write_bytes(b'mcp-' + version.encode())
        (directory / 'cosmoedge-mcp').chmod(0o755)
        identity = {key: self.host.identity[key] for key in ('version', 'revision', 'modified', 'platform')}
        (directory / 'candidate.json').write_text(json.dumps(identity))
        manifest['mcp'] = {'transport': 'stdio', 'entrypoint': './cmd/cosmoedge-mcp',
                           'executablePath': 'payload/mcp/cosmoedge-mcp', 'candidatePath': 'payload/mcp/candidate.json'}
        for path in sorted(directory.iterdir()):
            executable = path.name == 'cosmoedge-mcp'
            manifest['files'].append({'path': path.relative_to(root).as_posix(), 'sha256': installer.sha256(path),
                                      'size': path.stat().st_size, 'role': 'mcp' if executable else 'mcp-candidate', 'executable': executable})
        (root / 'manifest.json').write_text(json.dumps(manifest))
        return root

    def test_mcp_configuration_follows_current_release_and_separates_clients(self):
        first = self.mcp_bundle('mcp-first')
        self.install(first)
        initial = self.inst.mcp_config('codex')['mcpServers']['cosmoedge']
        self.assertTrue(initial['command'].endswith('/payload/mcp/cosmoedge-mcp'))
        self.assertIn(str(self.inst.root / 'mcp-state/codex'), initial['args'])
        self.assertIn(str(self.inst.root / 'mcp-state/claude'), self.inst.mcp_config('claude')['mcpServers']['cosmoedge']['args'])
        self.assertNotIn(self.inst.token.read_text().strip(), json.dumps(initial))
        second = self.mcp_bundle('mcp-second')
        installed = self.install(second)
        self.assertNotEqual(initial['command'], self.inst.mcp_config('codex')['mcpServers']['cosmoedge']['command'])
        self.host.identity['version'] = 'mcp-first'
        with self.inst.locked():
            self.inst.restore(self.inst.root / 'backups' / installed['backup'])
        self.assertEqual(initial, self.inst.mcp_config('codex')['mcpServers']['cosmoedge'])
        with self.assertRaises(installer.InstallError):
            self.inst.mcp_config('../outside')

    def test_mcp_config_rejects_changed_adapter(self):
        self.install(self.mcp_bundle('mcp-corrupt'))
        record, manifest = self.inst.paired_manifest()
        (Path(record['release']) / manifest['mcp']['executablePath']).write_bytes(b'changed')
        with self.assertRaises(installer.InstallError):
            self.inst.mcp_config('codex')

    def test_mcp_status_and_config_reject_executable_permission_drift(self):
        self.install(self.mcp_bundle('mcp-mode'))
        record, manifest = self.inst.paired_manifest()
        binary = Path(record['release']) / manifest['mcp']['executablePath']
        original = binary.read_bytes()
        for mode in (0o644, 0o775, 0o4755):
            with self.subTest(mode=oct(mode)):
                binary.chmod(mode)
                self.assertEqual(binary.read_bytes(), original)
                with self.assertRaises(installer.InstallError):
                    self.inst.mcp_config('codex')
                self.assertFalse(self.inst.status()['pairingVerified'])
        binary.chmod(0o755)
        self.assertTrue(self.inst.status()['pairingVerified'])

    def plugin_bundle(self, version='plugin-v1'):
        root = self.bundle(version)
        manifest = json.loads((root / 'manifest.json').read_text())
        identity = {'product': 'cosmoedge-connect', 'version': version, 'revision': 'a' * 40, 'modified': False, 'platform': manifest['platform']}
        plugin_version = '0.1.0-paired.c' + hashlib.sha256(json.dumps(identity, sort_keys=True, separators=(',', ':')).encode()).hexdigest()[:20]
        plugin = root / installer.PLUGIN_PATH
        (plugin / '.codebuddy-plugin').mkdir(parents=True)
        (plugin / 'hooks').mkdir()
        (plugin / 'scripts').mkdir()
        market = root / installer.PLUGIN_PAYLOAD / '.codebuddy-plugin'
        market.mkdir()
        (market / 'marketplace.json').write_text(json.dumps({'name': 'cosmoedge-summary-report-guard-local', 'plugins': [
            {'name': 'cosmoedge-summary-report-guard', 'source': './plugins/cosmoedge-summary-report-guard', 'version': plugin_version}]}))
        (plugin / '.codebuddy-plugin/plugin.json').write_text(json.dumps({'name': 'cosmoedge-summary-report-guard', 'version': plugin_version}))
        (plugin / 'candidate.json').write_text(json.dumps({'schemaVersion': 1, 'candidate': identity}))
        (plugin / 'hooks/hooks.json').write_text('{"hooks":{"PostToolUse":[]}}\n')
        (plugin / 'scripts/post_read.py').write_text('raise RuntimeError("verification must not run hooks")\n')
        manifest['workbuddyPlugin'] = {'schemaVersion': 1, 'name': 'cosmoedge-summary-report-guard', 'version': plugin_version,
            'sourceVersion': '0.1.0', 'marketplaceName': 'cosmoedge-summary-report-guard-local',
            'sourceDirectory': 'integrations/workbuddy/plugins/summary-report-guard',
            'payloadPath': installer.PLUGIN_PAYLOAD, 'pluginPath': installer.PLUGIN_PATH, 'requiresNativeInstallAndEnable': True}
        for path in sorted((root / installer.PLUGIN_PAYLOAD).rglob('*')):
            if path.is_file():
                manifest['files'].append({'path': path.relative_to(root).as_posix(), 'sha256': installer.sha256(path),
                    'size': path.stat().st_size, 'role': 'workbuddy-plugin', 'executable': False})
        (root / 'manifest.json').write_text(json.dumps(manifest))
        native = self.base / ('native-' + version)
        shutil.copytree(plugin, native)
        return root, native.resolve()

    def test_verify_plugin_exact_files_does_not_claim_enable_or_touch_host(self):
        bundle, native = self.plugin_bundle()
        before = {p.relative_to(self.base).as_posix(): (p.read_bytes(), stat.S_IMODE(p.stat().st_mode))
                  for p in self.base.rglob('*') if p.is_file()}
        checksum = installer.sha256(bundle / 'manifest.json')
        result = installer.verify_native_plugin(bundle, checksum, native)
        self.assertTrue(result['pluginFilesVerified'])
        self.assertFalse(result['nativeEnableVerified'])
        self.assertFalse(result['completeCandidateReadinessVerified'])
        self.assertIsNone(result['enabled'])
        self.assertEqual(len(result['files']), 4)
        self.assertEqual(before, {p.relative_to(self.base).as_posix(): (p.read_bytes(), stat.S_IMODE(p.stat().st_mode))
                                 for p in self.base.rglob('*') if p.is_file()})
        output = io.StringIO()
        with mock.patch.object(sys, 'argv', ['paired_installer.py', 'verify-plugin', '--bundle', str(bundle),
                '--expected-manifest-sha256', checksum, '--plugin-dir', str(native)]), \
                mock.patch.object(installer, 'Installer', side_effect=AssertionError('no Installer allowed')), \
                mock.patch.object(installer, 'MacHost', side_effect=AssertionError('no OS host allowed')), \
                mock.patch('sys.stdout', output):
            self.assertEqual(installer.main(), 0)
        self.assertTrue(json.loads(output.getvalue())['pluginFilesVerified'])
        self.assertEqual(self.host.events, [])

    def test_verify_plugin_rejects_tamper_missing_extra_and_links(self):
        bundle, native = self.plugin_bundle()
        checksum = installer.sha256(bundle / 'manifest.json')
        target = native / 'scripts/post_read.py'
        original = target.read_bytes()
        target.write_bytes(b'tampered')
        with self.assertRaises(installer.InstallError):
            installer.verify_native_plugin(bundle, checksum, native)
        target.unlink()
        with self.assertRaises(installer.InstallError):
            installer.verify_native_plugin(bundle, checksum, native)
        target.write_bytes(original)
        extra = native / 'extra'
        extra.mkdir()
        with self.assertRaises(installer.InstallError):
            installer.verify_native_plugin(bundle, checksum, native)
        extra.rmdir()
        outside = self.base / 'outside.py'
        outside.write_bytes(original)
        target.unlink()
        target.symlink_to(outside)
        with self.assertRaises((installer.InstallError, OSError)):
            installer.verify_native_plugin(bundle, checksum, native)
        target.unlink()
        os.link(outside, target)
        with self.assertRaises(installer.InstallError):
            installer.verify_native_plugin(bundle, checksum, native)
        target.unlink()
        target.write_bytes(original)
        target.chmod(0o666)
        with self.assertRaises(installer.InstallError):
            installer.verify_native_plugin(bundle, checksum, native)
        linked = self.base / 'linked-native'
        linked.symlink_to(native, target_is_directory=True)
        with self.assertRaises((installer.InstallError, OSError)):
            installer.verify_native_plugin(bundle, checksum, linked)

    def test_verify_plugin_rejects_wrong_manifest_candidate_or_missing_metadata(self):
        bundle, native = self.plugin_bundle()
        with self.assertRaises(installer.InstallError):
            installer.verify_native_plugin(bundle, 'f' * 64, native)
        manifest_path = bundle / 'manifest.json'
        manifest = json.loads(manifest_path.read_text())
        binding = bundle / installer.PLUGIN_PATH / 'candidate.json'
        old = binding.read_text()
        data = json.loads(old)
        data['candidate']['version'] = 'old-candidate'
        binding.write_text(json.dumps(data))
        entry = next(e for e in manifest['files'] if e['path'] == installer.PLUGIN_PATH + '/candidate.json')
        entry.update(sha256=installer.sha256(binding), size=binding.stat().st_size)
        manifest_path.write_text(json.dumps(manifest))
        with self.assertRaisesRegex(installer.InstallError, 'paired candidate'):
            installer.verify_native_plugin(bundle, installer.sha256(manifest_path), native)
        manifest.pop('workbuddyPlugin')
        manifest_path.write_text(json.dumps(manifest))
        with self.assertRaisesRegex(installer.InstallError, 'metadata'):
            installer.verify_bundle(bundle)

    def test_verify_plugin_accepts_only_validated_host_leases_without_claiming_liveness(self):
        bundle, native = self.plugin_bundle()
        leases = native / '.in_use'
        leases.mkdir(mode=0o755)
        for pid, mode in ((32032, 0o644), (32033, 0o600)):
            path = leases / str(pid)
            path.write_text(json.dumps({'pid': pid, 'procStart': '2026-09-09T00:00:00.000Z'}, separators=(',', ':')) + '\n')
            path.chmod(mode)
            self.assertEqual(path.stat().st_size, 53)
        before = {p.relative_to(native).as_posix(): (p.read_bytes(), p.stat().st_mode)
                  for p in native.rglob('*') if p.is_file()}
        with mock.patch.object(installer.os, 'kill', side_effect=AssertionError('no process probe')), \
                mock.patch.object(installer.subprocess, 'run', side_effect=AssertionError('no process launch')):
            result = installer.verify_native_plugin(bundle, installer.sha256(bundle / 'manifest.json'), native)
        self.assertEqual(result['hostLeaseFilesValidated'], 2)
        self.assertEqual(len(result['files']), 4)
        self.assertFalse(result['nativeEnableVerified'])
        self.assertFalse(result['completeCandidateReadinessVerified'])
        self.assertIsNone(result['enabled'])
        self.assertEqual(before, {p.relative_to(native).as_posix(): (p.read_bytes(), p.stat().st_mode)
                                 for p in native.rglob('*') if p.is_file()})
        self.assertEqual(self.host.events, [])
        for path in leases.iterdir():
            path.unlink()
        self.assertEqual(installer.verify_native_plugin(bundle, installer.sha256(bundle / 'manifest.json'), native)['hostLeaseFilesValidated'], 0)

    def test_verify_plugin_rejects_lease_schema_pid_date_and_extra_data(self):
        bundle, native = self.plugin_bundle()
        (native / '.in_use').mkdir()
        path = native / '.in_use/32032'
        valid = {'pid': 32032, 'procStart': '2026-09-09T00:00:00.000Z'}
        invalid = [dict(valid, pid=True), dict(valid, pid=32032.0), dict(valid, pid=32033),
                   dict(valid, procStart='2026-02-30T00:00:00.000Z'),
                   dict(valid, procStart='2026-09-09T00:00:00.000+00:00'),
                   dict(valid, procStart='2026-09-09T00:00:00Z'),
                   dict(valid, processStart=1), {'pid': 32032}, [],
                   dict(valid, procStartFt=1), dict(valid, code='unlisted')]
        for value in invalid:
            with self.subTest(value=value):
                path.write_text(json.dumps(value))
                with self.assertRaises(installer.InstallError):
                    installer.verify_native_plugin(bundle, installer.sha256(bundle / 'manifest.json'), native)
        for raw in (b'{"pid":32032,"pid":32032,"procStart":"2026-09-09T00:00:00.000Z"}',
                    json.dumps(valid).encode('utf-16'), b'not json'):
            path.write_bytes(raw)
            with self.assertRaises(installer.InstallError):
                installer.verify_native_plugin(bundle, installer.sha256(bundle / 'manifest.json'), native)

    def test_verify_plugin_rejects_other_host_paths_and_unpublished_markers(self):
        bundle, native = self.plugin_bundle()
        (native / '.in_use').mkdir()
        value = b'{"pid":32032,"procStart":"2026-09-09T00:00:00.000Z"}\n'
        for name in ('0', '032032', '-1', '2147483648', '\u0663\u0662\u0660\u0663\u0662',
                     '32032.tmp.1788912000000.abc', 'README', '.in_use.json'):
            with self.subTest(name=name):
                path = native / '.in_use' / name
                path.write_bytes(value)
                with self.assertRaises(installer.InstallError):
                    installer.verify_native_plugin(bundle, installer.sha256(bundle / 'manifest.json'), native)
                path.unlink()
        nested = native / 'scripts/.in_use'
        nested.mkdir()
        with self.assertRaises(installer.InstallError):
            installer.verify_native_plugin(bundle, installer.sha256(bundle / 'manifest.json'), native)

    def test_verify_plugin_lease_does_not_relax_links_types_permissions_or_owner(self):
        bundle, native = self.plugin_bundle()
        leases = native / '.in_use'
        leases.mkdir()
        path = leases / '32032'
        outside = self.base / 'outside-lease'
        outside.write_bytes(b'{"pid":32032,"procStart":"2026-09-09T00:00:00.000Z"}\n')
        check = lambda: installer.verify_native_plugin(bundle, installer.sha256(bundle / 'manifest.json'), native)
        for make in (lambda: path.symlink_to(outside), lambda: os.link(outside, path),
                     lambda: os.mkfifo(path), lambda: path.mkdir()):
            make()
            with self.assertRaises((installer.InstallError, OSError)):
                check()
            path.rmdir() if path.is_dir() else path.unlink()
        path.write_bytes(outside.read_bytes())
        for mode in (0o666, 0o755, 0o4600):
            path.chmod(mode)
            with self.assertRaises(installer.InstallError):
                check()
        path.chmod(0o600)
        original_fstat = installer.os.fstat
        inode = path.stat().st_ino

        def foreign_owner(fd):
            info = original_fstat(fd)
            if info.st_ino == inode:
                fields = list(info)
                fields[4] = os.getuid() + 1
                return os.stat_result(fields)
            return info

        with mock.patch.object(installer.os, 'fstat', side_effect=foreign_owner):
            with self.assertRaises(installer.InstallError):
                check()
        path.unlink()
        for mode in (0o777, 0o2755):
            leases.chmod(mode)
            with self.assertRaises(installer.InstallError):
                check()
        leases.chmod(0o755)
        leases.rmdir()
        leases.symlink_to(self.base, target_is_directory=True)
        with self.assertRaises((installer.InstallError, OSError)):
            check()

    def test_verify_plugin_lease_read_is_bounded_and_changes_rejected(self):
        bundle, native = self.plugin_bundle()
        (native / '.in_use').mkdir()
        path = native / '.in_use/32032'
        path.write_bytes(b'x' * 129)
        original_read = installer.os.read
        inode = path.stat().st_ino
        check = lambda: installer.verify_native_plugin(bundle, installer.sha256(bundle / 'manifest.json'), native)

        def reject_lease_read(fd, size):
            if os.fstat(fd).st_ino == inode:
                raise AssertionError('oversized lease must not be read')
            return original_read(fd, size)

        with mock.patch.object(installer.os, 'read', side_effect=reject_lease_read):
            with self.assertRaises(installer.InstallError):
                check()
        original = b'{"pid":32032,"procStart":"2026-09-09T00:00:00.000Z"}\n'
        path.write_bytes(original)
        requests = []

        def growing_read(fd, size):
            if os.fstat(fd).st_ino == inode:
                requests.append(size)
                return b'x' * size
            return original_read(fd, size)

        with mock.patch.object(installer.os, 'read', side_effect=growing_read):
            with self.assertRaises(installer.InstallError):
                check()
        self.assertEqual(requests, [129])

        def changing_read(fd, size):
            data = original_read(fd, size)
            if os.fstat(fd).st_ino == inode:
                with path.open('ab') as stream:
                    stream.write(b' ')
            return data

        with mock.patch.object(installer.os, 'read', side_effect=changing_read):
            with self.assertRaisesRegex(installer.InstallError, 'changed during verification'):
                check()

    def test_verify_plugin_size_rejection_precedes_read_and_growth_is_bounded(self):
        bundle, native = self.plugin_bundle()
        checksum = installer.sha256(bundle / 'manifest.json')
        target = native / '.codebuddy-plugin/plugin.json'  # First regular file in sorted traversal.
        original = target.read_bytes()
        with target.open('r+b') as stream:
            stream.truncate(128 * 1024 * 1024)
        with mock.patch.object(installer.os, 'read', side_effect=AssertionError('wrong size must not be read')):
            with self.assertRaises(installer.InstallError):
                installer.verify_native_plugin(bundle, checksum, native)
        target.write_bytes(original)
        with mock.patch.object(installer.os, 'read', side_effect=lambda fd, size: b'x' * size) as reads:
            with self.assertRaises(installer.InstallError):
                installer.verify_native_plugin(bundle, checksum, native)
        self.assertEqual(reads.call_count, 1)
        self.assertEqual(reads.call_args.args[1], len(original) + 1)

    def test_service_pairing_remains_distinct_from_native_plugin_readiness(self):
        bundle, native = self.plugin_bundle()
        self.install(bundle)
        # A paired service install preserves the plugin payload in its release,
        # but neither edits the explicit native tree nor enables it in the host.
        (native / 'scripts/post_read.py').unlink()
        status = self.inst.status()
        self.assertTrue(status['pairingVerified'])
        self.assertTrue(status['workbuddyPlugin']['required'])
        self.assertFalse(status['workbuddyPlugin']['pluginFilesVerified'])
        self.assertFalse(status['workbuddyPlugin']['nativeEnableVerified'])
        self.assertIsNone(status['workbuddyPlugin']['enabled'])

    def app_bundle(self, version='app-v1'):
        return self.bundle(version)

    def test_app_install_uses_own_identity_and_registers_before_single_start(self):
        result = self.install(self.app_bundle())
        plist = plistlib.loads((self.inst.agents / (installer.LABEL + '.plist')).read_bytes())
        self.assertEqual(plist['AssociatedBundleIdentifiers'], ['com.cosmoedge.connect.development'])
        self.assertEqual(plist['ProgramArguments'][0], str(self.inst.app / 'Contents/MacOS/cosmoedge-connect'))
        self.assertEqual(plist['Label'], installer.LABEL)
        register_index = self.host.events.index(('register_app', str(self.inst.app)))
        start_index = next(i for i, event in enumerate(self.host.events) if event[0] == 'start')
        self.assertLess(register_index, start_index)
        self.assertTrue(self.inst.status()['pairingVerified'])
        self.assertFalse(result['localNetworkAuthorizationVerified'])
        self.assertEqual(result['macOSApp']['signing'], 'development-adhoc')
        self.assertEqual(len(self.host.listeners()), 1)

    def test_app_upgrade_failure_restores_app_host_metadata_and_original_identity(self):
        self.install(self.app_bundle('app-v1'))
        old_service = (self.inst.app / 'Contents/MacOS/cosmoedge-connect').read_bytes()
        metadata = self.inst.skill / '_user_meta.json'
        metadata.write_text('{"description":"host owned"}')
        metadata.chmod(0o666)
        token = self.inst.token.read_bytes()
        state = self.inst.root / 'runtime-state/important.db'
        state.write_bytes(b'keep-runtime')
        self.host.fail_next_start = True
        with self.assertRaisesRegex(installer.InstallError, 'Previous files and launch state were restored'):
            self.install(self.app_bundle('app-v2'))
        self.assertEqual((self.inst.app / 'Contents/MacOS/cosmoedge-connect').read_bytes(), old_service)
        self.assertEqual(metadata.read_text(), '{"description":"host owned"}')
        self.assertEqual(stat.S_IMODE(metadata.stat().st_mode), 0o666)
        self.assertEqual(self.inst.token.read_bytes(), token)
        self.assertEqual(state.read_bytes(), b'keep-runtime')
        self.assertEqual(self.inst.status()['version'], 'app-v1')
        self.assertTrue(self.inst.status()['pairingVerified'])
        self.assertEqual(len(self.host.listeners()), 1)

    def test_app_registration_failure_restores_previous_without_claiming_authorization(self):
        self.install(self.bundle('previous-v1'))
        self.host.fail_next_registration = True
        with self.assertRaisesRegex(installer.InstallError, 'Previous files and launch state were restored'):
            self.install(self.app_bundle())
        self.assertTrue(self.inst.app.exists())
        self.assertTrue(self.inst.status()['pairingVerified'])
        self.assertEqual(self.inst.status()['version'], 'previous-v1')

    def test_backup_missing_app_material_rejected_without_stopping(self):
        self.install(self.bundle('previous-v1'))
        result = self.install(self.app_bundle())
        backup = self.inst.root / 'backups' / result['backup']
        data = json.loads((backup / 'backup.json').read_text())
        data['files'] = [entry for entry in data['files'] if not entry.get('path', '').startswith('app/')]
        (backup / 'backup.json').write_text(json.dumps(data))
        events = list(self.host.events)
        with self.inst.locked(), self.assertRaisesRegex(installer.InstallError, 'does not cover'):
            self.inst.restore(backup)
        self.assertEqual(self.host.events, events)
        self.assertTrue(self.inst.status()['pairingVerified'])

    def test_invalid_app_signature_and_identity_refuse_before_old_listener_stops(self):
        self.previous_candidate()
        candidate = self.app_bundle()
        old_pid = self.host.job(installer.LABEL)['pid']
        self.host.events.clear()
        self.host.fail_signature = True
        with self.assertRaisesRegex(installer.InstallError, 'invalid signature'):
            self.install(candidate)
        self.assertEqual(self.host.listeners(), {old_pid})
        self.assertFalse(any(e[0] == 'stop' for e in self.host.events))
        self.host.fail_signature = False
        manifest = json.loads((candidate / 'manifest.json').read_text())
        manifest['service']['macOSApp']['bundleIdentifier'] = 'com.tencent.WorkBuddy'
        (candidate / 'manifest.json').write_text(json.dumps(manifest))
        with self.assertRaisesRegex(installer.InstallError, 'signing identity'):
            self.install(candidate)
        self.assertEqual(self.host.listeners(), {old_pid})

    def test_app_target_symlink_or_hardlink_blocks_rollback_before_stopping(self):
        self.install(self.app_bundle('app-v1'))
        result = self.install(self.app_bundle('app-v2'))
        backup = self.inst.root / 'backups' / result['backup']
        program = self.inst.app / 'Contents/MacOS/cosmoedge-connect'
        content = program.read_bytes()
        outside = self.base / 'outside'
        outside.write_bytes(content)
        for kind in ('symbolic', 'hard'):
            with self.subTest(kind=kind):
                program.unlink()
                if kind == 'symbolic':
                    program.symlink_to(outside)
                else:
                    os.link(outside, program)
                events = list(self.host.events)
                listeners = self.host.listeners()
                with self.assertRaises(installer.InstallError):
                    self.inst.restore(backup)
                self.assertEqual(self.host.events, events)
                self.assertEqual(self.host.listeners(), listeners)
                self.assertFalse(self.inst.pending.exists())
        program.unlink()
        program.write_bytes(content)
        program.chmod(0o700)

    def test_status_detects_active_app_hash_modes_extras_and_foreign_attribution(self):
        self.install(self.app_bundle())
        program = self.inst.app / 'Contents/MacOS/cosmoedge-connect'
        original = program.read_bytes()
        program.write_bytes(b'tampered')
        self.assertFalse(self.inst.status()['pairingVerified'])
        program.write_bytes(original)
        program.chmod(0o755)
        self.assertIn('mode differs', ' '.join(self.inst.status()['pairingFailures']))
        program.chmod(0o700)
        extra = self.inst.app / 'unlisted'
        extra.mkdir(mode=0o700)
        self.assertIn('unlisted directory', ' '.join(self.inst.status()['pairingFailures']))
        extra.rmdir()
        path = self.inst.agents / (installer.LABEL + '.plist')
        plist = plistlib.loads(path.read_bytes())
        plist['AssociatedBundleIdentifiers'] = ['com.tencent.WorkBuddy']
        path.write_bytes(plistlib.dumps(plist))
        self.assertIn('own paired CosmoEdge Connect app', ' '.join(self.inst.status()['pairingFailures']))

    def test_upgrade_rejects_damaged_old_app_before_snapshot_or_stop(self):
        self.install(self.app_bundle('app-v1'))
        old_pid = self.host.job(installer.LABEL)['pid']
        (self.inst.app / 'Contents/MacOS/cosmoedge-connect').write_bytes(b'damaged-old-app')
        candidate = self.app_bundle('app-v2')
        backups = set((self.inst.root / 'backups').iterdir())
        self.host.events.clear()
        with self.assertRaisesRegex(installer.InstallError, 'Installed app differs'):
            self.install(candidate)
        self.assertEqual(self.host.listeners(), {old_pid})
        self.assertEqual(set((self.inst.root / 'backups').iterdir()), backups)
        self.assertFalse(any(e[0] in ('stop', 'start', 'register_app') for e in self.host.events))
        self.assertFalse(self.inst.pending.exists())

    def test_rollback_rechecks_backup_app_against_paired_release_before_stop(self):
        self.install(self.app_bundle('app-v1'))
        result = self.install(self.app_bundle('app-v2'))
        backup = self.inst.root / 'backups' / result['backup']
        program = backup / 'app/Contents/MacOS/cosmoedge-connect'
        program.write_bytes(b'corrupt-backup')
        # Even a locally recomputed backup checksum cannot replace the paired
        # release identity of the app we promise to restore.
        data = json.loads((backup / 'backup.json').read_text())
        next(e for e in data['files'] if e.get('path') == 'app/Contents/MacOS/cosmoedge-connect')['sha256'] = installer.sha256(program)
        (backup / 'backup.json').write_text(json.dumps(data))
        events, listeners = list(self.host.events), self.host.listeners()
        with self.assertRaisesRegex(installer.InstallError, 'Installed app differs'):
            self.inst.restore(backup)
        self.assertEqual(self.host.events, events)
        self.assertEqual(self.host.listeners(), listeners)
        self.assertFalse(self.inst.pending.exists())

    def previous_candidate(self):
        candidate = self.bundle('previous')
        (candidate / installer.SKILL).write_text('previous skill')
        manifest = json.loads((candidate / 'manifest.json').read_text())
        for entry in manifest['files']:
            if entry['path'] == installer.SKILL:
                entry.update(sha256=installer.sha256(candidate / installer.SKILL), size=(candidate / installer.SKILL).stat().st_size)
        (candidate / 'manifest.json').write_text(json.dumps(manifest))
        self.install(candidate)
        (self.inst.root / 'runtime-state/important.db').write_bytes(b'private-existing-state')
        self.inst.token.write_text('c' * 64 + '\n')
        self.inst.token.chmod(0o600)

    def test_non_app_or_other_product_candidate_rejected_before_mutations(self):
        for case in ('non-app', 'other-product'):
            with self.subTest(case=case):
                candidate = self.bundle(case)
                manifest = json.loads((candidate / 'manifest.json').read_text())
                if case == 'non-app':
                    manifest['service'].pop('macOSApp')
                else:
                    manifest['product'] = 'unrelated-product'
                (candidate / 'manifest.json').write_text(json.dumps(manifest))
                with self.assertRaises(installer.InstallError):
                    self.install(candidate)
                self.assertEqual(self.host.events, [])
                self.assertFalse(self.inst.record.exists())

    def test_empty_existing_skill_directory_can_be_restored_after_first_install_failure(self):
        self.inst.skill.mkdir()
        self.host.fail_next_start = True
        with self.assertRaisesRegex(installer.InstallError, 'Previous files and launch state were restored'):
            self.install(self.bundle())
        self.assertEqual(list(self.inst.skill.iterdir()), [])
        self.assertFalse(self.inst.record.exists())
        self.assertFalse(self.inst.pending.exists())
        self.assertFalse(self.host.listeners())

    def test_cold_install_pairs_files_token_permissions_and_unique_listener(self):
        bundle = self.bundle()
        result = self.install(bundle)
        self.assertTrue(result['installed'])
        self.assertEqual(stat.S_IMODE(self.inst.token.stat().st_mode), 0o600)
        self.assertRegex(self.inst.token.read_text(), r'^[0-9a-f]{64}\n$')
        self.assertEqual(stat.S_IMODE(self.inst.python_path.stat().st_mode), 0o600)
        self.assertEqual(self.inst.python_path.read_text(), str(Path(sys.executable).resolve()) + '\n')
        status = self.inst.status()
        self.assertTrue(status['pairingVerified'])
        self.assertEqual(status['listenerPids'], [101])
        plist = plistlib.loads((self.inst.agents / (installer.LABEL + '.plist')).read_bytes())
        self.assertIn(str(self.inst.root / 'runtime-state'), plist['ProgramArguments'])
        self.assertEqual(plist['Umask'], 0o077)

    def test_repeat_install_preserves_state_and_token_without_two_instances(self):
        self.previous_candidate()
        token = self.inst.token.read_bytes()
        state = self.inst.root / 'runtime-state/important.db'
        bundle = self.bundle()
        self.install(bundle)
        self.install(bundle)
        self.assertEqual(self.inst.token.read_bytes(), token)
        self.assertEqual(state.read_bytes(), b'private-existing-state')
        self.assertEqual(len(self.host.listeners()), 1)
        self.assertEqual(len(list((self.inst.root / 'releases').iterdir())), 2)

    def test_startup_failure_recovers_previous_skill_launch_and_state(self):
        self.previous_candidate()
        old_pid = self.host.job(installer.LABEL)['pid']
        bundle = self.bundle()
        self.host.fail_next_start = True
        with self.assertRaisesRegex(installer.InstallError, 'Previous files and launch state were restored'):
            self.install(bundle)
        failure = json.loads(next((self.inst.root / 'backups').glob('*/failure.json')).read_text())
        self.assertEqual(failure['error'], 'simulated startup failure')
        self.assertEqual(failure['listenerPids'], [])
        self.assertEqual((self.inst.skill / 'SKILL.md').read_text(), 'previous skill')
        self.assertTrue(self.inst.record.exists())
        self.assertTrue(self.inst.python_path.exists())
        self.assertFalse(self.inst.pending.exists())
        self.assertNotEqual(self.host.job(installer.LABEL)['pid'], old_pid)
        self.assertEqual((self.inst.root / 'runtime-state/important.db').read_bytes(), b'private-existing-state')
        self.assertEqual(self.inst.token.read_text(), 'c' * 64 + '\n')

    def test_manual_rollback_restores_previous_pair(self):
        self.install(self.bundle('v1'))
        old_python = self.inst.python_path.read_bytes()
        result = self.install(self.bundle('v2'))
        with self.inst.locked():
            self.inst.restore(self.inst.root / 'backups' / result['backup'])
        self.assertEqual(self.inst.status()['version'], 'v1')
        self.assertEqual(self.inst.python_path.read_bytes(), old_python)
        self.assertEqual(len(self.host.listeners()), 1)

    def test_rollback_unsafe_current_targets_refuse_before_stopping_listener(self):
        self.install(self.bundle('v1'))
        result = self.install(self.bundle('v2'))
        backup = self.inst.root / 'backups' / result['backup']
        snapshot = (backup / 'backup.json').read_bytes()
        events = list(self.host.events)
        listeners = self.host.listeners()
        outside = self.base / 'outside-unchanged'
        outside.write_bytes(b'outside')
        for target in (self.inst.skill / 'scripts/cosmoedge_operations.py', self.inst.record,
                       self.inst.agents / (installer.LABEL + '.plist')):
            with self.subTest(target=target.name):
                content, mode = target.read_bytes(), stat.S_IMODE(target.stat().st_mode)
                target.unlink()
                target.symlink_to(outside)
                try:
                    with self.assertRaisesRegex(installer.InstallError, '[Ss]ymbolic link'):
                        self.inst.restore(backup)
                    self.assertEqual(self.host.events, events)
                    self.assertEqual(self.host.listeners(), listeners)
                    self.assertFalse(self.inst.pending.exists())
                    self.assertEqual((backup / 'backup.json').read_bytes(), snapshot)
                    self.inst.backup_data(backup)
                finally:
                    target.unlink()
                    target.write_bytes(content)
                    target.chmod(mode)
        self.assertEqual(outside.read_bytes(), b'outside')
        self.assertTrue(self.inst.status()['pairingVerified'])

    def test_rollback_wrong_target_type_preserves_existing_pending_and_listener(self):
        self.install(self.bundle('v1'))
        result = self.install(self.bundle('v2'))
        backup = self.inst.root / 'backups' / result['backup']
        events = list(self.host.events)
        listeners = self.host.listeners()
        pending = b'{"backup":"existing","phase":"files_changed"}\n'
        self.inst.pending.write_bytes(pending)
        self.inst.python_path.unlink()
        self.inst.python_path.mkdir()
        with self.assertRaisesRegex(installer.InstallError, 'unexpected file type'):
            self.inst.restore(backup)
        self.assertEqual(self.host.events, events)
        self.assertEqual(self.host.listeners(), listeners)
        self.assertEqual(self.inst.pending.read_bytes(), pending)
        self.inst.backup_data(backup)

    def test_corrupt_bundle_fails_before_stopping_existing_service(self):
        self.previous_candidate()
        bundle = self.bundle()
        (bundle / installer.CLIENT).write_text('tampered')
        count = len(self.host.events)
        with self.assertRaisesRegex(installer.InstallError, 'checksum failed'):
            self.install(bundle)
        self.assertEqual(len(self.host.events), count)
        self.assertEqual((self.inst.skill / 'SKILL.md').read_text(), 'previous skill')

    def test_source_identity_mismatch_rejects(self):
        bundle = self.bundle()
        self.host.identity['revision'] = 'd' * 40
        with self.assertRaisesRegex(installer.InstallError, 'identity'):
            self.install(bundle)
        self.assertEqual(self.host.events, [])

    def test_unmanaged_listener_is_not_stopped(self):
        bundle = self.bundle()
        self.host.listener_pids.add(999)
        with self.assertRaisesRegex(installer.InstallError, 'unmanaged process'):
            self.install(bundle)
        self.assertEqual(self.host.events, [])
        self.assertFalse(self.inst.token.exists())

    def test_unpaired_loaded_job_rejected_without_stopping(self):
        path = self.inst.agents / (installer.LABEL + '.plist')
        path.write_bytes(plistlib.dumps({'Label': installer.LABEL, 'ProgramArguments': ['/unmanaged/program']}))
        path.chmod(0o600)
        self.host.start(path)
        events = list(self.host.events)
        with self.assertRaisesRegex(installer.InstallError, 'no paired installation record'):
            self.install(self.bundle())
        self.assertFalse(any(event[0] == 'stop' for event in self.host.events[len(events):]))

    def test_old_pid_must_exit_before_candidate_can_start(self):
        self.previous_candidate()
        bundle = self.bundle()
        self.host.stuck = True
        starts = sum(event[0] == 'start' for event in self.host.events)
        with self.assertRaisesRegex(installer.InstallError, 'recovery is incomplete'):
            self.install(bundle)
        self.assertEqual(sum(event[0] == 'start' for event in self.host.events), starts)
        self.assertTrue(self.inst.pending.exists())
        self.assertEqual((self.inst.skill / 'SKILL.md').read_text(), 'previous skill')

    def test_invalid_existing_token_preserved(self):
        self.inst.token.write_text('invalid-existing-token')
        self.inst.token.chmod(0o600)
        with self.assertRaisesRegex(installer.InstallError, 'token is invalid'):
            self.install(self.bundle())
        self.assertEqual(self.inst.token.read_text(), 'invalid-existing-token')
        self.assertEqual(self.host.events, [])

    def test_symlink_skill_rejected_before_changes(self):
        target = self.base / 'outside'
        target.mkdir()
        self.inst.skill.symlink_to(target)
        with self.assertRaisesRegex(installer.InstallError, 'symbolic link'):
            self.install(self.bundle())
        self.assertEqual(list(target.iterdir()), [])

    def test_installed_client_drift_fails_pairing(self):
        self.install(self.bundle())
        (self.inst.skill / 'scripts/cosmoedge_operations.py').write_text('drift')
        result = self.inst.status()
        self.assertFalse(result['pairingVerified'])
        self.assertIn('differs', result['pairingFailures'][0])

    def test_manifest_path_traversal_and_extra_files_rejected(self):
        bundle = self.bundle()
        (bundle / 'unlisted.txt').write_text('extra')
        with self.assertRaisesRegex(installer.InstallError, 'unlisted'):
            installer.verify_bundle(bundle)
        (bundle / 'unlisted.txt').unlink()
        manifest = json.loads((bundle / 'manifest.json').read_text())
        manifest['files'][0]['path'] = '../outside'
        (bundle / 'manifest.json').write_text(json.dumps(manifest))
        with self.assertRaisesRegex(installer.InstallError, 'unsafe'):
            installer.verify_bundle(bundle)

    def test_loaded_program_and_launch_configuration_drift_reject(self):
        self.install(self.bundle())
        self.host.loaded[installer.LABEL]['program'] = '/another/service'
        self.assertIn('different service candidate', self.inst.status()['pairingFailures'][0])
        self.host.loaded[installer.LABEL]['program'] = str(self.inst.app / 'Contents/MacOS/cosmoedge-connect')
        path = self.inst.agents / (installer.LABEL + '.plist')
        data = plistlib.loads(path.read_bytes())
        data['ProgramArguments'][-1] = '127.0.0.1:37790'
        path.write_bytes(plistlib.dumps(data))
        self.assertIn('launch agent differs', self.inst.status()['pairingFailures'][0])

    def imported_modes(self):
        for path in [self.inst.skill] + list(self.inst.skill.rglob('*')):
            path.chmod(0o755 if path.is_dir() else 0o666)

    def test_launcher_extra_execute_bits_are_accepted_without_permission_mutation(self):
        self.install(self.bundle())
        launcher = self.inst.skill / 'scripts/cosmoedge-operations'
        original = launcher.read_bytes()
        events = list(self.host.events)
        for mode in (0o700, 0o701, 0o710, 0o711):
            with self.subTest(mode=oct(mode)):
                launcher.chmod(mode)
                with mock.patch.object(installer.os, 'fchmod') as chmod:
                    status = self.inst.status()
                chmod.assert_not_called()
                self.assertTrue(status['pairingVerified'], status['pairingFailures'])
                projected = next(item for item in status['skillModes'] if item['path'] == 'scripts/cosmoedge-operations')
                self.assertTrue(projected['modeAccepted'])
                self.assertEqual(projected['normalizedMode'], '0700')
                self.assertEqual(projected['acceptedModes'], ['0700', '0701', '0710', '0711'])
                self.assertNotIn('expectedMode', projected)
                self.assertEqual(stat.S_IMODE(launcher.stat().st_mode), mode)
                self.assertEqual(launcher.read_bytes(), original)
        self.assertEqual(self.host.events, events)

    def test_launcher_mode_exception_rejects_read_write_special_bits_and_other_paths(self):
        self.install(self.bundle())
        paths = {
            'scripts/cosmoedge-operations': (0o700, (0o600, 0o740, 0o720, 0o707, 0o755, 0o770, 0o4700, 0o1700)),
            'scripts/cosmoedge_operations.py': (0o600, (0o601, 0o611, 0o700, 0o711)),
            'SKILL.md': (0o600, (0o601, 0o644)),
            'scripts': (0o700, (0o701, 0o711, 0o755)),
            '.': (0o700, (0o701, 0o711)),
        }
        for relative, (normal, modes) in paths.items():
            path = self.inst.skill / relative
            for mode in modes:
                with self.subTest(path=relative, mode=oct(mode)):
                    path.chmod(mode)
                    status = self.inst.status()
                    self.assertFalse(status['pairingVerified'])
                    self.assertTrue(any('Imported Skill mode differs: ' + relative + ' (' in failure for failure in status['pairingFailures']))
                path.chmod(normal)
        self.assertTrue(self.inst.status()['pairingVerified'])

    def test_restart_accepts_launcher_execute_bits_but_still_rejects_content_drift_before_stop(self):
        self.install(self.bundle())
        launcher = self.inst.skill / 'scripts/cosmoedge-operations'
        launcher.chmod(0o711)
        with mock.patch.object(installer.Path, 'home', return_value=self.home), \
             mock.patch.object(installer, 'MacHost', return_value=self.host), \
             mock.patch.object(installer.sys, 'platform', 'darwin'), \
             mock.patch.object(installer.sys, 'argv', ['paired_installer.py', 'restart']):
            old_pid = self.host.job(installer.LABEL)['pid']
            output = io.StringIO()
            with mock.patch.object(installer.sys, 'stdout', output):
                self.assertEqual(installer.main(), 0)
            self.assertTrue(json.loads(output.getvalue())['pairingVerified'])
            self.assertNotEqual(self.host.job(installer.LABEL)['pid'], old_pid)
            self.assertEqual(stat.S_IMODE(launcher.stat().st_mode), 0o711)
            launcher.write_bytes(launcher.read_bytes() + b'\n# modified\n')
            events, listeners = list(self.host.events), self.host.listeners()
            with mock.patch.object(installer.sys, 'stderr', io.StringIO()):
                self.assertEqual(installer.main(), 1)
            self.assertEqual(self.host.events, events)
            self.assertEqual(self.host.listeners(), listeners)

    def test_finalize_host_import_restores_modes_and_preserves_metadata_and_runtime(self):
        self.install(self.bundle())
        self.imported_modes()
        metadata = self.inst.skill / '_user_meta.json'
        metadata.write_bytes(b'{"description":"host-owned"}\n')
        metadata.chmod(0o666)
        state = self.inst.root / 'runtime-state/important.db'
        state.write_bytes(b'keep-state')
        untouched = {p: (p.read_bytes(), p.stat().st_mtime_ns, stat.S_IMODE(p.stat().st_mode))
                     for p in (metadata, state, self.inst.token, self.inst.python_path, self.inst.record)}
        events = list(self.host.events)
        before = self.inst.status()
        self.assertFalse(before['pairingVerified'])
        self.assertTrue(any('0666' in failure for failure in before['pairingFailures']))
        self.assertTrue(any(item['path'] == '.' and item['mode'] == '0755' for item in before['skillModes']))
        with self.inst.locked(prepare=False):
            result = self.inst.finalize_skill_import()
        self.assertTrue(result['finalized'])
        self.assertTrue(result['hostMetadataPreserved'])
        self.assertEqual(stat.S_IMODE((self.inst.skill / 'scripts/cosmoedge-operations').stat().st_mode), 0o700)
        self.assertEqual(stat.S_IMODE((self.inst.skill / 'SKILL.md').stat().st_mode), 0o600)
        self.assertEqual(stat.S_IMODE(self.inst.skill.stat().st_mode), 0o700)
        self.assertTrue(self.inst.status()['pairingVerified'])
        self.assertEqual(self.host.events, events)
        for path, snapshot in untouched.items():
            self.assertEqual((path.read_bytes(), path.stat().st_mtime_ns, stat.S_IMODE(path.stat().st_mode)), snapshot)
        self.assertEqual(self.inst.finalize_skill_import()['changedModes'], [])

    def test_finalize_tampered_content_refuses_before_any_chmod(self):
        self.install(self.bundle())
        self.imported_modes()
        (self.inst.skill / 'scripts/cosmoedge_operations.py').write_text('tampered')
        with mock.patch.object(installer.os, 'fchmod') as chmod:
            with self.assertRaisesRegex(installer.InstallError, 'differs from its paired candidate'):
                self.inst.finalize_skill_import()
            chmod.assert_not_called()
        self.assertEqual(stat.S_IMODE(self.inst.skill.stat().st_mode), 0o755)
        self.assertFalse(self.inst.status()['pairingVerified'])

    def test_finalize_missing_or_unlisted_material_refuses_before_chmod(self):
        self.install(self.bundle())
        self.imported_modes()
        extra = self.inst.skill / 'scripts/unlisted.py'
        extra.write_text('extra')
        with mock.patch.object(installer.os, 'fchmod') as chmod:
            with self.assertRaisesRegex(installer.InstallError, 'unlisted file'):
                self.inst.finalize_skill_import()
            extra.unlink()
            (self.inst.skill / 'SKILL.md').unlink()
            with self.assertRaisesRegex(installer.InstallError, 'missing paired files'):
                self.inst.finalize_skill_import()
            chmod.assert_not_called()

    def test_finalize_symbolic_links_in_candidate_or_host_metadata_are_rejected(self):
        self.install(self.bundle())
        outside = self.base / 'untouched'
        outside.write_bytes((self.inst.skill / 'SKILL.md').read_bytes())
        outside.chmod(0o644)
        for relative in ('SKILL.md', '_user_meta.json'):
            with self.subTest(path=relative):
                target = self.inst.skill / relative
                original = target.read_bytes() if target.exists() else None
                if target.exists():
                    target.unlink()
                target.symlink_to(outside)
                with mock.patch.object(installer.os, 'fchmod') as chmod:
                    with self.assertRaisesRegex(installer.InstallError, 'symbolic link'):
                        self.inst.finalize_skill_import()
                    chmod.assert_not_called()
                self.assertFalse(self.inst.status()['pairingVerified'])
                target.unlink()
                if original is not None:
                    target.write_bytes(original)
        self.assertEqual(stat.S_IMODE(outside.stat().st_mode), 0o644)

    def test_finalize_hard_link_cannot_change_another_path_permissions(self):
        self.install(self.bundle())
        target = self.inst.skill / 'SKILL.md'
        outside = self.base / 'hard-link-target'
        os.link(target, outside)
        before = stat.S_IMODE(outside.stat().st_mode)
        with self.assertRaisesRegex(installer.InstallError, 'hard link'):
            self.inst.finalize_skill_import()
        self.assertEqual(stat.S_IMODE(outside.stat().st_mode), before)

    def test_finalize_wrong_owner_rejected_before_changes(self):
        self.install(self.bundle())
        self.inst.uid += 1
        with mock.patch.object(installer.os, 'fchmod') as chmod:
            with self.assertRaisesRegex(installer.InstallError, 'another user'):
                self.inst.finalize_skill_import()
            chmod.assert_not_called()

    def test_finalize_does_not_follow_path_replaced_after_verification(self):
        self.install(self.bundle())
        self.imported_modes()
        target = self.inst.skill / 'SKILL.md'
        outside = self.base / 'replacement-target'
        outside.write_bytes(target.read_bytes())
        outside.chmod(0o644)
        chmod = os.fchmod
        swapped = False
        def swap_then_chmod(fd, mode):
            nonlocal swapped
            if not swapped:
                swapped = True
                target.unlink()
                target.symlink_to(outside)
            chmod(fd, mode)
        with mock.patch.object(installer.os, 'fchmod', side_effect=swap_then_chmod):
            with self.assertRaisesRegex(installer.InstallError, 'symbolic link'):
                self.inst.finalize_skill_import()
        self.assertEqual(stat.S_IMODE(outside.stat().st_mode), 0o644)

    def test_finalize_pending_recovery_refuses_and_status_exposes_reason(self):
        self.install(self.bundle())
        self.inst.pending.write_text('{}')
        with self.assertRaisesRegex(installer.InstallError, 'rollback'):
            self.inst.finalize_skill_import()
        result = self.inst.status()
        self.assertFalse(result['pairingVerified'])
        self.assertIn('An interrupted installation needs rollback.', result['pairingFailures'])

    def test_status_cli_returns_nonzero_for_modes_and_finalize_does_not_start_service(self):
        self.install(self.bundle())
        self.imported_modes()
        events = list(self.host.events)
        with mock.patch.object(installer.Path, 'home', return_value=self.home), \
             mock.patch.object(installer, 'MacHost', return_value=self.host), \
             mock.patch.object(installer.sys, 'platform', 'darwin'):
            for command, expected in [('status', 1), ('finalize-skill-import', 0), ('status', 0)]:
                output = io.StringIO()
                with mock.patch.object(installer.sys, 'argv', ['paired_installer.py', command]), \
                     mock.patch.object(installer.sys, 'stdout', output):
                    self.assertEqual(installer.main(), expected)
                data = json.loads(output.getvalue())
                self.assertIn('skillModes', data)
        self.assertEqual(self.host.events, events)

    def test_interrupted_transaction_blocks_new_install_until_recovery(self):
        self.previous_candidate()
        backup = self.inst.snapshot(self.inst.jobs())
        with self.assertRaisesRegex(installer.InstallError, 'interrupted installation'):
            self.install(self.bundle())
        with self.inst.locked():
            self.inst.restore(backup)
        self.assertFalse(self.inst.pending.exists())
        self.assertEqual((self.inst.skill / 'SKILL.md').read_text(), 'previous skill')

    def test_operations_probe_requires_protocol_and_exact_identity(self):
        self.inst.provision_token()
        identity = {'product': 'cosmoedge-connect', 'version': 'v1', 'revision': 'a' * 40, 'modified': False, 'platform': 'darwin/arm64'}
        response = mock.MagicMock()
        response.status = 200
        response.__enter__.return_value = response
        opener = mock.Mock()
        opener.open.return_value = response
        real_host = installer.MacHost(os.getuid())
        with mock.patch.object(installer.urllib.request, 'build_opener', return_value=opener):
            response.read.return_value = json.dumps({'ok': True, 'protocol': 'cosmoedge.operations.v1', 'version': identity}).encode()
            self.assertTrue(real_host.ready(self.inst.token, identity, 'cosmoedge.operations.v1'))
            self.assertEqual(opener.open.call_args[0][0].full_url, 'http://127.0.0.1:37789/operations/v1/version')
            response.read.return_value = json.dumps({'ok': True, 'protocol': 'cosmoedge.operations.v1', 'version': dict(identity, version='other')}).encode()
            self.assertFalse(real_host.ready(self.inst.token, identity, 'cosmoedge.operations.v1'))
            response.read.return_value = b'{"capabilities": []}'
            self.assertFalse(real_host.ready(self.inst.token, identity, 'cosmoedge.operations.v1'))
            self.assertFalse(real_host.ready(self.inst.token, identity, 'other.v1'))

    def test_delayed_readiness_has_separate_sixty_second_budget(self):
        self.install(self.bundle())
        self.inst.ready_timeout = 60
        with mock.patch.object(installer.time, 'monotonic', side_effect=[0, 0, 30]), mock.patch.object(installer.time, 'sleep'), mock.patch.object(self.host, 'ready', side_effect=[False, True]):
            self.inst.wait_ready()
        self.assertEqual(self.inst.timeout, 0.01)

    def test_rollback_waits_for_previous_authenticated_listener(self):
        self.previous_candidate()
        backup = self.inst.snapshot(self.inst.jobs())
        self.inst.ready_timeout = 60
        # Stop observes no old PID after bootout, then previous readiness remains
        # within its separate budget even when it takes thirty seconds.
        with mock.patch.object(installer.time, 'monotonic', side_effect=[0, 0, 0, 0, 30]), mock.patch.object(installer.time, 'sleep'), mock.patch.object(self.host, 'ready', side_effect=[False, True]):
            result = self.inst.restore(backup)
        self.assertTrue(result['listenerRestored'])
        self.assertFalse(self.inst.pending.exists())

    def test_unready_rollback_retains_pending_instead_of_claiming_recovered(self):
        self.previous_candidate()
        backup = self.inst.snapshot(self.inst.jobs())
        with mock.patch.object(self.host, 'ready', return_value=False):
            with self.assertRaisesRegex(installer.InstallError, 'Candidate did not become'):
                self.inst.restore(backup)
        self.assertTrue(self.inst.pending.exists())
        self.assertFalse((backup / 'restored.json').exists())

    def test_loaded_but_unstarted_candidate_is_unloaded_before_rollback(self):
        self.previous_candidate()
        actual_start = self.host.start
        first = True
        def fail_kickstart(plist):
            nonlocal first
            if first:
                first = False
                data = plistlib.loads(plist.read_bytes())
                self.host.loaded[data['Label']] = {'pid': None, 'program': data['ProgramArguments'][0]}
                self.host.events.append(('bootstrap_without_spawn', str(plist)))
                raise installer.InstallError('launchd loaded the job but could not explicitly start it.')
            actual_start(plist)
        with mock.patch.object(self.host, 'start', side_effect=fail_kickstart):
            with self.assertRaisesRegex(installer.InstallError, 'Previous files and launch state were restored'):
                self.install(self.bundle())
        self.assertEqual(self.host.job(installer.LABEL)['program'], str(self.inst.app / 'Contents/MacOS/cosmoedge-connect'))
        self.assertEqual(len(self.host.listeners()), 1)
        self.assertFalse(self.inst.pending.exists())

    def test_lock_prevents_second_writer(self):
        with self.inst.locked():
            other = installer.Installer(self.home, self.host)
            with self.assertRaisesRegex(installer.InstallError, 'Another paired installation'):
                with other.locked():
                    self.fail('second writer entered')


class MacAppBoundaryTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.app = Path(self.tmp.name) / 'payload-app'
        (self.app / 'Contents/MacOS').mkdir(parents=True)
        self.metadata = {'bundleIdentifier': 'com.cosmoedge.connect.development', 'signing': 'development-adhoc',
                         'teamIdentifier': None, 'buildUUID': 'AAAAAAAA-BBBB-CCCC-DDDD-EEEEEEEEEEEE'}
        self.info = {'CFBundleIdentifier': self.metadata['bundleIdentifier'], 'CFBundleExecutable': 'cosmoedge-connect',
                     'CFBundlePackageType': 'APPL', 'LSUIElement': True, 'NSLocalNetworkUsageDescription': '读取选定设备。'}
        self.write_info()
        self.program = self.app / 'Contents/MacOS/cosmoedge-connect'
        self.program.write_bytes(struct.pack('<8I', 0xfeedfacf, 0x100000c, 0, 2, 1, 24, 0, 0)
                                 + struct.pack('<2I', 0x1b, 24) + bytes.fromhex('aaaaaaaabbbbccccddddeeeeeeeeeeee'))
        self.host = installer.MacHost(501)

    def tearDown(self):
        self.tmp.cleanup()

    def write_info(self):
        (self.app / 'Contents/Info.plist').write_bytes(plistlib.dumps(self.info))

    def test_development_signature_and_uuid_checked_without_launching_or_registering(self):
        details = 'Identifier=com.cosmoedge.connect.development\nSignature=adhoc\nTeamIdentifier=not set\n'
        with mock.patch.object(self.host, 'command', side_effect=[mock.Mock(returncode=0), mock.Mock(returncode=0, stderr=details)]) as command:
            self.host.verify_app(self.app, self.metadata)
        self.assertEqual(command.call_args_list, [
            mock.call('/usr/bin/codesign', '--verify', '--strict', '--verbose=2', str(self.app)),
            mock.call('/usr/bin/codesign', '--display', '--verbose=4', str(self.app))])

    def test_apple_signing_requires_apple_anchor_bundle_and_same_team(self):
        self.metadata.update(bundleIdentifier='com.cosmoedge.connect', signing='apple', teamIdentifier='ABCDE12345')
        self.info['CFBundleIdentifier'] = self.metadata['bundleIdentifier']
        self.write_info()
        details = 'Identifier=com.cosmoedge.connect\nTeamIdentifier=ABCDE12345\n'
        with mock.patch.object(self.host, 'command', side_effect=[mock.Mock(returncode=0), mock.Mock(returncode=0, stderr=details)]) as command:
            self.host.verify_app(self.app, self.metadata)
        requirement = command.call_args_list[0].args[-2]
        self.assertEqual(requirement, 'anchor apple generic and identifier "com.cosmoedge.connect" and certificate leaf[subject.OU] = "ABCDE12345"')

    def test_foreign_signing_identity_and_signature_failure_are_closed_errors(self):
        secret = 'fake-private-url-or-credential-must-not-escape'
        with mock.patch.object(self.host, 'command', return_value=mock.Mock(returncode=1, stderr=secret)):
            with self.assertRaisesRegex(installer.InstallError, '^CosmoEdge Connect app signature verification failed.$'):
                self.host.verify_app(self.app, self.metadata)
        details = 'Identifier=other.app\nSignature=adhoc\nTeamIdentifier=not set\n' + secret
        with mock.patch.object(self.host, 'command', side_effect=[mock.Mock(returncode=0), mock.Mock(returncode=0, stderr=details)]):
            with self.assertRaisesRegex(installer.InstallError, '^CosmoEdge Connect code signing identifier differs from its app identity.$'):
                self.host.verify_app(self.app, self.metadata)

    def test_uuid_mismatch_or_missing_usage_description_reject_before_codesign(self):
        with mock.patch.object(self.host, 'command') as command:
            changed = dict(self.metadata, buildUUID='00000000-0000-0000-0000-000000000000')
            with self.assertRaisesRegex(installer.InstallError, 'UUID differs'):
                self.host.verify_app(self.app, changed)
            self.info.pop('NSLocalNetworkUsageDescription')
            self.write_info()
            with self.assertRaisesRegex(installer.InstallError, 'local network use'):
                self.host.verify_app(self.app, self.metadata)
            command.assert_not_called()

    def test_macho_uuid_reader_rejects_truncated_or_missing_load_commands(self):
        self.assertEqual(installer.mach_o_uuid(self.program), self.metadata['buildUUID'])
        self.program.write_bytes(struct.pack('<8I', 0xfeedfacf, 0x100000c, 0, 2, 0, 0, 0, 0))
        with self.assertRaisesRegex(installer.InstallError, 'exactly one build UUID'):
            installer.mach_o_uuid(self.program)
        self.program.write_bytes(struct.pack('<8I', 0xfeedfacf, 0x100000c, 0, 2, 1, 24, 0, 0))
        with self.assertRaisesRegex(installer.InstallError, 'truncated'):
            installer.mach_o_uuid(self.program)

    def test_registration_is_a_separate_explicit_api_boundary(self):
        with mock.patch.object(installer, 'register_launch_services') as register, mock.patch.object(self.host, 'command') as command:
            self.host.register_app(self.app)
            register.assert_called_once_with(self.app)
            command.assert_not_called()


class MacHostCommandTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.plist = Path(self.tmp.name) / (installer.LABEL + '.plist')
        self.plist.write_bytes(plistlib.dumps({'Label': installer.LABEL, 'ProgramArguments': ['/a/service']}))
        self.host = installer.MacHost(501)

    def tearDown(self):
        self.tmp.cleanup()

    def test_loaded_without_spawn_state_is_available_for_failure_evidence(self):
        output = "program = /a/service\nstate = not running\nruns = 0\npended non-demand spawn = speculative\n"
        with mock.patch.object(self.host, 'command', return_value=mock.Mock(returncode=0, stdout=output)):
            status = self.host.job(installer.LABEL)
        self.assertEqual(status, {'pid': None, 'program': '/a/service', 'state': 'not running', 'runs': 0})

    def test_bootstrap_is_followed_by_explicit_non_killing_kickstart(self):
        with mock.patch.object(self.host, 'command', return_value=mock.Mock(returncode=0)) as command:
            self.host.start(self.plist)
        self.assertEqual(command.call_args_list, [
            mock.call('/bin/launchctl', 'bootstrap', 'gui/501', str(self.plist)),
            mock.call('/bin/launchctl', 'kickstart', 'gui/501/' + installer.LABEL)])

    def test_unknown_or_mismatched_label_never_reaches_launchctl(self):
        self.plist.write_bytes(plistlib.dumps({'Label': 'unrelated.application'}))
        with mock.patch.object(self.host, 'command') as command:
            with self.assertRaisesRegex(installer.InstallError, 'label does not match'):
                self.host.start(self.plist)
            command.assert_not_called()

    def test_bootstrap_failure_does_not_kickstart(self):
        with mock.patch.object(self.host, 'command', return_value=mock.Mock(returncode=1)) as command:
            with self.assertRaisesRegex(installer.InstallError, 'could not load'):
                self.host.start(self.plist)
        self.assertEqual(command.call_count, 1)

    def test_kickstart_failure_is_a_failure_after_bootstrap(self):
        with mock.patch.object(self.host, 'command', side_effect=[mock.Mock(returncode=0), mock.Mock(returncode=1)]) as command:
            with self.assertRaisesRegex(installer.InstallError, 'could not explicitly start'):
                self.host.start(self.plist)
        self.assertEqual(command.call_count, 2)


if __name__ == '__main__':
    unittest.main()
