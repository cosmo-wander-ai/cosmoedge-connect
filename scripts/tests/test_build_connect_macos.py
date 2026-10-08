import os
import contextlib
import hashlib
import importlib.util
import io
import json
from pathlib import Path
import plistlib
import shutil
import stat
import struct
import subprocess
import tempfile
import unittest
from unittest import mock
import uuid
import zipfile


if os.name == 'nt':
    raise unittest.SkipTest('POSIX macOS packaging contract; native Windows suites run separately')


SCRIPT = Path(__file__).resolve().parents[1] / 'build-connect-macos.py'
SPEC = importlib.util.spec_from_file_location('build_connect_macos', SCRIPT)
builder = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(builder)


def macho(value=b'\x01' * 16, arch='arm64', commands=None):
    commands = [(0x1b, value)] if commands is None else commands
    raw = b''.join(struct.pack('<2I', command, len(body) + 8) + body for command, body in commands)
    cpu = {'arm64': 0x100000c, 'amd64': 0x1000007}[arch]
    return struct.pack('<8I', 0xfeedfacf, cpu, 0, 2, len(commands), len(raw), 0, 0) + raw


class AppBuilderTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.base = Path(self.temporary.name)
        self.repo = self.base / 'repo'
        self.skill = self.repo / 'integrations/workbuddy/skills/cosmoedge-operations'
        (self.skill / 'scripts').mkdir(parents=True)
        (self.skill / 'SKILL.md').write_text('synthetic skill\n')
        (self.skill / 'scripts/operations_client.py').write_text('synthetic_client = True\n')
        (self.repo / 'skills/cosmoedge-operations').mkdir(parents=True)
        (self.repo / 'skills/cosmoedge-operations/SKILL.md').write_text('synthetic MCP skill\n')
        for name in ('LICENSE', 'NOTICE'):
            (self.repo / name).write_text('synthetic ' + name + '\n')
        (self.repo / 'third_party/licenses/example').mkdir(parents=True)
        (self.repo / 'third_party/licenses/example/LICENSE').write_text('synthetic dependency license\n')
        deploy = self.repo / 'integrations/workbuddy/deploy/macos'
        deploy.mkdir(parents=True)
        for name in ('cosmoedge-operations', 'paired_installer.py', 'install-paired.sh', 'PAIRED-INSTALL.md'):
            (deploy / name).write_text('synthetic ' + name + '\n')
        self.market = self.repo / builder.PLUGIN_SOURCE
        self.plugin = self.market / builder.PLUGIN_RELATIVE
        (self.market / '.codebuddy-plugin').mkdir(parents=True)
        (self.plugin / '.codebuddy-plugin').mkdir(parents=True)
        (self.plugin / 'hooks').mkdir()
        (self.plugin / 'scripts').mkdir()
        (self.market / '.codebuddy-plugin/marketplace.json').write_text(json.dumps({
            'name': 'cosmoedge-summary-report-guard-local', 'plugins': [
                {'name': 'cosmoedge-summary-report-guard', 'version': '0.1.0', 'source': './plugins/cosmoedge-summary-report-guard'}]}))
        (self.plugin / '.codebuddy-plugin/plugin.json').write_text(json.dumps({'name': 'cosmoedge-summary-report-guard', 'version': '0.1.0'}))
        (self.plugin / 'hooks/hooks.json').write_text('{"hooks":{"PostToolUse":[]}}\n')
        (self.plugin / 'scripts/post_read.py').write_text('raise RuntimeError("synthetic hook must never run during build")\n')
        self.calls = []
        self.signature_identifier = None
        self.team = None
        self.force_adhoc = False
        self.fail_sign = False
        self.mutate_uuid = False
        self.omit_uuid = False
        self.initial_binary_suffix = b'compiled with synthetic toolchain A'
        for patcher in (
                mock.patch.object(builder, 'ROOT', self.repo),
                mock.patch.object(builder.platform, 'system', return_value='Darwin'),
                mock.patch.object(builder, 'source_inventory', return_value=[{'path': 'synthetic.go', 'sha256': 'c' * 64}]),
                mock.patch.object(builder, 'run', side_effect=self.git),
                mock.patch.object(builder.subprocess, 'run', side_effect=self.tool)):
            patcher.start()
            self.addCleanup(patcher.stop)

    def git(self, *args):
        if args == ('git', 'rev-parse', 'HEAD'):
            return 'a' * 40
        if args == ('git', 'rev-parse', 'HEAD^{tree}'):
            return 'b' * 40
        if args == ('git', 'status', '--porcelain', '--untracked-files=normal'):
            return ''
        self.fail('unexpected source command: ' + repr(args))

    def tool(self, args, **kwargs):
        self.calls.append(list(args))
        if args[:2] == ['go', 'build']:
            output = Path(args[args.index('-o') + 1])
            output.parent.mkdir(parents=True, exist_ok=True)
            flags = args[args.index('-ldflags') + 1]
            build_uuid = hashlib.sha256(flags.encode()).digest()[:16]
            raw = macho(build_uuid, arch=kwargs['env']['GOARCH'], commands=[] if self.omit_uuid else None)
            output.write_bytes(raw + self.initial_binary_suffix)
            return subprocess.CompletedProcess(args, 0)
        self.assertEqual(args[0], '/usr/bin/codesign')
        app = Path(args[-1])
        self.assertTrue(app.name.endswith('.app'), 'sign and verify before removing the .app suffix')
        executable = app / 'Contents/MacOS/cosmoedge-connect'
        info = plistlib.loads((app / 'Contents/Info.plist').read_bytes())
        self.assertTrue(executable.stat().st_mode & stat.S_IXUSR)
        if '--sign' in args:
            if self.fail_sign:
                raise subprocess.CalledProcessError(1, args)
            self.identity = args[args.index('--sign') + 1]
            self.assertEqual(args[args.index('--identifier') + 1], info['CFBundleIdentifier'])
            content = executable.read_bytes()
            if self.mutate_uuid:
                content = content[:40] + b'\x07' * 16 + content[56:]
            executable.write_bytes(content + b'synthetic signature added after compilation')
            signature = app / 'Contents/_CodeSignature'
            signature.mkdir()
            (signature / 'CodeResources').write_bytes(b'synthetic sealed resources')
        elif '--display' in args:
            identifier = self.signature_identifier or info['CFBundleIdentifier']
            adhoc = self.identity == '-' or self.force_adhoc
            team = self.team if self.team is not None else ('not set' if adhoc else 'ABCDE12345')
            signature = 'Signature=adhoc' if adhoc else 'Authority=Apple synthetic test authority'
            return subprocess.CompletedProcess(args, 0, stdout='', stderr=f'Identifier={identifier}\nTeamIdentifier={team}\n{signature}\n')
        else:
            self.assertIn('--verify', args)
            self.assertIn('--strict', args)
        return subprocess.CompletedProcess(args, 0, stdout='', stderr='')

    def build(self, name='candidate', *flags):
        output = self.base / name
        if '--development-app' not in flags and '--signing-identity' not in flags:
            flags = ('--development-app', *flags)
        with contextlib.redirect_stdout(io.StringIO()):
            builder.main(['--version', 'phase1-rc5', '--output', str(output), '--arch', 'arm64', *flags])
        return output, json.loads((output / 'manifest.json').read_text())

    def assert_inventory(self, root, manifest):
        entries = {entry['path']: entry for entry in manifest['files']}
        actual = {path.relative_to(root).as_posix() for path in root.rglob('*') if path.is_file()}
        self.assertEqual(actual, set(entries) | {'manifest.json', 'source-files.json'})
        for name, entry in entries.items():
            path = root / name
            self.assertEqual(entry['sha256'], builder.digest(path))
            self.assertEqual(entry['size'], path.stat().st_size)
            self.assertEqual(bool(stat.S_IMODE(path.stat().st_mode) & 0o111), entry['executable'])
        return entries

    def test_only_signed_app_layout_is_packaged(self):
        root, manifest = self.build()
        self.assertEqual(manifest['service']['entrypoint'], './cmd/cosmoedge-connect')
        self.assertEqual(manifest['service']['healthProtocol'], 'cosmoedge.operations.v1')
        self.assertEqual(manifest['service']['executablePath'], builder.APP_SERVICE)
        self.assertTrue((root / builder.APP_SERVICE).is_file())
        self.assertFalse((root / 'payload/bin').exists())
        self.assertNotIn('workbuddyPlugin', manifest)
        self.assert_inventory(root, manifest)

    def test_signing_mode_required_and_arbitrary_entrypoint_rejected(self):
        for flags in ([], ['--development-app', '--binary-source', './cmd/other']):
            with self.subTest(flags=flags), contextlib.redirect_stderr(io.StringIO()), self.assertRaises(SystemExit):
                builder.parse_args(['--version', 'candidate', '--output', str(self.base / 'unused'), *flags])
        self.assertEqual(self.calls, [])

    def test_mcp_is_bound_to_same_candidate_and_executable_inventory(self):
        root, manifest = self.build('mcp-pair', '--with-mcp')
        self.assertEqual(manifest['mcp']['transport'], 'stdio')
        self.assertEqual((root / 'payload/mcp/candidate.json').read_bytes(),
                         (root / 'payload/skill/candidate.json').read_bytes())
        entries = self.assert_inventory(root, manifest)
        self.assertTrue(entries['payload/mcp/cosmoedge-mcp']['executable'])
        self.assertEqual(entries['payload/mcp/cosmoedge-mcp']['role'], 'mcp')
        self.assertEqual(entries['skills/cosmoedge-operations/SKILL.md']['role'], 'mcp-skill')
        self.assertIn('LICENSE', entries)
        self.assertIn('NOTICE', entries)
        self.assertIn('third_party/licenses/example/LICENSE', entries)
        self.assertNotEqual((root / 'skills/cosmoedge-operations/SKILL.md').read_bytes(),
                            (root / 'payload/skill/SKILL.md').read_bytes())
        self.assertEqual(self.calls[-1][-1], './cmd/cosmoedge-mcp')
        self.assertIn('SourceRevision=' + manifest['source']['revision'], self.calls[-1][self.calls[-1].index('-ldflags') + 1])

    def test_both_links_embed_the_same_manifest_source_identity(self):
        for dirty in (False, True):
            with self.subTest(dirty=dirty):
                original_git = self.git
                def git(*args):
                    if args == ('git', 'status', '--porcelain', '--untracked-files=normal'):
                        return ' M synthetic.go' if dirty else ''
                    return original_git(*args)
                self.calls.clear()
                with mock.patch.object(builder, 'run', side_effect=git):
                    root, manifest = self.build('paired-' + str(dirty), '--development-app', '--allow-dirty')
                candidate = json.loads((root / 'payload/skill/candidate.json').read_text())
                self.assertEqual(candidate['revision'], manifest['source']['revision'])
                self.assertIs(candidate['modified'], dirty)
                self.assertIs(manifest['source']['modified'], dirty)
                builds = [call for call in self.calls if call[:2] == ['go', 'build']]
                self.assertEqual(len(builds), 2)
                for call in builds:
                    flags = call[call.index('-ldflags') + 1]
                    self.assertIn('-X github.com/cosmo-wander-ai/cosmoedge-connect/internal/buildinfo.SourceRevision=' + candidate['revision'], flags)
                    self.assertIn('-X github.com/cosmo-wander-ai/cosmoedge-connect/internal/buildinfo.SourceModified=' + str(dirty).lower(), flags)
                    self.assertIn('-X github.com/cosmo-wander-ai/cosmoedge-connect/internal/buildinfo.Version=' + candidate['version'], flags)

    def test_source_change_never_emits_a_paired_candidate(self):
        for changed in ('revision', 'inventory', 'modified'):
            with self.subTest(changed=changed):
                calls = {'revision': 0, 'modified': 0}
                original_git = self.git
                def git(*args):
                    key = ('revision' if args == ('git', 'rev-parse', 'HEAD') else
                           'modified' if args == ('git', 'status', '--porcelain', '--untracked-files=normal') else None)
                    if key:
                        calls[key] += 1
                        if changed == key and calls[key] > 1:
                            return 'd' * 40 if key == 'revision' else ' M synthetic.go'
                    return original_git(*args)
                inventories = [[{'path': 'synthetic.go', 'sha256': 'c' * 64}]] * 2
                if changed == 'inventory':
                    inventories[1] = [{'path': 'synthetic.go', 'sha256': 'd' * 64}]
                with mock.patch.object(builder, 'run', side_effect=git), \
                        mock.patch.object(builder, 'source_inventory', side_effect=inventories), \
                        self.assertRaisesRegex(RuntimeError, 'source changed during build'):
                    self.build('changed-' + changed)
                self.assertFalse((self.base / ('changed-' + changed)).exists())
                self.assertEqual(list(self.base.glob('.cosmoedge-connect-build-*')), [])

    def test_default_build_does_not_require_optional_plugin_material(self):
        shutil.rmtree(self.market)
        with mock.patch.object(builder, 'read_plugin_source', side_effect=AssertionError('default build requested optional plugin packaging')):
            root, manifest = self.build('without-plugin-source', '--development-app')
        self.assertNotIn('workbuddyPlugin', manifest)
        self.assertFalse((root / builder.PLUGIN_PAYLOAD).exists())
        candidate = json.loads((root / 'payload/skill/candidate.json').read_text())
        self.assertEqual(candidate['serviceSHA256'], builder.digest(root / builder.APP_SERVICE))
        self.assert_inventory(root, manifest)

    def test_explicit_optional_plugin_is_separate_fully_hashed_and_bound_to_candidate(self):
        source_bytes = {p.relative_to(self.market).as_posix(): p.read_bytes() for p in self.market.rglob('*') if p.is_file()}
        root, manifest = self.build('candidate', '--with-summary-report-guard')
        identity = {'product': 'cosmoedge-connect', 'version': 'phase1-rc5', 'revision': 'a' * 40, 'modified': False, 'platform': 'darwin/arm64'}
        expected_version = '0.1.0-paired.c' + hashlib.sha256(json.dumps(identity, sort_keys=True, separators=(',', ':')).encode()).hexdigest()[:20]
        self.assertEqual(manifest['workbuddyPlugin'], {
            'schemaVersion': 1, 'name': 'cosmoedge-summary-report-guard', 'version': expected_version, 'sourceVersion': '0.1.0',
            'marketplaceName': 'cosmoedge-summary-report-guard-local', 'sourceDirectory': builder.PLUGIN_SOURCE,
            'payloadPath': 'payload/workbuddy-plugin', 'pluginPath': 'payload/workbuddy-plugin/plugins/cosmoedge-summary-report-guard',
            'requiresNativeInstallAndEnable': True})
        plugin = root / manifest['workbuddyPlugin']['pluginPath']
        self.assertEqual(json.loads((plugin / 'candidate.json').read_text()), {'schemaVersion': 1, 'candidate': identity})
        self.assertEqual(json.loads((plugin / '.codebuddy-plugin/plugin.json').read_text())['version'], expected_version)
        self.assertEqual(json.loads((root / builder.PLUGIN_PAYLOAD / '.codebuddy-plugin/marketplace.json').read_text())['plugins'][0]['version'], expected_version)
        entries = self.assert_inventory(root, manifest)
        self.assertTrue(all(e['role'] == 'workbuddy-plugin' for n, e in entries.items() if n.startswith('payload/workbuddy-plugin/')))
        self.assertEqual(source_bytes, {p.relative_to(self.market).as_posix(): p.read_bytes() for p in self.market.rglob('*') if p.is_file()})
        with zipfile.ZipFile(root / 'cosmoedge-operations.zip') as archive:
            self.assertFalse(any('post_read.py' in n or 'marketplace.json' in n for n in archive.namelist()))
        _, other = self.build('next-version', '--version', 'phase1-rc6', '--with-summary-report-guard')
        self.assertNotEqual(other['workbuddyPlugin']['version'], expected_version)

    def test_missing_plugin_source_fails_before_compilation(self):
        shutil.rmtree(self.market)
        with self.assertRaisesRegex(ValueError, 'plugin source'):
            self.build('candidate', '--with-summary-report-guard')
        self.assertEqual(self.calls, [])
        self.assertFalse((self.base / 'candidate').exists())

    def test_plugin_links_are_never_followed(self):
        outside = self.base / 'outside.py'
        outside.write_text('secret must never be copied')
        script = self.plugin / 'scripts/post_read.py'
        script.unlink()
        script.symlink_to(outside)
        with self.assertRaisesRegex(ValueError, 'regular files'):
            self.build('candidate', '--with-summary-report-guard')
        self.assertEqual(self.calls, [])
        script.unlink()
        script.write_text('synthetic')
        actual = self.base / 'actual-market'
        self.market.rename(actual)
        self.market.symlink_to(actual, target_is_directory=True)
        with self.assertRaisesRegex(ValueError, 'linked'):
            self.build('candidate', '--with-summary-report-guard')
        self.assertEqual(self.calls, [])

    def test_plugin_requires_local_source_and_complete_material(self):
        marketplace = self.market / '.codebuddy-plugin/marketplace.json'
        data = json.loads(marketplace.read_text())
        data['plugins'][0]['source'] = '../external'
        marketplace.write_text(json.dumps(data))
        with self.assertRaisesRegex(ValueError, 'identity'):
            self.build('candidate', '--with-summary-report-guard')
        data['plugins'][0]['source'] = './plugins/cosmoedge-summary-report-guard'
        data['plugins'][0]['version'] = '0.2.0'
        marketplace.write_text(json.dumps(data))
        with self.assertRaisesRegex(ValueError, 'identity'):
            self.build('candidate', '--with-summary-report-guard')
        data['plugins'][0]['version'] = '0.1.0'
        marketplace.write_text(json.dumps(data))
        (self.plugin / 'hooks/hooks.json').unlink()
        with self.assertRaisesRegex(ValueError, 'material'):
            self.build('candidate', '--with-summary-report-guard')
        self.assertEqual(self.calls, [])

    def test_development_app_hashes_signed_payload_and_keeps_only_main_executable(self):
        root, manifest = self.build('development', '--development-app', '--app-build-version', '12.3')
        app = root / builder.APP_PAYLOAD
        service = root / builder.APP_SERVICE
        metadata = manifest['service']['macOSApp']
        info = plistlib.loads((app / 'Contents/Info.plist').read_bytes())
        self.assertEqual(metadata, {'payloadPath': builder.APP_PAYLOAD, 'bundleIdentifier': 'com.cosmoedge.connect.development',
                                   'signing': 'development-adhoc', 'teamIdentifier': None,
                                   'buildUUID': builder.macho_build_uuid(service, 'arm64')})
        self.assertEqual(manifest['service']['executablePath'], builder.APP_SERVICE)
        self.assertEqual(info['CFBundleExecutable'], 'cosmoedge-connect')
        self.assertEqual(info['CFBundlePackageType'], 'APPL')
        self.assertEqual(info['CFBundleName'], 'CosmoEdge Connect Development')
        self.assertEqual(info['CFBundleDisplayName'], info['CFBundleName'])
        self.assertEqual(info['CFBundleVersion'], '12.3')
        self.assertEqual(info['CFBundleShortVersionString'], '12.3.0')
        self.assertTrue(info['LSUIElement'])
        self.assertIn('局域网', info['NSLocalNetworkUsageDescription'])
        self.assertFalse(any(path.name.endswith('.app') for path in root.rglob('*')))
        self.assertFalse((root / 'payload/bin').exists())
        entries = self.assert_inventory(root, manifest)
        self.assertEqual([name for name, entry in entries.items() if entry['role'] == 'service'], [builder.APP_SERVICE])
        self.assertEqual(entries[builder.APP_PAYLOAD + '/Contents/_CodeSignature/CodeResources']['role'], 'service-resource')
        self.assertFalse(entries[builder.APP_PAYLOAD + '/Contents/Info.plist']['executable'])
        candidate = json.loads((root / 'payload/skill/candidate.json').read_text())
        self.assertEqual(candidate['serviceSHA256'], builder.digest(service))
        self.assertIn(b'synthetic signature', service.read_bytes())
        with zipfile.ZipFile(root / 'cosmoedge-operations.zip') as archive:
            zipped = json.loads(archive.read('cosmoedge-operations/candidate.json'))
        self.assertEqual(zipped['serviceSHA256'], candidate['serviceSHA256'])
        builds = [call for call in self.calls if call[:2] == ['go', 'build']]
        self.assertEqual(len(builds), 2)
        self.assertNotIn('-buildid=', builds[0][builds[0].index('-ldflags') + 1])
        self.assertIn('-buildid=', builds[1][builds[1].index('-ldflags') + 1])
        self.assertEqual(self.identity, '-')

    def test_apple_app_requires_apple_anchor_and_team(self):
        _, manifest = self.build('apple', '--signing-identity', 'a' * 40)
        app = manifest['service']['macOSApp']
        self.assertEqual(app['signing'], 'apple')
        self.assertEqual(app['bundleIdentifier'], 'com.cosmoedge.connect')
        self.assertEqual(app['teamIdentifier'], 'ABCDE12345')
        self.assertEqual(self.identity, 'A' * 40)
        verify = next(call for call in self.calls if '--verify' in call)
        self.assertEqual(verify[verify.index('--test-requirement') + 1], 'anchor apple generic')

    def test_uuid_changes_for_app_identity_and_actual_compiler_output(self):
        _, development = self.build('dev', '--development-app')
        _, production = self.build('prod', '--signing-identity', 'a' * 40)
        self.initial_binary_suffix = b'compiled with synthetic toolchain B'
        _, rebuilt = self.build('rebuilt', '--development-app')
        uuids = {manifest['service']['macOSApp']['buildUUID'] for manifest in (development, production, rebuilt)}
        self.assertEqual(len(uuids), 3)

    def test_signature_failure_never_emits_candidate_and_removes_staging(self):
        self.fail_sign = True
        with self.assertRaises(subprocess.CalledProcessError):
            self.build('failed', '--development-app')
        self.assertFalse((self.base / 'failed').exists())
        self.assertEqual(list(self.base.glob('.cosmoedge-connect-build-*')), [])

    def test_wrong_identifier_is_rejected(self):
        self.signature_identifier = 'com.unrelated.product'
        with self.assertRaisesRegex(ValueError, 'identifier'):
            self.build('wrong-id', '--development-app')
        self.assertFalse((self.base / 'wrong-id').exists())

    def test_apple_signature_without_team_is_rejected(self):
        self.team = 'not set'
        with self.assertRaisesRegex(ValueError, 'Team Identifier'):
            self.build('no-team', '--signing-identity', 'a' * 40)

    def test_apple_mode_cannot_silently_fall_back_to_adhoc(self):
        self.force_adhoc = True
        with self.assertRaisesRegex(ValueError, 'Team Identifier'):
            self.build('adhoc-fallback', '--signing-identity', 'a' * 40)

    def test_signing_must_preserve_uuid(self):
        self.mutate_uuid = True
        with self.assertRaisesRegex(ValueError, 'UUID changed'):
            self.build('uuid-changed', '--development-app')

    def test_missing_uuid_rejected_before_signing(self):
        self.omit_uuid = True
        with self.assertRaisesRegex(ValueError, 'exactly one nonzero'):
            self.build('uuid-missing', '--development-app')
        self.assertFalse(any('--sign' in call for call in self.calls))


class ArgumentAndMachOTests(unittest.TestCase):
    def parse(self, *flags):
        if '--development-app' not in flags and '--signing-identity' not in flags:
            flags = ('--development-app', *flags)
        with mock.patch.object(builder.platform, 'system', return_value='Darwin'):
            return builder.parse_args(['--version', 'v1-rc1', '--output', '/tmp/synthetic-output', *flags])

    def test_signing_modes_are_exclusive_and_identity_is_exact_sha1(self):
        for flags in (('--development-app', '--signing-identity', 'a' * 40),
                      ('--signing-identity', '-'), ('--signing-identity', 'Developer ID Application: Someone'),
                      ('--signing-identity', 'a' * 39), ('--signing-identity', 'g' * 40)):
            with self.subTest(flags=flags), contextlib.redirect_stderr(io.StringIO()), self.assertRaises(SystemExit):
                self.parse(*flags)

    def test_numeric_app_version_validation(self):
        for version in ('1', '1.0', '1.0.0', '9999.99.99'):
            with self.subTest(version=version):
                self.assertEqual(self.parse('--app-build-version', version).app_build_version, version)
        for version in ('0', '1.0-rc1', '1.0.0.0', '10000.0', '1.100', '01.0', '1.01', '-1'):
            with self.subTest(version=version), contextlib.redirect_stderr(io.StringIO()), self.assertRaises(SystemExit):
                self.parse('--app-build-version', version)

    def test_app_mode_rejects_non_macos_build_host_before_tools(self):
        with mock.patch.object(builder.platform, 'system', return_value='Linux'), \
                mock.patch.object(builder.subprocess, 'run') as tool, \
                contextlib.redirect_stderr(io.StringIO()), self.assertRaises(SystemExit):
            builder.parse_args(['--version', 'v1', '--output', '/tmp/synthetic-output', '--development-app'])
        tool.assert_not_called()

    def test_parser_accepts_go_uuid_variant_and_each_supported_arch(self):
        value = bytes.fromhex('0aeb500ae0a9344cd4fd7417feb5d38d')
        with tempfile.TemporaryDirectory() as raw:
            path = Path(raw) / 'synthetic-macho'
            for arch in ('arm64', 'amd64'):
                path.write_bytes(macho(value, arch))
                self.assertEqual(builder.macho_build_uuid(path, arch), str(uuid.UUID(bytes=value)).upper())

    def test_malformed_missing_duplicate_zero_or_wrong_arch_uuid_is_rejected(self):
        malformed = {
            'not Mach-O': b'ordinary text',
            'truncated': macho()[:44],
            'missing': macho(commands=[]),
            'duplicate': macho(commands=[(0x1b, b'\x01' * 16), (0x1b, b'\x02' * 16)]),
            'zero': macho(b'\x00' * 16),
            'short command': macho(commands=[(0x1b, b'\x01' * 8)]),
            'wrong architecture': macho(arch='amd64'),
        }
        with tempfile.TemporaryDirectory() as raw:
            path = Path(raw) / 'synthetic-macho'
            for name, content in malformed.items():
                with self.subTest(name=name), self.assertRaises(ValueError):
                    path.write_bytes(content)
                    builder.macho_build_uuid(path, 'arm64')


if __name__ == '__main__':
    unittest.main()
