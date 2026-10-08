"""Native Windows security/durability tests; all data and services are synthetic."""
import contextlib
import io
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

SCRIPTS = Path(__file__).resolve().parents[1] / 'skills/cosmoedge-operations/scripts'
sys.path.insert(0, str(SCRIPTS))
import local_files as files
import operations_client as client
import cosmoedge_operations as transport


@unittest.skipUnless(os.name == 'nt', 'native Windows DACL and publication contract')
class WindowsFilesTests(unittest.TestCase):
    def setUp(self):
        self.directory = files.private_tempdir('cosmoedge-windows-test-')

    def tearDown(self):
        shutil.rmtree(self.directory)

    def file(self, name, content=b'private fixture'):
        path = self.directory / name
        with os.fdopen(files.create_file(path), 'wb') as stream:
            stream.write(content)
            stream.flush()
            os.fsync(stream.fileno())
        return path

    def test_new_files_and_directories_are_private_and_readable(self):
        files.validate(self.directory, directory=True)
        path = self.file('request.json', b'{"sourceName":"synthetic"}')
        files.validate(path)
        self.assertEqual(client.secure_read(path, 128, private=True), path.read_bytes())
        self.assertEqual(client.secure_read(path, 128), path.read_bytes())

    def test_inherited_acl_is_rejected_then_explicitly_protected(self):
        path = self.file('token', b'a' * 64)
        subprocess.run(['icacls', str(path), '/inheritance:e'], check=True, capture_output=True)
        with self.assertRaises(OSError):
            files.validate(path)
        with self.assertRaises(transport.ClientError):
            transport._load_token(path)
        files.protect(path)
        self.assertEqual(transport._load_token(path), 'a' * 64)

    def test_current_owner_can_protect_a_file_with_an_empty_dacl(self):
        path = self.file('empty-dacl', b'private fixture')
        handle = files._open(path, access=0x00060000)
        descriptor = files.PTR()
        try:
            files._check(files.advapi.ConvertStringSecurityDescriptorToSecurityDescriptorW(
                'D:P', 1, files.c.byref(descriptor), None))
            present, defaulted, dacl = files.w.BOOL(), files.w.BOOL(), files.PTR()
            files._check(files.advapi.GetSecurityDescriptorDacl(
                descriptor, files.c.byref(present), files.c.byref(dacl), files.c.byref(defaulted)))
            result = files.advapi.SetSecurityInfo(handle, 1, 0x80000004, None, None, dacl, None)
            self.assertEqual(result, 0)
        finally:
            files.kernel.LocalFree(descriptor)
            files.kernel.CloseHandle(handle)
        try:
            with self.assertRaises(OSError):
                files.validate(path)
            with self.assertRaises(PermissionError):
                path.read_bytes()
            files.protect(path)
            files.validate(path)
            self.assertEqual(path.read_bytes(), b'private fixture')
        finally:
            files.protect(path)

    def test_foreign_owner_refusal_never_changes_dacl_or_owner(self):
        path = self.file('foreign-owner-check')
        # Inject the owner mismatch at the SID comparison, without requiring
        # elevated privileges to assign a real fixture to a different user.
        with mock.patch.object(files.advapi, 'EqualSid', return_value=False), \
                mock.patch.object(files.advapi, 'SetSecurityInfo') as update:
            with self.assertRaisesRegex(OSError, "another user's object"):
                files.protect(path)
            update.assert_not_called()
        files.validate(path)
        self.assertEqual(path.read_bytes(), b'private fixture')

    def test_protected_install_directory_allows_copy_then_explicit_file_protection(self):
        source = self.file('source.py', b'# synthetic install fixture\n')
        directory = self.directory / 'install-copy'
        directory.mkdir()
        files.protect(directory, directory=True)
        files.validate(directory, directory=True)
        copied = directory / 'copied.py'
        subprocess.run(['powershell.exe', '-NoProfile', '-NonInteractive', '-Command',
                        'Copy-Item -LiteralPath $env:COSMOEDGE_CONNECT_TEST_SOURCE -Destination $env:COSMOEDGE_CONNECT_TEST_DESTINATION'],
                       env=dict(os.environ, COSMOEDGE_CONNECT_TEST_SOURCE=str(source), COSMOEDGE_CONNECT_TEST_DESTINATION=str(copied)),
                       check=True, capture_output=True)
        self.assertEqual(copied.read_bytes(), source.read_bytes())
        with self.assertRaises(OSError):
            files.validate(copied)
        files.protect(copied)
        files.validate(copied)
        self.assertEqual(client.secure_read(copied, 128), source.read_bytes())

    def test_even_read_only_grant_to_everyone_rejects_private_inputs(self):
        path = self.file('token', b'b' * 64)
        subprocess.run(['icacls', str(path), '/grant', '*S-1-1-0:(R)'], check=True, capture_output=True)
        with self.assertRaises(OSError):
            files.validate(path)
        with self.assertRaises(transport.ClientError):
            transport._load_token(path)
        with self.assertRaises(transport.ClientError):
            client.secure_read(path, 128, private=True)

    def test_hardlink_is_rejected_without_changing_the_original(self):
        path = self.file('original')
        alias = self.directory / 'alias'
        os.link(path, alias)
        for value in (path, alias):
            with self.assertRaises(OSError):
                files.open_read(value)
            with self.assertRaises(OSError):
                files.protect(value)
        self.assertEqual(path.read_bytes(), b'private fixture')

    def test_reparse_point_is_rejected_when_symlink_creation_is_available(self):
        path = self.file('original')
        alias = self.directory / 'alias'
        try:
            alias.symlink_to(path)
        except OSError as error:
            if getattr(error, 'winerror', None) == 1314:
                self.skipTest('Windows account cannot create symbolic links')
            raise
        with self.assertRaises(OSError):
            files.open_read(alias)
        with self.assertRaises(OSError):
            files.protect(alias)

    def test_check_and_open_file_replacement_is_rejected(self):
        original = self.file('original', b'first')
        replacement = self.file('replacement', b'other')
        real_open = files.open_read
        def replace_then_open(path):
            files.replace_durable(replacement, original)
            return real_open(path)
        with mock.patch.object(files, 'open_read', side_effect=replace_then_open):
            with self.assertRaises(transport.ClientError):
                client.secure_read(original, 64, private=True)

    def test_candidate_parent_junction_is_rejected(self):
        outside = files.private_tempdir('cosmoedge-junction-target-')
        junction = self.directory / 'redirect'
        try:
            subprocess.run(['cmd.exe', '/d', '/c', 'mklink', '/J', str(junction), str(outside)],
                           check=True, capture_output=True)
            with self.assertRaises(transport.ClientError):
                client.paired_path(self.directory, 'redirect/helper.py')
        finally:
            if junction.exists():
                junction.rmdir()
            shutil.rmtree(outside)

    def test_existing_unprotected_lock_is_not_hardened_or_accepted(self):
        path = self.directory / 'lock'
        path.write_bytes(b'')
        with self.assertRaises(OSError):
            files.create_file(path, existing=True)

    def test_lock_excludes_another_process_and_releases_on_close(self):
        path = self.directory / 'lock'
        descriptor = files.create_file(path)
        script = ('import os,sys; import local_files as f; '
                  'fd=f.create_file(sys.argv[1],existing=True); f.lock_exclusive(fd); os.close(fd)')
        env = dict(os.environ, PYTHONPATH=str(SCRIPTS), PYTHONDONTWRITEBYTECODE='1')
        try:
            files.lock_exclusive(descriptor)
            blocked = subprocess.run([sys.executable, '-c', script, str(path)], env=env,
                                     capture_output=True, timeout=5)
            self.assertNotEqual(blocked.returncode, 0)
            self.assertIn(b'WinError 33', blocked.stderr)
        finally:
            os.close(descriptor)
        released = subprocess.run([sys.executable, '-c', script, str(path)], env=env,
                                  capture_output=True, timeout=5)
        self.assertEqual(released.returncode, 0, released.stderr)

    def test_exclusive_publication_preserves_collided_target(self):
        staging = self.file('staging', b'new')
        target = self.file('target', b'prior')
        with self.assertRaises(OSError):
            files.publish_exclusive(staging, target)
        self.assertEqual(target.read_bytes(), b'prior')
        self.assertEqual(staging.read_bytes(), b'new')
        fresh = self.directory / 'fresh'
        files.publish_exclusive(staging, fresh)
        self.assertFalse(staging.exists())
        self.assertEqual(client.secure_read(fresh, 16, private=True), b'new')

    def test_replace_is_atomic_write_through_and_preserves_private_acl(self):
        staging = self.file('staging', b'new')
        target = self.file('target', b'prior')
        files.replace_durable(staging, target)
        self.assertFalse(staging.exists())
        self.assertEqual(client.secure_read(target, 16, private=True), b'new')
        files.validate(target)

    def test_flush_and_publish_failures_prevent_any_http_or_token_read(self):
        for label, target in [('flush', client.os), ('publish', files)]:
            with self.subTest(stage=label):
                path = self.file(label + '.json', json.dumps({'sessionRef': 'a' * 32 + '.1788768000.' + 'c' * 64,
                                  'sourceName': 'synthetic', 'question': 'synthetic'}).encode())
                original = path.read_bytes()
                output = io.StringIO()
                name = 'fsync' if label == 'flush' else 'replace_durable'
                with mock.patch.object(target, name, side_effect=OSError('synthetic disk failure')), \
                        mock.patch.object(client, 'Client') as http, \
                        mock.patch.object(transport, '_load_token') as token, \
                        contextlib.redirect_stdout(output):
                    status = client.main(['capture', '--request-file', str(path)])
                result = json.loads(output.getvalue())
                self.assertEqual((status, result['code']), (1, 'request_persistence_failed'))
                self.assertFalse(result['requestSubmitted'])
                self.assertEqual(path.read_bytes(), original)
                self.assertFalse(http.called)
                self.assertFalse(token.called)

    def test_recovery_binding_survives_process_boundary_and_prevents_resubmit(self):
        path = self.file('request.json', b'{"sourceName":"synthetic","question":"synthetic"}')
        arguments = client.parser().parse_args(['capture', '--request-file', str(path),
                    '--session-ref', 'a' * 32 + '.1788768000.' + 'c' * 64])
        client.apply_request_file(arguments)
        client.validate_args(arguments)
        client.persist_request(arguments)
        saved = json.loads(client.secure_read(path, 16384, private=True))
        self.assertEqual(saved['operationKind'], 'observation')
        self.assertEqual(saved['requestId'], arguments.request_id)
        command = [sys.executable, str(SCRIPTS / 'operations_client.py'), 'capture', '--request-file', str(path)]
        process = subprocess.run(command, capture_output=True, text=True, encoding='utf-8', timeout=5,
                                 env=dict(os.environ, PYTHONUTF8='1', PYTHONDONTWRITEBYTECODE='1'))
        self.assertEqual(process.returncode, 1)
        result = json.loads(process.stdout)
        self.assertEqual(result['code'], 'request_recovery_required')
        self.assertFalse(result['requestSubmitted'])

    def test_windows_without_iana_database_uses_only_known_timezone_rules(self):
        import zoneinfo
        with mock.patch.object(zoneinfo, 'ZoneInfo', side_effect=zoneinfo.ZoneInfoNotFoundError):
            self.assertEqual(client.date_value('2026-09-15T00:00:00', 'Asia/Shanghai'), '2026-09-15T00:00:00+08:00')
            self.assertEqual(client.date_value('2026-09-15T00:00:00', 'UTC'), '2026-09-15T00:00:00+00:00')
            self.assertEqual(client.date_value('1990-09-15T00:00:00+08:00', 'Asia/Shanghai'), '1990-09-15T00:00:00+08:00')
            for zone, date in [('America/New_York', '2026-09-15'), ('Asia/Shanghai', '1990-09-15')]:
                with self.assertRaises(transport.ClientError):
                    client.date_value(date, zone)


if __name__ == '__main__':
    unittest.main()
