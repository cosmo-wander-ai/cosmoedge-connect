import contextlib
import importlib.util
import io
import hashlib
import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest import mock


SCRIPT = Path(__file__).resolve().parents[1] / 'build-connect-windows.py'
SPEC = importlib.util.spec_from_file_location('build_connect_windows', SCRIPT)
builder = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(builder)


class WindowsBuilderTests(unittest.TestCase):
    def test_mcp_and_first_install_helper_are_in_paired_inventory(self):
        with tempfile.TemporaryDirectory() as root:
            output = Path(root) / 'bundle'
            arguments = [str(SCRIPT), '--output', str(output), '--version', 'test-mcp', '--with-mcp']
            def compile(args, **kwargs):
                self.assertEqual(kwargs['env']['GOOS'], 'windows')
                Path(args[args.index('-o') + 1]).write_bytes(args[-1].encode())
            def git(*args):
                return '' if args[0] == 'status' else 'a' * 40
            with mock.patch.object(sys, 'argv', arguments), mock.patch.object(builder, 'git', side_effect=git), \
                    mock.patch.object(builder, 'inventory', return_value={'source': 'identity'}), \
                    mock.patch.object(builder.subprocess, 'run', side_effect=compile), contextlib.redirect_stdout(io.StringIO()):
                builder.main()
            manifest = json.loads((output / 'manifest.json').read_text())
            entries = {item['path']: item for item in manifest['files']}
            self.assertIn('provision-token.py', entries)
            self.assertIn('payload/cosmoedge-mcp.exe', entries)
            self.assertIn('payload/mcp-candidate.json', entries)
            self.assertIn('skills/cosmoedge-operations/SKILL.md', entries)
            self.assertIn('LICENSE', entries)
            self.assertIn('NOTICE', entries)
            self.assertIn('third_party/licenses/index.json', entries)
            self.assertEqual(manifest['candidate']['mcpSHA256'], entries['payload/cosmoedge-mcp.exe']['sha256'])
            self.assertEqual(json.loads((output / 'payload/mcp-candidate.json').read_text()), manifest['candidate'])
            for name, entry in entries.items():
                self.assertEqual(entry['sha256'], hashlib.sha256((output / name).read_bytes()).hexdigest())

    def test_invalid_version_is_rejected_before_creating_output_or_running_tools(self):
        for version in ('dev -cpuprofile injected.profile', 'dev" -X injected=value',
                        'dev\n', '', 'v' * 81):
            with self.subTest(version=version), tempfile.TemporaryDirectory() as root:
                output = Path(root) / 'bundle'
                arguments = [str(SCRIPT), '--go', 'must-not-execute.exe',
                             '--output', str(output), '--version', version]
                with mock.patch.object(sys, 'argv', arguments), \
                        mock.patch.object(builder, 'git') as git, \
                        mock.patch.object(builder, 'inventory') as inventory, \
                        mock.patch.object(builder.subprocess, 'run') as run, \
                        contextlib.redirect_stderr(io.StringIO()), \
                        self.assertRaises(SystemExit) as error:
                    builder.main()
                self.assertEqual(error.exception.code, 2)
                self.assertFalse(output.exists())
                git.assert_not_called()
                inventory.assert_not_called()
                run.assert_not_called()


if __name__ == '__main__':
    unittest.main()
