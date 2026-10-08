"""Test discovery must not replace the exception class used by public clients."""
import json
from pathlib import Path
import subprocess
import sys
import textwrap
import unittest


class ModuleIdentityTests(unittest.TestCase):
    def test_discovery_orders_preserve_catchable_client_errors(self):
        modules = ('test_connection_options', 'test_cosmoedge_operations',
                   'test_windows_local_files')
        probe = textwrap.dedent('''
            import importlib
            import json
            from pathlib import Path
            import sys
            import tempfile
            for name in sys.argv[1:]:
                importlib.import_module(name)
            client = importlib.import_module('operations_client')
            transport = importlib.import_module('cosmoedge_operations')
            codes = []
            with tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                calls = (
                    lambda: client.secure_read(root / 'missing', 64, private=True),
                    lambda: client.paired_path(root, '../escape'),
                    lambda: client.date_value('2026-09-15', 'Unknown/FixtureZone'),
                )
                for call in calls:
                    try:
                        call()
                    except transport.ClientError as error:
                        codes.append(error.code)
                    else:
                        raise AssertionError('unsafe input was accepted')
            print(json.dumps(codes))
        ''')
        for order in (modules, tuple(reversed(modules))):
            with self.subTest(order=order):
                result = subprocess.run(
                    [sys.executable, '-c', probe, *order],
                    cwd=Path(__file__).resolve().parent, capture_output=True,
                    text=True, encoding='utf-8', timeout=15)
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertEqual(json.loads(result.stdout),
                                 ['invalid_arguments', 'version_mismatch', 'invalid_arguments'])
