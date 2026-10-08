"""Both public Python entry points emit UTF-8 independently of host code pages."""
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest


SCRIPTS = Path(__file__).resolve().parents[1] / 'skills/cosmoedge-operations/scripts'


class CLIEncodingTests(unittest.TestCase):
    def test_chinese_refusal_is_utf8_under_a_legacy_redirected_code_page(self):
        with tempfile.TemporaryDirectory() as directory:
            missing_token = str(Path(directory) / 'missing.token')
            environment = dict(os.environ, PYTHONIOENCODING='cp1252:strict', PYTHONUTF8='0',
                               PYTHONDONTWRITEBYTECODE='1', COSMOEDGE_CONNECT_LOG_DIR='')
            for script, command in (('cosmoedge_operations.py', 'capabilities'),
                                    ('cosmoedge_operations.py', 'catalog'),
                                    ('operations_client.py', 'catalog')):
                with self.subTest(script=script, command=command):
                    process = subprocess.run(
                        [sys.executable, str(SCRIPTS / script), command, '--token-file', missing_token],
                        env=environment, capture_output=True, timeout=10)
                    self.assertEqual(process.returncode, 1, process.stderr)
                    self.assertEqual(process.stderr, b'')
                    text = process.stdout.decode('utf-8')
                    self.assertEqual(len(text.splitlines()), 1)
                    result = json.loads(text)
                    self.assertFalse(result['ok'])
                    self.assertRegex(result['userMessage'], r'[\u3400-\u9fff]')
                    self.assertNotIn('\ufffd', text)


if __name__ == '__main__':
    unittest.main()
