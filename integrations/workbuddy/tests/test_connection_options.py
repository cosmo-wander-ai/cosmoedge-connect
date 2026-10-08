"""Both public client routes obey the same connection configuration."""
import os
from pathlib import Path
import sys
import unittest
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'skills/cosmoedge-operations/scripts'))
import cosmoedge_operations as transport
import operations_client


class ConnectionOptionsTests(unittest.TestCase):
    def test_environment_and_explicit_overrides_apply_to_both_routes(self):
        settings = {'COSMOEDGE_CONNECT_URL': 'http://127.0.0.1:12345',
                    'COSMOEDGE_CONNECT_TOKEN_FILE': '/private/test-token-path'}
        with mock.patch.dict(os.environ, settings):
            for parser, command in ((transport._build_parser(), 'capabilities'),
                                    (operations_client.parser(), 'catalog')):
                with self.subTest(command=command):
                    args = parser.parse_args([command])
                    self.assertEqual(args.base_url, settings['COSMOEDGE_CONNECT_URL'])
                    self.assertEqual(args.token_file, settings['COSMOEDGE_CONNECT_TOKEN_FILE'])
                    args = parser.parse_args([command, '--base-url', 'http://127.0.0.1:54321',
                                             '--token-file', '/private/explicit-token-path'])
                    self.assertEqual(args.base_url, 'http://127.0.0.1:54321')
                    self.assertEqual(args.token_file, '/private/explicit-token-path')
