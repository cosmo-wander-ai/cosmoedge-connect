import importlib.util
import os
from pathlib import Path
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[5]


def load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


provisioner = load('provision_token', Path(__file__).resolve().parents[1] / 'provision-token.py')
files = load('token_local_files', ROOT / 'integrations/workbuddy/skills/cosmoedge-operations/scripts/local_files.py')


class ProvisionTokenTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.base = Path(self.temp.name)
        self.root = self.base / 'new-install'

    def test_fresh_install_creates_private_token_and_reuses_exact_bytes(self):
        self.assertTrue(provisioner.provision(self.root, files))
        token = self.root / 'access.token'
        original = token.read_bytes()
        self.assertRegex(original.decode(), r'^[0-9a-f]{64}\n$')
        files.validate(self.root, directory=True)
        files.validate(token)
        self.assertFalse(provisioner.provision(self.root, files))
        self.assertEqual(token.read_bytes(), original)

    def test_missing_token_never_rotates_existing_installation(self):
        self.root.mkdir()
        (self.root / 'windows-install.json').write_text('historical record')
        with self.assertRaises(ValueError):
            provisioner.provision(self.root, files)
        self.assertFalse((self.root / 'access.token').exists())

    def test_invalid_existing_token_is_preserved(self):
        self.root.mkdir()
        files.protect(self.root, directory=True)
        token = self.root / 'access.token'
        descriptor = files.create_file(token)
        with os.fdopen(descriptor, 'wb') as stream:
            stream.write(b'invalid\n')
        with self.assertRaises(ValueError):
            provisioner.provision(self.root, files)
        self.assertEqual(token.read_bytes(), b'invalid\n')

    @unittest.skipIf(os.name == 'nt', 'POSIX symlink case; Windows native DACL gate runs separately')
    def test_linked_root_is_rejected_without_writing_destination(self):
        destination = self.base / 'other'
        destination.mkdir()
        self.root.symlink_to(destination, target_is_directory=True)
        with self.assertRaises(ValueError):
            provisioner.provision(self.root, files)
        self.assertEqual(list(destination.iterdir()), [])


if __name__ == '__main__':
    unittest.main()
