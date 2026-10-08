"""Create one protected first-install transport token; never replace a token."""
import argparse
import os
from pathlib import Path
import re
import secrets
import sys


def provision(root, files):
    """The verified installer passes its paired local_files module explicitly."""
    token = root / 'access.token'
    if root.is_symlink():
        raise ValueError('Installation root cannot be linked')
    if token.exists() or token.is_symlink():
        files.validate(root, directory=True)
        descriptor = files.open_read(token)
        try:
            files.validate(token, descriptor=descriptor)
            with os.fdopen(descriptor, 'rb', closefd=False) as stream:
                if not re.fullmatch(b'[0-9a-f]{64}\n?', stream.read(67)):
                    raise ValueError('Existing token is invalid; it was preserved')
        finally:
            os.close(descriptor)
        return False
    if root.exists() and (not root.is_dir() or any(root.iterdir())):
        raise ValueError('Missing token in an existing installation; no replacement was created')
    root.mkdir(parents=True, exist_ok=True)
    files.protect(root, directory=True)
    files.validate(root, directory=True)
    descriptor = files.create_file(token)  # CREATE_NEW + protected DACL on Windows.
    try:
        with os.fdopen(descriptor, 'wb', closefd=False) as stream:
            stream.write((secrets.token_hex(32) + '\n').encode('ascii'))
            stream.flush()
            os.fsync(descriptor)
        files.validate(token, descriptor=descriptor)
    finally:
        os.close(descriptor)
    return True


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--scripts', type=Path, required=True)
    parser.add_argument('--root', type=Path, required=True)
    args = parser.parse_args()
    sys.path.insert(0, str(args.scripts))
    import local_files
    try:
        provision(args.root, local_files)
    except (OSError, ValueError):
        print('Token provisioning failed; existing material was preserved.', file=sys.stderr)
        return 1
    return 0


if __name__ == '__main__':
    sys.exit(main())
