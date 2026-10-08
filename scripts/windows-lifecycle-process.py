"""Test-only subprocess capture; the PowerShell caller owns the total deadline.

Do not inherit the caller's output pipes into a background service. Keep capture
files in the already-private test root until its owned processes are stopped.
"""
import argparse
import os
from pathlib import Path
import subprocess
import sys


def replay(local_files, path, output):
    descriptor = local_files.open_read(path)
    with os.fdopen(descriptor, 'rb') as stream:
        # The direct child's complete output is available after wait(). A
        # descendant may retain the regular file; its EOF is irrelevant here.
        remaining = os.fstat(stream.fileno()).st_size
        while remaining:
            chunk = stream.read(min(remaining, 65536))
            if not chunk:
                raise OSError('capture truncated during read')
            output.write(chunk)
            remaining -= len(chunk)
        output.flush()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--capture-root', type=Path, required=True)
    parser.add_argument('--local-files', type=Path, required=True)
    parser.add_argument('command', nargs=argparse.REMAINDER)
    args = parser.parse_args()
    command = args.command[1:] if args.command[:1] == ['--'] else args.command
    if not command:
        parser.error('a child executable and its arguments are required')
    sys.path.insert(0, str(args.local_files))
    import local_files
    local_files.validate(args.capture_root, directory=True)
    stdout_fd, stdout_name = local_files.private_tempfile('process-stdout-', args.capture_root)
    try:
        stderr_fd, stderr_name = local_files.private_tempfile('process-stderr-', args.capture_root)
        try:
            child = subprocess.Popen(command, stdin=subprocess.DEVNULL,
                                     stdout=stdout_fd, stderr=stderr_fd,
                                     close_fds=True, shell=False, env=dict(os.environ))
        finally:
            os.close(stderr_fd)
    finally:
        os.close(stdout_fd)
    # The outer live runner process remains an ancestor, so its bounded
    # Kill(entireProcessTree: true) can terminate this invocation on timeout.
    code = child.wait()
    replay(local_files, Path(stdout_name), sys.stdout.buffer)
    replay(local_files, Path(stderr_name), sys.stderr.buffer)
    return code


if __name__ == '__main__':
    try:
        raise SystemExit(main())
    except Exception as error:
        # Never log argv, inherited environment, or captured contents on an
        # internal runner error. The private files remain available to cleanup.
        print('Lifecycle capture runner failed: ' + type(error).__name__, file=sys.stderr)
        raise SystemExit(125)
