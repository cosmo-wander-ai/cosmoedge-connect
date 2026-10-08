#!/usr/bin/env python3
"""Plan or run conservative checks for Git changes, locally and in CI."""

import argparse
import json
import os
from pathlib import Path
import re
import subprocess
import sys


ROOT = Path(__file__).resolve().parents[1]
ROOT_DOCS = {
    'CONTRIBUTING.md', 'SECURITY.md', 'SUPPORT.md', 'CHANGELOG.md',
    'CODE_OF_CONDUCT.md',
}
IMAGE_EXTENSIONS = {'.svg', '.png', '.jpg', '.jpeg', '.webp', '.gif'}
PYTHON_SUITES = (
    'integrations/workbuddy/tests',
    'integrations/workbuddy/deploy/macos/tests',
    'integrations/workbuddy/deploy/windows/tests',
    'scripts/tests',
)


class ComparisonError(Exception):
    """The changed-file set cannot be established reliably."""


def git(root, *args):
    try:
        result = subprocess.run(
            ['git', *args], cwd=root, capture_output=True, check=False, timeout=30)
    except OSError as error:
        raise ComparisonError('Git could not be started') from error
    except subprocess.TimeoutExpired as error:
        raise ComparisonError('Git change inspection timed out') from error
    if result.returncode:
        raise ComparisonError('git {} failed (exit {})'.format(args[0], result.returncode))
    return result.stdout


def resolve_commit(root, ref):
    try:
        value = git(root, 'rev-parse', '--verify', '--end-of-options', ref + '^{commit}').strip()
    except ComparisonError as error:
        raise ComparisonError('Cannot resolve commit ref {!r}: {}'.format(ref, error)) from error
    if not re.fullmatch(rb'(?:[0-9a-f]{40}|[0-9a-f]{64})', value):
        raise ComparisonError('Git did not return a commit identity')
    return value.decode('ascii')


def nul_paths(output):
    if not output:
        return set()
    if not output.endswith(b'\0'):
        raise ComparisonError('Git returned incomplete NUL-delimited paths')
    paths = output[:-1].split(b'\0')
    if any(not path for path in paths):
        raise ComparisonError('Git returned an empty changed path')
    return {os.fsdecode(path) for path in paths}


def diff_paths(root, *revisions):
    # Disabling rename detection preserves both sides, including code -> Markdown.
    return nul_paths(git(
        root, 'diff', '--no-ext-diff', '--no-textconv', '--no-renames',
        '--ignore-submodules=none', '--name-only', '-z', *revisions, '--'))


def is_documentation(path):
    parts = path.split('/')
    if any(part in ('', '.', '..') for part in parts):
        return False
    if len(parts) == 1:
        return path in ROOT_DOCS or (
            path.startswith('README') and path.endswith('.md'))
    if path == 'scripts/README.md':
        return True
    if parts[0] == 'docs' and path.endswith('.md'):
        return True
    return (len(parts) >= 3 and parts[:2] == ['docs', 'assets']
            and Path(parts[-1]).suffix in IMAGE_EXTENSIONS)


def classify_paths(files, reason):
    files = sorted(set(files))
    other = [path for path in files if not is_documentation(path)]
    scope = 'full' if other else 'docs' if files else 'none'
    if other:
        reason = 'Changes outside the documentation allowlist: {}. {}'.format(
            ', '.join(repr(path) for path in other[:3]), reason)
    elif files:
        reason = 'All {} changed paths are documentation. {}'.format(len(files), reason)
    else:
        reason = 'No changed paths. ' + reason
    return {'scope': scope, 'full': scope == 'full', 'docs': scope != 'none',
            'files': files, 'reason': reason}


def plan_checks(root, *, base=None, head=None, all_checks=False):
    if all_checks:
        return {'scope': 'full', 'full': True, 'docs': True, 'files': [],
                'reason': 'Full checks explicitly requested with --all.'}
    files = set()
    try:
        head_commit = resolve_commit(root, head if head is not None else 'HEAD')
        if base is not None:
            base_commit = resolve_commit(root, base)
            comparison = 'Exact comparison {}..{}.'.format(base_commit, head_commit)
        else:
            for candidate in ('refs/remotes/origin/main', 'refs/heads/main'):
                try:
                    anchor = resolve_commit(root, candidate)
                    break
                except ComparisonError:
                    continue
            else:
                raise ComparisonError('Neither origin/main nor main is available; specify --base')
            # An automatic local baseline describes this branch's work, without
            # counting unrelated changes that have landed on main since branching.
            merge_bases = git(root, 'merge-base', '--all', anchor, head_commit).splitlines()
            if len(merge_bases) != 1:
                raise ComparisonError('The automatic baseline has no unique merge-base; specify --base')
            base_commit = resolve_commit(root, merge_bases[0].decode('ascii'))
            comparison = 'Automatic base {} at merge-base {}.'.format(candidate, base_commit)
        files.update(diff_paths(root, base_commit, head_commit))
        if head is None:
            # Separate views retain staged changes even if the worktree cancels them.
            files.update(diff_paths(root, '--cached', head_commit))
            files.update(diff_paths(root))
            files.update(nul_paths(git(root, 'ls-files', '--others', '--exclude-standard', '-z')))
            comparison += ' Includes staged, unstaged and non-ignored untracked files.'
        return classify_paths(files, comparison)
    except (ComparisonError, UnicodeError) as error:
        return {'scope': 'full', 'full': True, 'docs': True, 'files': sorted(files),
                'reason': 'Cannot reliably compare changes; running full checks. ' + str(error)}


def check_commands(scope, *, python, go, windows=None):
    if scope == 'none':
        return []
    docs = [python, 'scripts/check-docs.py']
    if scope == 'docs':
        return [docs]
    if scope != 'full':
        raise ValueError('Unknown check scope: ' + scope)
    commands = [[go, 'test', '-p', '1', '-count=1', './...']]
    if windows is None:
        windows = os.name == 'nt'
    if windows:
        # Preserve the native Windows owner setup and restoration for all suites.
        commands.append([
            'pwsh', '-NoLogo', '-NoProfile', '-NonInteractive', '-File',
            'scripts/test-windows-python.ps1', '-Python', python])
    else:
        commands.extend([python, '-m', 'unittest', 'discover', '-s', suite, '-v']
                        for suite in PYTHON_SUITES)
    commands.extend([[go, 'vet', './...'], docs])
    return commands


def run_checks(root, scope, *, python, go):
    for command in check_commands(scope, python=python, go=go):
        print('Running: ' + ' '.join(repr(arg) for arg in command), file=sys.stderr, flush=True)
        try:
            result = subprocess.run(command, cwd=root, stdout=sys.stderr, stderr=sys.stderr)
        except OSError as error:
            print('Unable to run check: ' + str(error), file=sys.stderr)
            return 1
        if result.returncode:
            return result.returncode if result.returncode > 0 else 1
    return 0


def main(argv=None, *, root=ROOT):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--base', help='Explicit comparison base; defaults to origin/main or main merge-base')
    parser.add_argument('--head', help='Exact committed endpoint; omit to also include local changes')
    parser.add_argument('--all', action='store_true', help='Force full checks without comparing Git refs')
    parser.add_argument('--json', action='store_true', help='Print the plan as JSON')
    parser.add_argument('--github-output', type=Path, help='Append scope, full and docs GitHub job outputs')
    parser.add_argument('--run', action='store_true', help='Run the selected checks; otherwise only show the plan')
    parser.add_argument('--go', default='go', help='Go executable used by --run')
    parser.add_argument('--python', default=sys.executable, help='Python executable used by --run')
    args = parser.parse_args(argv)
    plan = plan_checks(root, base=args.base, head=args.head, all_checks=args.all)
    if args.github_output:
        try:
            with args.github_output.open('a', encoding='utf-8', newline='\n') as output:
                for name in ('full', 'docs', 'scope'):
                    value = str(plan[name]).lower() if isinstance(plan[name], bool) else plan[name]
                    output.write('{}={}\n'.format(name, value))
        except OSError as error:
            print('Unable to write GitHub outputs: ' + str(error), file=sys.stderr)
            return 2
    if args.json:
        print(json.dumps(plan, ensure_ascii=True, indent=2), flush=True)
    else:
        print('Check scope: {}\n{}'.format(plan['scope'], plan['reason']), flush=True)
        for path in plan['files']:
            print('  ' + repr(path))
    if args.run:
        return run_checks(root, plan['scope'], python=args.python, go=args.go)
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
