"""Exercise change selection in isolated Git repositories without running checks."""

import contextlib
import importlib.util
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


SCRIPT = Path(__file__).resolve().parents[1] / 'check-changes.py'
SPEC = importlib.util.spec_from_file_location('check_changes', SCRIPT)
checker = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(checker)
GIT = shutil.which('git')


@unittest.skipUnless(GIT, 'Git is required for isolated change-classifier tests')
class GitChangeTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix='connect changes ')
        self.addCleanup(temporary.cleanup)
        self.temporary = Path(temporary.name)
        self.root = self.temporary / 'repository'
        self.root.mkdir()
        # Do not inherit signing, hooks, index overrides, or the user's Git config.
        environment = {key: value for key, value in os.environ.items()
                       if not key.startswith('GIT_')}
        environment.update({
            'GIT_CONFIG_NOSYSTEM': '1',
            'GIT_CONFIG_GLOBAL': os.devnull,
            'GIT_AUTHOR_NAME': 'Classifier Test',
            'GIT_AUTHOR_EMAIL': 'classifier@example.invalid',
            'GIT_COMMITTER_NAME': 'Classifier Test',
            'GIT_COMMITTER_EMAIL': 'classifier@example.invalid',
            'GIT_TERMINAL_PROMPT': '0',
        })
        environment_patch = mock.patch.dict(os.environ, environment, clear=True)
        environment_patch.start()
        self.addCleanup(environment_patch.stop)
        self.git('init', '-q')
        self.git('symbolic-ref', 'HEAD', 'refs/heads/main')
        self.git('config', 'core.autocrlf', 'false')
        self.git('config', 'core.hooksPath', str(self.temporary / 'no-hooks'))
        self.git('config', 'commit.gpgsign', 'false')
        self.write('README.md', '# Test repository\n')
        self.write('internal/worker.go', 'package worker\n')
        self.write('.gitignore', 'ignored/\n*.cache\n')
        self.base = self.commit()

    def git(self, *arguments):
        result = subprocess.run([GIT, *arguments], cwd=self.root,
                                capture_output=True, check=False)
        self.assertEqual(result.returncode, 0,
                         '{}: {}'.format(arguments, os.fsdecode(result.stderr)))
        return result.stdout.decode('ascii').strip()

    def write(self, name, content='test content\n'):
        path = self.root / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content, encoding='utf-8')
        return path

    def commit(self):
        self.git('add', '-A')
        self.git('commit', '-q', '-m', 'Synthetic classifier change')
        return self.git('rev-parse', 'HEAD')

    def plan(self, **options):
        return checker.plan_checks(self.root, **options)

    def assert_plan(self, plan, scope, files):
        self.assertEqual(plan['scope'], scope, plan)
        self.assertEqual(plan['full'], scope == 'full', plan)
        self.assertEqual(plan['docs'], scope != 'none', plan)
        self.assertEqual(plan['files'], sorted(files), plan)

    def test_documentation_allowlist_from_committed_paths(self):
        names = [
            'README.md', 'README.zh-CN.md', 'CONTRIBUTING.md', 'SECURITY.md',
            'SUPPORT.md', 'CHANGELOG.md', 'CODE_OF_CONDUCT.md',
            'scripts/README.md', 'docs/development.md', 'docs/nested/guide.md',
        ] + ['docs/assets/nested/picture' + extension
             for extension in ('.svg', '.png', '.jpg', '.jpeg', '.webp', '.gif')]
        for name in names:
            self.write(name)
        head = self.commit()
        self.assert_plan(self.plan(base=self.base, head=head), 'docs', names)

    def test_code_mixed_with_documentation_requires_full(self):
        self.write('README.md', '# Updated\n')
        self.write('internal/worker.go', 'package changed\n')
        self.assert_plan(self.plan(base=self.base, head=self.commit()), 'full',
                         ['README.md', 'internal/worker.go'])

    def test_non_allowlisted_paths_require_full(self):
        for name in (
                'docs/unknown.txt', 'docs/assets/data.json', 'docs/picture.svg',
                'docs/example.py', 'notes.md', 'skills/operator/SKILL.md',
                'integrations/workbuddy/README.md', 'scripts/guide.md',
                'scripts/check-changes.py', 'Makefile', '.github/workflows/ci.yml',
                'third_party/licenses/README.md'):
            with self.subTest(path=name):
                path = self.write(name)
                try:
                    self.assert_plan(self.plan(base=self.base), 'full', [name])
                finally:
                    path.unlink()

    def test_deleted_code_is_classified_without_existing_file(self):
        (self.root / 'internal/worker.go').unlink()
        self.assert_plan(self.plan(base=self.base, head=self.commit()), 'full',
                         ['internal/worker.go'])

    def test_deleted_documentation_stays_documentation(self):
        (self.root / 'README.md').unlink()
        self.assert_plan(self.plan(base=self.base, head=self.commit()), 'docs',
                         ['README.md'])

    def assert_rename(self, source, destination, scope):
        target = self.root / destination
        target.parent.mkdir(parents=True, exist_ok=True)
        (self.root / source).rename(target)
        head = self.commit()
        self.assert_plan(self.plan(base=self.base, head=head), scope,
                         [source, destination])

    def test_code_renamed_to_documentation_keeps_deleted_code_side(self):
        self.assert_rename('internal/worker.go', 'docs/worker.md', 'full')

    def test_documentation_renamed_to_code_keeps_both_sides(self):
        self.assert_rename('README.md', 'internal/example.go', 'full')

    def test_documentation_rename_stays_documentation(self):
        self.assert_rename('README.md', 'docs/renamed.md', 'docs')

    def test_explicit_missing_refs_conservatively_require_full(self):
        for arguments in ({'base': 'missing-base', 'head': 'HEAD'},
                          {'base': self.base, 'head': 'missing-head'}):
            with self.subTest(arguments=arguments):
                plan = self.plan(**arguments)
                self.assert_plan(plan, 'full', [])
                self.assertIn('Cannot reliably compare', plan['reason'])

    def test_empty_unborn_repository_requires_full(self):
        empty_root = self.temporary / 'empty-repository'
        self.git('init', '-q', str(empty_root))
        plan = checker.plan_checks(empty_root)
        self.assert_plan(plan, 'full', [])
        self.assertIn('Cannot reliably compare', plan['reason'])
        self.assertIn('HEAD', plan['reason'])

    def test_all_bypasses_even_missing_refs_and_git(self):
        with mock.patch.object(checker, 'git', side_effect=AssertionError('No Git needed')):
            plan = self.plan(base='missing', head='missing', all_checks=True)
        self.assert_plan(plan, 'full', [])
        self.assertIn('--all', plan['reason'])

    def test_automatic_origin_main_takes_priority_over_local_main(self):
        self.git('update-ref', 'refs/remotes/origin/main', self.base)
        self.write('internal/worker.go', 'package changed\n')
        self.commit()
        self.git('checkout', '-q', '-b', 'feature')
        plan = self.plan(head='HEAD')
        self.assert_plan(plan, 'full', ['internal/worker.go'])
        self.assertIn('refs/remotes/origin/main', plan['reason'])

    def test_automatic_base_falls_back_to_local_main(self):
        self.git('checkout', '-q', '-b', 'feature')
        self.write('docs/feature.md')
        self.commit()
        plan = self.plan(head='HEAD')
        self.assert_plan(plan, 'docs', ['docs/feature.md'])
        self.assertIn('refs/heads/main', plan['reason'])

    def test_automatic_base_missing_requires_full(self):
        self.git('branch', '-m', 'feature')
        plan = self.plan(head='HEAD')
        self.assert_plan(plan, 'full', [])
        self.assertIn('Neither origin/main nor main', plan['reason'])

    def test_automatic_merge_base_excludes_unrelated_main_changes(self):
        self.git('checkout', '-q', '-b', 'feature')
        self.write('docs/feature.md')
        self.commit()
        self.git('checkout', '-q', 'main')
        self.write('internal/worker.go', 'package unrelated\n')
        main_head = self.commit()
        self.git('update-ref', 'refs/remotes/origin/main', main_head)
        self.git('checkout', '-q', 'feature')
        plan = self.plan(head='HEAD')
        self.assert_plan(plan, 'docs', ['docs/feature.md'])
        self.assertIn('merge-base ' + self.base, plan['reason'])
        # An explicit base intentionally compares the exact two trees instead.
        self.assert_plan(self.plan(base=main_head, head='HEAD'), 'full',
                         ['docs/feature.md', 'internal/worker.go'])

    def test_automatic_base_without_common_ancestor_requires_full(self):
        tree = self.git('rev-parse', 'HEAD^{tree}')
        unrelated = self.git('commit-tree', tree, '-m', 'Unrelated history')
        self.git('update-ref', 'refs/remotes/origin/main', unrelated)
        plan = self.plan(head='HEAD')
        self.assert_plan(plan, 'full', [])
        self.assertIn('Cannot reliably compare', plan['reason'])

    def test_multiple_merge_bases_require_full_instead_of_arbitrary_selection(self):
        tree = self.git('rev-parse', 'HEAD^{tree}')
        left = self.git('commit-tree', tree, '-p', self.base, '-m', 'Left branch')
        right = self.git('commit-tree', tree, '-p', self.base, '-m', 'Right branch')
        first_merge = self.git('commit-tree', tree, '-p', left, '-p', right, '-m', 'First merge')
        second_merge = self.git('commit-tree', tree, '-p', right, '-p', left, '-m', 'Second merge')
        self.assertEqual(set(self.git('merge-base', '--all', first_merge, second_merge).splitlines()),
                         {left, right})
        self.git('update-ref', 'refs/remotes/origin/main', first_merge)
        plan = self.plan(head=second_merge)
        self.assert_plan(plan, 'full', [])
        self.assertIn('Cannot reliably compare', plan['reason'])

    def test_dirty_staged_unstaged_untracked_and_ignored(self):
        self.write('docs/staged.md')
        self.git('add', 'docs/staged.md')
        self.write('README.md', '# Unstaged\n')
        self.write('docs/untracked/nested.md')
        self.write('ignored/do-not-test.go')
        self.write('scratch.cache')
        self.assert_plan(self.plan(), 'docs',
                         ['README.md', 'docs/staged.md', 'docs/untracked/nested.md'])

    def test_staged_change_cannot_be_hidden_by_worktree_cancellation(self):
        self.write('internal/worker.go', 'package staged\n')
        self.git('add', 'internal/worker.go')
        self.write('internal/worker.go', 'package worker\n')
        self.assertEqual(self.git('diff', '--name-only', 'HEAD'), '')
        self.assert_plan(self.plan(), 'full', ['internal/worker.go'])

    def test_staged_deletion_and_untracked_replacement_preserve_path(self):
        self.git('rm', '-q', 'internal/worker.go')
        self.write('internal/worker.go', 'package worker\n')
        self.assert_plan(self.plan(), 'full', ['internal/worker.go'])

    def test_explicit_head_excludes_all_dirty_views(self):
        self.write('internal/worker.go', 'package staged\n')
        self.git('add', 'internal/worker.go')
        self.write('README.md', '# Unstaged\n')
        self.write('unknown.new')
        self.assert_plan(self.plan(base=self.base, head='HEAD'), 'none', [])

    def test_space_and_chinese_paths_are_preserved(self):
        names = ['docs/with spaces.md', 'docs/中文 文档.md']
        for name in names:
            self.write(name)
        self.assert_plan(self.plan(base=self.base, head=self.commit()), 'docs', names)

    @unittest.skipIf(os.name == 'nt', 'Windows filenames cannot contain control characters')
    def test_nul_delimited_git_paths_preserve_newline_and_tab(self):
        names = ['docs/line\nbreak.md', 'docs/tab\tname.md']
        for name in names:
            self.write(name)
        self.assert_plan(self.plan(), 'docs', names)
        self.assert_plan(self.plan(base=self.base, head=self.commit()), 'docs', names)

    def test_cli_json_and_three_github_outputs_for_each_scope(self):
        output_path = self.temporary / 'github-output.txt'
        for scope in ('none', 'docs', 'full'):
            with self.subTest(scope=scope):
                if scope == 'docs':
                    self.write('docs/guide.md')
                    self.commit()
                elif scope == 'full':
                    self.write('internal/worker.go', 'package changed\n')
                    self.commit()
                output_path.write_bytes(b'existing=value\n')
                stdout = io.StringIO()
                with contextlib.redirect_stdout(stdout), mock.patch.object(checker, 'run_checks') as run:
                    status = checker.main([
                        '--base', self.base, '--head', 'HEAD', '--json',
                        '--github-output', str(output_path)], root=self.root)
                self.assertEqual(status, 0)
                run.assert_not_called()
                plan = json.loads(stdout.getvalue())
                self.assertEqual(plan['scope'], scope)
                self.assertEqual(plan['full'], scope == 'full')
                self.assertEqual(plan['docs'], scope != 'none')
                self.assertEqual(output_path.read_bytes(), (
                    'existing=value\nfull={}\ndocs={}\nscope={}\n'.format(
                        str(scope == 'full').lower(), str(scope != 'none').lower(), scope)
                ).encode('utf-8'))

    def test_cli_run_passes_selected_scope_executables_and_exit_code(self):
        self.write('docs/untracked.md')
        with contextlib.redirect_stdout(io.StringIO()), \
                mock.patch.object(checker, 'run_checks', return_value=7) as run:
            status = checker.main(['--run', '--json', '--python', 'selected-python',
                                   '--go', 'selected-go'], root=self.root)
        self.assertEqual(status, 7)
        run.assert_called_once_with(self.root, 'docs', python='selected-python', go='selected-go')

    def test_cli_output_write_failure_does_not_start_checks(self):
        with contextlib.redirect_stderr(io.StringIO()), \
                mock.patch.object(checker, 'run_checks') as run:
            status = checker.main(['--all', '--run', '--github-output',
                                   str(self.temporary / 'missing' / 'output')], root=self.root)
        self.assertEqual(status, 2)
        run.assert_not_called()


class ParserAndRunnerTests(unittest.TestCase):
    def test_git_start_failure_and_timeout_conservatively_require_full(self):
        for error, reason in (
                (FileNotFoundError('git is unavailable'), 'Git could not be started'),
                (subprocess.TimeoutExpired(['git', 'rev-parse'], 30), 'Git change inspection timed out')):
            with self.subTest(error=type(error).__name__), \
                    mock.patch.object(checker.subprocess, 'run', side_effect=error) as run:
                plan = checker.plan_checks(Path('synthetic-repository'))
            self.assertEqual(plan['scope'], 'full', plan)
            self.assertTrue(plan['full'])
            self.assertTrue(plan['docs'])
            self.assertEqual(plan['files'], [])
            self.assertIn(reason, plan['reason'])
            self.assertEqual(run.call_count, 1)
            self.assertEqual(run.call_args.kwargs['timeout'], 30)

    def test_nul_parser_rejects_incomplete_or_empty_paths(self):
        self.assertEqual(checker.nul_paths(b''), set())
        self.assertEqual(checker.nul_paths(b'docs/a\nb.md\0docs/a\nb.md\0'), {'docs/a\nb.md'})
        for value in (b'docs/unterminated.md', b'\0', b'docs/one.md\0\0'):
            with self.subTest(value=value), self.assertRaises(checker.ComparisonError):
                checker.nul_paths(value)

    def test_unsafe_path_components_are_not_documentation(self):
        for name in ('docs/../code.md', 'docs//guide.md', './README.md', '/docs/guide.md'):
            with self.subTest(path=name):
                self.assertFalse(checker.is_documentation(name))

    def test_no_changes_runs_nothing(self):
        with mock.patch.object(checker.subprocess, 'run') as run:
            self.assertEqual(checker.run_checks(Path('.'), 'none', python='python', go='go'), 0)
        run.assert_not_called()

    def test_docs_runner_only_runs_documentation_checker(self):
        root = Path('synthetic-repository')
        with contextlib.redirect_stderr(io.StringIO()) as stderr, \
                mock.patch.object(checker.subprocess, 'run', return_value=mock.Mock(returncode=0)) as run:
            status = checker.run_checks(root, 'docs', python='selected-python', go='must-not-run')
        self.assertEqual(status, 0)
        run.assert_called_once_with(['selected-python', 'scripts/check-docs.py'],
                                    cwd=root, stdout=stderr, stderr=stderr)

    def test_full_posix_commands_include_all_four_python_suites(self):
        commands = checker.check_commands('full', python='selected-python', go='selected-go', windows=False)
        self.assertEqual(commands, [
            ['selected-go', 'test', '-p', '1', '-count=1', './...'],
            ['selected-python', '-m', 'unittest', 'discover', '-s', 'integrations/workbuddy/tests', '-v'],
            ['selected-python', '-m', 'unittest', 'discover', '-s', 'integrations/workbuddy/deploy/macos/tests', '-v'],
            ['selected-python', '-m', 'unittest', 'discover', '-s', 'integrations/workbuddy/deploy/windows/tests', '-v'],
            ['selected-python', '-m', 'unittest', 'discover', '-s', 'scripts/tests', '-v'],
            ['selected-go', 'vet', './...'],
            ['selected-python', 'scripts/check-docs.py'],
        ])

    def test_full_windows_commands_preserve_owner_wrapper(self):
        self.assertEqual(checker.check_commands('full', python='selected-python.exe', go='selected-go.exe', windows=True), [
            ['selected-go.exe', 'test', '-p', '1', '-count=1', './...'],
            ['pwsh', '-NoLogo', '-NoProfile', '-NonInteractive', '-File',
             'scripts/test-windows-python.ps1', '-Python', 'selected-python.exe'],
            ['selected-go.exe', 'vet', './...'],
            ['selected-python.exe', 'scripts/check-docs.py'],
        ])

    def test_runner_stops_after_failure_and_preserves_positive_exit_code(self):
        for child_status, expected_status in ((7, 7), (-9, 1)):
            with self.subTest(child_status=child_status), \
                    contextlib.redirect_stderr(io.StringIO()), \
                    mock.patch.object(checker.subprocess, 'run', return_value=mock.Mock(returncode=child_status)) as run:
                status = checker.run_checks(Path('.'), 'full', python='python', go='go')
                self.assertEqual(status, expected_status)
                self.assertEqual(run.call_count, 1)
                self.assertEqual(run.call_args.args[0], ['go', 'test', '-p', '1', '-count=1', './...'])

    def test_runner_returns_failure_if_executable_cannot_start(self):
        with contextlib.redirect_stderr(io.StringIO()), \
                mock.patch.object(checker.subprocess, 'run', side_effect=FileNotFoundError('missing executable')):
            self.assertEqual(checker.run_checks(Path('.'), 'docs', python='missing', go='go'), 1)


if __name__ == '__main__':
    unittest.main()
