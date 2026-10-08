"""Exercise the actual test runner without installing or starting CosmoEdge Connect."""
import importlib.util
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import time
import unittest


ROOT = Path(__file__).resolve().parents[2]
LOCAL_FILES = ROOT / 'integrations/workbuddy/skills/cosmoedge-operations/scripts'
SPEC = importlib.util.spec_from_file_location('lifecycle_local_files', LOCAL_FILES / 'local_files.py')
local_files = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(local_files)
PWSH = shutil.which('pwsh')


@unittest.skipUnless(PWSH, 'requires PowerShell 7 to exercise the real lifecycle helper')
class LifecycleProcessTests(unittest.TestCase):
    def setUp(self):
        self.root = local_files.private_tempdir('cosmoedge-connect-process-test-')
        self.addCleanup(shutil.rmtree, self.root)
        self.harness = self.root / 'harness.ps1'
        self.write_private(self.harness, r'''
param([string]$Repository,[string]$Root,[string]$Python,[string]$Request)
$ErrorActionPreference='Stop'
$tokens=$null; $errors=$null
$ast=[System.Management.Automation.Language.Parser]::ParseFile((Join-Path $Repository 'scripts/test-windows-lifecycle.ps1'),[ref]$tokens,[ref]$errors)
if($errors.Count -ne 0){throw 'Lifecycle source did not parse.'}
$function=$ast.Find({param($node) $node -is [System.Management.Automation.Language.FunctionDefinitionAst] -and $node.Name -eq 'Invoke-TestProcess'},$true)
. ([scriptblock]::Create($function.Extent.Text))
$repositoryRoot=$Repository; $testRoot=$Root; $pythonExecutable=$Python
$windowsPowerShell=Join-Path $Root 'unused-windows-powershell-marker'
$localFiles=Join-Path $Repository 'integrations/workbuddy/skills/cosmoedge-operations/scripts'
$requestData=Get-Content -LiteralPath $Request -Raw -Encoding UTF8 | ConvertFrom-Json
$privateRootsReady=$requestData.privateCapture
$clock=[Diagnostics.Stopwatch]::StartNew()
try {
    $result=Invoke-TestProcess -Executable $Python -Arguments ([string[]]$requestData.arguments) -TimeoutSeconds $requestData.timeout -Stage 'regression'
    $reply=@{status='ok';output=$result}
} catch {
    $reply=@{status='failed';error=$_.Exception.Message}
}
$clock.Stop()
$reply['elapsedSeconds']=$clock.Elapsed.TotalSeconds
$reply | ConvertTo-Json -Compress
'''.lstrip())

    def write_private(self, path, value):
        with os.fdopen(local_files.create_file(path), 'w', encoding='utf-8') as stream:
            stream.write(value)

    def invoke(self, code, *, private=True, timeout=1):
        request = self.root / 'request.json'
        self.write_private(request, json.dumps({'arguments': ['-c', code],
                                               'privateCapture': private, 'timeout': timeout}))
        result = subprocess.run([PWSH, '-NoLogo', '-NoProfile', '-NonInteractive', '-File', str(self.harness),
                                 '-Repository', str(ROOT), '-Root', str(self.root), '-Python', sys.executable,
                                 '-Request', str(request)], capture_output=True, text=True, encoding='utf-8',
                                timeout=12, env=dict(os.environ, COSMOEDGE_CONNECT_TEST_PRIVATE_MARKER='not-for-diagnostics'))
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertNotIn('not-for-diagnostics', result.stdout + result.stderr)
        return json.loads(result.stdout.splitlines()[-1]), result.stdout + result.stderr

    def wait_for_holder(self, marker):
        deadline = time.monotonic() + 6
        while not marker.exists() and time.monotonic() < deadline:
            time.sleep(0.05)
        self.assertTrue(marker.exists(), 'The bounded test descendant did not finish.')

    def test_parent_exit_with_background_output_holder_returns_under_one_second(self):
        marker = self.root / 'holder-done'
        holder = 'import time,pathlib; time.sleep(3); pathlib.Path(' + repr(str(marker)) + ').write_text("done")'
        code = 'import subprocess,sys; subprocess.Popen([sys.executable,"-c",' + repr(holder) + ']); sys.stdout.buffer.write(b"parent-output\\n"); sys.stdout.buffer.flush()'
        try:
            reply, output = self.invoke(code)
            self.assertEqual(reply['status'], 'ok', output)
            self.assertEqual(reply['output'], 'parent-output')
            self.assertLess(reply['elapsedSeconds'], 1)
            self.assertFalse(marker.exists(), 'The helper waited for the background holder.')
            files = list(self.root.glob('process-*-*'))
            self.assertEqual(len(files), 2)
            for path in files:
                local_files.validate(path)
            self.assertEqual(next(self.root.glob('process-stdout-*')).read_bytes(), b'parent-output\n')
        finally:
            self.wait_for_holder(marker)

    def test_child_nonzero_and_exact_stream_bytes_are_preserved_privately(self):
        code = 'import sys; sys.stdout.buffer.write(b"original stdout\\n"); sys.stderr.buffer.write(b"original stderr\\n"); sys.exit(7)'
        reply, output = self.invoke(code, timeout=2)
        self.assertEqual(reply['status'], 'failed')
        self.assertIn('Lifecycle subprocess failed (7)', reply['error'])
        self.assertIn('original stdout', reply['error'])
        self.assertIn('original stderr', reply['error'])
        self.assertEqual(next(self.root.glob('process-stdout-*')).read_bytes(), b'original stdout\n')
        self.assertEqual(next(self.root.glob('process-stderr-*')).read_bytes(), b'original stderr\n')
        for path in self.root.glob('process-*-*'):
            local_files.validate(path)

    def test_timeout_kills_only_this_runner_tree(self):
        marker = self.root / 'must-not-be-written'
        code = 'import time,pathlib; time.sleep(3); pathlib.Path(' + repr(str(marker)) + ').write_text("unexpected")'
        reply, output = self.invoke(code)
        self.assertEqual(reply['status'], 'failed', output)
        self.assertIn('Lifecycle subprocess timed out:', reply['error'])
        self.assertLess(reply['elapsedSeconds'], 2)
        time.sleep(2.5)
        self.assertFalse(marker.exists(), 'The timed-out child escaped the owned process tree.')

    def test_bootstrap_output_drain_has_the_same_total_deadline(self):
        marker = self.root / 'bootstrap-holder-done'
        holder = 'import time,pathlib; time.sleep(3); pathlib.Path(' + repr(str(marker)) + ').write_text("done")'
        code = 'import subprocess,sys; subprocess.Popen([sys.executable,"-c",' + repr(holder) + ']); print("parent-exit",flush=True)'
        try:
            reply, output = self.invoke(code, private=False)
            self.assertEqual(reply['status'], 'failed', output)
            self.assertIn('Lifecycle output capture timed out:', reply['error'])
            self.assertLess(reply['elapsedSeconds'], 2)
        finally:
            self.wait_for_holder(marker)


if __name__ == '__main__':
    unittest.main()
