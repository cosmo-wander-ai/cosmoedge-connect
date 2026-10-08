import hashlib
import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest


INSTALLER = Path(__file__).resolve().parents[1] / 'install-windows.ps1'
POWERSHELL = Path(os.environ.get('SystemRoot', r'C:\Windows')) / 'System32/WindowsPowerShell/v1.0/powershell.exe'


@unittest.skipUnless(os.name == 'nt' and POWERSHELL.is_file(), 'requires Windows PowerShell')
class WindowsInstallerTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.bundle = self.root / 'bundle'
        self.scripts = self.bundle / 'payload/skill/scripts'
        self.scripts.mkdir(parents=True)
        module = self.scripts / 'local_files.py'
        module.write_text('raise RuntimeError("test package must never be imported")\n')
        manifest = {
            'schemaVersion': 1,
            'candidate': {'platform': 'windows/amd64', 'version': 'test-windows'},
            'files': [{'path': module.relative_to(self.bundle).as_posix(),
                       'sha256': hashlib.sha256(module.read_bytes()).hexdigest()}],
        }
        manifest_path = self.bundle / 'manifest.json'
        manifest_path.write_text(json.dumps(manifest), encoding='utf-8')
        self.manifest_hash = hashlib.sha256(manifest_path.read_bytes()).hexdigest()
        self.runtime_marker = self.root / 'runtime-invoked.txt'
        self.runtime = self.root / 'runtime-probe.cmd'
        self.runtime.write_bytes(b'@echo off\r\n> "%COSMOEDGE_CONNECT_TEST_RUNTIME_MARKER%" echo invoked\r\nexit /b 1\r\n')
        self.env = dict(os.environ, PSModulePath='', LOCALAPPDATA=str(self.root / 'local'),
                        USERPROFILE=str(self.root / 'profile'),
                        COSMOEDGE_CONNECT_TEST_RUNTIME_MARKER=str(self.runtime_marker))

    def run_powershell(self, *arguments):
        return subprocess.run([str(POWERSHELL), '-NoLogo', '-NoProfile', '-NonInteractive',
                               '-ExecutionPolicy', 'Bypass', *arguments],
                              cwd=self.root, env=self.env, capture_output=True,
                              text=True, errors='replace', timeout=30)

    def run_installer_validation(self):
        result = self.run_powershell('-File', str(INSTALLER), '-Bundle', str(self.bundle),
                                    '-ExpectedManifestSHA256', self.manifest_hash,
                                    '-Python', str(self.runtime), '-NoStartup')
        self.assertNotEqual(result.returncode, 0)
        # The probe runtime always fails before token checks or installation.
        self.assertFalse((self.root / 'local/CosmoEdgeConnect').exists())
        self.assertFalse((self.root / 'profile/.workbuddy').exists())
        return result.stdout + result.stderr

    def test_exact_inventory_reaches_runtime_validation_without_installing(self):
        output = self.run_installer_validation()
        self.assertIn('Python validation failed.', output)
        self.assertTrue(self.runtime_marker.is_file())

    def test_extra_module_package_is_rejected_before_any_python_runs(self):
        package = self.scripts / 'local_files'
        package.mkdir()
        (package / '__init__.py').write_text('raise RuntimeError("unlisted module must never run")\n')
        output = self.run_installer_validation()
        self.assertIn('Unexpected file outside the package manifest.', output)
        self.assertFalse(self.runtime_marker.exists())

    def test_failure_diagnostics_errors_do_not_prevent_file_recovery(self):
        # Execute the installer's actual catch body, with process operations and
        # permission changes replaced by inert stubs. Real copies occur only in
        # this test's temporary directory, never in the user's installation.
        harness = self.root / 'recovery-harness.ps1'
        harness.write_text(r'''
param([string]$Source, [string]$Root, [string]$FailureMode)
$ErrorActionPreference = 'Stop'
# Match the installer's normalized roots before Safe-Child compares prefixes.
# Windows tempfile may use an 8.3 path that .NET Framework expands to a long path.
$Root = [IO.Path]::GetFullPath($Root)
$errors = $null; $tokens = $null
$ast = [System.Management.Automation.Language.Parser]::ParseFile($Source, [ref]$tokens, [ref]$errors)
if (@($errors).Count -ne 0) { throw 'Installer did not parse.' }
$cutover = @($ast.EndBlock.Statements | Where-Object { $_ -is [System.Management.Automation.Language.TryStatementAst] })
if ($cutover.Count -ne 1) { throw 'Expected one installation transaction.' }
$body = $cutover[0].CatchClauses[0].Body.Extent.Text
$recovery = [scriptblock]::Create($body.Substring(1, $body.Length - 2))
$safeFunction = $ast.Find({param($node) $node -is [System.Management.Automation.Language.FunctionDefinitionAst] -and $node.Name -eq 'Safe-Child'}, $true)
. ([scriptblock]::Create($safeFunction.Extent.Text))
$installRoot = Join-Path $Root 'installation'
$backupRoot = Join-Path $Root 'backup'
$releaseTarget = Join-Path $installRoot 'releases\candidate'
$allowedSkillRoot = Join-Path $Root 'skills'
$skillTarget = Join-Path $allowedSkillRoot 'cosmoedge-operations'
$pathEscapeRejected = $false
try { $null = Safe-Child $allowedSkillRoot '..\outside-fixture' } catch {
    if ($_.Exception.Message -ne 'Path escaped its package root.') { throw }
    $pathEscapeRejected = $true
}
if (-not $pathEscapeRejected) { throw 'Safe-Child accepted an escaping test path.' }
$startupLink = Join-Path $Root 'startup.lnk'
$cutoverStarted = $true
$NoStartup = $false
$script:diagnosticFailure = ''
function Get-Process { @() }
function Stop-Process { throw 'A test must never stop a process.' }
function Wait-Process { throw 'A test must never wait for a process.' }
function Protect-Tree { }
function Set-PrivatePath([string]$Path) {
    if ($FailureMode -eq 'protect' -and (Split-Path $Path -Leaf) -eq 'failure.json') {
        $script:diagnosticFailure = 'protect'
        throw 'simulated diagnostic permission failure'
    }
}
function Set-Content {
    [CmdletBinding()] param([Parameter(ValueFromPipeline=$true)]$Value, [string]$LiteralPath, [string]$Encoding)
    process {
        if ($FailureMode -eq 'write' -and (Split-Path $LiteralPath -Leaf) -eq 'failure.json') {
            $script:diagnosticFailure = 'write'
            throw 'simulated diagnostic disk full'
        }
        Microsoft.PowerShell.Management\Set-Content -LiteralPath $LiteralPath -Value $Value -Encoding $Encoding
    }
}
try {
    try { throw 'original cutover failure' } catch { & $recovery }
    throw 'Recovery did not preserve the original failure.'
} catch {
    if ($_.Exception.Message -ne 'original cutover failure') { throw }
    if ($script:diagnosticFailure -ne $FailureMode) { throw 'Expected diagnostic failure was not reached.' }
    [pscustomobject]@{ originalFailurePreserved = $true; pathEscapeRejected = $pathEscapeRejected } | ConvertTo-Json -Compress
}
'''.lstrip(), encoding='utf-8-sig')
        for mode in ('write', 'protect'):
            with self.subTest(failure=mode):
                root = self.root / mode
                backup = root / 'backup'
                active = root / 'installation'
                skill = root / 'skills/cosmoedge-operations'
                (backup / 'skill').mkdir(parents=True)
                active.mkdir()
                skill.mkdir(parents=True)
                (backup / 'skill/SKILL.md').write_text('previous skill')
                (skill / 'SKILL.md').write_text('failed candidate skill')
                (skill / 'new-candidate-only.txt').write_text('must be removed')
                expected = {'python.path': 'previous runtime',
                            'windows-install.json': 'previous paired record',
                            'cosmoedge-connect-control.ps1': 'previous lifecycle'}
                for name, value in expected.items():
                    (backup / name).write_text(value)
                    (active / name).write_text('failed candidate')
                (backup / 'startup.lnk').write_bytes(b'previous shortcut')
                (root / 'startup.lnk').write_bytes(b'failed shortcut')
                result = self.run_powershell('-File', str(harness), '-Source', str(INSTALLER),
                                            '-Root', str(root), '-FailureMode', mode)
                self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
                self.assertIn('"originalFailurePreserved":true', result.stdout)
                self.assertIn('"pathEscapeRejected":true', result.stdout)
                self.assertIn('continuing file recovery', result.stdout + result.stderr)
                self.assertEqual((skill / 'SKILL.md').read_text(), 'previous skill')
                self.assertFalse((skill / 'new-candidate-only.txt').exists())
                for name, value in expected.items():
                    self.assertEqual((active / name).read_text(), value)
                self.assertEqual((root / 'startup.lnk').read_bytes(), b'previous shortcut')


if __name__ == '__main__':
    unittest.main()
