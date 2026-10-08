#Requires -Version 7.0
<#
Runs a real, isolated Windows installation and stdio MCP lifecycle check.
The supplied package is read-only. No device is configured, no WorkBuddy GUI is
used, and the MCP example only discovers tools and calls capabilities.
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory=$true)][string]$Bundle,
    [Parameter(Mandatory=$true)][ValidatePattern('^[0-9a-fA-F]{64}$')][string]$ExpectedManifestSHA256,
    [string]$Python = 'python',
    [string]$Go = 'go'
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
if (-not $IsWindows) { throw 'This lifecycle test requires native Windows and PowerShell 7.' }

$repositoryRoot = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..'))
$bundleRoot = [IO.Path]::GetFullPath((Resolve-Path -LiteralPath $Bundle).Path)
$pythonExecutable = (Get-Command $Python -CommandType Application -ErrorAction Stop | Select-Object -First 1).Source
$goExecutable = (Get-Command $Go -CommandType Application -ErrorAction Stop | Select-Object -First 1).Source
$windowsPowerShell = Join-Path $env:SystemRoot 'System32\WindowsPowerShell\v1.0\powershell.exe'
if (-not (Test-Path -LiteralPath $windowsPowerShell -PathType Leaf)) { throw 'Windows PowerShell is unavailable.' }

$manifestPath = Join-Path $bundleRoot 'manifest.json'
if ((Get-FileHash -LiteralPath $manifestPath -Algorithm SHA256).Hash.ToLowerInvariant() -ne $ExpectedManifestSHA256.ToLowerInvariant()) {
    throw 'The supplied package manifest does not match the expected checksum.'
}
$manifest = Get-Content -LiteralPath $manifestPath -Raw -Encoding UTF8 | ConvertFrom-Json
if ($manifest.candidate.platform -ne 'windows/amd64' -or -not $manifest.candidate.mcpSHA256 -or
    $manifest.candidate.version -notmatch '^[A-Za-z0-9][A-Za-z0-9._-]{0,79}$') {
    throw 'Build a Windows amd64 package with --with-mcp before this test.'
}

function Get-TestListener {
    @(Get-NetTCPConnection -LocalPort 37789 -State Listen -ErrorAction SilentlyContinue)
}
if (@(Get-TestListener).Count -ne 0) {
    throw 'Port 37789 is already occupied. The test will not stop or replace an existing listener.'
}

if (-not ('CosmoEdgeConnectLifecycle.TokenOwnerScope' -as [type])) {
    Add-Type -Path (Join-Path $PSScriptRoot 'windows-lifecycle-token-owner.cs')
}
$testTemporaryBase = [CosmoEdgeConnectLifecycle.TokenOwnerScope]::CanonicalTemporaryBase([IO.Path]::GetTempPath())
$testRoot = Join-Path $testTemporaryBase ('cosmoedge-connect-windows-lifecycle-' + [guid]::NewGuid().ToString('N'))
$isolatedLocalAppData = Join-Path $testRoot 'local-app-data'
$isolatedUserProfile = Join-Path $testRoot 'user-profile'
$installRoot = Join-Path $isolatedLocalAppData 'CosmoEdgeConnect'
$releaseRoot = Join-Path $installRoot ('releases\' + $manifest.candidate.version)
$serviceExecutable = [IO.Path]::GetFullPath((Join-Path $releaseRoot 'cosmoedge-connect.exe'))
$mcpExecutable = [IO.Path]::GetFullPath((Join-Path $releaseRoot 'cosmoedge-mcp.exe'))
$exampleExecutable = Join-Path $testRoot 'mcp-client-lifecycle.exe'
$controlScript = Join-Path $installRoot 'cosmoedge-connect-control.ps1'
$startupDirectory = [Environment]::GetFolderPath('Startup')
$startupShortcut = if ($startupDirectory) { Join-Path $startupDirectory 'CosmoEdge Connect.lnk' } else { $null }
$startupBefore = if ($startupShortcut -and (Test-Path -LiteralPath $startupShortcut)) {
    (Get-FileHash -LiteralPath $startupShortcut -Algorithm SHA256).Hash
} else { $null }

function Invoke-TestProcess {
    param(
        [Parameter(Mandatory=$true)][string]$Executable,
        [Parameter(Mandatory=$true)][string[]]$Arguments,
        [switch]$Isolated,
        [ValidatePattern('^[a-z][a-z0-9-]{0,39}$')][string]$Stage = 'subprocess',
        [ValidateRange(1,900)]
        [int]$TimeoutSeconds = 90
    )
    $startInfo = [Diagnostics.ProcessStartInfo]::new()
    $startInfo.FileName = $Executable
    $startInfo.WorkingDirectory = $repositoryRoot
    $startInfo.UseShellExecute = $false
    $startInfo.CreateNoWindow = $true
    $startInfo.RedirectStandardOutput = $true
    $startInfo.RedirectStandardError = $true
    $startInfo.StandardOutputEncoding = [Text.UTF8Encoding]::new($false)
    $startInfo.StandardErrorEncoding = [Text.UTF8Encoding]::new($false)
    foreach ($argument in $Arguments) { $startInfo.ArgumentList.Add($argument) }
    $startInfo.Environment['PYTHONUTF8'] = '1'
    $startInfo.Environment['PYTHONDONTWRITEBYTECODE'] = '1'
    if ([string]::Equals([IO.Path]::GetFullPath($Executable), [IO.Path]::GetFullPath($windowsPowerShell), [StringComparison]::OrdinalIgnoreCase)) {
        # Process.Start bypasses PS7's native-command WinPSModulePath handoff.
        # Let Windows PowerShell construct its own compatible default paths.
        $null = $startInfo.Environment.Remove('PSModulePath')
    }
    if ($Isolated) {
        # Only these child processes and their descendants see the private
        # installation paths. The parent environment and HOME/CODEX_HOME stay intact.
        $startInfo.Environment['LOCALAPPDATA'] = $isolatedLocalAppData
        $startInfo.Environment['USERPROFILE'] = $isolatedUserProfile
    }
    if ($privateRootsReady) {
        # The runner's children inherit private regular files, not our output
        # pipes. A background service cannot keep the runner's pipes open.
        $startInfo.FileName = $pythonExecutable
        $startInfo.ArgumentList.Clear()
        foreach ($argument in @((Join-Path $repositoryRoot 'scripts/windows-lifecycle-process.py'),
            '--capture-root', $testRoot, '--local-files', $localFiles, '--', $Executable) + $Arguments) {
            $startInfo.ArgumentList.Add($argument)
        }
    }
    $process = [Diagnostics.Process]::new()
    $process.StartInfo = $startInfo
    $clock = [Diagnostics.Stopwatch]::StartNew()
    $budgetMilliseconds = $TimeoutSeconds * 1000
    try {
        if (-not $process.Start()) { throw 'Could not start a lifecycle test subprocess.' }
        Write-Host ([ordered]@{ phase = 'subprocess-start'; stage = $Stage; privateFileCapture = $privateRootsReady } | ConvertTo-Json -Compress)
        $stdoutTask = $process.StandardOutput.ReadToEndAsync()
        $stderrTask = $process.StandardError.ReadToEndAsync()
        $remaining = [int][Math]::Max(0, $budgetMilliseconds - $clock.ElapsedMilliseconds)
        if (-not $process.WaitForExit($remaining)) {
            Write-Host ([ordered]@{ phase = 'subprocess-timeout'; stage = $Stage; waitStage = 'exit'; elapsedMs = $clock.ElapsedMilliseconds } | ConvertTo-Json -Compress)
            # Kill only the subprocess tree this invocation started.
            $process.Kill($true)
            $null = $process.WaitForExit(5000)
            throw ('Lifecycle subprocess timed out: ' + [IO.Path]::GetFileName($Executable))
        }
        Write-Host ([ordered]@{ phase = 'subprocess-exit'; stage = $Stage; elapsedMs = $clock.ElapsedMilliseconds;
            exitCode = $process.ExitCode; readerDone = ($stdoutTask.IsCompleted -and $stderrTask.IsCompleted) } | ConvertTo-Json -Compress)
        $readers = [Threading.Tasks.Task]::WhenAll([Threading.Tasks.Task[]]@($stdoutTask, $stderrTask))
        $remaining = [int][Math]::Max(0, $budgetMilliseconds - $clock.ElapsedMilliseconds)
        if (-not $readers.Wait($remaining)) {
            Write-Host ([ordered]@{ phase = 'subprocess-timeout'; stage = $Stage; waitStage = 'output'; elapsedMs = $clock.ElapsedMilliseconds;
                exitCode = $process.ExitCode; readerDone = $false } | ConvertTo-Json -Compress)
            throw ('Lifecycle output capture timed out: ' + [IO.Path]::GetFileName($Executable))
        }
        $stdout = $stdoutTask.GetAwaiter().GetResult()
        $stderr = $stderrTask.GetAwaiter().GetResult()
        Write-Host ([ordered]@{ phase = 'subprocess-output'; stage = $Stage; elapsedMs = $clock.ElapsedMilliseconds;
            exitCode = $process.ExitCode; readerDone = $true } | ConvertTo-Json -Compress)
        if ($process.ExitCode -ne 0) {
            throw ('Lifecycle subprocess failed (' + $process.ExitCode + '): ' + [IO.Path]::GetFileName($Executable) +
                [Environment]::NewLine + $stdout + $stderr)
        }
        return $stdout.Trim()
    } finally {
        $process.Dispose()
    }
}

function Invoke-Control([string]$Action, [string]$ClientId = '') {
    $arguments = @('-NoLogo', '-NoProfile', '-NonInteractive', '-ExecutionPolicy', 'Bypass',
        '-File', $controlScript, '-Action', $Action)
    if ($ClientId) { $arguments += @('-ClientId', $ClientId) }
    $raw = Invoke-TestProcess -Executable $windowsPowerShell -Arguments $arguments -Isolated -Stage ('control-' + $Action.ToLowerInvariant())
    return ($raw | ConvertFrom-Json)
}

function Assert-Running($Status) {
    if ($Status.status -ne 'running' -or $Status.pairingVerified -ne $true) {
        throw 'The paired service is not reported as running.'
    }
    $listeners = @(Get-TestListener)
    if ($listeners.Count -ne 1 -or $listeners[0].LocalAddress -ne '127.0.0.1' -or
        $listeners[0].OwningProcess -ne $Status.processId) {
        throw 'The test service is not the unique expected loopback listener.'
    }
    $ownedProcess = Get-Process -Id $Status.processId -ErrorAction Stop
    if (-not [string]::Equals($ownedProcess.Path, $serviceExecutable, [StringComparison]::OrdinalIgnoreCase)) {
        throw 'The reported process does not belong to this temporary installation.'
    }
    return $ownedProcess.StartTime.ToUniversalTime()
}

function Assert-Stopped {
    if (@(Get-TestListener).Count -ne 0) { throw 'The listener did not stop; no unknown process will be terminated.' }
    $status = Invoke-Control 'Status'
    if ($status.status -ne 'stopped' -or $status.pairingVerified -ne $true) { throw 'Stopped package pairing failed.' }
}

function Invoke-McpProbe($Configuration) {
    $entry = $Configuration.mcpServers.cosmoedge
    if (-not [string]::Equals($entry.command, $mcpExecutable, [StringComparison]::OrdinalIgnoreCase)) {
        throw 'MCP configuration points outside the exact installed adapter.'
    }
    $expectedArguments = @('--base-url', 'http://127.0.0.1:37789', '--token-file', (Join-Path $installRoot 'access.token'),
        '--state-root', (Join-Path $installRoot 'mcp-state\lifecycle-ci'), '--candidate-file', (Join-Path $releaseRoot 'mcp-candidate.json'))
    if (@($entry.args).Count -ne $expectedArguments.Count) { throw 'Unexpected MCP argument list.' }
    for ($i = 0; $i -lt $expectedArguments.Count; $i++) {
        if ([string]$entry.args[$i] -ne $expectedArguments[$i]) { throw 'MCP configuration changed the isolated connection contract.' }
    }
    # The example without --mock only lists tools and calls capabilities. It
    # neither creates a business context nor captures or changes a device.
    $arguments = @('--server', [string]$entry.command) + @($entry.args)
    $raw = Invoke-TestProcess -Executable $exampleExecutable -Arguments $arguments -Isolated -Stage 'mcp-probe'
    $probe = $raw | ConvertFrom-Json
    if ($probe.mock -ne $false -or $probe.tools -ne 12 -or $probe.capabilities.ok -ne $true -or
        $probe.capabilities.data.serviceAvailable -ne $true) {
        throw 'The real stdio MCP capability probe did not pass.'
    }
    return $probe
}

$failure = $null
$summary = $null
$cleanupFailed = $false
$createdRoot = $false
$privateRootsReady = $false
$tokenOwnerScope = $null
try {
    $tokenOwnerScope = [CosmoEdgeConnectLifecycle.TokenOwnerScope]::new()
    # Record only comparisons, never account names or SID values. A hosted
    # elevated runner may default to Administrators; production remains strict.
    Write-Host ([ordered]@{ phase = 'test-process-owner';
        originalOwnerMatchesUser = $tokenOwnerScope.OriginalOwnerMatchesUser;
        originalOwnerIsAdministrators = $tokenOwnerScope.OriginalOwnerIsAdministrators } | ConvertTo-Json -Compress)
    $tokenOwnerScope.UseCurrentUser()
    if (Test-Path -LiteralPath $testRoot) { throw 'Refusing a preexisting temporary test root.' }
    $null = New-Item -ItemType Directory -Path $testRoot -ErrorAction Stop
    $createdRoot = $true
    $localFiles = Join-Path $repositoryRoot 'integrations\workbuddy\skills\cosmoedge-operations\scripts'
    $protect = 'import sys; from pathlib import Path; sys.path.insert(0,sys.argv[1]); import local_files as f; [(p.mkdir(parents=True,exist_ok=True),f.protect(p,directory=True)) for p in map(Path,sys.argv[2:])]'
    $null = Invoke-TestProcess -Executable $pythonExecutable -Arguments @('-c', $protect, $localFiles, $testRoot, $isolatedLocalAppData, $isolatedUserProfile) -Stage 'protect'
    $privateRootsReady = $true
    # Windows PowerShell can initialize USERPROFILE during startup. Claim and
    # protect every isolated directory before starting even the read-only probe.
    $preflightCommand = '$ErrorActionPreference="Stop"; foreach($name in @("Get-FileHash","ConvertFrom-Json","Get-NetTCPConnection")) { $null=Get-Command -Name $name -ErrorAction Stop }; [pscustomobject]@{cmdletsAvailable=$true; desktopEdition=($PSVersionTable.PSEdition -eq "Desktop"); majorVersion=$PSVersionTable.PSVersion.Major} | ConvertTo-Json -Compress'
    $preflight = (Invoke-TestProcess -Executable $windowsPowerShell -Arguments @('-NoLogo', '-NoProfile', '-NonInteractive',
        '-ExecutionPolicy', 'Bypass', '-Command', $preflightCommand) -Isolated -Stage 'preflight') | ConvertFrom-Json
    if ($preflight.cmdletsAvailable -ne $true -or $preflight.desktopEdition -ne $true -or $preflight.majorVersion -ne 5) {
        throw 'The isolated Windows PowerShell command environment is unavailable.'
    }
    Write-Host ([ordered]@{ phase = 'windows-powershell-preflight'; cmdletsAvailable = $true; desktopEdition = $true } | ConvertTo-Json -Compress)
    $null = Invoke-TestProcess -Executable $goExecutable -Arguments @('build', '-o', $exampleExecutable, './examples/mcp-client') -TimeoutSeconds 300 -Stage 'build'

    $installer = Join-Path $bundleRoot 'install-windows.ps1'
    $null = Invoke-TestProcess -Executable $windowsPowerShell -Arguments @('-NoLogo', '-NoProfile', '-NonInteractive',
        '-ExecutionPolicy', 'Bypass', '-File', $installer, '-Bundle', $bundleRoot,
        '-ExpectedManifestSHA256', $ExpectedManifestSHA256, '-Python', $pythonExecutable, '-NoStartup') -Isolated -TimeoutSeconds 180 -Stage 'install'
    $first = Invoke-Control 'Status'
    $firstStartedAt = Assert-Running $first
    $startedAgain = Invoke-Control 'Start'
    $null = Assert-Running $startedAgain
    if ($startedAgain.processId -ne $first.processId) { throw 'Idempotent start replaced the running service.' }

    $configuration = Invoke-Control 'McpConfig' 'lifecycle-ci'
    $probe = Invoke-McpProbe $configuration
    $stopped = Invoke-Control 'Stop'
    if ($stopped.status -ne 'stopped' -or $stopped.stoppedProcesses -ne 1) { throw 'The first stop did not target exactly one owned process.' }
    Assert-Stopped
    $restarted = Invoke-Control 'Start'
    $restartedAt = Assert-Running $restarted
    if ($restartedAt -le $firstStartedAt) { throw 'The restart did not create a fresh service process.' }
    $null = Invoke-McpProbe (Invoke-Control 'McpConfig' 'lifecycle-ci')
    $null = Invoke-Control 'Stop'
    Assert-Stopped

    $summary = [ordered]@{ status = 'passed'; candidate = $manifest.candidate.version;
        firstInstall = $true; pairedStatus = $true; idempotentStart = $true; restart = $true;
        mcpProtocolVersion = $probe.protocolVersion; mcpTools = $probe.tools;
        realStdio = $true; mock = $false; deviceConfigured = $false; deviceWrites = 0;
        workBuddyGuiTested = $false; startupRegistrationRequested = $false }
} catch {
    $failure = $_
} finally {
    try {
        # No cleanup action may use a preexisting directory rejected above.
        if ($createdRoot) {
            try {
                if (Test-Path -LiteralPath $controlScript) { $null = Invoke-Control 'Stop' }
            } catch {
                Write-Warning 'Managed stop did not complete; checking only exact test-owned executable paths.'
            }
            $ownedPaths = @($serviceExecutable, $mcpExecutable, [IO.Path]::GetFullPath($exampleExecutable))
            foreach ($process in @(Get-Process -Name 'cosmoedge-connect', 'cosmoedge-mcp', 'mcp-client-lifecycle' -ErrorAction SilentlyContinue)) {
                if ($process.Path -and $ownedPaths -contains [IO.Path]::GetFullPath($process.Path)) {
                    try { $process.Kill(); $null = $process.WaitForExit(20000) } catch { $cleanupFailed = $true }
                }
            }
            $remaining = @(Get-Process -Name 'cosmoedge-connect', 'cosmoedge-mcp', 'mcp-client-lifecycle' -ErrorAction SilentlyContinue | Where-Object {
                $_.Path -and $ownedPaths -contains [IO.Path]::GetFullPath($_.Path)
            })
            if ($remaining.Count -ne 0) { $cleanupFailed = $true }
            $startupAfter = if ($startupShortcut -and (Test-Path -LiteralPath $startupShortcut)) {
                (Get-FileHash -LiteralPath $startupShortcut -Algorithm SHA256).Hash
            } else { $null }
            if ($startupAfter -ne $startupBefore) { $cleanupFailed = $true; Write-Warning 'The preexisting Startup shortcut changed during the isolated test.' }
            if (-not $cleanupFailed -and (Test-Path -LiteralPath $testRoot)) {
                try { Remove-Item -LiteralPath $testRoot -Recurse -Force } catch { $cleanupFailed = $true }
            }
        }
    } finally {
        # This runs even if cleanup throws, and changes no account or machine policy.
        if ($null -ne $tokenOwnerScope) {
            $tokenOwnerScope.Dispose()
            Write-Host ([ordered]@{ phase = 'test-process-owner-restored';
                restored = $tokenOwnerScope.Restored } | ConvertTo-Json -Compress)
        }
    }
}

if ($cleanupFailed) { throw ('Isolated lifecycle cleanup requires attention; preserved path: ' + $testRoot) }
if ($failure) { throw $failure }
$summary['cleanupVerified'] = $true
$summary['testProcessOwnerRestored'] = $tokenOwnerScope.Restored
$summary | ConvertTo-Json -Depth 6 -Compress
