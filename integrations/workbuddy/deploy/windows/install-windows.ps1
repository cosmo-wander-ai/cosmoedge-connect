[CmdletBinding()]
param(
    [Parameter(Mandatory=$true)][string]$Bundle,
    [Parameter(Mandatory=$true)][string]$ExpectedManifestSHA256,
    [Parameter(Mandatory=$true)][string]$Python,
    [switch]$NoStartup
)
$ErrorActionPreference = 'Stop'

function Set-PrivatePath([string]$Path) {
    # Native SetSecurityInfo changes only the DACL and does not request the
    # audit-policy privilege that Windows PowerShell's Set-Acl may require.
    & $pythonCommand -c 'import sys; from pathlib import Path; sys.path.insert(0,sys.argv[1]); import local_files as f; p=Path(sys.argv[2]); f.protect(p,directory=p.is_dir())' (Join-Path $bundleRoot 'payload\skill\scripts') $Path
    if ($LASTEXITCODE -ne 0) { throw 'Could not protect an installation path.' }
}
function New-PrivateDirectory([string]$Path) {
    New-Item -ItemType Directory -Path $Path -Force | Out-Null
    Set-PrivatePath $Path
}
function Protect-Tree([string]$Path) {
    & $pythonCommand -c 'import sys; from pathlib import Path; sys.path.insert(0,sys.argv[1]); import local_files as f; root=Path(sys.argv[2]); f.protect(root,directory=root.is_dir()); [(f.protect(p,directory=p.is_dir())) for p in root.rglob(chr(42))]' (Join-Path $bundleRoot 'payload\skill\scripts') $Path
    if ($LASTEXITCODE -ne 0) { throw 'Could not protect the installation tree.' }
}
function Safe-Child([string]$Root, [string]$Relative) {
    $resolved = [IO.Path]::GetFullPath((Join-Path $Root $Relative))
    if (-not $resolved.StartsWith($Root.TrimEnd('\') + '\', [StringComparison]::OrdinalIgnoreCase)) { throw 'Path escaped its package root.' }
    return $resolved
}

$bundleRoot = [IO.Path]::GetFullPath((Resolve-Path -LiteralPath $Bundle).Path)
$manifestPath = Join-Path $bundleRoot 'manifest.json'
if ((Get-FileHash -LiteralPath $manifestPath -Algorithm SHA256).Hash.ToLowerInvariant() -ne $ExpectedManifestSHA256.ToLowerInvariant()) {
    throw 'Package manifest checksum did not match.'
}
$manifest = Get-Content -LiteralPath $manifestPath -Raw -Encoding UTF8 | ConvertFrom-Json
if ($manifest.schemaVersion -ne 1 -or $manifest.candidate.platform -ne 'windows/amd64' -or $manifest.candidate.version -notmatch '^[A-Za-z0-9][A-Za-z0-9._-]{0,79}$') {
    throw 'Invalid Windows package identity.'
}
# Verify the complete inventory before importing any Python from the package.
# An extra package directory could otherwise shadow a verified Python module.
if ((Get-Item -LiteralPath $bundleRoot).Attributes -band [IO.FileAttributes]::ReparsePoint) { throw 'The package root cannot be a link.' }
$expectedFiles = New-Object 'System.Collections.Generic.HashSet[string]' ([StringComparer]::OrdinalIgnoreCase)
$null = $expectedFiles.Add($manifestPath)
foreach ($file in $manifest.files) {
    if ([string]::IsNullOrWhiteSpace($file.path)) { throw 'A package file path is missing.' }
    $path = Safe-Child $bundleRoot $file.path
    if (-not $expectedFiles.Add($path)) { throw 'Duplicate package file path.' }
}
$actualFileCount = 0
foreach ($item in Get-ChildItem -LiteralPath $bundleRoot -Recurse -Force) {
    if ($item.Attributes -band [IO.FileAttributes]::ReparsePoint) { throw 'Package paths cannot be links.' }
    if (-not $item.PSIsContainer) {
        if (-not $expectedFiles.Contains($item.FullName)) { throw 'Unexpected file outside the package manifest.' }
        $actualFileCount++
    }
}
if ($actualFileCount -ne $expectedFiles.Count) { throw 'A package manifest file is missing.' }
foreach ($file in $manifest.files) {
    $path = Safe-Child $bundleRoot $file.path
    if ((Get-Item -LiteralPath $path).Attributes -band [IO.FileAttributes]::ReparsePoint) { throw 'Package files cannot be links.' }
    if ((Get-FileHash -LiteralPath $path -Algorithm SHA256).Hash.ToLowerInvariant() -ne $file.sha256) { throw ('Package checksum failed: ' + $file.path) }
}
$pythonCommand = [IO.Path]::GetFullPath((Resolve-Path -LiteralPath $Python).Path)
& $pythonCommand -c 'import sys,ctypes,msvcrt,json,hashlib; assert sys.version_info >= (3,9)'
if ($LASTEXITCODE -ne 0) { throw 'Python validation failed.' }
$installRoot = [IO.Path]::GetFullPath((Join-Path $env:LOCALAPPDATA 'CosmoEdgeConnect'))
$skillTarget = [IO.Path]::GetFullPath((Join-Path $env:USERPROFILE '.workbuddy\skills\cosmoedge-operations'))
$releaseTarget = Safe-Child $installRoot ('releases\' + $manifest.candidate.version)
$backupId = (Get-Date -Format 'yyyyMMdd-HHmmss') + '-' + [guid]::NewGuid().ToString('N').Substring(0,8)
$backupRoot = [IO.Path]::GetFullPath((Join-Path $env:LOCALAPPDATA ('CosmoEdgeConnectBackups\' + $backupId)))
if (Test-Path -LiteralPath $releaseTarget) { throw 'This release directory already exists; preserve it and select a new candidate version.' }
if (@(Get-NetTCPConnection -LocalPort 37789 -State Listen -ErrorAction SilentlyContinue).Count -gt 0) {
    throw 'An existing service is still listening on port 37789; stop its owned instance before upgrading.'
}
# Validate the existing token through the paired transport without printing it.
$env:PYTHONUTF8 = '1'
$env:PYTHONDONTWRITEBYTECODE = '1'
& $pythonCommand (Join-Path $bundleRoot 'provision-token.py') --scripts (Join-Path $bundleRoot 'payload\skill\scripts') --root $installRoot
if ($LASTEXITCODE -ne 0) { throw 'The installation token could not be provisioned or validated; existing files were preserved.' }
& $pythonCommand -c 'import sys; from pathlib import Path; sys.path.insert(0,sys.argv[1]); import cosmoedge_operations as t; t._load_token(Path(sys.argv[2]))' (Join-Path $bundleRoot 'payload\skill\scripts') (Join-Path $installRoot 'access.token')
if ($LASTEXITCODE -ne 0) { throw 'The existing token did not pass native permission validation.' }
New-PrivateDirectory $backupRoot
foreach ($name in @('bin', 'runtime-state', 'access.token', 'python.path', 'windows-install.json', 'cosmoedge-connect-control.ps1')) {
    $source = Join-Path $installRoot $name
    if (Test-Path -LiteralPath $source) { Copy-Item -LiteralPath $source -Destination (Join-Path $backupRoot $name) -Recurse -Force }
}
if (Test-Path -LiteralPath $skillTarget) { Copy-Item -LiteralPath $skillTarget -Destination (Join-Path $backupRoot 'skill') -Recurse -Force }
Protect-Tree $backupRoot
New-PrivateDirectory $releaseTarget
New-PrivateDirectory (Join-Path $installRoot 'logs')
foreach ($name in @('phase2.stdout.log', 'phase2.stderr.log')) {
    $path = Join-Path $installRoot ('logs\' + $name)
    if (-not (Test-Path -LiteralPath $path)) { [IO.File]::WriteAllText($path, '') }
    Set-PrivatePath $path
}
$startupLink = $null
if (-not $NoStartup) {
    $startupDirectory = [Environment]::GetFolderPath('Startup')
    if ([string]::IsNullOrWhiteSpace($startupDirectory)) { throw 'The current-user Startup directory is unavailable.' }
    $startupLink = Join-Path $startupDirectory 'CosmoEdge Connect.lnk'
}
if (-not $NoStartup -and (Test-Path -LiteralPath $startupLink)) { Copy-Item -LiteralPath $startupLink -Destination (Join-Path $backupRoot 'startup.lnk') }
$cutoverStarted = $false
try {
    Copy-Item -LiteralPath (Join-Path $bundleRoot 'payload\cosmoedge-connect.exe') -Destination (Join-Path $releaseTarget 'cosmoedge-connect.exe')
    if ($manifest.candidate.mcpSHA256) {
        Copy-Item -LiteralPath (Join-Path $bundleRoot 'payload\cosmoedge-mcp.exe') -Destination (Join-Path $releaseTarget 'cosmoedge-mcp.exe')
        Copy-Item -LiteralPath (Join-Path $bundleRoot 'payload\mcp-candidate.json') -Destination (Join-Path $releaseTarget 'mcp-candidate.json')
    }
    Copy-Item -LiteralPath $manifestPath -Destination (Join-Path $releaseTarget 'manifest.json')
    Copy-Item -LiteralPath (Join-Path $bundleRoot 'source-files.json') -Destination (Join-Path $releaseTarget 'source-files.json')
    Protect-Tree $releaseTarget
    $cutoverStarted = $true
    # The exact existing Skill was copied to the private backup before replacement.
    $allowedSkillRoot = [IO.Path]::GetFullPath((Join-Path $env:USERPROFILE '.workbuddy\skills'))
    if ($skillTarget -ne (Safe-Child $allowedSkillRoot 'cosmoedge-operations')) { throw 'Unexpected Skill target.' }
    if (-not (Test-Path -LiteralPath $allowedSkillRoot)) { New-PrivateDirectory $allowedSkillRoot }
    if (Test-Path -LiteralPath $skillTarget) { Remove-Item -LiteralPath $skillTarget -Recurse -Force }
    Copy-Item -LiteralPath (Join-Path $bundleRoot 'payload\skill') -Destination $skillTarget -Recurse
    $oldMetadata = Join-Path $backupRoot 'skill\_user_meta.json'
    if (Test-Path -LiteralPath $oldMetadata) { Copy-Item -LiteralPath $oldMetadata -Destination (Join-Path $skillTarget '_user_meta.json') }
    Protect-Tree $skillTarget
    [IO.File]::WriteAllText((Join-Path $installRoot 'python.path'), $pythonCommand + [Environment]::NewLine, (New-Object Text.UTF8Encoding($false)))
    Set-PrivatePath (Join-Path $installRoot 'python.path')
    Copy-Item -LiteralPath (Join-Path $bundleRoot 'cosmoedge-connect-control.ps1') -Destination (Join-Path $installRoot 'cosmoedge-connect-control.ps1') -Force
    Set-PrivatePath (Join-Path $installRoot 'cosmoedge-connect-control.ps1')
    $skillFiles = [ordered]@{}
    foreach ($file in $manifest.files) {
        if ($file.path.StartsWith('payload/skill/')) { $skillFiles[$file.path.Substring('payload/skill/'.Length)] = $file.sha256 }
    }
    $record = [ordered]@{ schemaVersion = 1; candidate = $manifest.candidate; service = (Join-Path $releaseTarget 'cosmoedge-connect.exe');
        serviceSHA256 = $manifest.candidate.serviceSHA256; skill = $skillTarget; skillFiles = $skillFiles;
        packageManifestSHA256 = $ExpectedManifestSHA256; installedAt = [DateTime]::UtcNow.ToString('o'); backup = $backupRoot }
    if ($manifest.candidate.mcpSHA256) {
        $record['mcp'] = Join-Path $releaseTarget 'cosmoedge-mcp.exe'
        $record['mcpSHA256'] = $manifest.candidate.mcpSHA256
        $record['mcpCandidate'] = Join-Path $releaseTarget 'mcp-candidate.json'
        $record['mcpCandidateSHA256'] = (Get-FileHash -LiteralPath $record.mcpCandidate -Algorithm SHA256).Hash.ToLowerInvariant()
    }
    $record | ConvertTo-Json -Depth 12 | Set-Content -LiteralPath (Join-Path $installRoot 'windows-install.json') -Encoding UTF8
    Set-PrivatePath (Join-Path $installRoot 'windows-install.json')
    & powershell.exe -NoLogo -NoProfile -ExecutionPolicy Bypass -File (Join-Path $installRoot 'cosmoedge-connect-control.ps1') -Action Start
    if ($LASTEXITCODE -ne 0) { throw 'Paired CosmoEdge Connect did not start.' }
    if (-not $NoStartup) {
        $shell = New-Object -ComObject WScript.Shell
        $shortcut = $shell.CreateShortcut($startupLink)
        $shortcut.TargetPath = Join-Path $env:SystemRoot 'System32\WindowsPowerShell\v1.0\powershell.exe'
        $shortcut.Arguments = '-NoLogo -NoProfile -ExecutionPolicy Bypass -WindowStyle Hidden -File "' + (Join-Path $installRoot 'cosmoedge-connect-control.ps1') + '" -Action Start'
        $shortcut.WorkingDirectory = $installRoot
        $shortcut.WindowStyle = 7
        $shortcut.Description = 'Start the installed CosmoEdge Connect for WorkBuddy'
        $shortcut.Save()
    }
    [pscustomobject]@{ status = 'installed'; version = $manifest.candidate.version; skill = $skillTarget; backup = $backupRoot; startup = (-not $NoStartup) } | ConvertTo-Json -Compress
} catch {
    $installationFailure = $_
    if ($cutoverStarted) {
        $newService = Join-Path $releaseTarget 'cosmoedge-connect.exe'
        foreach ($process in @(Get-Process -Name 'cosmoedge-connect' -ErrorAction SilentlyContinue | Where-Object { $_.Path -eq $newService })) {
            Stop-Process -Id $process.Id -Force
            Wait-Process -Id $process.Id -Timeout 20 -ErrorAction SilentlyContinue
        }
        # Keep current database state: replaying a pre-startup snapshot could
        # resurrect dispatched actions or completed cleanup. The private backup
        # includes the earlier state for separately controlled recovery only.
        try {
            [pscustomobject]@{ status = 'installation_failed'; runtimeStatePreserved = $true; previousStateSnapshot = 'runtime-state'; failedAt = [DateTime]::UtcNow.ToString('o') } |
                ConvertTo-Json -Compress | Set-Content -LiteralPath (Join-Path $backupRoot 'failure.json') -Encoding UTF8
            Set-PrivatePath (Join-Path $backupRoot 'failure.json')
        } catch {
            Write-Warning 'Could not save failure diagnostics; continuing file recovery.'
        }
        if (Test-Path -LiteralPath (Join-Path $backupRoot 'skill')) {
            if ($skillTarget -ne (Safe-Child $allowedSkillRoot 'cosmoedge-operations')) { throw 'Unexpected rollback Skill target.' }
            if (Test-Path -LiteralPath $skillTarget) { Remove-Item -LiteralPath $skillTarget -Recurse -Force }
            Copy-Item -LiteralPath (Join-Path $backupRoot 'skill') -Destination $skillTarget -Recurse
            Protect-Tree $skillTarget
        } elseif (Test-Path -LiteralPath $skillTarget) {
            if ($skillTarget -ne (Safe-Child $allowedSkillRoot 'cosmoedge-operations')) { throw 'Unexpected first-install recovery Skill target.' }
            Remove-Item -LiteralPath $skillTarget -Recurse -Force
        }
        foreach ($name in @('python.path', 'windows-install.json', 'cosmoedge-connect-control.ps1')) {
            $saved = Join-Path $backupRoot $name
            $active = Join-Path $installRoot $name
            if (Test-Path -LiteralPath $saved) { Copy-Item -LiteralPath $saved -Destination $active -Force; Set-PrivatePath $active }
            elseif (Test-Path -LiteralPath $active) { Remove-Item -LiteralPath $active -Force }
        }
        if (-not $NoStartup) {
            if (Test-Path -LiteralPath (Join-Path $backupRoot 'startup.lnk')) { Copy-Item -LiteralPath (Join-Path $backupRoot 'startup.lnk') -Destination $startupLink -Force }
            elseif (Test-Path -LiteralPath $startupLink) { Remove-Item -LiteralPath $startupLink -Force }
        }
    }
    throw $installationFailure
}
