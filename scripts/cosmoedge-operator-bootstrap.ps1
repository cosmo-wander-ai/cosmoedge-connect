[CmdletBinding()]
param(
    [string]$BundleRoot = "",
    [string]$OperatorHome = $(if ($env:LOCALAPPDATA) { Join-Path $env:LOCALAPPDATA "CosmoEdgeOperator" } else { Join-Path $HOME ".cosmoedge-operator" }),
    [string]$CodexHome = $(if ($env:CODEX_HOME) { $env:CODEX_HOME } else { Join-Path $HOME ".codex" }),
    [switch]$NoSkill
)

$ErrorActionPreference = "Stop"

if ([string]::IsNullOrWhiteSpace($BundleRoot)) { $BundleRoot = $PSScriptRoot }

function Resolve-RequiredFile {
    param([string]$Path, [string]$Name)
    if ([string]::IsNullOrWhiteSpace($Path) -or -not (Test-Path -LiteralPath $Path -PathType Leaf)) {
        throw "$Name not found: $Path"
    }
    return [System.IO.Path]::GetFullPath((Resolve-Path -LiteralPath $Path))
}

function Resolve-InstallRoot {
    param([string]$Path)
    if ([string]::IsNullOrWhiteSpace($Path)) { throw "OperatorHome is unavailable." }
    $full = [System.IO.Path]::GetFullPath($Path).TrimEnd([System.IO.Path]::DirectorySeparatorChar, [System.IO.Path]::AltDirectorySeparatorChar)
    $volume = [System.IO.Path]::GetPathRoot($full).TrimEnd([System.IO.Path]::DirectorySeparatorChar, [System.IO.Path]::AltDirectorySeparatorChar)
    $profile = [System.IO.Path]::GetFullPath($HOME).TrimEnd([System.IO.Path]::DirectorySeparatorChar, [System.IO.Path]::AltDirectorySeparatorChar)
    if ([string]::Equals($full, $volume, [System.StringComparison]::OrdinalIgnoreCase) -or
        [string]::Equals($full, $profile, [System.StringComparison]::OrdinalIgnoreCase)) {
        throw "OperatorHome must be a dedicated subdirectory, not a volume or user-profile root."
    }
    return $full
}

function Assert-OperatorRootMarker {
    param([string]$Root, [switch]$Initialize)
    $marker = Join-Path $Root ".cosmoedge-operator-root"
    if (Test-Path -LiteralPath $Root) {
        if (-not (Test-Path -LiteralPath $Root -PathType Container)) { throw "OperatorHome is not a directory: $Root" }
        $children = @(Get-ChildItem -LiteralPath $Root -Force)
        if (-not (Test-Path -LiteralPath $marker -PathType Leaf) -and $children.Count -gt 0) {
            throw "Refusing to install into a non-empty directory that is not an Operator root: $Root"
        }
    }
    if ($Initialize) {
        New-Item -ItemType Directory -Force -Path $Root | Out-Null
        if (Test-Path -LiteralPath $marker -PathType Leaf) {
            $value = (Get-Content -LiteralPath $marker -Raw -Encoding UTF8).Trim()
            if ($value -ne "CosmoEdgeOperator/v1") { throw "Operator root marker is invalid: $marker" }
        } else {
            Set-Content -LiteralPath $marker -Encoding ASCII -NoNewline -Value "CosmoEdgeOperator/v1"
        }
    }
}

$bundleRootFull = [System.IO.Path]::GetFullPath((Resolve-Path -LiteralPath $BundleRoot))
$operatorSource = Resolve-RequiredFile -Path (Join-Path $bundleRootFull "cosmoedge-operator.exe") -Name "cosmoedge-operator.exe"
$OperatorHome = Resolve-InstallRoot -Path $OperatorHome
$CodexHome = [System.IO.Path]::GetFullPath($CodexHome)
if ($bundleRootFull.StartsWith($OperatorHome + [System.IO.Path]::DirectorySeparatorChar, [System.StringComparison]::OrdinalIgnoreCase) -or
    $CodexHome.StartsWith($OperatorHome + [System.IO.Path]::DirectorySeparatorChar, [System.StringComparison]::OrdinalIgnoreCase) -or
    [string]::Equals($OperatorHome, $CodexHome, [System.StringComparison]::OrdinalIgnoreCase)) {
    throw "OperatorHome must not contain the bundle or Codex home."
}
$skillSource = Join-Path $bundleRootFull "demo\skill\cosmoedge-operator"
if (-not $NoSkill -and -not (Test-Path -LiteralPath (Join-Path $skillSource "SKILL.md") -PathType Leaf)) {
    throw "cosmoedge-operator Skill not found: $skillSource"
}

$null = Assert-OperatorRootMarker -Root $OperatorHome -Initialize
$binDir = Join-Path $OperatorHome "bin"
if (Test-Path -LiteralPath $binDir) { Remove-Item -LiteralPath $binDir -Recurse -Force }
New-Item -ItemType Directory -Force -Path $binDir | Out-Null
Copy-Item -LiteralPath $operatorSource -Destination (Join-Path $binDir "cosmoedge-operator.exe") -Force

$launcher = Join-Path $binDir "cosmoedge-operator.ps1"
$cmdLauncher = Join-Path $binDir "cosmoedge-operator.cmd"
$statusLauncher = Join-Path $binDir "cosmoedge-operator-status.ps1"
$removeLauncher = Join-Path $binDir "cosmoedge-operator-remove.ps1"

Set-Content -LiteralPath $launcher -Encoding UTF8 -Value @'
$ErrorActionPreference = "Stop"
$exe = Join-Path $PSScriptRoot "cosmoedge-operator.exe"
if ($args.Count -gt 0) { throw "The ordinary CosmoEdge Operator entry accepts no command-line arguments." }
if (-not (Test-Path -LiteralPath $exe -PathType Leaf)) { throw "cosmoedge-operator.exe not found next to launcher: $exe" }
& $exe status *> $null
if ($LASTEXITCODE -eq 0) {
    & $exe open home
    if ($LASTEXITCODE -ne 0) { throw "The running CosmoEdge Operator could not open its local page." }
    [pscustomobject]@{ status = "opened" } | ConvertTo-Json -Compress
    exit 0
}
$process = Start-Process -FilePath $exe -PassThru -WindowStyle Hidden
[pscustomobject]@{ status = "started"; processId = $process.Id } | ConvertTo-Json -Compress
'@

Set-Content -LiteralPath $cmdLauncher -Encoding ASCII -Value @'
@echo off
powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp0cosmoedge-operator.ps1" %*
exit /b %ERRORLEVEL%
'@

Set-Content -LiteralPath $statusLauncher -Encoding UTF8 -Value @'
$ErrorActionPreference = "Stop"
$exe = Join-Path $PSScriptRoot "cosmoedge-operator.exe"
if ($args.Count -gt 0) { throw "The CosmoEdge Operator status entry accepts no command-line arguments." }
if (-not (Test-Path -LiteralPath $exe -PathType Leaf)) { throw "cosmoedge-operator.exe not found next to status entry: $exe" }
& $exe status
exit $LASTEXITCODE
'@

Set-Content -LiteralPath $removeLauncher -Encoding UTF8 -Value @'
[CmdletBinding()]
param()
$ErrorActionPreference = "Stop"
$operatorHome = [System.IO.Path]::GetFullPath((Join-Path $PSScriptRoot ".."))
$operatorExe = [System.IO.Path]::GetFullPath((Join-Path $PSScriptRoot "cosmoedge-operator.exe"))
$codexHome = if ($env:CODEX_HOME) { $env:CODEX_HOME } else { Join-Path $HOME ".codex" }
$volume = [System.IO.Path]::GetPathRoot($operatorHome).TrimEnd([System.IO.Path]::DirectorySeparatorChar, [System.IO.Path]::AltDirectorySeparatorChar)
$profile = [System.IO.Path]::GetFullPath($HOME).TrimEnd([System.IO.Path]::DirectorySeparatorChar, [System.IO.Path]::AltDirectorySeparatorChar)
$marker = Join-Path $operatorHome ".cosmoedge-operator-root"
if ([string]::Equals($operatorHome.TrimEnd('\','/'), $volume, [System.StringComparison]::OrdinalIgnoreCase) -or
    [string]::Equals($operatorHome.TrimEnd('\','/'), $profile, [System.StringComparison]::OrdinalIgnoreCase) -or
    -not (Test-Path -LiteralPath $marker -PathType Leaf) -or
    (Get-Content -LiteralPath $marker -Raw -Encoding UTF8).Trim() -ne "CosmoEdgeOperator/v1") {
    throw "Refusing to remove an unmarked or unsafe Operator root: $operatorHome"
}
if ([string]::IsNullOrWhiteSpace($env:LOCALAPPDATA)) { throw "LOCALAPPDATA is unavailable." }
$stateRoot = Join-Path $env:LOCALAPPDATA "CosmoEdge\Operator"
$locatorPath = Join-Path $stateRoot "locator.json"
if (Test-Path -LiteralPath $locatorPath -PathType Leaf) {
    try {
        $locator = Get-Content -LiteralPath $locatorPath -Raw -Encoding UTF8 | ConvertFrom-Json
        $process = Get-Process -Id ([int]$locator.processId) -ErrorAction SilentlyContinue
        if ($process) {
            $actual = $null
            try { $actual = [System.IO.Path]::GetFullPath($process.Path) } catch {}
            if ($actual -and [string]::Equals($actual, $operatorExe, [System.StringComparison]::OrdinalIgnoreCase)) {
                Stop-Process -Id $process.Id -Force
                Wait-Process -Id $process.Id -ErrorAction SilentlyContinue
            } else {
                throw "Refusing to stop an unowned process from a stale Operator locator."
            }
        }
    } catch {
        if (Test-Path -LiteralPath $locatorPath) { throw }
    }
}
if (Test-Path -LiteralPath $stateRoot) { Remove-Item -LiteralPath $stateRoot -Recurse -Force }
$skill = Join-Path $codexHome "skills\cosmoedge-operator"
if (Test-Path -LiteralPath $skill) { Remove-Item -LiteralPath $skill -Recurse -Force }
if (Test-Path -LiteralPath $operatorHome) { Remove-Item -LiteralPath $operatorHome -Recurse -Force }
[pscustomobject]@{ status = "removed"; operatorHome = $operatorHome; skill = $skill; state = $stateRoot } | ConvertTo-Json -Compress
'@

$skillTarget = ""
if (-not $NoSkill) {
    $skillTarget = Join-Path $CodexHome "skills\cosmoedge-operator"
    if (Test-Path -LiteralPath $skillTarget) { Remove-Item -LiteralPath $skillTarget -Recurse -Force }
    New-Item -ItemType Directory -Force -Path $skillTarget | Out-Null
    Copy-Item -Recurse -Force -Path (Join-Path $skillSource "*") -Destination $skillTarget
}

[pscustomobject]@{
    status = "installed"
    operator = (Join-Path $binDir "cosmoedge-operator.exe")
    launcher = $launcher
    cmdLauncher = $cmdLauncher
    statusLauncher = $statusLauncher
    removeLauncher = $removeLauncher
    skill = $skillTarget
    operatorHome = $OperatorHome
    codexHome = $CodexHome
} | ConvertTo-Json -Depth 4
