[CmdletBinding()]
param(
    [ValidateSet("Build", "Start", "Status", "Begin", "Probe", "Finish", "Stop", "Path", "InstallSkill")]
    [string]$Action = "Status",
    [ValidateRange(1, 600)]
    [int]$DurationSeconds = 600,
    [string]$Commit = "",
    [string]$ChangeDigest = "",
    [string]$RequestJson = ""
)

$ErrorActionPreference = "Stop"
$repoRoot = [System.IO.Path]::GetFullPath((Join-Path $PSScriptRoot ".."))
$artifactRoot = Join-Path $repoRoot ".parity\tools"
$executable = Join-Path $artifactRoot "cosmoedge-device-lab.exe"
$stateRoot = Join-Path $env:LOCALAPPDATA "CosmoEdge\DevLab"

function Build-DeviceLab {
    New-Item -ItemType Directory -Force -Path $artifactRoot | Out-Null
    Push-Location $repoRoot
    try {
        go build -trimpath -buildvcs=false -o $executable .\tools\device-lab
        if ($LASTEXITCODE -ne 0) { throw "Device Lab build failed." }
    } finally {
        Pop-Location
    }
}

function Invoke-DeviceLab {
    param([string]$Command, [string]$InputJson = "", [switch]$Quiet)
    if (-not (Test-Path -LiteralPath $executable -PathType Leaf)) { Build-DeviceLab }
	$previousErrorAction = $ErrorActionPreference
	$ErrorActionPreference = "Continue"
	try {
        if ($InputJson) {
            $output = $InputJson | & $executable $Command 2>&1
        } else {
            $output = & $executable $Command 2>&1
        }
		$exitCode = $LASTEXITCODE
	} finally {
		$ErrorActionPreference = $previousErrorAction
    }
    if (-not $Quiet -and $output) { $output | Write-Output }
    if ($exitCode -ne 0) { throw "Device Lab $Command failed." }
}

function Test-DeviceLabRunning {
    if (-not (Test-Path -LiteralPath $executable -PathType Leaf)) { return $false }
	$previousErrorAction = $ErrorActionPreference
	$ErrorActionPreference = "SilentlyContinue"
	try {
        $null = & $executable status 2>$null
		$exitCode = $LASTEXITCODE
	} finally {
		$ErrorActionPreference = $previousErrorAction
	}
    return $exitCode -eq 0
}

function Remove-StaleOwnership {
    $locatorPath = Join-Path $stateRoot "locator.json"
    $lockPath = Join-Path $stateRoot "owner.lock"
    if (Test-Path -LiteralPath $locatorPath -PathType Leaf) {
        $locator = Get-Content -LiteralPath $locatorPath -Raw -Encoding UTF8 | ConvertFrom-Json
        if ($locator.processId -and (Get-Process -Id ([int]$locator.processId) -ErrorAction SilentlyContinue)) {
            throw "Device Lab process exists but its control endpoint is unavailable."
        }
    }
    Remove-Item -LiteralPath $locatorPath -Force -ErrorAction SilentlyContinue
    Remove-Item -LiteralPath $lockPath -Force -ErrorAction SilentlyContinue
}

switch ($Action) {
    "Build" {
        Build-DeviceLab
        [ordered]@{ status = "built"; path = $executable } | ConvertTo-Json -Compress
    }
    "Start" {
        Build-DeviceLab
        if (Test-DeviceLabRunning) {
            [ordered]@{ status = "already_running" } | ConvertTo-Json -Compress
            break
        }
        Remove-StaleOwnership
        $process = Start-Process -FilePath $executable -ArgumentList "serve" -WindowStyle Hidden -PassThru
        $ready = $false
        for ($attempt = 0; $attempt -lt 100; $attempt++) {
            Start-Sleep -Milliseconds 100
            if (Test-DeviceLabRunning) { $ready = $true; break }
            if ($process.HasExited) { break }
        }
        if (-not $ready) { throw "Device Lab did not become ready." }
        [ordered]@{ status = "started"; processId = $process.Id } | ConvertTo-Json -Compress
    }
    "Status" { Invoke-DeviceLab -Command "status" }
    "Begin" {
        if (-not (Test-DeviceLabRunning)) { throw "Device Lab is not running." }
        Push-Location $repoRoot
        try {
            if ([string]::IsNullOrWhiteSpace($Commit)) { $Commit = (git rev-parse HEAD).Trim() }
            if ([string]::IsNullOrWhiteSpace($ChangeDigest)) {
                $statusText = (git status --porcelain=v1 --untracked-files=all | Out-String)
                $hashInput = [System.Text.Encoding]::UTF8.GetBytes($statusText)
				$hasher = [Security.Cryptography.SHA256]::Create()
                try {
					$hash = $hasher.ComputeHash($hashInput)
					$ChangeDigest = ([BitConverter]::ToString($hash) -replace "-", "").ToLowerInvariant()
                } finally {
                    [Array]::Clear($hashInput, 0, $hashInput.Length)
					$hasher.Dispose()
                }
            }
        } finally {
            Pop-Location
        }
        $payload = [ordered]@{ durationSeconds = $DurationSeconds; commit = $Commit; changeDigest = $ChangeDigest } | ConvertTo-Json -Compress
        Invoke-DeviceLab -Command "begin" -InputJson $payload
    }
    "Probe" {
        if ([string]::IsNullOrWhiteSpace($RequestJson)) { throw "RequestJson is required." }
        $null = $RequestJson | ConvertFrom-Json
        Invoke-DeviceLab -Command "probe" -InputJson $RequestJson
    }
    "Finish" { Invoke-DeviceLab -Command "finish" -InputJson "{}" }
    "Stop" {
        if (-not (Test-DeviceLabRunning)) {
            [ordered]@{ status = "not_running" } | ConvertTo-Json -Compress
            break
        }
        Invoke-DeviceLab -Command "stop" -InputJson "{}"
        for ($attempt = 0; $attempt -lt 50 -and (Test-DeviceLabRunning); $attempt++) { Start-Sleep -Milliseconds 100 }
        if (Test-DeviceLabRunning) { throw "Device Lab did not stop." }
    }
    "Path" {
        if (-not (Test-Path -LiteralPath $executable -PathType Leaf)) { Build-DeviceLab }
        $executable
    }
    "InstallSkill" {
        $source = Join-Path $repoRoot "tools\device-lab"
        $target = Join-Path $HOME ".codex\skills\cosmoedge-device-lab"
        New-Item -ItemType Directory -Force -Path $target | Out-Null
        Copy-Item -LiteralPath (Join-Path $source "SKILL.md") -Destination (Join-Path $target "SKILL.md") -Force
        New-Item -ItemType Directory -Force -Path (Join-Path $target "agents") | Out-Null
        Copy-Item -LiteralPath (Join-Path $source "agents\openai.yaml") -Destination (Join-Path $target "agents\openai.yaml") -Force
        [ordered]@{ status = "installed"; path = $target } | ConvertTo-Json -Compress
    }
}
