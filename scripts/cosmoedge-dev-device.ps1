[CmdletBinding()]
param(
    [ValidateSet("Authorize", "Status", "VerifyRead", "VerifyTaskRoundtrip", "Revoke")]
    [string]$Action = "Status",
    [int]$TaskIndex = 0,
    [ValidateRange(1, 90)]
    [int]$ValidDays = 30,
    [switch]$AllowTaskSwitchRoundtrip
)

$ErrorActionPreference = "Stop"
$repoRoot = [System.IO.Path]::GetFullPath((Join-Path $PSScriptRoot ".."))
$tool = ".\tools\dev-device"

function Invoke-DevDevice {
    param([string[]]$Arguments, [string]$InputJson = "")
    Push-Location $repoRoot
    try {
        if ($InputJson) {
            $InputJson | go run -buildvcs=false $tool @Arguments
        } else {
            go run -buildvcs=false $tool @Arguments
        }
        if ($LASTEXITCODE -ne 0) { throw "Development device command failed." }
    } finally {
        Pop-Location
    }
}

switch ($Action) {
    "Authorize" {
        $endpoint = Read-Host "Device IP or private URL"
        $username = Read-Host "Device account"
        if ([string]::IsNullOrWhiteSpace($endpoint) -or [string]::IsNullOrWhiteSpace($username)) {
            throw "Device address and account are required."
        }
        $credential = Get-Credential -UserName $username -Message "CosmoEdge development device authorization"
        if (-not $credential) { throw "Credential entry was cancelled." }
        $plain = $credential.GetNetworkCredential().Password
        $bytes = [System.Text.Encoding]::UTF8.GetBytes($plain)
        try {
            $payload = [ordered]@{
                endpoint = $endpoint
                username = $username
                passwordBase64 = [Convert]::ToBase64String($bytes)
                validForHours = $ValidDays * 24
                allowTaskSwitchRoundTrip = [bool]$AllowTaskSwitchRoundtrip
            } | ConvertTo-Json -Compress
            Invoke-DevDevice -Arguments @("authorize") -InputJson $payload
        } finally {
            [Array]::Clear($bytes, 0, $bytes.Length)
            $plain = $null
            $credential = $null
            $payload = $null
        }
    }
    "Status" { Invoke-DevDevice -Arguments @("status") }
    "VerifyRead" { Invoke-DevDevice -Arguments @("verify-read") }
    "VerifyTaskRoundtrip" {
        if ($TaskIndex -lt 1) { throw "TaskIndex must be a displayed task list number." }
        Invoke-DevDevice -Arguments @("verify-task-roundtrip", [string]$TaskIndex)
    }
    "Revoke" { Invoke-DevDevice -Arguments @("revoke") }
}
