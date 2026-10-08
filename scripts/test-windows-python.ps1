#Requires -Version 7.0
<#
Run the ordinary Python suites on a native Windows hosted runner. Scope its
new-object default owner to the current user and restore it after every result;
production owner checks and the suites' assertions are unchanged.
#>
[CmdletBinding()]
param(
    [ValidateSet('integrations/workbuddy/tests', 'integrations/workbuddy/deploy/macos/tests',
        'integrations/workbuddy/deploy/windows/tests', 'scripts/tests')]
    [string[]]$TestDirectory = @('integrations/workbuddy/tests', 'integrations/workbuddy/deploy/macos/tests',
        'integrations/workbuddy/deploy/windows/tests', 'scripts/tests'),
    [string]$Python = 'python'
)

$ErrorActionPreference = 'Stop'
$PSNativeCommandUseErrorActionPreference = $false
Set-StrictMode -Version Latest
if (-not $IsWindows) { throw 'This test wrapper requires native Windows and PowerShell 7.' }
$pythonExecutable = (Get-Command $Python -CommandType Application -ErrorAction Stop | Select-Object -First 1).Source
if (-not ('CosmoEdgeConnectLifecycle.TokenOwnerScope' -as [type])) {
    Add-Type -Path (Join-Path $PSScriptRoot 'windows-lifecycle-token-owner.cs')
}

$tokenOwnerScope = $null
$failedSuites = @()
Push-Location ([IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..')))
try {
    $tokenOwnerScope = [CosmoEdgeConnectLifecycle.TokenOwnerScope]::new()
    Write-Host ([ordered]@{ phase = 'python-test-process-owner';
        originalOwnerMatchesUser = $tokenOwnerScope.OriginalOwnerMatchesUser;
        originalOwnerIsAdministrators = $tokenOwnerScope.OriginalOwnerIsAdministrators } | ConvertTo-Json -Compress)
    $tokenOwnerScope.UseCurrentUser()
    foreach ($directory in $TestDirectory) {
        Write-Host ('Running Python unittest suite: ' + $directory)
        & $pythonExecutable -m unittest discover -s $directory -v
        if ($LASTEXITCODE -ne 0) { $failedSuites += $directory }
    }
} finally {
    try {
        if ($null -ne $tokenOwnerScope) {
            $tokenOwnerScope.Dispose()
            Write-Host ([ordered]@{ phase = 'python-test-process-owner-restored';
                restored = $tokenOwnerScope.Restored } | ConvertTo-Json -Compress)
        }
    } finally { Pop-Location }
}
if ($failedSuites.Count -ne 0) { throw ('Python test suites failed: ' + ($failedSuites -join ', ')) }
