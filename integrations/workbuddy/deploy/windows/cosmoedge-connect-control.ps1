[CmdletBinding()]
param([ValidateSet('Start', 'Stop', 'Status', 'McpConfig')][string]$Action = 'Status',
      [ValidatePattern('^[a-z][a-z0-9-]{0,39}$')][string]$ClientId)
$ErrorActionPreference = 'Stop'
$installRoot = [IO.Path]::GetFullPath($PSScriptRoot)
$installRecord = Get-Content -LiteralPath (Join-Path $installRoot 'windows-install.json') -Raw -Encoding UTF8 | ConvertFrom-Json
$servicePath = [IO.Path]::GetFullPath([string]$installRecord.service)
if (-not $servicePath.StartsWith($installRoot + '\', [StringComparison]::OrdinalIgnoreCase)) {
    throw 'The service path is outside its installation directory.'
}

function Get-CosmoEdgeConnectListener {
    @(Get-NetTCPConnection -LocalPort 37789 -State Listen -ErrorAction SilentlyContinue)
}
function Get-OwnedCosmoEdgeConnect {
    @(Get-Process -Name 'cosmoedge-connect' -ErrorAction SilentlyContinue | Where-Object {
        $_.Path -and [string]::Equals([IO.Path]::GetFullPath($_.Path), $servicePath, [StringComparison]::OrdinalIgnoreCase)
    })
}
function Assert-PairedFiles {
    if ((Get-FileHash -LiteralPath $servicePath -Algorithm SHA256).Hash.ToLowerInvariant() -ne $installRecord.serviceSHA256) {
        throw 'Installed CosmoEdge Connect executable does not match its package.'
    }
    if ($installRecord.mcp) {
        foreach ($pair in @(@($installRecord.mcp, $installRecord.mcpSHA256), @($installRecord.mcpCandidate, $installRecord.mcpCandidateSHA256))) {
            $path = [IO.Path]::GetFullPath([string]$pair[0])
            if (-not $path.StartsWith($installRoot + '\', [StringComparison]::OrdinalIgnoreCase) -or
                (Get-FileHash -LiteralPath $path -Algorithm SHA256).Hash.ToLowerInvariant() -ne $pair[1]) {
                throw 'Installed MCP material does not match its package.'
            }
        }
    }
    $skillRoot = [IO.Path]::GetFullPath([string]$installRecord.skill)
    foreach ($entry in $installRecord.skillFiles.PSObject.Properties) {
        $file = [IO.Path]::GetFullPath((Join-Path $skillRoot $entry.Name))
        if (-not $file.StartsWith($skillRoot + '\', [StringComparison]::OrdinalIgnoreCase)) {
            throw 'Invalid Skill file path.'
        }
        if ((Get-FileHash -LiteralPath $file -Algorithm SHA256).Hash.ToLowerInvariant() -ne $entry.Value) {
            throw ('Installed Skill file differs from its package: ' + $entry.Name)
        }
    }
}
function Read-ServiceIdentity {
    Add-Type -AssemblyName System.Net.Http
    $handler = New-Object System.Net.Http.HttpClientHandler
    $handler.UseProxy = $false
    $http = New-Object System.Net.Http.HttpClient($handler)
    $http.Timeout = [TimeSpan]::FromSeconds(2)
    try {
        $secret = [IO.File]::ReadAllText((Join-Path $installRoot 'access.token')).Trim()
        $http.DefaultRequestHeaders.Authorization = New-Object System.Net.Http.Headers.AuthenticationHeaderValue('Bearer', $secret)
        $reply = $http.GetStringAsync('http://127.0.0.1:37789/operations/v1/version').GetAwaiter().GetResult() | ConvertFrom-Json
        if (-not $reply.ok -or $reply.protocol -ne 'cosmoedge.operations.v1' -or $reply.version.product -ne 'cosmoedge-connect') {
            throw 'Unexpected CosmoEdge Connect protocol.'
        }
        foreach ($key in @('version', 'revision', 'platform', 'modified')) {
            if ($reply.version.$key -ne $installRecord.candidate.$key) { throw 'Running service version does not match the Skill.' }
        }
        return $reply.version
    } finally {
        $secret = $null
        $http.Dispose()
        $handler.Dispose()
    }
}

$owned = @(Get-OwnedCosmoEdgeConnect)
if ($Action -eq 'Stop') {
    foreach ($process in $owned) {
        Stop-Process -Id $process.Id -Force
        Wait-Process -Id $process.Id -Timeout 20 -ErrorAction SilentlyContinue
    }
    [pscustomobject]@{ status = 'stopped'; stoppedProcesses = $owned.Count } | ConvertTo-Json -Compress
    exit 0
}
Assert-PairedFiles
if ($Action -eq 'McpConfig') {
    if (-not $installRecord.mcp -or [string]::IsNullOrWhiteSpace($ClientId)) { throw 'A paired MCP candidate and a unique ClientId are required.' }
    @{ mcpServers = @{ cosmoedge = @{ command = $installRecord.mcp; args = @('--base-url', 'http://127.0.0.1:37789',
       '--token-file', (Join-Path $installRoot 'access.token'), '--state-root', (Join-Path $installRoot ('mcp-state\' + $ClientId)),
       '--candidate-file', $installRecord.mcpCandidate) } } } | ConvertTo-Json -Depth 8
    exit 0
}
$listener = @(Get-CosmoEdgeConnectListener)
if ($listener.Count -gt 0 -and ($owned.Count -ne 1 -or @($listener | Where-Object {
        $_.OwningProcess -ne $owned[0].Id -or $_.LocalAddress -ne '127.0.0.1'
    }).Count -gt 0)) {
    throw 'Port 37789 is held by a process outside this CosmoEdge Connect installation.'
}
if ($Action -eq 'Start' -and $owned.Count -eq 0) {
    $arguments = '--state-root "' + (Join-Path $installRoot 'runtime-state') + '" --token-file "' +
        (Join-Path $installRoot 'access.token') + '" --listen 127.0.0.1:37789 --open-operator=false'
    $started = Start-Process -FilePath $servicePath -ArgumentList $arguments -WindowStyle Hidden -PassThru `
        -RedirectStandardOutput (Join-Path $installRoot 'logs\phase2.stdout.log') `
        -RedirectStandardError (Join-Path $installRoot 'logs\phase2.stderr.log')
    $startupReady = $false
    try {
      $deadline = [DateTime]::UtcNow.AddSeconds(40)
      do {
        $started.Refresh()
        if ($started.HasExited) { throw 'CosmoEdge Connect exited before it became ready.' }
        try {
            $identity = Read-ServiceIdentity
            $listener = @(Get-CosmoEdgeConnectListener)
            if ($listener.Count -ne 1 -or $listener[0].OwningProcess -ne $started.Id -or $listener[0].LocalAddress -ne '127.0.0.1') {
                throw 'The installed CosmoEdge Connect is not the unique loopback listener.'
            }
            $startupReady = $true
            [pscustomobject]@{ status = 'running'; processId = $started.Id; pairingVerified = $true; version = $identity.version } | ConvertTo-Json -Compress
            exit 0
        } catch {
            if ([DateTime]::UtcNow -gt $deadline) { throw }
            Start-Sleep -Milliseconds 300
        }
      } while ([DateTime]::UtcNow -lt $deadline)
      throw 'CosmoEdge Connect did not become ready before its startup deadline.'
    } finally {
        if (-not $startupReady) {
            $started.Refresh()
            if (-not $started.HasExited) {
                Stop-Process -Id $started.Id -Force
                Wait-Process -Id $started.Id -Timeout 20 -ErrorAction SilentlyContinue
            }
        }
    }
}
if ($owned.Count -eq 0) {
    [pscustomobject]@{ status = 'stopped'; pairingVerified = $true; version = $installRecord.candidate.version } | ConvertTo-Json -Compress
    exit 0
}
if ($owned.Count -ne 1) { throw 'More than one CosmoEdge Connect instance exists.' }
$identity = Read-ServiceIdentity
[pscustomobject]@{ status = 'running'; processId = $owned[0].Id; pairingVerified = $true; version = $identity.version } | ConvertTo-Json -Compress
