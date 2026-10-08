[CmdletBinding()]
param()

$ErrorActionPreference = 'Stop'
$root = (Resolve-Path (Join-Path $PSScriptRoot '..\..')).Path
$artifactRoot = Join-Path $root '.parity\candidate'
$operator = Join-Path $artifactRoot 'cosmoedge-operator.exe'
$results = Join-Path $artifactRoot 'phase3-normalized.json'
$baseline = Join-Path $root 'internal\parity\testdata\ordinary-baseline-normalized.json'

if (-not (Test-Path $baseline)) {
    throw 'Frozen baseline results are required for Phase 3 differential verification.'
}
New-Item -ItemType Directory -Force $artifactRoot | Out-Null

Push-Location $root
try {
    go build -buildvcs=false -o $operator .\cmd\cosmoedge-operator
    if ($LASTEXITCODE -ne 0) { throw 'Ordinary Operator differential build failed.' }

    $env:PARITY_BASELINE_OPERATOR = $operator
    $env:PARITY_IMPLEMENTATION = 'candidate'
    $env:PARITY_RESULTS_PATH = $results
    go test -buildvcs=false -count=1 -v .\internal\parity -run '^TestBaseline'
    if ($LASTEXITCODE -ne 0) { throw 'Ordinary Operator golden scenarios failed.' }

    Remove-Item Env:PARITY_RESULTS_PATH -ErrorAction SilentlyContinue
    Remove-Item Env:PARITY_BASELINE_OPERATOR -ErrorAction SilentlyContinue
    Remove-Item Env:PARITY_IMPLEMENTATION -ErrorAction SilentlyContinue
    $env:PARITY_FROZEN_RESULTS = $baseline
    $env:PARITY_CANDIDATE_RESULTS = $results
    go test -buildvcs=false -count=1 -v .\internal\parity -run '^TestPhase3DifferentialFiles$'
    if ($LASTEXITCODE -ne 0) { throw 'Ordinary Operator structured differential verification failed.' }

    $count = @((Get-Content -Raw -Encoding UTF8 $results | ConvertFrom-Json)).Count
    Write-Host "Ordinary Operator external parity: $count scenarios passed with only approved safety corrections."
} finally {
    Remove-Item Env:PARITY_RESULTS_PATH -ErrorAction SilentlyContinue
    Remove-Item Env:PARITY_BASELINE_OPERATOR -ErrorAction SilentlyContinue
    Remove-Item Env:PARITY_IMPLEMENTATION -ErrorAction SilentlyContinue
    Remove-Item Env:PARITY_FROZEN_RESULTS -ErrorAction SilentlyContinue
    Remove-Item Env:PARITY_CANDIDATE_RESULTS -ErrorAction SilentlyContinue
    Pop-Location
}
