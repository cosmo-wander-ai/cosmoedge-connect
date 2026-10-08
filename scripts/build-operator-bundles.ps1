[CmdletBinding()]
param()

$ErrorActionPreference = "Stop"
$root = (Resolve-Path (Join-Path $PSScriptRoot "..")).Path
$artifactRoot = Join-Path $root ".parity\release"
$allowedRoot = [System.IO.Path]::GetFullPath((Join-Path $root ".parity"))
$resolvedArtifact = [System.IO.Path]::GetFullPath($artifactRoot)
if (-not $resolvedArtifact.StartsWith($allowedRoot + [System.IO.Path]::DirectorySeparatorChar, [System.StringComparison]::OrdinalIgnoreCase)) {
    throw "release artifact root escaped the repository .parity directory"
}
if (Test-Path -LiteralPath $artifactRoot) {
    Remove-Item -LiteralPath $artifactRoot -Recurse -Force
}

$windows = Join-Path $artifactRoot "windows-amd64"
$darwinAMD64 = Join-Path $artifactRoot "darwin-amd64"
$darwinARM64 = Join-Path $artifactRoot "darwin-arm64"
$linuxAMD64 = Join-Path $artifactRoot "linux-amd64"
New-Item -ItemType Directory -Force -Path $windows, $darwinAMD64, $darwinARM64, $linuxAMD64 | Out-Null

$originalGOOS, $originalGOARCH, $originalCGO = $env:GOOS, $env:GOARCH, $env:CGO_ENABLED
Push-Location $root
try {
    $env:CGO_ENABLED = "0"
    $env:GOOS = "windows"; $env:GOARCH = "amd64"
    go build -trimpath -buildvcs=false -o (Join-Path $windows "cosmoedge-operator.exe") .\cmd\cosmoedge-operator
    if ($LASTEXITCODE -ne 0) { throw "Windows Operator build failed" }
    Copy-Item -LiteralPath .\scripts\cosmoedge-operator-bootstrap.ps1 -Destination (Join-Path $windows "cosmoedge-operator-bootstrap.ps1")
    $windowsSkill = Join-Path $windows "demo\skill\cosmoedge-operator"
    New-Item -ItemType Directory -Force -Path $windowsSkill | Out-Null
    Copy-Item -Recurse -Force -Path .\demo\skill\cosmoedge-operator\* -Destination $windowsSkill

    foreach ($target in @(
        @{ GOOS = "darwin"; GOARCH = "amd64"; Root = $darwinAMD64 },
        @{ GOOS = "darwin"; GOARCH = "arm64"; Root = $darwinARM64 }
    )) {
        $env:GOOS = $target.GOOS; $env:GOARCH = $target.GOARCH
        go build -trimpath -buildvcs=false -o (Join-Path $target.Root "cosmoedge-operator") .\cmd\cosmoedge-operator
        if ($LASTEXITCODE -ne 0) { throw "$($target.GOOS)-$($target.GOARCH) Operator build failed" }
        New-Item -ItemType Directory -Force -Path (Join-Path $target.Root "demo\skill\cosmoedge-operator"), (Join-Path $target.Root "scripts") | Out-Null
        Copy-Item -Recurse -Force -Path .\demo\skill\cosmoedge-operator\* -Destination (Join-Path $target.Root "demo\skill\cosmoedge-operator")
        Copy-Item -Force -Path .\scripts\cosmoedge-operator-*.sh -Destination (Join-Path $target.Root "scripts")
    }

    $env:GOOS = "linux"; $env:GOARCH = "amd64"
    go build -trimpath -buildvcs=false -o (Join-Path $linuxAMD64 "cosmoedge-operator") .\cmd\cosmoedge-operator
    if ($LASTEXITCODE -ne 0) { throw "Linux Operator build failed" }

    $manifest = Get-ChildItem -LiteralPath $artifactRoot -Recurse -File | Sort-Object FullName | ForEach-Object {
        $relative = $_.FullName.Substring($artifactRoot.Length).TrimStart([char[]]@([System.IO.Path]::DirectorySeparatorChar, [System.IO.Path]::AltDirectorySeparatorChar))
        [pscustomobject]@{
            path = $relative.Replace("\", "/")
            sha256 = (Get-FileHash -LiteralPath $_.FullName -Algorithm SHA256).Hash
            bytes = $_.Length
        }
    }
    $manifest | ConvertTo-Json -Depth 4 | Set-Content -LiteralPath (Join-Path $artifactRoot "manifest.json") -Encoding UTF8
    Write-Host "Operator bundles built at $artifactRoot"
} finally {
    $env:GOOS, $env:GOARCH, $env:CGO_ENABLED = $originalGOOS, $originalGOARCH, $originalCGO
    Pop-Location
}
