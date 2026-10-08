$ErrorActionPreference = 'Stop'
try {
    $runtimeFile = Join-Path $env:LOCALAPPDATA 'CosmoEdgeConnect\python.path'
    if (-not (Test-Path -LiteralPath $runtimeFile -PathType Leaf)) {
        throw 'Python runtime record is unavailable'
    }
    $runtimeItem = Get-Item -LiteralPath $runtimeFile
    if ($runtimeItem.Attributes -band [IO.FileAttributes]::ReparsePoint) {
        throw 'Python runtime record must not be a link'
    }
    $runtimeAcl = Get-Acl -LiteralPath $runtimeFile
    $currentSid = [Security.Principal.WindowsIdentity]::GetCurrent().User
    $ownerSid = $runtimeAcl.GetOwner([Security.Principal.SecurityIdentifier])
    if (-not $runtimeAcl.AreAccessRulesProtected -or $ownerSid.Value -ne $currentSid.Value) {
        throw 'Python runtime record is not private'
    }
    foreach ($rule in $runtimeAcl.GetAccessRules($true, $true, [Security.Principal.SecurityIdentifier])) {
        if ($rule.AccessControlType -eq [Security.AccessControl.AccessControlType]::Allow -and
            $rule.IdentityReference.Value -ne $currentSid.Value) {
            throw 'Python runtime record grants access to another principal'
        }
    }
    $pythonCommand = [IO.File]::ReadAllText($runtimeFile).Trim()
    if (-not [IO.Path]::IsPathRooted($pythonCommand) -or
        -not (Test-Path -LiteralPath $pythonCommand -PathType Leaf)) {
        throw 'Installed Python runtime is unavailable'
    }
    $env:PYTHONUTF8 = '1'
    $env:PYTHONIOENCODING = 'utf-8'
    $env:PYTHONDONTWRITEBYTECODE = '1'
    if ($args.Count -gt 0 -and $args[0] -eq '--protect-request') {
        if ($args.Count -ne 2) { throw 'A single request file is required' }
        & $pythonCommand (Join-Path $PSScriptRoot 'local_files.py') protect $args[1]
    } else {
        & $pythonCommand (Join-Path $PSScriptRoot 'cosmoedge_operations.py') @args
    }
    exit $LASTEXITCODE
} catch {
    Write-Output '{"ok":false,"userMessage":"本机客户端运行环境不可用，请重新运行 CosmoEdge Connect 安装包。"}'
    exit 1
}
