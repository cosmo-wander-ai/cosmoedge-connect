@echo off
setlocal
rem Windows PowerShell must use its own modules when the host is PowerShell 7.
set "PSModulePath="
powershell.exe -NoLogo -NoProfile -ExecutionPolicy Bypass -File "%~dp0cosmoedge-operations.ps1" %*
exit /b %ERRORLEVEL%
