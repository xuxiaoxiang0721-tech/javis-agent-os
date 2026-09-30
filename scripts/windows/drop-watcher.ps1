#Requires -Version 5.1
# Inactive reference template. The production task launches wsl.exe directly.
# Scheduled-task entry only. The Linux consumer owns both role queues and the lock.
[CmdletBinding()]
param()
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
try {
    $wslPath = Join-Path $env:SystemRoot 'System32\wsl.exe'
    if (-not (Test-Path -LiteralPath $wslPath -PathType Leaf)) { throw 'wsl.exe was not found.' }
    & $wslPath -d Ubuntu -u user --exec python3 -B /home/user/javis/scripts/drop-bridge.py --watch
    $consumerExitCode = $LASTEXITCODE
    if ($null -eq $consumerExitCode) { throw 'The WSL consumer did not return an exit code.' }
    exit ([int]$consumerExitCode)
} catch {
    [Console]::Error.WriteLine($_.Exception.Message)
    exit 1
}
