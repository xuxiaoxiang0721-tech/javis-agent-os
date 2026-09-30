#Requires -Version 5.1
# Inactive reference template. Current effective policy is Restricted; do not bypass it.
<#
.SYNOPSIS
Register the authorized per-user Javis drop watcher after deployment.
.DESCRIPTION
Does not start the task, modify execution policy, or submit a task to Codex.
Backs up any previous task with exactly this name and path before replacing it.
#>
[CmdletBinding(SupportsShouldProcess=$true, ConfirmImpact='Medium')]
param()
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

function Assert-PlainAncestors([string]$Path) {
    $item = Get-Item -LiteralPath $Path -Force -ErrorAction Stop
    while ($null -ne $item) {
        if (($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) { throw 'Deployment and backup paths must not use links.' }
        $linkType = $item.PSObject.Properties['LinkType']
        if ($null -ne $linkType -and -not [string]::IsNullOrEmpty([string]$linkType.Value)) { throw 'Deployment and backup paths must not use links.' }
        if ($item -is [IO.FileInfo]) { $item = $item.Directory } else { $item = $item.Parent }
    }
}

try {
    $taskName = 'Javis Drop Bridge'
    $taskPath = '\'
    $windowsRoot = 'C:\Users\user\javis'
    $backupRoot = 'C:\Users\user\javis\backups\scheduled-tasks'
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent().Name
    if (-not $identity.EndsWith('\user', [StringComparison]::OrdinalIgnoreCase)) {
        throw 'This task must be installed from the user interactive user account.'
    }
    Assert-PlainAncestors $windowsRoot
    if (-not (Get-Item -LiteralPath $windowsRoot -Force).PSIsContainer) { throw 'The deployed Windows root must be a directory.' }
    $wslPath = Join-Path $env:SystemRoot 'System32\wsl.exe'
    if (-not (Test-Path -LiteralPath $wslPath -PathType Leaf)) { throw 'wsl.exe was not found.' }
    $action = New-ScheduledTaskAction -Execute $wslPath -Argument '-d Ubuntu -u user --exec python3 -B /home/user/javis/scripts/drop-bridge.py --watch' -WorkingDirectory $windowsRoot
    $loginTrigger = New-ScheduledTaskTrigger -AtLogOn -User $identity
    $periodicTrigger = New-ScheduledTaskTrigger -Once -At (Get-Date).AddMinutes(1) -RepetitionInterval (New-TimeSpan -Minutes 1)
    $principal = New-ScheduledTaskPrincipal -UserId $identity -LogonType Interactive -RunLevel Limited
    $settings = New-ScheduledTaskSettingsSet -MultipleInstances IgnoreNew -RestartCount 3 -RestartInterval (New-TimeSpan -Minutes 1) -ExecutionTimeLimit ([TimeSpan]::Zero) -StartWhenAvailable -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries
    $task = New-ScheduledTask -Action $action -Trigger @($loginTrigger, $periodicTrigger) -Principal $principal -Settings $settings -Description 'Cards/Invest atomic drop consumer; user interactive login and one-minute supervision; no automatic approval changes.'
    # Listing the exact task folder distinguishes absence from a failed query.
    $previous = @(Get-ScheduledTask -TaskPath $taskPath -ErrorAction Stop | Where-Object { $_.TaskName -ceq $taskName })
    if ($previous.Count -gt 1) { throw 'More than one task matched the exact identity.' }
    $backupPath = $null
    if ($PSCmdlet.ShouldProcess(($taskPath + $taskName), 'Back up the previous definition and register the deployed watcher (do not start)')) {
        if ($previous.Count -eq 1) {
            $existingParent = $backupRoot
            while (-not (Test-Path -LiteralPath $existingParent)) { $existingParent = [IO.Directory]::GetParent($existingParent).FullName }
            Assert-PlainAncestors $existingParent
            $null = [IO.Directory]::CreateDirectory($backupRoot)
            Assert-PlainAncestors $backupRoot
            $backupPath = Join-Path $backupRoot ('Javis-Drop-Bridge-' + (Get-Date -Format 'yyyyMMdd-HHmmssfff') + '-' + [Guid]::NewGuid().ToString('N') + '.xml')
            $definition = Export-ScheduledTask -TaskName $taskName -TaskPath $taskPath
            $backupStream = [IO.File]::Open($backupPath, [IO.FileMode]::CreateNew, [IO.FileAccess]::Write, [IO.FileShare]::None)
            try {
                $encoded = [Text.Encoding]::Unicode.GetPreamble() + [Text.Encoding]::Unicode.GetBytes($definition)
                $backupStream.Write($encoded, 0, $encoded.Length)
                $backupStream.Flush($true)
            } finally { $backupStream.Dispose() }
        }
        $null = Register-ScheduledTask -TaskName $taskName -TaskPath $taskPath -InputObject $task -Force
        [ordered]@{task_name=$taskName; task_path=$taskPath; user=$identity; installed=$true; started_by_installer=$false; backup_path=$backupPath; restart_interval_seconds=60; restart_count=3; periodic_interval_seconds=60; periodic_expiry=$null; multiple_instances='IgnoreNew'} | ConvertTo-Json -Compress
    }
    exit 0
} catch {
    [Console]::Error.WriteLine($_.Exception.Message)
    exit 1
}
