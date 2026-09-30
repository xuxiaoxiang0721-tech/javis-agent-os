param(
    [ValidateSet('Status','Run','Disable','Enable','Uninstall','RestorePrevious')]
    [string]$Action = 'Status',
    [string]$ConfigPath = (Join-Path $PSScriptRoot 'config\backup-schedule.json'),
    [string]$PreviousXml
)
$ErrorActionPreference = 'Stop'
$config = Get-Content -LiteralPath $ConfigPath -Raw -Encoding UTF8 | ConvertFrom-Json
switch ($Action) {
    'Status' {
        $task = Get-ScheduledTask -TaskName $config.TaskName -ErrorAction SilentlyContinue
        $info = if ($task) { Get-ScheduledTaskInfo -TaskName $config.TaskName } else { $null }
        [ordered]@{ task_name = $config.TaskName; installed = [bool]$task
            state = $(if ($task) { [string]$task.State } else { 'missing' })
            user = $(if ($task) { $task.Principal.UserId } else { $null })
            last_run = $(if ($info) { $info.LastRunTime.ToString('o') } else { $null })
            last_result = $(if ($info) { $info.LastTaskResult } else { $null })
            next_run = $(if ($info) { $info.NextRunTime.ToString('o') } else { $null })
            timezone = $config.Timezone; intended_times = $config.Times
            triggers = @($task.Triggers | ForEach-Object { [ordered]@{ type = $_.CimClass.CimClassName; start_boundary = $_.StartBoundary; enabled = $_.Enabled } })
            destination = $config.DestinationLinux; off_machine_backup_verified = $false
        } | ConvertTo-Json -Depth 5
        & (Join-Path $PSScriptRoot 'backup-run.ps1') -ConfigPath $ConfigPath -Status
    }
    'Run' { Start-ScheduledTask -TaskName $config.TaskName }
    'Disable' { Disable-ScheduledTask -TaskName $config.TaskName | Out-Null }
    'Enable' { Enable-ScheduledTask -TaskName $config.TaskName | Out-Null }
    'Uninstall' {
        $backupDir = Join-Path $PSScriptRoot 'backup-task-history'
        New-Item -ItemType Directory -Path $backupDir -Force | Out-Null
        $path = Join-Path $backupDir ('uninstalled-' + [DateTime]::Now.ToString('yyyyMMdd-HHmmss-fffffff') + '.xml')
        [IO.File]::WriteAllText($path, (Export-ScheduledTask -TaskName $config.TaskName), [Text.Encoding]::Unicode)
        Unregister-ScheduledTask -TaskName $config.TaskName -Confirm:$false
        Write-Output ('Task uninstalled; backup archives retained. Task XML: ' + $path)
    }
    'RestorePrevious' {
        if (-not $PreviousXml -or -not (Test-Path -LiteralPath $PreviousXml -PathType Leaf)) { throw 'Supply the previous task XML path.' }
        Register-ScheduledTask -TaskName $config.TaskName -Xml (Get-Content -LiteralPath $PreviousXml -Raw) -Force | Out-Null
    }
}
