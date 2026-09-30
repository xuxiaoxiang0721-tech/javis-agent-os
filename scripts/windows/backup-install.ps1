param(
    [string]$ConfigPath = (Join-Path $PSScriptRoot 'config\backup-schedule.json'),
    [switch]$Preview,
    [string]$OutXml
)
$ErrorActionPreference = 'Stop'
$config = Get-Content -LiteralPath $ConfigPath -Raw -Encoding UTF8 | ConvertFrom-Json
if ($config.Timezone -ne 'Asia/Shanghai' -or ($config.Times -join ',') -ne '03:15,15:15') {
    throw 'This backup implementation requires Asia/Shanghai slots 03:15 and 15:15.'
}
if ((Get-TimeZone).Id -ne 'China Standard Time') {
    throw 'Windows timezone differs from the validated China Standard Time. Review the schedule before installing; no timezone was changed.'
}
$runner = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot 'backup-run.ps1'))
$configPathAbsolute = [IO.Path]::GetFullPath($ConfigPath)
if (-not (Test-Path -LiteralPath $runner -PathType Leaf)) { throw 'Backup runner is missing.' }
$user = [Security.Principal.WindowsIdentity]::GetCurrent().Name
$action = New-ScheduledTaskAction -Execute 'powershell.exe' -Argument (
    '-NoProfile -NonInteractive -WindowStyle Hidden -ExecutionPolicy Bypass -File "' + $runner + '" -ConfigPath "' + $configPathAbsolute + '"')
$triggers = @()
foreach ($slot in $config.Times) {
    $trigger = New-ScheduledTaskTrigger -Daily -At ([DateTime]::Today.Add([TimeSpan]::Parse($slot)))
    $trigger.StartBoundary = [DateTime]::Today.ToString('yyyy-MM-dd') + 'T' + $slot + ':00+08:00'
    $triggers += $trigger
}
$triggers += New-ScheduledTaskTrigger -AtLogOn -User $user
$settings = New-ScheduledTaskSettingsSet -StartWhenAvailable -MultipleInstances IgnoreNew `
    -ExecutionTimeLimit (New-TimeSpan -Hours 2) -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries
$principal = New-ScheduledTaskPrincipal -UserId $user -LogonType Interactive -RunLevel Limited
$task = New-ScheduledTask -Action $action -Trigger $triggers -Settings $settings -Principal $principal `
    -Description 'Javis verified application backup, Asia/Shanghai 03:15 and 15:15; catch up once when available or at login. Same-machine copy; independent backup not completed.'
# Build XML for review without registering or changing the existing task.
$service = New-Object -ComObject 'Schedule.Service'
$service.Connect()
$definition = $service.NewTask(0)
$definition.RegistrationInfo.Description = $task.Description
$definition.Principal.UserId = $user
$definition.Principal.LogonType = 3
$definition.Principal.RunLevel = 0
$definition.Settings.StartWhenAvailable = $true
$definition.Settings.MultipleInstances = 2
$definition.Settings.ExecutionTimeLimit = 'PT2H'
$definition.Settings.DisallowStartIfOnBatteries = $false
$definition.Settings.StopIfGoingOnBatteries = $false
$definition.Settings.WakeToRun = $false
foreach ($trigger in $triggers) {
    if ($trigger.CimClass.CimClassName -eq 'MSFT_TaskDailyTrigger') {
        $item = $definition.Triggers.Create(2)
        $item.StartBoundary = $trigger.StartBoundary
        $item.DaysInterval = 1
    } else {
        $item = $definition.Triggers.Create(9)
        $item.UserId = $user
    }
    $item.Enabled = $true
}
$execAction = $definition.Actions.Create(0)
$execAction.Path = $action.Execute
$execAction.Arguments = $action.Arguments
$xml = $definition.XmlText
if ($OutXml) { [IO.File]::WriteAllText([IO.Path]::GetFullPath($OutXml), $xml, [Text.Encoding]::Unicode) }
if ($Preview) {
    [ordered]@{ preview = $true; task_name = $config.TaskName; user = $user; timezone = $config.Timezone
        times = $config.Times; logon_catchup = $true; start_when_available = $true
        wake_computer = $false; requires_logged_in_user = $true; destination = $config.DestinationLinux
        off_machine_backup_verified = $false; runner = $runner; xml = $xml } | ConvertTo-Json -Depth 6
    exit 0
}
$existing = Get-ScheduledTask -TaskName $config.TaskName -ErrorAction SilentlyContinue
$backupPath = $null
if ($existing) {
    $backupDir = Join-Path $PSScriptRoot 'backup-task-history'
    New-Item -ItemType Directory -Path $backupDir -Force | Out-Null
    $backupPath = Join-Path $backupDir ('previous-' + [DateTime]::Now.ToString('yyyyMMdd-HHmmss-fffffff') + '.xml')
    [IO.File]::WriteAllText($backupPath, (Export-ScheduledTask -TaskName $config.TaskName), [Text.Encoding]::Unicode)
}
Register-ScheduledTask -TaskName $config.TaskName -Xml $xml -Force | Out-Null
[ordered]@{ installed = $true; task_name = $config.TaskName; previous_xml = $backupPath
    timezone = $config.Timezone; times = $config.Times; requires_logged_in_user = $true
    destination = $config.DestinationLinux; off_machine_backup_verified = $false } | ConvertTo-Json -Depth 4
