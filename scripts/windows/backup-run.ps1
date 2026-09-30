param(
    [string]$ConfigPath = (Join-Path $PSScriptRoot 'config\backup-schedule.json'),
    [switch]$Force,
    [switch]$RestoreCheck,
    [switch]$Status
)
$ErrorActionPreference = 'Stop'
$config = Get-Content -LiteralPath $ConfigPath -Raw -Encoding UTF8 | ConvertFrom-Json
if ($config.Timezone -ne 'Asia/Shanghai' -or ($config.Times -join ',') -ne '03:15,15:15') {
    throw 'This backup implementation requires Asia/Shanghai slots 03:15 and 15:15.'
}
$logDir = [IO.Path]::GetFullPath($config.LogDirectory)
New-Item -ItemType Directory -Path $logDir -Force | Out-Null
$started = [DateTimeOffset]::Now
$runId = [Guid]::NewGuid().ToString()
$exitCode = 1
$result = $null
$failure = $null
try {
    $wslArgs = @('-d', $config.Distribution, '--', 'env', ('JAVIS_ROOT=' + $config.LinuxRoot), 'bash', ($config.LinuxRoot + '/scripts/javis-daily-backup.sh'),
        '--destination', $config.DestinationLinux, '--destination-kind', $config.DestinationKind)
    if ($Status) { $wslArgs += '--status' }
    elseif (-not $Force) { $wslArgs += '--if-due' }
    if ($RestoreCheck) { $wslArgs += '--restore-check' }
    # Windows PowerShell 5 may wrap redirected native stderr as ErrorRecords.
    # Temporarily continue to capture it, then judge the real native exit code.
    $errorFile = Join-Path $logDir ('backup-stderr-' + $runId + '.txt')
    Get-Command wsl.exe -ErrorAction Stop | Out-Null
    $nativePreference = $ErrorActionPreference
    try {
        $ErrorActionPreference = 'Continue'
        $output = @(& wsl.exe @wslArgs 2> $errorFile)
        $exitCode = $LASTEXITCODE
    } finally { $ErrorActionPreference = $nativePreference }
    $joined = $output -join "`n"
    try { $result = $joined | ConvertFrom-Json } catch { $result = $null }
    if ($exitCode -ne 0) {
        $failure = if ($result.failure_reason) { $result.failure_reason } else { 'WSL backup failed; see stderr_file.' }
    } elseif (-not $result) {
        $failure = 'Backup did not return a valid JSON result.'
        $exitCode = 1
    }
    if ($result) { $result | ConvertTo-Json -Depth 10 }
    elseif ($joined) { Write-Output $joined }
    if ((Get-Item -LiteralPath $errorFile).Length -eq 0) {
        Remove-Item -LiteralPath $errorFile
        $errorFile = $null
    }
} catch {
    $failure = $_.Exception.Message
    $exitCode = 1
} finally {
    $record = [ordered]@{
        schema_version = 2; run_id = $runId; started_at = $started.ToString('o')
        finished_at = [DateTimeOffset]::Now.ToString('o'); timezone = $config.Timezone
        schedule = $config.Times; destination = $config.DestinationLinux
        destination_kind = $config.DestinationKind; off_machine_backup_verified = $false
        operation = $(if ($Status) { 'status' } elseif ($Force) { 'manual_backup' } else { 'scheduled_backup' })
        exit_code = $exitCode; failure_reason = $failure; stderr_file = $errorFile; result = $result
    }
    # The scheduled task has IgnoreNew; CLI callers each have a unique record.
    $recordPath = Join-Path $logDir ('scheduler-run-' + $runId + '.json')
    [IO.File]::WriteAllText($recordPath, ($record | ConvertTo-Json -Depth 12), [Text.UTF8Encoding]::new($false))
}
if ($failure) { Write-Output ('Backup failed: ' + $failure) }
exit $exitCode
