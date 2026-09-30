[CmdletBinding()]
param(
    [ValidateSet('Check','Monitor','RegisterTask','StartMonitor','StopMonitor','UnregisterTask','ExportTask')][string]$Action = 'Check',
    [switch]$ReplaceExisting,
    [string]$Distro = 'Ubuntu',
    [string]$LinuxUser = 'user',
    [string]$LinuxRoot = '/home/user/javis',
    [string]$LinuxScript = '/home/user/javis/scripts/preflight-linux.py',
    [string]$LogDirectory = (Join-Path $env:USERPROFILE 'Javis-Exchange\lifecycle'),
    [ValidateRange(5,60)][int]$IntervalSeconds = 30,
    [ValidateRange(0,100000)][int]$MaxChecks = 0,
    [ValidateRange(2,60)][int]$StartupGraceSeconds = 60
)
$ErrorActionPreference = 'Stop'
$taskName = 'Javis WSL Health Supervisor'
$identity = [Security.Principal.WindowsIdentity]::GetCurrent()
if ($identity.IsSystem) { throw 'Run as the Windows user who owns the Ubuntu distribution, not SYSTEM.' }
function Quote-ProcessArgument([string]$Value) {
    if ($Value.Contains([char]0) -or $Value.Contains("`r") -or $Value.Contains("`n")) { throw 'Invalid process argument' }
    if ($Value -and $Value -notmatch '[\s"]') { return $Value }
    return '"' + [regex]::Replace([regex]::Replace($Value, '(\\*)"', '$1$1\"'), '(\\+)$', '$1$1') + '"'
}
function Get-JavisHealth([int]$TimeoutMilliseconds = 30000) {
    $info = [Diagnostics.ProcessStartInfo]::new()
    $info.FileName = Join-Path $env:WINDIR 'System32\wsl.exe'
    $argsList = @('-d',$Distro,'-u',$LinuxUser,'--','python3',$LinuxScript,'--root',$LinuxRoot,'--health-only')
    $info.Arguments = ($argsList | ForEach-Object { Quote-ProcessArgument $_ }) -join ' '
    $info.UseShellExecute = $false; $info.CreateNoWindow = $true
    $info.RedirectStandardOutput = $true; $info.RedirectStandardError = $true
    $info.StandardOutputEncoding = [Text.UTF8Encoding]::new($false)
    $info.StandardErrorEncoding = [Text.UTF8Encoding]::new($false)
    $proc = [Diagnostics.Process]::new(); $proc.StartInfo = $info
    try {
        [void]$proc.Start()
        $outputTask = $proc.StandardOutput.ReadToEndAsync()
        $errorTask = $proc.StandardError.ReadToEndAsync()
        if (-not $proc.WaitForExit($TimeoutMilliseconds)) {
            $proc.Kill()
            throw 'WSL health command timed out; only this probe process was stopped.'
        }
        $stdout = $outputTask.GetAwaiter().GetResult()
        [void]$errorTask.GetAwaiter().GetResult()
        if ($proc.ExitCode -ne 0) { throw "WSL health probe exited $($proc.ExitCode); check Linux script path and distribution." }
        $health = $stdout | ConvertFrom-Json
        if ($health.user -ne $LinuxUser -or $health.uid -eq 0 -or $health.root -ne $LinuxRoot -or $health.root_owner_uid -ne $health.uid) {
            throw 'Linux identity or Javis root owner does not match the configured non-root user.'
        }
        return $health
    } finally { $proc.Dispose() }
}
function Write-LifecycleLog($Record) {
    [void][IO.Directory]::CreateDirectory($LogDirectory)
    $path = Join-Path $LogDirectory ('supervisor-' + (Get-Date -Format 'yyyy-MM-dd') + '.jsonl')
    [IO.File]::AppendAllText($path, ($Record | ConvertTo-Json -Depth 8 -Compress) + "`n", [Text.UTF8Encoding]::new($false))
}
function Stop-JavisHold($Hold) {
    if ($null -eq $Hold) { return }
    $proc = $Hold.Process
    try {
        $proc.StandardInput.Close()
        if (-not $proc.WaitForExit(5000)) { $proc.Kill(); [void]$proc.WaitForExit(2000) }
    } catch [InvalidOperationException] {
        # Only this helper may already have exited; never terminate the distro.
    } finally { $proc.Dispose() }
}
function Start-JavisHold([DateTime]$Deadline) {
    $info = [Diagnostics.ProcessStartInfo]::new()
    $info.FileName = Join-Path $env:WINDIR 'System32\wsl.exe'
    $python = 'import os,sys; print(os.getpid(),flush=True); sys.stdin.buffer.read()'
    $argsList = @('-d',$Distro,'-u',$LinuxUser,'--','python3','-u','-c',$python)
    $info.Arguments = ($argsList | ForEach-Object { Quote-ProcessArgument $_ }) -join ' '
    $info.UseShellExecute = $false; $info.CreateNoWindow = $true
    $info.RedirectStandardInput = $true; $info.RedirectStandardOutput = $true; $info.RedirectStandardError = $true
    $info.StandardOutputEncoding = [Text.UTF8Encoding]::new($false)
    $info.StandardErrorEncoding = [Text.UTF8Encoding]::new($false)
    $proc = [Diagnostics.Process]::new(); $proc.StartInfo = $info
    $hold = @{ Process=$proc; LinuxPid=$null }
    try {
        [void]$proc.Start()
        $hold.ErrorReader = $proc.StandardError.ReadToEndAsync()
        $pidReader = $proc.StandardOutput.ReadLineAsync()
        $timeout = [Math]::Max(1,[Math]::Min(30000,($Deadline - [DateTime]::UtcNow).TotalMilliseconds))
        if (-not $pidReader.Wait([int]$timeout)) { throw 'WSL foreground hold did not become ready within startup grace.' }
        $line = $pidReader.GetAwaiter().GetResult()
        if ($line -notmatch '^\d+$' -or $proc.HasExited) { throw 'WSL foreground hold failed to start.' }
        $hold.LinuxPid = [int]$line
        return $hold
    } catch {
        Write-LifecycleLog @{ schema_version='javis.lifecycle.startup.v1'; captured_at=[DateTimeOffset]::Now.ToString('o');
                             status='failed'; error=$_.Exception.Message; phase='foreground_hold_start'; windows_user=$identity.Name; distro=$Distro }
        Stop-JavisHold $hold
        throw
    }
}
function Wait-JavisReady($Hold, [DateTime]$Deadline) {
    $attempt = 0
    $lastFailure = 'Services are still starting.'
    while ([DateTime]::UtcNow -lt $Deadline) {
        $attempt++
        $record = @{ schema_version='javis.lifecycle.startup.v1'; captured_at=[DateTimeOffset]::Now.ToString('o');
                     windows_user=$identity.Name; distro=$Distro; attempt=$attempt; hold_pid=$Hold.Process.Id; hold_linux_pid=$Hold.LinuxPid }
        try {
            if ($Hold.Process.HasExited) { throw 'WSL foreground hold exited unexpectedly.' }
            $timeout = [Math]::Max(1,[Math]::Min(30000,($Deadline - [DateTime]::UtcNow).TotalMilliseconds))
            $health = Get-JavisHealth -TimeoutMilliseconds ([int]$timeout)
            if ($health.lifecycle_ready) { return @{ Health=$health; Attempts=$attempt } }
            $record.health = $health
            $lastFailure = 'Linux identity is valid but services are not yet healthy.'
        } catch { $lastFailure=$_.Exception.Message }
        $record.status='starting'; $record.error=$lastFailure
        Write-LifecycleLog $record
        if ($Hold.Process.HasExited) { break }
        $remaining = ($Deadline - [DateTime]::UtcNow).TotalMilliseconds
        if ($remaining -gt 0) { Start-Sleep -Milliseconds ([int][Math]::Min(2000,$remaining)) }
    }
    Write-LifecycleLog @{ schema_version='javis.lifecycle.startup.v1'; captured_at=[DateTimeOffset]::Now.ToString('o');
                         status='failed'; error=$lastFailure; startup_grace_seconds=$StartupGraceSeconds; attempt=$attempt;
                         hold_pid=$Hold.Process.Id; hold_linux_pid=$Hold.LinuxPid }
    throw "Javis did not become healthy within the $StartupGraceSeconds-second startup grace; see supervisor log."
}
switch ($Action) {
    'Check' { Get-JavisHealth | ConvertTo-Json -Depth 8; break }
    'RegisterTask' {
        $existing = Get-ScheduledTask -TaskName $taskName -ErrorAction SilentlyContinue
        if ($existing -and -not $ReplaceExisting) { throw "Task already exists: $taskName. Export/review it, then use -ReplaceExisting for an intentional update." }
        if ($existing) {
            [void][IO.Directory]::CreateDirectory($LogDirectory)
            $backupName = 'Javis-WSL-Health-Supervisor-before-' + (Get-Date -Format 'yyyyMMdd-HHmmss') + '.xml'
            Export-ScheduledTask -TaskName $taskName | Set-Content -LiteralPath (Join-Path $LogDirectory $backupName) -Encoding Unicode
        }
        $hold = $null
        try {
        $deadline = [DateTime]::UtcNow.AddSeconds($StartupGraceSeconds)
        $hold = Start-JavisHold $deadline
        $ready = Wait-JavisReady $hold $deadline
        [void][IO.Directory]::CreateDirectory($LogDirectory)
        $arguments = @('-NoProfile','-NonInteractive','-WindowStyle','Hidden','-ExecutionPolicy','Bypass','-File',$PSCommandPath,
                       '-Action','Monitor','-Distro',$Distro,'-LinuxUser',$LinuxUser,'-LinuxRoot',$LinuxRoot,'-LinuxScript',$LinuxScript,
                       '-LogDirectory',$LogDirectory,'-IntervalSeconds',[string]$IntervalSeconds,'-StartupGraceSeconds',[string]$StartupGraceSeconds)
        $taskAction = New-ScheduledTaskAction -Execute (Join-Path $env:WINDIR 'System32\WindowsPowerShell\v1.0\powershell.exe') -Argument (($arguments | ForEach-Object { Quote-ProcessArgument $_ }) -join ' ')
        $principal = New-ScheduledTaskPrincipal -UserId $identity.Name -LogonType Interactive -RunLevel Limited
        $logonTrigger = New-ScheduledTaskTrigger -AtLogOn -User $identity.Name
        # Repetition without Duration is indefinite. IgnoreNew below ensures the
        # minute trigger only fills an absent supervisor; it cannot overlap one.
        $recoveryTrigger = New-ScheduledTaskTrigger -Once -At ((Get-Date).AddMinutes(1)) -RepetitionInterval (New-TimeSpan -Minutes 1)
        $settings = New-ScheduledTaskSettingsSet -MultipleInstances IgnoreNew -StartWhenAvailable -RestartCount 3 -RestartInterval (New-TimeSpan -Minutes 1) -ExecutionTimeLimit ([TimeSpan]::Zero) -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries
        $settings.UseUnifiedSchedulingEngine = $true
        Register-ScheduledTask -TaskName $taskName -Action $taskAction -Principal $principal -Trigger @($logonTrigger,$recoveryTrigger) -Settings $settings -Force:$ReplaceExisting -Description 'Starts WSL as its owner and probes Javis services every 30 seconds; an indefinite one-minute trigger recovers a missing supervisor. IgnoreNew prevents overlap. Logged-in operation only; no model requests or task replay.' | Out-Null
        Export-ScheduledTask -TaskName $taskName | Set-Content -LiteralPath (Join-Path $LogDirectory 'Javis-WSL-Health-Supervisor.xml') -Encoding Unicode
        "Registered for $($identity.Name). Start-ScheduledTask -TaskName '$taskName' starts supervision."
        } finally { Stop-JavisHold $hold }
        break
    }
    'StartMonitor' { Enable-ScheduledTask -TaskName $taskName | Out-Null; Start-ScheduledTask -TaskName $taskName; 'Supervisor enabled and start requested.'; break }
    'StopMonitor' { Disable-ScheduledTask -TaskName $taskName | Out-Null; Stop-ScheduledTask -TaskName $taskName; 'Supervisor disabled and stopped for maintenance; Linux tasks and Neo4j are not terminated.'; break }
    'UnregisterTask' { Disable-ScheduledTask -TaskName $taskName -ErrorAction SilentlyContinue | Out-Null; Stop-ScheduledTask -TaskName $taskName -ErrorAction SilentlyContinue; Unregister-ScheduledTask -TaskName $taskName -Confirm:$false; 'Supervisor task removed; Linux data and services remain.'; break }
    'ExportTask' { Export-ScheduledTask -TaskName $taskName; break }
    'Monitor' {
        $mutexName = 'Local\JavisWslHealth-' + $identity.User.Value + '-' + $Distro
        $mutex = [Threading.Mutex]::new($false,$mutexName)
        $held = $false
        $hold = $null
        try {
            try { $held = $mutex.WaitOne(0) } catch [Threading.AbandonedMutexException] { $held = $true }
            if (-not $held) { throw 'Another supervisor instance is active for this Windows user and distribution.' }
            $deadline = [DateTime]::UtcNow.AddSeconds($StartupGraceSeconds)
            $hold = Start-JavisHold $deadline
            $ready = Wait-JavisReady $hold $deadline
            $checks = 0
            while ($MaxChecks -eq 0 -or $checks -lt $MaxChecks) {
                $record = @{ schema_version='javis.lifecycle.supervision.v1'; captured_at=[DateTimeOffset]::Now.ToString('o'); windows_user=$identity.Name; distro=$Distro;
                             supervisor_pid=$PID; hold_pid=$hold.Process.Id; hold_linux_pid=$hold.LinuxPid; startup_attempts=$ready.Attempts }
                try {
                    if ($hold.Process.HasExited) { throw 'WSL foreground hold exited unexpectedly.' }
                    $health = $(if ($checks -eq 0) { $ready.Health } else { Get-JavisHealth })
                    $record.health = $health
                    $record.status = $(if ($health.lifecycle_ready) {'healthy'} else {'needs_attention'})
                } catch { $record.status='failed'; $record.error=$_.Exception.Message }
                Write-LifecycleLog $record
                if ($record.status -ne 'healthy') { throw 'Javis lifecycle check failed; failure recorded in supervisor log.' }
                $checks++
                if ($MaxChecks -ne 0 -and $checks -ge $MaxChecks) { break }
                Start-Sleep -Seconds $IntervalSeconds
            }
        } finally { Stop-JavisHold $hold; if ($held) { $mutex.ReleaseMutex() }; $mutex.Dispose() }
        break
    }
}
