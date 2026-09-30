$ErrorActionPreference = 'Stop'
$tempDirectory = Join-Path $PSScriptRoot ('lifecycle-test-' + [Guid]::NewGuid().ToString('N'))
[void][IO.Directory]::CreateDirectory($tempDirectory)
$fixture = Join-Path $tempDirectory 'fixture with spaces.py'
$fixtureText = @'
import json
print(json.dumps({"schema_version":"test_only","user":"user","uid":1000,"root":"/home/user/javis","root_owner_uid":1000,"lifecycle_ready":True}))
'@
[IO.File]::WriteAllText($fixture, $fixtureText, [Text.UTF8Encoding]::new($false))
$drive = $fixture.Substring(0,1).ToLowerInvariant()
$linuxFixture = '/mnt/' + $drive + $fixture.Substring(2).Replace('\','/')
$runner = Join-Path $PSScriptRoot 'lifecycle-windows.ps1'
$powershell = Join-Path $env:WINDIR 'System32\WindowsPowerShell\v1.0\powershell.exe'
$checks = @()
function Assert-HoldStopped($Row) {
    for ($i=0; $i -lt 20; $i++) {
        if (-not (Get-Process -Id $Row.hold_pid -ErrorAction SilentlyContinue)) { break }
        Start-Sleep -Milliseconds 250
    }
    if (Get-Process -Id $Row.hold_pid -ErrorAction SilentlyContinue) { throw 'Owned Windows WSL hold process survived the monitor' }
    & wsl.exe -d Ubuntu -u user -- test ! -e ('/proc/' + $Row.hold_linux_pid)
    if ($LASTEXITCODE -ne 0) { throw 'Owned Linux stdin hold survived its parent pipe closure' }
}
function Invoke-BoundedMonitor([string]$Scenario, [string]$PythonText, [int]$GraceSeconds = 8) {
    $scenarioDirectory = Join-Path $tempDirectory $Scenario
    [void][IO.Directory]::CreateDirectory($scenarioDirectory)
    $scriptPath = Join-Path $scenarioDirectory 'health.py'
    [IO.File]::WriteAllText($scriptPath, $PythonText, [Text.UTF8Encoding]::new($false))
    $linuxPath = '/mnt/' + $scriptPath.Substring(0,1).ToLowerInvariant() + $scriptPath.Substring(2).Replace('\','/')
    $arguments = @('-NoProfile','-NonInteractive','-ExecutionPolicy','Bypass','-File',('"' + $runner + '"'),'-Action','Monitor','-LinuxScript',('"' + $linuxPath + '"'),'-LogDirectory',('"' + $scenarioDirectory + '"'),'-MaxChecks','1','-StartupGraceSeconds',[string]$GraceSeconds)
    $child = Start-Process -FilePath $powershell -ArgumentList $arguments -WindowStyle Hidden -PassThru -Wait -RedirectStandardOutput (Join-Path $scenarioDirectory 'run.out') -RedirectStandardError (Join-Path $scenarioDirectory 'run.err')
    $logs = @(Get-ChildItem -LiteralPath $scenarioDirectory -Filter 'supervisor-*.jsonl')
    $rows = @($logs | ForEach-Object { [IO.File]::ReadAllLines($_.FullName) } | ForEach-Object { $_ | ConvertFrom-Json })
    return @{ ExitCode=$child.ExitCode; Rows=$rows }
}
try {
    $out = & $powershell -NoProfile -NonInteractive -ExecutionPolicy Bypass -File $runner -Action Check -LinuxScript $linuxFixture
    if ($LASTEXITCODE -ne 0 -or -not (($out -join "`n") | ConvertFrom-Json).lifecycle_ready) { throw 'Path with spaces probe failed' }
    $checks += 'quoted_linux_path_with_spaces'
    $argsList = @('-NoProfile','-NonInteractive','-ExecutionPolicy','Bypass','-File',('"' + $runner + '"'),'-Action','Monitor','-LinuxScript',('"' + $linuxFixture + '"'),'-LogDirectory',('"' + $tempDirectory + '"'),'-IntervalSeconds','5','-MaxChecks','2')
    $first = Start-Process -FilePath $powershell -ArgumentList $argsList -WindowStyle Hidden -PassThru -RedirectStandardOutput (Join-Path $tempDirectory 'first.out') -RedirectStandardError (Join-Path $tempDirectory 'first.err')
    Start-Sleep -Milliseconds 1500
    $secondArgs = @('-NoProfile','-NonInteractive','-ExecutionPolicy','Bypass','-File',('"' + $runner + '"'),'-Action','Monitor','-LinuxScript',('"' + $linuxFixture + '"'),'-LogDirectory',('"' + $tempDirectory + '"'),'-MaxChecks','1')
    $second = Start-Process -FilePath $powershell -ArgumentList $secondArgs -WindowStyle Hidden -PassThru -Wait -RedirectStandardOutput (Join-Path $tempDirectory 'second.out') -RedirectStandardError (Join-Path $tempDirectory 'second.err')
    if ($second.ExitCode -eq 0) { throw 'Duplicate supervisor was not rejected' }
    $secondError = [IO.File]::ReadAllText((Join-Path $tempDirectory 'second.err'))
    if ($secondError -notmatch 'Another supervisor instance') { throw 'Second monitor failed for an unexpected reason' }
    $checks += 'duplicate_supervisor_rejected'
    if (-not $first.WaitForExit(20000)) { $first.Kill(); throw 'First bounded supervisor did not exit' }
    $first.Refresh()
    if ($null -ne $first.ExitCode -and $first.ExitCode -ne 0) { throw ('First supervisor failed: ' + [IO.File]::ReadAllText((Join-Path $tempDirectory 'first.err'))) }
    if (-not [string]::IsNullOrWhiteSpace([IO.File]::ReadAllText((Join-Path $tempDirectory 'first.err')))) { throw 'First supervisor wrote unexpected errors' }
    $log = @(Get-ChildItem -LiteralPath $tempDirectory -Filter 'supervisor-*.jsonl')[0]
    $rows = @([IO.File]::ReadAllLines($log.FullName) | ForEach-Object { $_ | ConvertFrom-Json })
    if ($rows.Count -ne 2 -or @($rows | Where-Object {$_.status -ne 'healthy'}).Count -ne 0) { throw 'Expected two successful synthetic checks' }
    $checks += 'bounded_monitor_logs_each_check'
    if ($rows[0].hold_pid -ne $rows[1].hold_pid -or $rows[0].hold_linux_pid -ne $rows[1].hold_linux_pid) { throw 'Hold identity changed between checks' }
    Assert-HoldStopped $rows[0]
    $checks += 'hold_persists_between_checks_and_exits_on_eof'
    $delayedFixture = @'
import json
from pathlib import Path
counter = Path(__file__).with_name("counter.txt")
count = int(counter.read_text()) + 1 if counter.exists() else 1
counter.write_text(str(count))
print(json.dumps({"schema_version":"test_only","user":"user","uid":1000,"root":"/home/user/javis","root_owner_uid":1000,"lifecycle_ready":count >= 3}))
'@
    $delayed = Invoke-BoundedMonitor 'delayed' $delayedFixture
    if ($delayed.ExitCode -ne 0 -or @($delayed.Rows | Where-Object {$_.status -eq 'starting'}).Count -ne 2 -or @($delayed.Rows | Where-Object {$_.status -eq 'healthy'}).Count -ne 1) { throw 'Delayed health did not recover within bounded startup grace' }
    Assert-HoldStopped $delayed.Rows[-1]
    $checks += 'startup_retries_delayed_health'
    $failedFixture = $fixtureText.Replace('True','False')
    $failed = Invoke-BoundedMonitor 'failed' $failedFixture 3
    if ($failed.ExitCode -eq 0 -or $failed.Rows[-1].status -ne 'failed') { throw 'Unhealthy startup did not exit with a logged failure' }
    Assert-HoldStopped $failed.Rows[-1]
    $checks += 'startup_timeout_fails_and_releases_hold'
    $abruptDirectory = Join-Path $tempDirectory 'abrupt'
    [void][IO.Directory]::CreateDirectory($abruptDirectory)
    $abruptArgs = @('-NoProfile','-NonInteractive','-ExecutionPolicy','Bypass','-File',('"' + $runner + '"'),'-Action','Monitor','-LinuxScript',('"' + $linuxFixture + '"'),'-LogDirectory',('"' + $abruptDirectory + '"'),'-IntervalSeconds','30','-MaxChecks','0')
    $abrupt = Start-Process -FilePath $powershell -ArgumentList $abruptArgs -WindowStyle Hidden -PassThru -RedirectStandardOutput (Join-Path $abruptDirectory 'run.out') -RedirectStandardError (Join-Path $abruptDirectory 'run.err')
    try {
        $abruptRows = @()
        for ($i=0; $i -lt 30; $i++) {
            $abruptLog = @(Get-ChildItem -LiteralPath $abruptDirectory -Filter 'supervisor-*.jsonl')
            if ($abruptLog.Count) { $abruptRows = @([IO.File]::ReadAllLines($abruptLog[0].FullName) | ForEach-Object { $_ | ConvertFrom-Json }); break }
            Start-Sleep -Milliseconds 200
        }
        if (-not $abruptRows.Count -or $abruptRows[-1].status -ne 'healthy') { throw 'Abrupt-exit test did not reach healthy monitoring' }
        $abrupt.Kill()
        [void]$abrupt.WaitForExit(5000)
        Assert-HoldStopped $abruptRows[-1]
        $checks += 'parent_termination_closes_hold_stdin'
    } finally { if (-not $abrupt.HasExited) { $abrupt.Kill(); [void]$abrupt.WaitForExit(5000) } }
    @{ passed = $checks; count = $checks.Count; scope = 'synthetic health responses plus actual isolated WSL stdin hold processes; no services, scheduled tasks or system settings changed' } | ConvertTo-Json
} finally {
    # Only remove this test's verified UUID directory under its script workspace.
    $resolvedTest = [IO.Path]::GetFullPath($tempDirectory)
    $resolvedParent = [IO.Path]::GetFullPath($PSScriptRoot).TrimEnd('\') + '\'
    if ($resolvedTest.StartsWith($resolvedParent,[StringComparison]::OrdinalIgnoreCase) -and (Split-Path -Leaf $resolvedTest) -match '^lifecycle-test-[a-f0-9]{32}$') {
        Remove-Item -LiteralPath $resolvedTest -Recurse -Force
    }
}
