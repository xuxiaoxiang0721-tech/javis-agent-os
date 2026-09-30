param([string]$ModulePath = '')
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
if ([string]::IsNullOrEmpty($ModulePath)) {
    foreach ($candidate in @((Join-Path $PSScriptRoot '..\windows\JavisVault.psm1'), (Join-Path $PSScriptRoot '..\..\windows\JavisVault.psm1'))) {
        if ([IO.File]::Exists($candidate)) { $ModulePath = $candidate; break }
    }
    if ([string]::IsNullOrEmpty($ModulePath)) { throw 'test_module_not_found' }
}
Import-Module $ModulePath -Force
$cli = 'C:\Users\user\AppData\Local\Programs\KeePassXC-2.7.12\KeePassXC-2.7.12-Win64\keepassxc-cli.exe'
$fixture = Join-Path $PSScriptRoot ('fixtures-' + [Guid]::NewGuid().ToString('N'))
[void][IO.Directory]::CreateDirectory($fixture)
foreach ($dir in @('personal','program','control')) { [void][IO.Directory]::CreateDirectory((Join-Path $fixture $dir)) }
$personal = Join-Path $fixture 'personal\personal.kdbx'
$program = Join-Path $fixture 'program\program.kdbx'
$personalMaster = 'Personal-' + [Guid]::NewGuid().ToString('N') + '!'
$programMaster = 'Program-' + [Guid]::NewGuid().ToString('N') + '!'
$personalSecret = 'PersonalSecret-' + [Guid]::NewGuid().ToString('N')
$programSecret = 'ProgramSecret-' + [Guid]::NewGuid().ToString('N')
$decoySecret = 'OtherSecret-' + [Guid]::NewGuid().ToString('N')
$unicodeMaster = 'UnicodeMaster-' + [char]0x4E3B + [char]0x5BC6 + [char]0x00E9 + '-' + [Guid]::NewGuid().ToString('N')
$unicodeSecret = 'UnicodeSecret-' + [char]0x94A5 + [char]0x5319 + [char]0x00F6 + '-' + [Guid]::NewGuid().ToString('N')
$results = [Collections.Generic.List[object]]::new()
function Check([string]$Name, [scriptblock]$Code) {
    try { & $Code; $results.Add([pscustomobject]@{ name = $Name; passed = $true }) }
    catch { $results.Add([pscustomobject]@{ name = $Name; passed = $false; error = 'assertion_or_operation_failed_details_suppressed' }) }
}
function Assert-True([bool]$Condition) { if (-not $Condition) { throw 'assertion_failed' } }
function Cli-Ok([string[]]$ArgsList, [string]$StdinText) {
    $r = Invoke-VaultProcess -Executable $cli -Arguments $ArgsList -InputText $StdinText -TimeoutSeconds 15
    if ($r.ExitCode -ne 0) { throw 'fixture_cli_failed' }
    $r = $null
}
function Secure([string]$Value) { ConvertTo-SecureString -String $Value -AsPlainText -Force }
try {
    Check 'separate_databases_created_with_distinct_master_passwords' {
        Assert-True ($personalMaster -cne $programMaster)
        Cli-Ok @('db-create','-q','-p','-t','100',$personal) ($personalMaster + "`n" + $personalMaster + "`n")
        Cli-Ok @('db-create','-q','-p','-t','100',$program) ($programMaster + "`n" + $programMaster + "`n")
        Assert-True ([IO.File]::Exists($personal) -and [IO.File]::Exists($program))
    }
    Check 'actual_group_and_entry_creation_using_stdin_secrets' {
        Cli-Ok @('mkdir','-q',$personal,'Personal') ($personalMaster + "`n")
        Cli-Ok @('add','-q','-u','fixture-personal','-p',$personal,'Personal/Synthetic') ($personalMaster + "`n" + $personalSecret + "`n")
        Cli-Ok @('mkdir','-q',$program,'Javis') ($programMaster + "`n")
        Cli-Ok @('add','-q','-u','fixture-program','-p',$program,'Javis/Neo4j') ($programMaster + "`n" + $programSecret + "`n")
        Cli-Ok @('add','-q','-u','fixture-decoy','-p',$program,'Javis/Other') ($programMaster + "`n" + $decoySecret + "`n")
    }
    Check 'program_read_returns_fixed_neo4j_entry_only' {
        $master = Secure $programMaster
        try {
            $credential = Read-JavisProgramCredential -Cli $cli -Database $program -MasterPassword $master
            Assert-True ($credential.username -ceq 'fixture-program')
            Assert-True ($credential.password -ceq $programSecret)
            Assert-True ($credential.password -cne $decoySecret)
            Assert-True (-not (Get-Command Read-JavisProgramCredential).Parameters.ContainsKey('Entry'))
        } finally { $master.Dispose(); $credential = $null }
    }
    Check 'personal_master_cannot_unlock_program_database' {
        $master = Secure $personalMaster; $refused = $false
        try { $null = Read-JavisProgramCredential -Cli $cli -Database $program -MasterPassword $master }
        catch { $refused = $_.Exception.Message -eq 'unlock_failed_or_program_entry_unavailable' }
        finally { $master.Dispose() }
        Assert-True $refused
    }
    Check 'program_master_cannot_unlock_personal_database' {
        $r = Invoke-VaultProcess -Executable $cli -Arguments @('show','-q','-s','-a','Password',$personal,'Personal/Synthetic') -InputText ($programMaster + "`n") -TimeoutSeconds 15
        Assert-True ($r.ExitCode -ne 0)
        Assert-True (-not $r.Output.Contains($personalSecret))
        $r = $null
    }
    Check 'personal_entry_not_accepted_as_program_credential' {
        $master = Secure $personalMaster; $refused = $false
        try { $null = Read-JavisProgramCredential -Cli $cli -Database $personal -MasterPassword $master }
        catch { $refused = $_.Exception.Message -eq 'unlock_failed_or_program_entry_unavailable' }
        finally { $master.Dispose() }
        Assert-True $refused
    }
    Check 'noninteractive_unlock_refused' {
        Assert-True ([Console]::IsInputRedirected)
        $refused = $false
        try { Assert-VaultInteractive } catch { $refused = $_.Exception.Message.StartsWith('waiting_unlock:') }
        Assert-True $refused
    }
    Check 'non_ascii_master_and_entry_password_round_trip_without_corruption' {
        $database = Join-Path $fixture 'unicode.kdbx'
        Cli-Ok @('db-create','-q','-p','-t','100',$database) ($unicodeMaster + "`n" + $unicodeMaster + "`n")
        Cli-Ok @('mkdir','-q',$database,'Javis') ($unicodeMaster + "`n")
        Cli-Ok @('add','-q','-u','fixture-unicode','-p',$database,'Javis/Neo4j') ($unicodeMaster + "`n" + $unicodeSecret + "`n")
        $master = Secure $unicodeMaster
        try {
            $credential = Read-JavisProgramCredential -Cli $cli -Database $database -MasterPassword $master
            Assert-True ($credential.username -ceq 'fixture-unicode' -and $credential.password -ceq $unicodeSecret)
        } finally { $master.Dispose(); $credential = $null }
    }
    Check 'username_over_128_characters_refused' {
        $database = Join-Path $fixture 'invalid-username.kdbx'
        Cli-Ok @('db-create','-q','-p','-t','100',$database) ($programMaster + "`n" + $programMaster + "`n")
        Cli-Ok @('mkdir','-q',$database,'Javis') ($programMaster + "`n")
        Cli-Ok @('add','-q','-u',('a' * 129),'-p',$database,'Javis/Neo4j') ($programMaster + "`n" + $programSecret + "`n")
        $master = Secure $programMaster; $refused = $false
        try { $null = Read-JavisProgramCredential -Cli $cli -Database $database -MasterPassword $master }
        catch { $refused = $_.Exception.Message -eq 'unlock_failed_or_program_entry_unavailable' }
        finally { $master.Dispose() }
        Assert-True $refused
    }
    Check 'backup_copies_both_encrypted_databases_and_manifest' {
        $script:backup = Backup-JavisVault -Root $fixture
        Assert-True ($backup.status -eq 'ok' -and $backup.encrypted_files -eq 2 -and -not $backup.off_machine_backup_verified)
        $manifest = Get-Content -LiteralPath (Join-Path $backup.backup_directory 'manifest.json') -Raw | ConvertFrom-Json
        Assert-True ($manifest.storage -eq 'same_machine' -and $manifest.files.Count -eq 2)
        foreach ($kind in @('personal','program')) {
            $a = Get-FileHash -LiteralPath (Join-Path $fixture ($kind + '\' + $kind + '.kdbx')) -Algorithm SHA256
            $b = Get-FileHash -LiteralPath (Join-Path $backup.backup_directory ($kind + '.kdbx')) -Algorithm SHA256
            Assert-True ($a.Hash -ceq $b.Hash)
        }
    }
    Check 'restored_program_copy_decrypts_and_retains_exact_credential' {
        $master = Secure $programMaster
        try {
            $credential = Read-JavisProgramCredential -Cli $cli -Database (Join-Path $backup.backup_directory 'program.kdbx') -MasterPassword $master
            Assert-True ($credential.username -ceq 'fixture-program' -and $credential.password -ceq $programSecret)
        } finally { $master.Dispose(); $credential = $null }
    }
    Check 'restored_personal_copy_decrypts_and_retains_exact_entry' {
        $r = Invoke-VaultProcess -Executable $cli -Arguments @('show','-q','-s','-a','Password',(Join-Path $backup.backup_directory 'personal.kdbx'),'Personal/Synthetic') -InputText ($personalMaster + "`n") -TimeoutSeconds 15
        Assert-True ($r.ExitCode -eq 0 -and $r.Output.TrimEnd([char[]]"`r`n") -ceq $personalSecret)
        $r = $null
    }
    Check 'plaintext_disguised_as_kdbx_refused_without_success_manifest' {
        $invalidRoot = Join-Path $fixture 'invalid-backup'
        [void][IO.Directory]::CreateDirectory((Join-Path $invalidRoot 'program'))
        [IO.File]::WriteAllText((Join-Path $invalidRoot 'program\program.kdbx'),'SYNTHETIC_NOT_A_DATABASE_NO_SECRET')
        $refused = $false
        try { $null = Backup-JavisVault -Root $invalidRoot }
        catch { $refused = $_.Exception.Message -eq 'invalid_kdbx_header_no_backup_created' }
        Assert-True $refused
        Assert-True (@(Get-ChildItem -LiteralPath $invalidRoot -Recurse -File -Filter 'manifest.json').Count -eq 0)
        Assert-True (-not [IO.Directory]::Exists((Join-Path $invalidRoot 'backups')))
    }
    Check 'audit_records_reference_and_status_without_values' {
        $auditPath = Join-Path $fixture 'control\access.jsonl'
        Write-VaultAudit -Path $auditPath -Action 'graph-check' -Status 'ok'
        Write-VaultAudit -Path $auditPath -Action 'backup' -Status 'ok'
        $audit = @(Get-Content -LiteralPath $auditPath | ForEach-Object { $_ | ConvertFrom-Json })
        Assert-True ($audit.Count -eq 2 -and $audit[0].credential_ref -eq 'program.neo4j')
        Assert-True (-not $audit[1].PSObject.Properties.Name.Contains('credential_ref'))
    }
    Check 'timeout_refuses_and_terminates_direct_child' {
        $pidFile = Join-Path $fixture 'timeout-child.pid'
        $childFile = Join-Path $fixture 'timeout-child.ps1'
        $childScript = '[IO.File]::WriteAllText(''' + $pidFile.Replace("'", "''") + ''', [string]$PID); Start-Sleep -Seconds 15'
        [IO.File]::WriteAllText($childFile, $childScript)
        $timedOut = $false; $timer = [Diagnostics.Stopwatch]::StartNew()
        try { $null = Invoke-VaultProcess -Executable (Join-Path $env:WINDIR 'System32\WindowsPowerShell\v1.0\powershell.exe') -Arguments @('-NoProfile','-NonInteractive','-File',$childFile) -InputText '' -TimeoutSeconds 2 }
        catch { $timedOut = $_.Exception.Message -eq 'vault_process_failed_or_timed_out' }
        $timer.Stop()
        Assert-True ($timedOut -and $timer.Elapsed.TotalSeconds -lt 8)
        Assert-True ([IO.File]::Exists($pidFile))
        $childPid = [int][IO.File]::ReadAllText($pidFile)
        Assert-True ($null -eq (Get-Process -Id $childPid -ErrorAction SilentlyContinue))
    }
    Check 'blocked_large_stdin_is_bounded_and_child_terminated' {
        $pidFile = Join-Path $fixture 'blocked-input-child.pid'
        $childFile = Join-Path $fixture 'blocked-input-child.ps1'
        $childScript = '[IO.File]::WriteAllText(''' + $pidFile.Replace("'", "''") + ''', [string]$PID); Start-Sleep -Seconds 15'
        [IO.File]::WriteAllText($childFile, $childScript)
        $timedOut = $false; $timer = [Diagnostics.Stopwatch]::StartNew()
        $largeInput = 'SYNTHETIC-BLOCKED-INPUT-' * 50000
        try { $null = Invoke-VaultProcess -Executable (Join-Path $env:WINDIR 'System32\WindowsPowerShell\v1.0\powershell.exe') -Arguments @('-NoProfile','-NonInteractive','-File',$childFile) -InputText $largeInput -TimeoutSeconds 1 }
        catch { $timedOut = $_.Exception.Message -eq 'vault_process_failed_or_timed_out' }
        finally { $largeInput = $null }
        $timer.Stop()
        Assert-True ($timedOut -and $timer.Elapsed.TotalSeconds -lt 8)
        Assert-True ([IO.File]::Exists($pidFile))
        $childPid = [int][IO.File]::ReadAllText($pidFile)
        Assert-True ($null -eq (Get-Process -Id $childPid -ErrorAction SilentlyContinue))
    }
    Check 'no_plaintext_generated_secrets_in_any_fixture_artifact' {
        $secrets = @($personalMaster,$programMaster,$personalSecret,$programSecret,$decoySecret,$unicodeMaster,$unicodeSecret)
        foreach ($f in Get-ChildItem -LiteralPath $fixture -Recurse -File) {
            $bytes = [IO.File]::ReadAllBytes($f.FullName)
            $utf8 = [Text.Encoding]::UTF8.GetString($bytes)
            $utf16 = [Text.Encoding]::Unicode.GetString($bytes)
            foreach ($secret in $secrets) { Assert-True (-not $utf8.Contains($secret) -and -not $utf16.Contains($secret)) }
            [Array]::Clear($bytes,0,$bytes.Length); $utf8 = $null; $utf16 = $null
        }
        $secrets = $null
    }
} finally {
    $personalMaster = $null; $programMaster = $null; $personalSecret = $null; $programSecret = $null; $decoySecret = $null
    $unicodeMaster = $null; $unicodeSecret = $null
}
$failed = @($results | Where-Object { -not $_.passed }).Count
$report = [ordered]@{ schema_version = 1; synthetic_only = $true; tested_module = (Get-FileHash -LiteralPath $ModulePath -Algorithm SHA256).Hash; fixture_directory = $fixture; passed = ($failed -eq 0); total = $results.Count; failed = $failed; tests = @($results.ToArray()) }
$json = $report | ConvertTo-Json -Depth 6
[IO.File]::WriteAllText((Join-Path $PSScriptRoot 'windows-test-results.json'),$json,[Text.UTF8Encoding]::new($false))
$json
if ($failed -ne 0) { exit 1 }
