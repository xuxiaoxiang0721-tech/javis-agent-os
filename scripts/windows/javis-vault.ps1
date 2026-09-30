param([ValidateSet('Status','CreatePersonal','CreateProgram','OpenPersonal','OpenProgram','Backup','GraphCheck','GraphSync')][string]$Action = 'Status')
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
Import-Module (Join-Path $PSScriptRoot 'JavisVault.psm1') -Force
$paths = Get-JavisVaultPaths
$master = $null
$credential = $null
$payload = $null
$auditAction = $null
$failureStatus = 'failed'
try {
    if (-not (Test-Path -LiteralPath $paths.Cli -PathType Leaf)) { throw 'KeePassXC is not installed at the configured location.' }
    switch ($Action) {
        'Status' {
            [pscustomobject]@{ personal_initialized = [IO.File]::Exists($paths.Personal); program_initialized = [IO.File]::Exists($paths.Program); program_unlock = 'manual_each_use'; automatic_unlock = $false; current_keys_migrated = $false } | ConvertTo-Json
        }
        { $_ -in 'CreatePersonal','CreateProgram' } {
            Assert-VaultInteractive
            $database = if ($Action -eq 'CreatePersonal') { $paths.Personal } else { $paths.Program }
            if (Test-Path -LiteralPath $database) { throw 'Database already exists. Open it instead; no overwrite performed.' }
            Write-Host 'Set your OWN master password locally. Use a different master password for each database.'
            & $paths.Cli db-create -p -t 2000 $database
            if ($LASTEXITCODE -ne 0) { throw 'Database creation did not complete.' }
            Write-Host ('Database created: ' + $database)
        }
        { $_ -in 'OpenPersonal','OpenProgram' } {
            $database = if ($Action -eq 'OpenPersonal') { $paths.Personal } else { $paths.Program }
            if (-not [IO.File]::Exists($database)) { throw 'Create the database with the matching Create launcher first.' }
            Start-Process -FilePath $paths.Gui -ArgumentList ('"' + $database + '"') | Out-Null
        }
        'Backup' {
            $auditAction = 'backup'
            $receipt = Backup-JavisVault -Root $paths.Root
            Write-VaultAudit -Path $paths.Audit -Action $auditAction -Status $receipt.status
            $receipt | ConvertTo-Json
        }
        { $_ -in 'GraphCheck','GraphSync' } {
            $auditAction = if ($Action -eq 'GraphCheck') { 'graph-check' } else { 'graph-sync' }
            if (-not [IO.File]::Exists($paths.Program)) {
                $failureStatus = 'not_initialized'
                throw 'Program vault is not initialized. No existing service keys have been migrated.'
            }
            $failureStatus = 'waiting_unlock'
            Assert-VaultInteractive
            $failureStatus = 'failed'
            Write-Host ('Unlock for one action: ' + $auditAction + '; entry: program.neo4j; target: local Neo4j.')
            $master = Read-Host 'Program vault master password (hidden; never enter it in chat)' -AsSecureString
            $credential = Read-JavisProgramCredential -Cli $paths.Cli -Database $paths.Program -MasterPassword $master
            $master.Dispose(); $master = $null
            $payload = $credential | ConvertTo-Json -Compress
            $credential = $null
            $run = Invoke-VaultProcess -Executable (Join-Path $env:WINDIR 'System32\wsl.exe') -Arguments @('-d','Ubuntu','-u','user','--','/home/user/javis/tools/graphiti/.venv/bin/python','-B','/home/user/javis/scripts/vault-graph.py',$auditAction) -InputText ($payload + "`n") -TimeoutSeconds 55
            $payload = $null
            # Only an allowlisted outcome crosses back to the console.
            $outcome = $run.Output | ConvertFrom-Json
            if ($run.ExitCode -ne 0 -or $outcome.schema_version -isnot [int] -or $outcome.schema_version -ne 1 -or $outcome.action -cne $auditAction -or $outcome.status -cne 'ok') { throw 'Program action failed. Details suppressed to protect credentials.' }
            Write-VaultAudit -Path $paths.Audit -Action $auditAction -Status 'ok'
            [pscustomobject]@{ action = $auditAction; status = 'ok'; credential_ref = 'program.neo4j'; unlock_reused = $false } | ConvertTo-Json
        }
    }
} catch {
    if ($auditAction) {
        try { Write-VaultAudit -Path $paths.Audit -Action $auditAction -Status $failureStatus } catch { }
        if ($failureStatus -eq 'not_initialized') { Write-Host 'Create the Program vault and add the Javis/Neo4j entry locally first. Existing service keys have not been migrated.' }
        else { Write-Host 'Action failed or manual unlock is required. No secret values are included in this message.' }
    } else { Write-Host $_.Exception.Message }
    exit 1
} finally {
    if ($master) { $master.Dispose() }
    $credential = $null; $payload = $null; $run = $null
}
