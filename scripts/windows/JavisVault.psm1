Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

function Get-JavisVaultPaths {
    $root = Join-Path $env:USERPROFILE 'Javis-Vault'
    $app = Join-Path $env:LOCALAPPDATA 'Programs\KeePassXC-2.7.12\KeePassXC-2.7.12-Win64'
    [pscustomobject]@{
        Root = $root
        Personal = Join-Path $root 'personal\personal.kdbx'
        Program = Join-Path $root 'program\program.kdbx'
        Backups = Join-Path $root 'backups'
        Audit = Join-Path $root 'control\access.jsonl'
        Cli = Join-Path $app 'keepassxc-cli.exe'
        Gui = Join-Path $app 'KeePassXC.exe'
    }
}

function Assert-VaultInteractive {
    if ($Host.Name -ne 'ConsoleHost' -or [Console]::IsInputRedirected) {
        throw 'waiting_unlock: run the launcher yourself in a local console.'
    }
}

function ConvertTo-NativeArgument([string]$Value) {
    # Windows CommandLineToArgvW quoting; secret values are never arguments.
    '"' + [regex]::Replace([regex]::Replace($Value, '(\\*)"', '$1$1\"'), '(\\+)$', '$1$1') + '"'
}

function Invoke-VaultProcess {
    param([string]$Executable, [string[]]$Arguments, [string]$InputText, [int]$TimeoutSeconds = 30)
    $start = New-Object Diagnostics.ProcessStartInfo
    $start.FileName = $Executable
    $start.Arguments = (($Arguments | ForEach-Object { ConvertTo-NativeArgument $_ }) -join ' ')
    $start.UseShellExecute = $false
    $start.CreateNoWindow = $true
    $start.RedirectStandardInput = $true
    $start.RedirectStandardOutput = $true
    $start.RedirectStandardError = $true
    $start.StandardOutputEncoding = New-Object Text.UTF8Encoding($false)
    $start.StandardErrorEncoding = New-Object Text.UTF8Encoding($false)
    $process = New-Object Diagnostics.Process
    $process.StartInfo = $start
    $bytes = $null
    $started = $false
    $watch = [Diagnostics.Stopwatch]::StartNew()
    try {
        if (-not $process.Start()) { throw 'process_failed' }
        $started = $true
        $stdout = $process.StandardOutput.ReadToEndAsync()
        $stderr = $process.StandardError.ReadToEndAsync()
        $bytes = [Text.Encoding]::UTF8.GetBytes($InputText)
        $write = $process.StandardInput.BaseStream.WriteAsync($bytes, 0, $bytes.Length)
        if (-not $write.Wait($TimeoutSeconds * 1000)) { throw 'process_input_timeout' }
        $process.StandardInput.Close()
        $remaining = [Math]::Max(1, $TimeoutSeconds * 1000 - [int]$watch.ElapsedMilliseconds)
        if (-not $process.WaitForExit($remaining)) { throw 'process_timeout' }
        # Never expose stderr; password manager / driver failures may echo input.
        if (-not $stdout.Wait(3000) -or -not $stderr.Wait(3000)) { throw 'process_output_timeout' }
        [void]$stderr.GetAwaiter().GetResult()
        [pscustomobject]@{ ExitCode = $process.ExitCode; Output = $stdout.GetAwaiter().GetResult() }
    } catch {
        throw 'vault_process_failed_or_timed_out'
    } finally {
        if ($started) {
            try { if (-not $process.HasExited) { $process.Kill(); [void]$process.WaitForExit(3000) } } catch { }
        }
        if ($bytes) { [Array]::Clear($bytes, 0, $bytes.Length) }
        $InputText = $null
        $process.Dispose()
    }
}

function Read-JavisProgramCredential {
    param([string]$Cli, [string]$Database, [Security.SecureString]$MasterPassword)
    $ptr = [IntPtr]::Zero
    $plain = $null
    $result = $null
    try {
        $ptr = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($MasterPassword)
        $plain = [Runtime.InteropServices.Marshal]::PtrToStringBSTR($ptr)
        if ([string]::IsNullOrEmpty($plain) -or $plain -match '[\r\n\x00]') { throw 'invalid_unlock_input' }
        $result = Invoke-VaultProcess -Executable $Cli -Arguments @('show','-q','-s','-a','UserName','-a','Password',$Database,'Javis/Neo4j') -InputText ($plain + "`n")
        if ($result.ExitCode -ne 0) { throw 'unlock_or_entry_failed' }
        $lines = $result.Output.Replace("`r`n", "`n").Split([char]10)
        if ($lines.Length -ne 3 -or $lines[2] -ne '' -or [string]::IsNullOrEmpty($lines[0]) -or [string]::IsNullOrEmpty($lines[1])) { throw 'invalid_entry' }
        if ($lines[0].Length -gt 128 -or $lines[1].Length -gt 4096 -or $lines[0] -match '[\x00-\x1f]' -or $lines[1] -match '[\x00-\x1f]') { throw 'invalid_entry' }
        [pscustomobject]@{ schema_version = 1; username = $lines[0]; password = $lines[1] }
    } catch {
        throw 'unlock_failed_or_program_entry_unavailable'
    } finally {
        if ($ptr -ne [IntPtr]::Zero) { [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($ptr) }
        $plain = $null; $result = $null; $lines = $null
    }
}

function Write-VaultAudit {
    param([string]$Path, [ValidateSet('graph-check','graph-sync','backup')][string]$Action,
          [ValidateSet('ok','failed','waiting_unlock','not_initialized')][string]$Status)
    $record = [ordered]@{ timestamp = [DateTime]::UtcNow.ToString('o'); action = $Action; status = $Status }
    if ($Action -ne 'backup') { $record['credential_ref'] = 'program.neo4j' }
    [IO.File]::AppendAllText($Path, (($record | ConvertTo-Json -Compress) + "`n"), [Text.UTF8Encoding]::new($false))
}

function Backup-JavisVault {
    param([string]$Root)
    $rootPath = [IO.Path]::GetFullPath($Root)
    $destination = Join-Path $rootPath ('backups\' + [DateTime]::UtcNow.ToString('yyyyMMdd-HHmmss-fffffff') + '-' + [Guid]::NewGuid().ToString('N').Substring(0,8))
    $records = @()
    foreach ($kind in @('personal','program')) {
        $source = Join-Path $rootPath ($kind + '\' + $kind + '.kdbx')
        if (-not [IO.File]::Exists($source)) { continue }
        if (((Get-Item -LiteralPath $source).Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) { throw 'vault_link_refused' }
        $stream = [IO.File]::OpenRead($source)
        try {
            $header = New-Object byte[] 8
            if ($stream.Read($header, 0, 8) -ne 8 -or [BitConverter]::ToString($header) -ne '03-D9-A2-9A-67-FB-4B-B5') { throw 'invalid_kdbx_header_no_backup_created' }
        } finally { $stream.Dispose() }
        [void][IO.Directory]::CreateDirectory($destination)
        $target = Join-Path $destination ($kind + '.kdbx')
        $before = (Get-FileHash -LiteralPath $source -Algorithm SHA256).Hash
        [IO.File]::Copy($source, $target, $false)
        $copy = (Get-FileHash -LiteralPath $target -Algorithm SHA256).Hash
        $after = (Get-FileHash -LiteralPath $source -Algorithm SHA256).Hash
        if ($before -ne $copy -or $copy -ne $after) { throw 'vault_changed_during_backup_retry_after_save' }
        $records += [ordered]@{ kind = $kind; file = ($kind + '.kdbx'); sha256 = $copy; bytes = (Get-Item -LiteralPath $target).Length }
    }
    if ($records.Count -eq 0) { return [pscustomobject]@{ status = 'not_initialized'; encrypted_files = 0 } }
    $manifest = [ordered]@{ schema_version = 1; created_at = [DateTime]::UtcNow.ToString('o'); storage = 'same_machine'; off_machine_backup_verified = $false; files = $records }
    [IO.File]::WriteAllText((Join-Path $destination 'manifest.json'), ($manifest | ConvertTo-Json -Depth 5), [Text.UTF8Encoding]::new($false))
    [pscustomobject]@{ status = 'ok'; encrypted_files = $records.Count; backup_directory = $destination; off_machine_backup_verified = $false }
}

Export-ModuleMember -Function Get-JavisVaultPaths,Assert-VaultInteractive,Invoke-VaultProcess,Read-JavisProgramCredential,Write-VaultAudit,Backup-JavisVault
