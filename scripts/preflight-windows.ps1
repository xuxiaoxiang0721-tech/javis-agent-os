[CmdletBinding()]
param(
    [string]$Distro = 'Ubuntu',
    [string]$LinuxUser = 'user',
    [string]$LinuxRoot = '/home/user/javis',
    [string]$LinuxScript = '/home/user/javis/scripts/preflight-linux.py',
    [string]$OutputPath = ''
)
$ErrorActionPreference = 'Stop'
function Invoke-WslInventory([string[]]$Arguments) {
    $priorEncoding = [Console]::OutputEncoding
    try {
        [Console]::OutputEncoding = [System.Text.Encoding]::Unicode
        $lines = & wsl.exe @Arguments 2>&1
        $code = $LASTEXITCODE
        return @{ exit_code = $code; output = (($lines | ForEach-Object { $_.ToString() }) -join "`n").Replace([string][char]0, '') }
    } finally { [Console]::OutputEncoding = $priorEncoding }
}
$os = Get-CimInstance Win32_OperatingSystem
$computer = Get-CimInstance Win32_ComputerSystem
$cpu = Get-CimInstance Win32_Processor
$reg = Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion'
$wsl = @{ status = Invoke-WslInventory @('--status'); version = Invoke-WslInventory @('--version'); distributions = Invoke-WslInventory @('--list', '--verbose') }
$oldEncoding = [Console]::OutputEncoding
try {
    [Console]::OutputEncoding = [System.Text.UTF8Encoding]::new($false)
    $linuxText = & wsl.exe -d $Distro -u $LinuxUser -- python3 $LinuxScript --root $LinuxRoot 2>&1
    if ($LASTEXITCODE -ne 0) { throw "Linux preflight failed with exit code $LASTEXITCODE" }
    $linux = ($linuxText -join "`n") | ConvertFrom-Json
} finally { [Console]::OutputEncoding = $oldEncoding }
$networkConfig = @{}
$wslConfig = Join-Path $env:USERPROFILE '.wslconfig'
if (Test-Path -LiteralPath $wslConfig) {
    foreach ($line in [IO.File]::ReadAllLines($wslConfig)) {
        if ($line -match '^\s*(networkingMode|dnsTunneling|autoProxy|memory|processors|swap)\s*=\s*([^#;]+)') { $networkConfig[$Matches[1]] = $Matches[2].Trim() }
    }
}
$taskData = @(Get-ScheduledTask | Where-Object { $_.TaskName -like 'Javis*' } | ForEach-Object {
    $info = Get-ScheduledTaskInfo -TaskName $_.TaskName -TaskPath $_.TaskPath
    @{ name = $_.TaskName; state = [string]$_.State; user = $_.Principal.UserId; logon_type = [string]$_.Principal.LogonType;
       last_result = $info.LastTaskResult; last_run = $info.LastRunTime.ToString('o'); next_run = $info.NextRunTime.ToString('o') }
})
$toDeskService = Get-Service -Name 'ToDesk_Service' -ErrorAction SilentlyContinue
$toDeskFile = Get-Item -LiteralPath 'C:\Program Files\ToDesk\ToDesk.exe' -ErrorAction SilentlyContinue
$report = [ordered]@{
    schema_version = 'javis.environment.v1'; captured_at = [DateTimeOffset]::Now.ToString('o'); time_zone = (Get-TimeZone).Id
    windows = @{ machine = $env:COMPUTERNAME; current_user = [Security.Principal.WindowsIdentity]::GetCurrent().Name;
       interactive_user = $computer.UserName; caption = $os.Caption; version = $os.Version; display_version = $reg.DisplayVersion;
       build = $os.BuildNumber; architecture = $os.OSArchitecture; last_boot = $os.LastBootUpTime.ToString('o');
       cpu = @($cpu | ForEach-Object {$_.Name}); logical_processors = $computer.NumberOfLogicalProcessors;
       ram_bytes = $computer.TotalPhysicalMemory; hypervisor_present = $computer.HypervisorPresent;
       virtualization_firmware_reported = @($cpu | ForEach-Object {$_.VirtualizationFirmwareEnabled});
       virtualization_note = 'Running WSL2 and HypervisorPresent are direct evidence; firmware flags can be unavailable with a hypervisor active.';
       support = $(if ($os.BuildNumber -eq '22621' -and $reg.EditionID -eq 'Professional') { 'Windows 11 Pro 22H2 ended updates 2024-10-08' } else { 'Check Microsoft lifecycle for exact installed edition/version' }) }
    disks = @(Get-CimInstance Win32_LogicalDisk -Filter 'DriveType=3' | ForEach-Object { @{ device = $_.DeviceID; filesystem = $_.FileSystem; total_bytes = $_.Size; free_bytes = $_.FreeSpace } })
    wsl = $wsl; wsl_settings = $networkConfig; linux = $linux; scheduled_tasks = $taskData
    desktop = @{ todesk_installed = ($null -ne $toDeskFile); todesk_version = $(if ($toDeskFile) {$toDeskFile.VersionInfo.FileVersion} else {$null});
       todesk_process_count = @(Get-Process -Name 'ToDesk' -ErrorAction SilentlyContinue).Count;
       todesk_service = $(if ($toDeskService) {[string]$toDeskService.Status} else {'not_found'});
       human_takeover = 'not_tested'; ai_windows_desktop = 'not_implemented' }
    acceptance = @{ terminal_close = 'not_tested_this_round'; wsl_restart = 'not_tested_this_round'; windows_restart = 'not_tested';
       signed_out_start = 'not_tested'; power_policy_changed = $false; systemd_activated_this_round = $false }
}
$json = $report | ConvertTo-Json -Depth 10
if ($OutputPath) { [IO.File]::WriteAllText([IO.Path]::GetFullPath($OutputPath), $json + "`n", [Text.UTF8Encoding]::new($false)) }
$json
