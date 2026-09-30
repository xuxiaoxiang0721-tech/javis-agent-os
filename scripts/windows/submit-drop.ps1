#Requires -Version 5.1
# Inactive reference template: use the Linux submit-drop.py producer or approved file operations.
<#
.SYNOPSIS
Atomically submit original UTF-8 bytes to an authorized Cards/Invest queue.
.DESCRIPTION
Publishing a .ready directory authorizes the existing consumer to execute work.
This helper does not grant approval, bypass review, or execute WSL itself.
BasePath is an optional isolated queue root for controlled tests.
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory=$true)][ValidateSet('cards-master','invest')][string]$Role,
    [Parameter(Mandatory=$true)][string]$MessageFile,
    [Parameter(Mandatory=$true)][string]$SubmissionId,
    [string]$MessageId,
    [string]$BasePath = 'C:\Users\user\javis'
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
[Console]::OutputEncoding = [Text.UTF8Encoding]::new($false)

function Assert-PlainPath([string]$Path, [bool]$RequireFile = $false) {
    $item = Get-Item -LiteralPath $Path -Force -ErrorAction Stop
    if ($item.PSProvider.Name -ne 'FileSystem') { throw 'Only filesystem paths are supported.' }
    if ($RequireFile -and -not ($item -is [IO.FileInfo])) { throw 'MessageFile must be a regular file.' }
    $cursor = $item
    while ($null -ne $cursor) {
        if (($cursor.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
            throw 'Links and reparse-point paths are not accepted.'
        }
        $linkType = $cursor.PSObject.Properties['LinkType']
        if ($null -ne $linkType -and -not [string]::IsNullOrEmpty([string]$linkType.Value)) {
            throw 'Linked files and directories are not accepted.'
        }
        if ($cursor -is [IO.FileInfo]) { $cursor = $cursor.Directory }
        else { $cursor = $cursor.Parent }
    }
    return $item.FullName
}

function Ensure-PlainDirectory([string]$Path) {
    $ancestor = $Path
    while (-not (Test-Path -LiteralPath $ancestor)) {
        $parent = [IO.Directory]::GetParent($ancestor)
        if ($null -eq $parent) { throw 'Queue path has no existing filesystem parent.' }
        $ancestor = $parent.FullName
    }
    $null = Assert-PlainPath $ancestor
    $null = [IO.Directory]::CreateDirectory($Path)
    $verified = Assert-PlainPath $Path
    if (-not (Get-Item -LiteralPath $verified -Force).PSIsContainer) { throw 'Queue path must be a directory.' }
    return $verified
}

function Write-NewBytes([string]$Path, [byte[]]$Bytes) {
    $stream = [IO.File]::Open($Path, [IO.FileMode]::CreateNew, [IO.FileAccess]::Write, [IO.FileShare]::None)
    try { $stream.Write($Bytes, 0, $Bytes.Length); $stream.Flush($true) }
    finally { $stream.Dispose() }
}

try {
    if ($SubmissionId -cnotmatch '\A[A-Za-z0-9_-]{1,80}\z') {
        throw 'SubmissionId must contain 1 to 80 ASCII letters, digits, underscores or hyphens.'
    }
    $strictUtf8 = [Text.UTF8Encoding]::new($false, $true)
    $hasMessageId = $PSBoundParameters.ContainsKey('MessageId')
    if ($hasMessageId) {
        if ([string]::IsNullOrWhiteSpace($MessageId)) { throw 'MessageId must be a real non-empty upstream ID, or omitted.' }
        try { $null = $strictUtf8.GetByteCount($MessageId) }
        catch { throw 'MessageId contains invalid Unicode.' }
        $codePoints = 0
        for ($i = 0; $i -lt $MessageId.Length; $i++) {
            $category = [Globalization.CharUnicodeInfo]::GetUnicodeCategory($MessageId, $i)
            if ($category -in @([Globalization.UnicodeCategory]::Control,
                               [Globalization.UnicodeCategory]::Format,
                               [Globalization.UnicodeCategory]::Surrogate,
                               [Globalization.UnicodeCategory]::LineSeparator,
                               [Globalization.UnicodeCategory]::ParagraphSeparator,
                               [Globalization.UnicodeCategory]::OtherNotAssigned,
                               [Globalization.UnicodeCategory]::PrivateUse) -or
                ($category -eq [Globalization.UnicodeCategory]::SpaceSeparator -and [int][char]$MessageId[$i] -ne 32)) {
                throw 'MessageId must not contain control or non-printing characters.'
            }
            $codePoints++
            if ([char]::IsHighSurrogate($MessageId[$i])) { $i++ }
        }
        if ($codePoints -gt 160) { throw 'MessageId must not exceed 160 Unicode characters.' }
    }
    $source = Assert-PlainPath $MessageFile $true
    $sourceStream = [IO.File]::Open($source, [IO.FileMode]::Open, [IO.FileAccess]::Read, [IO.FileShare]::Read)
    try {
        if ($sourceStream.Length -gt 1048576) { throw 'MessageFile exceeds 1 MiB.' }
        $bytes = [byte[]]::new([int]$sourceStream.Length)
        $offset = 0
        while ($offset -lt $bytes.Length) {
            $count = $sourceStream.Read($bytes, $offset, $bytes.Length - $offset)
            if ($count -eq 0) { throw 'MessageFile changed or ended while being read.' }
            $offset += $count
        }
        if ($sourceStream.ReadByte() -ne -1) { throw 'MessageFile changed while being read.' }
    } finally { $sourceStream.Dispose() }
    try { $decodedMessage = $strictUtf8.GetString($bytes) }
    catch { throw 'MessageFile is not valid strict UTF-8.' }
    if ($decodedMessage.IndexOf([char]0) -ge 0) { throw 'MessageFile must not contain NUL.' }
    if ([string]::IsNullOrWhiteSpace($decodedMessage.TrimStart([char]0xFEFF))) { throw 'MessageFile must contain non-whitespace text.' }

    if (-not [IO.Path]::IsPathRooted($BasePath) -or $BasePath.StartsWith('\\')) {
        throw 'BasePath must be an absolute local directory.'
    }
    $base = [IO.Path]::GetFullPath($BasePath).TrimEnd('\','/')
    if ($base.Length -le 3) { throw 'BasePath cannot be a drive root.' }
    $queueName = if ($Role -eq 'cards-master') { 'cards-drop' } else { 'invest-drop' }
    $roleRoot = Join-Path $base $queueName
    $inbox = Ensure-PlainDirectory (Join-Path $roleRoot 'inbox')
    $deliveryId = [Guid]::NewGuid().ToString('N')
    $temporary = Join-Path $inbox ($deliveryId + '.tmp')
    $ready = Join-Path $inbox ($deliveryId + '.ready')
    $null = New-Item -ItemType Directory -Path $temporary -ErrorAction Stop
    $null = Assert-PlainPath $temporary
    Write-NewBytes (Join-Path $temporary 'message.txt') $bytes
    $request = [ordered]@{schema_version=1; submission_id=$SubmissionId}
    if ($hasMessageId) { $request['message_id'] = $MessageId }
    $requestJson = ConvertTo-Json -InputObject $request -Compress
    Write-NewBytes (Join-Path $temporary 'request.json') $strictUtf8.GetBytes($requestJson)
    $null = Assert-PlainPath $inbox
    [IO.Directory]::Move($temporary, $ready)

    $sha = [Security.Cryptography.SHA256]::Create()
    try { $inputHash = [BitConverter]::ToString($sha.ComputeHash($bytes)).Replace('-','').ToLowerInvariant() }
    finally { $sha.Dispose() }
    [ordered]@{
        schema_version = 1
        submission_status = 'queued'
        role_id = $Role
        delivery_id = $deliveryId
        submission_id = $SubmissionId
        message_id = $(if ($hasMessageId) { $MessageId } else { $null })
        input_sha256 = $inputHash
        ready_path = $ready
        receipt_locations = [ordered]@{
            done = Join-Path (Join-Path $roleRoot 'done') ($deliveryId + '\receipt.json')
            fail = Join-Path (Join-Path $roleRoot 'fail') ($deliveryId + '\receipt.json')
        }
    } | ConvertTo-Json -Depth 4 -Compress
    exit 0
} catch {
    # Incomplete .tmp directories are deliberately left uncommitted and are never consumed.
    [Console]::Error.WriteLine($_.Exception.Message)
    exit 1
}
