<#
.SYNOPSIS
    Investigation queries for incident 01 - IAM role activity in CloudTrail.

.DESCRIPTION
    Reconstructs a single actor's activity from CloudTrail, the way an analyst
    would: start from the role assumption, pivot on the session identity, then
    separate what succeeded from what was denied.

    Writes JSON evidence into ./evidence/ for the write-up.

.PARAMETER SessionName
    The role session name to pivot on.

.PARAMETER StartUtc / EndUtc
    Investigation window in UTC, e.g. 2026-08-09T19:05:00Z
#>

[CmdletBinding()]
param(
    [string]$SessionName = "incident-01-test",
    [Parameter(Mandatory)][string]$StartUtc,
    [Parameter(Mandatory)][string]$EndUtc
)

$ErrorActionPreference = "Stop"
$evidenceDir = Join-Path $PSScriptRoot "evidence"
New-Item -ItemType Directory -Force -Path $evidenceDir | Out-Null

Write-Host "Window : $StartUtc -> $EndUtc"
Write-Host "Session: $SessionName"
Write-Host ""

# --- Pull management events --------------------------------------------------
# lookup-events covers MANAGEMENT events only. S3 object access is a data event
# and will not appear here - see the S3 log section below.
$raw = aws cloudtrail lookup-events `
    --start-time $StartUtc --end-time $EndUtc `
    --max-items 200 --output json | ConvertFrom-Json

$events = $raw.Events | ForEach-Object { $_.CloudTrailEvent | ConvertFrom-Json }
Write-Host "Management events in window: $($events.Count)"

# --- Step 1: find the pivot --------------------------------------------------
$assume = $events | Where-Object {
    $_.eventName -eq "AssumeRole" -and $_.requestParameters.roleSessionName -eq $SessionName
}

Write-Host ""
Write-Host "=== 1. Role assumption (the pivot) ===" -ForegroundColor Cyan
$assume | ForEach-Object {
    "  time        : $($_.eventTime)"
    "  who         : $($_.userIdentity.arn)"
    "  source IP   : $($_.sourceIPAddress)"
    "  user agent  : $($_.userAgent)"
    "  role assumed: $($_.requestParameters.roleArn)"
    "  session     : $($_.requestParameters.roleSessionName)"
    "  expires     : $($_.responseElements.credentials.expiration)"
}

# --- Step 2: everything done as that session ---------------------------------
$session = $events | Where-Object { $_.userIdentity.arn -like "*/$SessionName" } | Sort-Object eventTime

Write-Host ""
Write-Host "=== 2. Actions performed as the assumed role ===" -ForegroundColor Cyan
$session | ForEach-Object {
    $status = if ($_.errorCode) { "DENIED ($($_.errorCode))" } else { "allowed" }
    "  {0}  {1,-14} {2,-22} {3}" -f $_.eventTime, $_.eventSource.Replace(".amazonaws.com", ""), $_.eventName, $status
}

# --- Step 3: denials, isolated ----------------------------------------------
$denied = $session | Where-Object { $_.errorCode }

Write-Host ""
Write-Host "=== 3. Denied attempts - what the actor TRIED to do ===" -ForegroundColor Yellow
$denied | ForEach-Object {
    "  {0}  {1}" -f $_.eventName, $_.errorMessage
}

# --- Save evidence -----------------------------------------------------------
$assume | ConvertTo-Json -Depth 20 | Set-Content "$evidenceDir\01-assume-role.json" -Encoding utf8
$session | ConvertTo-Json -Depth 20 | Set-Content "$evidenceDir\02-session-activity.json" -Encoding utf8
$denied | ConvertTo-Json -Depth 20 | Set-Content "$evidenceDir\03-denied-attempts.json" -Encoding utf8

Write-Host ""
# @() forces an array - in PowerShell 5.1 a single object has no .Count and
# renders as blank, which silently understates the counts.
Write-Host "Summary" -ForegroundColor Magenta
Write-Host "  total as session : $(@($session).Count)"
Write-Host "  allowed          : $(@($session | Where-Object { -not $_.errorCode }).Count)"
Write-Host "  denied           : $(@($denied).Count)"
Write-Host ""
Write-Host "Evidence written to $evidenceDir"
Write-Host ""
Write-Host "NOTE: S3 GetObject/ListObjects are DATA events and never appear in"
Write-Host "lookup-events. Read them from the trail's S3 bucket instead:"
Write-Host "  aws s3 ls s3://cloudsec-lab-cloudtrail-<account-id>/AWSLogs/ --recursive"
