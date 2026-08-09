<#
.SYNOPSIS
    Detects insecure S3 bucket configuration across an AWS account.

.DESCRIPTION
    Evaluates every bucket against six controls and reports PASS / FAIL / WARN.

    Written because Security Hub's S3 controls are evaluated by AWS Config
    rules, and AWS Config is not enabled in this account (deliberately - it has
    no free tier and bills per configuration item). Without Config those
    controls report "No data" rather than detecting anything, so this script
    provides equivalent coverage at no cost.

    Controls evaluated:
      S3-1  Block Public Access enabled (all four settings)
      S3-2  No anonymous grant in the bucket policy
      S3-3  ACLs disabled (BucketOwnerEnforced)
      S3-4  Explicit default encryption configured
      S3-5  Versioning enabled
      S3-6  Policy denies plaintext (non-TLS) requests

.PARAMETER BucketPrefix
    Only evaluate buckets whose name starts with this. Omit to scan all.

.PARAMETER FailOnFinding
    Exit 1 if any FAIL is found. For use in CI.

.EXAMPLE
    ./s3-posture-check.ps1
    ./s3-posture-check.ps1 -BucketPrefix cloudsec-lab-incident-02
    ./s3-posture-check.ps1 -FailOnFinding
#>

[CmdletBinding()]
param(
    [string]$BucketPrefix = "",
    [switch]$FailOnFinding,
    [string]$JsonOut
)

$ErrorActionPreference = "Continue"
$ProgressPreference = "SilentlyContinue"

function Get-BucketJson {
    <#  Wraps an AWS CLI call that is expected to fail for absent
        configuration. Returns $null instead of throwing, so "no encryption
        configured" is distinguishable from "the call errored".  #>
    param([scriptblock]$Call)
    $out = & $Call 2>$null
    if ($LASTEXITCODE -ne 0 -or -not $out) { return $null }
    try { return ($out | ConvertFrom-Json) } catch { return $null }
}

$buckets = (aws s3api list-buckets --query 'Buckets[].Name' --output json | ConvertFrom-Json)
if ($BucketPrefix) { $buckets = $buckets | Where-Object { $_.StartsWith($BucketPrefix) } }

if (-not $buckets) { Write-Host "No buckets matched."; exit 0 }

$results = @()

foreach ($b in $buckets) {
    Write-Host ""
    Write-Host "=== $b ===" -ForegroundColor Cyan
    $findings = @()

    # --- S3-1: Block Public Access -------------------------------------------
    $pab = Get-BucketJson { aws s3api get-public-access-block --bucket $b --output json }
    $c = $pab.PublicAccessBlockConfiguration
    $pabOk = $c -and $c.BlockPublicAcls -and $c.BlockPublicPolicy -and $c.IgnorePublicAcls -and $c.RestrictPublicBuckets
    $findings += [pscustomobject]@{
        Control = "S3-1"; Name = "Block Public Access"
        Status  = if ($pabOk) { "PASS" } else { "FAIL" }
        Detail  = if (-not $c) { "no public access block configured" }
        elseif (-not $pabOk) { "acls=$($c.BlockPublicAcls) policy=$($c.BlockPublicPolicy) ignoreAcls=$($c.IgnorePublicAcls) restrict=$($c.RestrictPublicBuckets)" }
        else { "all four settings enabled" }
    }

    # --- S3-2: anonymous grant in policy -------------------------------------
    $polRaw = Get-BucketJson { aws s3api get-bucket-policy --bucket $b --output json }
    $publicStmt = @()
    $deniesInsecureTransport = $false
    if ($polRaw) {
        $pol = $polRaw.Policy | ConvertFrom-Json
        foreach ($s in @($pol.Statement)) {
            $prin = $s.Principal
            $isWildcard = ($prin -eq "*") -or ($prin.AWS -eq "*") -or ($prin.AWS -contains "*")
            if ($s.Effect -eq "Allow" -and $isWildcard) {
                # No ternary operator - this must run on Windows PowerShell 5.1.
                if ($s.Sid) { $publicStmt += $s.Sid } else { $publicStmt += "(unnamed)" }
            }
            if ($s.Effect -eq "Deny" -and $s.Condition.Bool.'aws:SecureTransport' -eq "false") {
                $deniesInsecureTransport = $true
            }
        }
    }
    $findings += [pscustomobject]@{
        Control = "S3-2"; Name = "No anonymous policy grant"
        Status  = if ($publicStmt.Count -gt 0) { "FAIL" } else { "PASS" }
        Detail  = if ($publicStmt.Count -gt 0) { "public Allow statement(s): $($publicStmt -join ', ')" } else { "no wildcard-principal Allow" }
    }

    # --- S3-3: ACLs disabled --------------------------------------------------
    $own = Get-BucketJson { aws s3api get-bucket-ownership-controls --bucket $b --output json }
    $ownership = $own.OwnershipControls.Rules[0].ObjectOwnership
    $findings += [pscustomobject]@{
        Control = "S3-3"; Name = "ACLs disabled"
        Status  = if ($ownership -eq "BucketOwnerEnforced") { "PASS" } else { "FAIL" }
        Detail  = "objectOwnership=$(if ($ownership) { $ownership } else { 'not set' })"
    }

    # --- S3-4: explicit encryption -------------------------------------------
    # S3 applies SSE-S3 by default to new buckets since Jan 2023, so absence
    # here means "no declared posture", not "plaintext at rest". WARN, not FAIL.
    $enc = Get-BucketJson { aws s3api get-bucket-encryption --bucket $b --output json }
    $algo = $enc.ServerSideEncryptionConfiguration.Rules[0].ApplyServerSideEncryptionByDefault.SSEAlgorithm
    $findings += [pscustomobject]@{
        Control = "S3-4"; Name = "Explicit default encryption"
        Status  = if ($algo) { "PASS" } else { "WARN" }
        Detail  = if ($algo) { "sseAlgorithm=$algo" } else { "none declared - relies on the S3 default (SSE-S3)" }
    }

    # --- S3-5: versioning -----------------------------------------------------
    $ver = Get-BucketJson { aws s3api get-bucket-versioning --bucket $b --output json }
    $findings += [pscustomobject]@{
        Control = "S3-5"; Name = "Versioning enabled"
        Status  = if ($ver.Status -eq "Enabled") { "PASS" } else { "FAIL" }
        Detail  = "status=$(if ($ver.Status) { $ver.Status } else { 'never enabled' })"
    }

    # --- S3-6: TLS required ---------------------------------------------------
    $findings += [pscustomobject]@{
        Control = "S3-6"; Name = "Denies plaintext requests"
        Status  = if ($deniesInsecureTransport) { "PASS" } else { "FAIL" }
        Detail  = if ($deniesInsecureTransport) { "aws:SecureTransport=false denied" } else { "no TLS-only deny statement" }
    }

    foreach ($f in $findings) {
        $colour = switch ($f.Status) { "PASS" { "Green" } "WARN" { "Yellow" } default { "Red" } }
        Write-Host ("  {0,-6} {1,-30} {2,-5} {3}" -f $f.Control, $f.Name, $f.Status, $f.Detail) -ForegroundColor $colour
        $results += [pscustomobject]@{ Bucket = $b; Control = $f.Control; Name = $f.Name; Status = $f.Status; Detail = $f.Detail }
    }
}

# --- Summary ------------------------------------------------------------------
$fails = @($results | Where-Object Status -eq "FAIL")
$warns = @($results | Where-Object Status -eq "WARN")

Write-Host ""
Write-Host ("SUMMARY  buckets={0}  checks={1}  PASS={2}  WARN={3}  FAIL={4}" -f `
        @($buckets).Count, @($results).Count,
    @($results | Where-Object Status -eq "PASS").Count,
    $warns.Count, $fails.Count) -ForegroundColor Magenta

if ($fails.Count -gt 0) {
    Write-Host ""
    Write-Host "FAILING:" -ForegroundColor Red
    $fails | ForEach-Object { Write-Host ("  {0}  {1}  {2}" -f $_.Bucket, $_.Control, $_.Detail) }
}

if ($JsonOut) {
    $results | ConvertTo-Json -Depth 5 | Set-Content $JsonOut -Encoding utf8
    Write-Host ""
    Write-Host "Results written to $JsonOut"
}

if ($FailOnFinding -and $fails.Count -gt 0) { exit 1 }
exit 0
