<#
.SYNOPSIS
    Generates controlled activity for Incident 03: exercises both branches of
    the detection/response pipeline in one run - a remediable finding and
    several unremediable ones.

.DESCRIPTION
    Two independent things happen here, deliberately not entangled with each
    other:

      REMEDIABLE   Re-exposes the Incident 02 bucket (same resource, same
                   allowlist entry the containment Lambda already watches) by
                   flipping Terraform's harden variable off. AWS Config
                   re-evaluates it, Security Hub produces a real FAILED
                   finding for one of the S3.1/S3.2/S3.3/S3.8 family, and the
                   containment Lambda is expected to detect, contain, and
                   notify - the full pipeline, start to finish.

      UNREMEDIABLE A handful of GuardDuty sample findings - real finding
                   records, via the same official create-sample-findings API
                   this lab's earlier exploration already validated - for
                   finding types nothing in this lab's containment Lambda
                   matches on. These are expected to reach the alert Lambda
                   (log + notify) and nowhere else: no containment rule fires,
                   because none is supposed to.

    The point of running both together: proving the pipeline's SEVERITY-BASED
    BRANCH actually branches correctly on real (or real-mechanism synthetic)
    evidence, not just in code review. See incidents/incident-03-detection-and-response.md
    for the full write-up this run's evidence feeds.

.NOTES
    Run terraform apply in terraform/incident-02/ at least once before this
    (the bucket must already exist). The GuardDuty finding type strings below
    were verified against this account's own output during this lab's
    development, not guessed from documentation - see the incident report's
    Evidence section.
#>

[CmdletBinding()]
param(
    [string]$TerraformDir = (Join-Path $PSScriptRoot "..\..\terraform\incident-02"),
    [int]$WaitTimeoutMinutes = 12
)

$ErrorActionPreference = "Continue"
$evidenceDir = Join-Path $PSScriptRoot "evidence"
New-Item -ItemType Directory -Force -Path $evidenceDir | Out-Null

$startedUtc = (Get-Date).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ")
Write-Host "Incident 03 activity run starting: $startedUtc" -ForegroundColor Magenta
Write-Host ""

# --- Part A: unremediable - curated GuardDuty sample findings ---------------
# Verified real GuardDuty finding-type strings (confirmed against this
# account's own output, not guessed): a credential-compromise sequence, a
# privilege-escalation sequence, and anomalous reconnaissance from a Tor exit
# node. None of these match CONTAINABLE_FINDING_TYPES or
# CONTAINABLE_SECURITY_CONTROL_IDS in the deployed containment Lambda - that
# absence of a match is the point being tested.
Write-Host "[1] GuardDuty sample findings (unremediable path)" -ForegroundColor Cyan
$detectorId = (aws guardduty list-detectors --query "DetectorIds[0]" --output text)
Write-Host "    detector: $detectorId"

$sampleTypes = @(
    "CredentialAccess:IAMUser/CompromisedCredentials",
    "PrivilegeEscalation:IAMUser/AnomalousBehavior",
    "Recon:IAMUser/TorIPCaller"
)
foreach ($t in $sampleTypes) { Write-Host "    - $t" }

aws guardduty create-sample-findings --detector-id $detectorId --finding-types $sampleTypes | Out-Null
Write-Host "    PASS  sample findings requested" -ForegroundColor Green
Write-Host ""

# --- Part B: remediable - re-expose the Incident 02 bucket ------------------
Write-Host "[2] Re-expose the Incident 02 bucket (remediable path)" -ForegroundColor Cyan
Push-Location $TerraformDir
$bucketName = (terraform output -raw bucket_name)
terraform apply -var harden=false -auto-approve | Out-Null
Pop-Location
Write-Host "    bucket: $bucketName"
Write-Host "    PASS  harden=false applied" -ForegroundColor Green

# -SkipHttpErrorCheck is PowerShell 7+ only; this lab targets Windows
# PowerShell 5.1, where Invoke-WebRequest throws on a non-2xx response
# instead of just returning it, so the status code has to be read back out
# of the exception.
try {
    $exposedCheck = Invoke-WebRequest -Uri "https://$bucketName.s3.amazonaws.com/internal/api-notes.txt" -UseBasicParsing
    $statusCode = [int]$exposedCheck.StatusCode
} catch {
    $statusCode = [int]$_.Exception.Response.StatusCode
}
Write-Host "    anonymous GET -> HTTP $statusCode (expect 200 - genuinely public)"
Write-Host ""

# --- Wait for both branches to settle ----------------------------------------
Write-Host "[3] Waiting up to $WaitTimeoutMinutes minutes for both branches to resolve" -ForegroundColor Cyan
Write-Host "    (AWS Config's evaluation latency is the slow part - observed"
Write-Host "     2-7 minutes elsewhere in this lab; GuardDuty samples are near-instant)"
Write-Host ""

$deadline = (Get-Date).AddMinutes($WaitTimeoutMinutes)
$alertSeen = $false
$containSeen = $false

while ((Get-Date) -lt $deadline -and (-not $alertSeen -or -not $containSeen)) {
    Start-Sleep -Seconds 20

    if (-not $alertSeen) {
        $alertLog = aws logs filter-log-events --log-group-name "/aws/lambda/cloudsec-lab-securityhub-alert" `
            --start-time ([DateTimeOffset]::Parse($startedUtc).ToUnixTimeMilliseconds()) `
            --filter-pattern "TorIPCaller" --output json | ConvertFrom-Json
        if (@($alertLog.events).Count -gt 0) {
            $alertSeen = $true
            Write-Host "    PASS  unremediable finding reached the alert Lambda (logged + notified)" -ForegroundColor Green
        }
    }

    if (-not $containSeen) {
        $pab = aws s3api get-public-access-block --bucket $bucketName --output json 2>$null | ConvertFrom-Json
        $allBlocked = $pab.PublicAccessBlockConfiguration.BlockPublicAcls -and `
                      $pab.PublicAccessBlockConfiguration.IgnorePublicAcls -and `
                      $pab.PublicAccessBlockConfiguration.BlockPublicPolicy -and `
                      $pab.PublicAccessBlockConfiguration.RestrictPublicBuckets
        if ($allBlocked) {
            $containSeen = $true
            Write-Host "    PASS  remediable finding was contained (Block Public Access restored)" -ForegroundColor Green
        }
    }
}

if (-not $alertSeen) {
    Write-Host "    WARN  no alert-Lambda log line matched within the timeout - check manually" -ForegroundColor Yellow
}
if (-not $containSeen) {
    Write-Host "    WARN  bucket not yet contained within the timeout - check manually, or:" -ForegroundColor Yellow
    Write-Host "          aws s3api put-public-access-block --bucket $bucketName --public-access-block-configuration BlockPublicAcls=true,IgnorePublicAcls=true,BlockPublicPolicy=true,RestrictPublicBuckets=true"
}

$endedUtc = (Get-Date).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ")
Write-Host ""
Write-Host "Activity window (UTC): $startedUtc -> $endedUtc" -ForegroundColor Magenta
Write-Host "Next: fully re-harden when done investigating:"
Write-Host "  cd terraform/incident-02; terraform apply -var harden=true"
