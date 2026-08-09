<#
.SYNOPSIS
    Generates controlled, authorized activity in your own AWS account for
    incident 01 (IAM investigation).

.DESCRIPTION
    Assumes the deliberately limited test role from terraform/incident-01/ and
    performs a scripted mix of permitted and denied actions.

    The denied actions are not mistakes. AccessDenied events are the highest
    signal evidence in an IAM investigation: they show what an actor TRIED to
    do, which is often more revealing than what succeeded.

    Everything runs against synthetic test data in your own account.

.NOTES
    Run terraform apply in terraform/incident-01/ first.
#>

[CmdletBinding()]
param(
    [string]$SessionName = "incident-01-test",
    [string]$TerraformDir = (Join-Path $PSScriptRoot "..\..\terraform\incident-01")
)

$ErrorActionPreference = "Continue"

# Resolve the target resources from Terraform outputs rather than hardcoding.
Push-Location $TerraformDir
$roleArn = (terraform output -raw role_arn)
$bucket = (terraform output -raw bucket_name)
Pop-Location

Write-Host "Role   : $roleArn"
Write-Host "Bucket : $bucket"
Write-Host "Session: $SessionName"
Write-Host ""

# --- Step 1: assume the role -------------------------------------------------
# Produces an sts:AssumeRole management event. Every later call is attributed
# to assumed-role/<role>/<session-name>.
Write-Host "[1] sts:AssumeRole" -ForegroundColor Cyan
$creds = aws sts assume-role `
    --role-arn $roleArn `
    --role-session-name $SessionName `
    --duration-seconds 3600 `
    --output json | ConvertFrom-Json

if (-not $creds) { throw "AssumeRole failed - cannot continue." }

$startedUtc = (Get-Date).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ")

# Scope the temporary credentials to this process only.
$env:AWS_ACCESS_KEY_ID = $creds.Credentials.AccessKeyId
$env:AWS_SECRET_ACCESS_KEY = $creds.Credentials.SecretAccessKey
$env:AWS_SESSION_TOKEN = $creds.Credentials.SessionToken

Write-Host "    assumed as $($creds.AssumedRoleUser.Arn)" -ForegroundColor Green
Write-Host ""

function Step {
    param([string]$Label, [string]$Expect, [scriptblock]$Action)
    Write-Host "[$script:n] $Label" -ForegroundColor Cyan
    Write-Host "    expect: $Expect"
    $out = & $Action 2>&1 | Out-String
    if ($out -match "AccessDenied|not authorized|Forbidden") {
        Write-Host "    -> DENIED" -ForegroundColor Yellow
    }
    elseif ($LASTEXITCODE -eq 0) {
        Write-Host "    -> allowed" -ForegroundColor Green
    }
    else {
        Write-Host "    -> error: $($out.Trim() -split "`n" | Select-Object -First 1)" -ForegroundColor Red
    }
    $script:n++
    Start-Sleep -Seconds 1
}

$script:n = 2

# --- Permitted actions -------------------------------------------------------
Step "sts:GetCallerIdentity" "allowed - always permitted" {
    aws sts get-caller-identity --output json
}

Step "s3:ListBucket (reports/ prefix)" "allowed - within the policy condition" {
    aws s3api list-objects-v2 --bucket $bucket --prefix "reports/" --output json
}

Step "s3:GetObject reports/quarterly-summary.txt" "allowed - inside permitted prefix" {
    aws s3api get-object --bucket $bucket --key "reports/quarterly-summary.txt" "$env:TEMP\dl1.txt" --output json
}

Step "s3:GetObject reports/runbook.txt" "allowed - inside permitted prefix" {
    aws s3api get-object --bucket $bucket --key "reports/runbook.txt" "$env:TEMP\dl2.txt" --output json
}

# --- Denied actions - the interesting evidence -------------------------------
Step "s3:GetObject restricted/payroll.txt" "DENIED - explicit deny on restricted/" {
    aws s3api get-object --bucket $bucket --key "restricted/payroll.txt" "$env:TEMP\dl3.txt" --output json
}

Step "s3:ListBucket (restricted/ prefix)" "DENIED - outside the s3:prefix condition" {
    aws s3api list-objects-v2 --bucket $bucket --prefix "restricted/" --output json
}

Step "s3:DeleteObject reports/runbook.txt" "DENIED - policy grants no write actions" {
    aws s3api delete-object --bucket $bucket --key "reports/runbook.txt" --output json
}

Step "s3:PutObject reports/implant.txt" "DENIED - policy grants no write actions" {
    aws s3api put-object --bucket $bucket --key "reports/implant.txt" --body "$env:TEMP\dl1.txt" --output json
}

Step "iam:ListUsers" "DENIED - no IAM permissions (reconnaissance attempt)" {
    aws iam list-users --output json
}

Step "iam:CreateAccessKey for mella-admin" "DENIED - privilege escalation attempt" {
    aws iam create-access-key --user-name mella-admin --output json
}

Step "s3:ListAllMyBuckets" "DENIED - enumeration attempt beyond the one bucket" {
    aws s3api list-buckets --output json
}

# --- Clean up credentials ----------------------------------------------------
Remove-Item Env:AWS_ACCESS_KEY_ID, Env:AWS_SECRET_ACCESS_KEY, Env:AWS_SESSION_TOKEN -ErrorAction SilentlyContinue
Remove-Item "$env:TEMP\dl1.txt", "$env:TEMP\dl2.txt", "$env:TEMP\dl3.txt" -ErrorAction SilentlyContinue

$endedUtc = (Get-Date).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ")

Write-Host ""
Write-Host "Activity window (UTC): $startedUtc  ->  $endedUtc" -ForegroundColor Magenta
Write-Host "Session name to search on: $SessionName"
Write-Host ""
Write-Host "Management events appear in CloudTrail Event History within minutes."
Write-Host "S3 data events do NOT appear there - they are only in the S3 log files,"
Write-Host "delivered every 5-15 minutes."
