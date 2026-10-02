<#
.SYNOPSIS
    End-to-end test for the Phase 9 automated containment pipeline.

.DESCRIPTION
    Exercises the real path:

        S3 PutPublicAccessBlock (test precondition)
              -> BatchImportFindings (synthetic finding)
              -> Security Hub -> EventBridge -> containment Lambda
              -> S3 PutPublicAccessBlock (the Lambda's own call, if allowed)

    Three scenarios, selected by -Scenario:

      Contain       (default) Flips Block Public Access off on the
                    allow-listed bucket, imports a finding matching both the
                    known type and the known resource, and verifies the
                    Lambda restores it - for real, verified against the
                    actual S3 API, not just a log line. If the deployed
                    stack has enable_auto_containment=false, this instead
                    verifies the dry-run log line and confirms the bucket
                    was NOT touched.

      WrongResource Same finding type, but against a bucket ARN that is not
                    on the allowlist. The Lambda IS invoked (the type
                    matches the EventBridge rule) but must skip - proves the
                    resource-allowlist check works, not just the type check.

      WrongType     A finding against the real allow-listed bucket, but
                    with a type the containment rule doesn't match. Expects
                    NO invocation at all within the timeout - proves the
                    EventBridge rule itself is the first line of defense,
                    not just the Lambda's internal logic.

    Why a direct S3 API call for the precondition, not a real misconfiguration:

    The containment Lambda only ever calls PutPublicAccessBlock - it never
    touches a bucket policy. The INC-02 bucket's hardened policy (Phase 6)
    has no wildcard Allow statement any more, so toggling Block Public
    Access alone does not actually expose the bucket publicly; it only
    recreates the one condition this Lambda is built to detect and fix. The
    test's blast radius is therefore exactly the setting under test, for as
    long as it takes the Lambda to react - typically a few seconds.

    Why a synthetic finding, not a real GuardDuty one: same reasoning as
    detections/test-high-severity-alert.ps1 - BatchImportFindings under the
    account's own "default" product is the supported way to place a finding
    on the EventBridge bus deterministically, without waiting on GuardDuty's
    real detection latency and without the ability to import findings under
    GuardDuty's own product ARN (that requires GuardDuty's own
    service-linked integration, not a regular IAM principal).

.PARAMETER Scenario
    Contain (default), WrongResource, or WrongType.

.PARAMETER TimeoutSeconds
    How long to wait for a log line (or, for WrongType, how long to wait to
    confirm one never appears).

.EXAMPLE
    ./test-automated-containment.ps1
    Full positive-path test against the real deployed pipeline.

.EXAMPLE
    ./test-automated-containment.ps1 -Scenario WrongResource

.EXAMPLE
    ./test-automated-containment.ps1 -Scenario WrongType
#>

[CmdletBinding()]
param(
    [ValidateSet('Contain', 'WrongResource', 'WrongType')]
    [string]$Scenario = 'Contain',

    [int]$TimeoutSeconds = 120
)

$ErrorActionPreference = 'Stop'

function Write-Step($Message) { Write-Host "`n==> $Message" -ForegroundColor Cyan }
function Write-Pass($Message) { Write-Host "    PASS  $Message" -ForegroundColor Green }
function Write-Fail($Message) { Write-Host "    FAIL  $Message" -ForegroundColor Red }
function Write-Info($Message) { Write-Host "    $Message" -ForegroundColor DarkGray }

function ConvertFrom-LambdaLogLine($RawMessage) {
    # A Lambda log line for a WARNING/INFO call is not bare JSON - Python's
    # logging handler prepends "[LEVEL]\t<timestamp>\t<request-id>\t" before
    # the message text, so ConvertFrom-Json on the raw string fails. The
    # containment handler's payload is always the first (and only) '{' in
    # the line; everything before it is that prefix.
    $jsonStart = $RawMessage.IndexOf('{')
    if ($jsonStart -lt 0) {
        throw "Log line has no JSON payload to parse: $RawMessage"
    }
    return $RawMessage.Substring($jsonStart) | ConvertFrom-Json
}

# --- Read the deployed configuration, don't hardcode it ---------------------

Write-Step 'Reading terraform/response outputs'

Push-Location (Join-Path $PSScriptRoot '..\terraform\response')
try {
    $functionName = terraform output -raw containment_function_name
    $logGroup = terraform output -raw containment_log_group
    $dlqUrl = terraform output -raw containment_dlq_url
    $enabledRaw = terraform output -raw auto_containment_enabled
    $autoContainEnabled = $enabledRaw -eq 'true'
    $findingTypesJson = terraform output -json containable_finding_types
    $findingType = ($findingTypesJson | ConvertFrom-Json)[0]
    $resourceArnsJson = terraform output -json containable_resource_arns
    $allowedArn = ($resourceArnsJson | ConvertFrom-Json)[0]
}
finally {
    Pop-Location
}

$allowedBucket = $allowedArn -replace '^arn:aws:s3:::', ''

Write-Info "function=$functionName"
Write-Info "allowed resource=$allowedArn"
Write-Info "finding type=$findingType"
Write-Info "enable_auto_containment=$autoContainEnabled"

if ($Scenario -eq 'Contain' -and -not $autoContainEnabled) {
    Write-Info 'auto-containment is OFF - this run proves the dry-run path (would_contain_but_disabled), not a real S3 change.'
}

# --- Context ------------------------------------------------------------

$identity = aws sts get-caller-identity --output json | ConvertFrom-Json
$accountId = $identity.Account
$region = aws configure get region
if ([string]::IsNullOrWhiteSpace($region)) { $region = 'us-east-1' }

$productArn = "arn:aws:securityhub:${region}:${accountId}:product/${accountId}/default"
$findingId = "lab-phase9-selftest-$([guid]::NewGuid().ToString('N').Substring(0,12))"
$now = (Get-Date).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ss.fffZ')

# --- Scenario-specific setup ----------------------------------------------

switch ($Scenario) {
    'Contain' {
        $targetArn = $allowedArn
        $findingTypeUsed = $findingType
    }
    'WrongResource' {
        $targetArn = 'arn:aws:s3:::this-bucket-is-not-on-the-allowlist-' + [guid]::NewGuid().ToString('N').Substring(0, 8)
        $findingTypeUsed = $findingType
    }
    'WrongType' {
        $targetArn = $allowedArn
        $findingTypeUsed = 'TTPs/Policy:S3-BucketBlockPublicAccessDisabled'
    }
}

# --- Precondition: only for the Contain scenario, only on the real bucket ---

if ($Scenario -eq 'Contain') {
    Write-Step "Precondition: disabling Block Public Access on $allowedBucket"

    aws s3api put-public-access-block --bucket $allowedBucket --public-access-block-configuration `
        "BlockPublicAcls=false,IgnorePublicAcls=false,BlockPublicPolicy=false,RestrictPublicBuckets=false" `
        --output json | Out-Null

    if ($LASTEXITCODE -ne 0) {
        Write-Fail "could not set the test precondition (exit $LASTEXITCODE) - does the bucket exist?"
        exit 1
    }

    $before = aws s3api get-public-access-block --bucket $allowedBucket --output json | ConvertFrom-Json
    $beforeBlocked = $before.PublicAccessBlockConfiguration.BlockPublicAcls -and
                     $before.PublicAccessBlockConfiguration.IgnorePublicAcls -and
                     $before.PublicAccessBlockConfiguration.BlockPublicPolicy -and
                     $before.PublicAccessBlockConfiguration.RestrictPublicBuckets

    if ($beforeBlocked) {
        Write-Fail 'precondition did not take effect - bucket still reports fully blocked'
        exit 1
    }
    Write-Pass 'Block Public Access is now off - bucket policy remains hardened throughout (no wildcard grant exists to reopen)'
}

# --- Build and import the synthetic finding ----------------------------

Write-Step "Importing synthetic finding ($Scenario)"

$finding = @{
    SchemaVersion = '2018-10-08'
    Id            = $findingId
    ProductArn    = $productArn
    GeneratorId   = 'cloudsec-lab/phase-9/self-test'
    AwsAccountId  = $accountId
    Region        = $region
    Types         = @($findingTypeUsed)
    CreatedAt     = $now
    UpdatedAt     = $now
    Severity      = @{ Label = 'HIGH' }
    Title         = "SYNTHETIC LAB FINDING - Phase 9 containment self-test ($Scenario)"
    Description   = 'Generated by detections/test-automated-containment.ps1 to verify the containment pipeline. Not a real security finding.'
    RecordState   = 'ACTIVE'
    Workflow      = @{ Status = 'NEW' }
    # Mirrors the real-world resource ordering observed in this account: the
    # IAM principal that made the call is listed before the affected bucket
    # - this is also a regression check that the Lambda doesn't assume
    # Resources[0] is the target.
    Resources     = @(
        @{
            Type      = 'AwsIamAccessKey'
            Id        = 'AWS::IAM::AccessKey:AKIAEXAMPLESELFTEST'
            Partition = 'aws'
            Region    = $region
        },
        @{
            Type      = 'AwsS3Bucket'
            Id        = $targetArn
            Partition = 'aws'
            Region    = $region
        }
    )
}

$tempFile = Join-Path $env:TEMP "phase9-finding-$findingId.json"
$findingJson = ConvertTo-Json -InputObject @($finding) -Depth 10
# BOM-less UTF-8 - see detections/test-high-severity-alert.ps1 for why a BOM
# here breaks the AWS CLI's JSON detection.
[System.IO.File]::WriteAllText($tempFile, $findingJson, (New-Object System.Text.UTF8Encoding($false)))

$startedAtMs = [DateTimeOffset]::UtcNow.ToUnixTimeMilliseconds()

try {
    $importJson = aws securityhub batch-import-findings --findings "file://$tempFile" --output json

    if ($LASTEXITCODE -ne 0) {
        Write-Fail "batch-import-findings failed (exit $LASTEXITCODE):"
        Write-Host $importJson
        exit 1
    }

    $import = $importJson | ConvertFrom-Json
    if ($import.FailedCount -gt 0) {
        Write-Fail "Security Hub rejected the finding: $($import.FailedFindings | ConvertTo-Json -Compress)"
        exit 1
    }

    Write-Pass "imported id=$findingId"
}
finally {
    Remove-Item $tempFile -ErrorAction SilentlyContinue
}

# --- Wait for the Lambda's decision -----------------------------------

Write-Step 'Waiting for the containment Lambda'
Write-Info "log group: $logGroup"

$deadline = (Get-Date).AddSeconds($TimeoutSeconds)
$found = $null

while ((Get-Date) -lt $deadline) {
    try {
        # `\"..\"` , not `"..."` or a backtick-escaped `"..."`: PowerShell
        # silently drops an embedded literal double-quote when handing a
        # string argument to a native exe unless it's backslash-escaped,
        # which survives the PowerShell-to-argv boundary intact. Confirmed
        # via `aws --debug`: the unescaped forms above all resulted in the
        # API receiving `filterPattern` with NO quotes at all, and an
        # unquoted, hyphenated, no-space term like a finding ID matched
        # nothing - unlike detections/test-high-severity-alert.ps1's
        # multi-word phrase, which happens to still match every word
        # independently even split apart, this finding ID does not.
        $eventsJson = aws logs filter-log-events `
            --log-group-name $logGroup `
            --start-time $startedAtMs `
            --filter-pattern "\`"$findingId\`"" `
            --output json 2>$null

        if ($LASTEXITCODE -eq 0 -and $eventsJson) {
            $events = @(($eventsJson | ConvertFrom-Json).events)
            # Belt and suspenders: re-check client-side rather than trusting
            # the server-side filter alone, same defensive habit as
            # test-high-severity-alert.ps1 - it's what would have masked
            # this exact bug here too, had it been present from the start.
            $match = @($events | Where-Object { $_.message -like "*$findingId*" })
            if ($match.Count -gt 0) {
                $found = $match[0]
                break
            }
        }
    }
    catch {
        # Group not created yet, or no matches - keep waiting.
    }

    Start-Sleep -Seconds 5
    Write-Host '.' -NoNewline -ForegroundColor DarkGray
}
Write-Host ''

# --- Verdict -------------------------------------------------------------

Write-Step 'Result'
$exitCode = 0

switch ($Scenario) {
    'WrongType' {
        # No invocation at all is the expected, correct outcome - the
        # EventBridge rule itself filters this out before the Lambda ever
        # runs. Absence of a log line is the proof, same as
        # test-high-severity-alert.ps1's -ExpectNoAlert.
        if ($null -eq $found) {
            Write-Pass 'no invocation for a non-matching finding type - the EventBridge rule filters as intended'
        }
        else {
            Write-Fail 'a finding of the wrong type still reached the Lambda - the rule is too broad'
            Write-Host $found.message
            $exitCode = 1
        }
    }

    'WrongResource' {
        if ($null -eq $found) {
            Write-Fail "no log line found within ${TimeoutSeconds}s - expected a skipped_resource_not_allowlisted entry"
            $exitCode = 1
        }
        else {
            $payload = ConvertFrom-LambdaLogLine $found.message
            if ($payload.containment_action -eq 'skipped_resource_not_allowlisted') {
                Write-Pass "correctly skipped - $($payload.containment_action)"
            }
            else {
                Write-Fail "expected skipped_resource_not_allowlisted, got '$($payload.containment_action)'"
                $exitCode = 1
            }
        }
    }

    'Contain' {
        if ($null -eq $found) {
            Write-Fail "no log line found within ${TimeoutSeconds}s"
            $exitCode = 1
        }
        else {
            $payload = ConvertFrom-LambdaLogLine $found.message
            Write-Info "containment_action = $($payload.containment_action)"

            $expectedAction = if ($autoContainEnabled) { 'contained' } else { 'would_contain_but_disabled' }

            if ($payload.containment_action -eq $expectedAction) {
                Write-Pass "logged '$expectedAction' as expected"
            }
            else {
                Write-Fail "expected '$expectedAction', got '$($payload.containment_action)'"
                $exitCode = 1
            }

            # The real proof: check actual S3 state, not just the log line.
            $after = aws s3api get-public-access-block --bucket $allowedBucket --output json | ConvertFrom-Json
            $afterBlocked = $after.PublicAccessBlockConfiguration.BlockPublicAcls -and
                            $after.PublicAccessBlockConfiguration.IgnorePublicAcls -and
                            $after.PublicAccessBlockConfiguration.BlockPublicPolicy -and
                            $after.PublicAccessBlockConfiguration.RestrictPublicBuckets

            if ($autoContainEnabled) {
                if ($afterBlocked) {
                    Write-Pass 'S3 confirms Block Public Access is restored - the Lambda actually made the API call'
                }
                else {
                    Write-Fail 'log says contained, but S3 still reports Block Public Access off'
                    $exitCode = 1
                }
            }
            else {
                if (-not $afterBlocked) {
                    Write-Pass 'S3 confirms nothing was touched, as expected with auto-containment off'
                }
                else {
                    Write-Fail 'bucket is blocked but auto-containment is off - something else changed it'
                    $exitCode = 1
                }
                Write-Info 'Manual cleanup needed: bucket is intentionally left with Block Public Access off. Re-run with enable_auto_containment=true, or restore manually:'
                Write-Info "  aws s3api put-public-access-block --bucket $allowedBucket --public-access-block-configuration BlockPublicAcls=true,IgnorePublicAcls=true,BlockPublicPolicy=true,RestrictPublicBuckets=true"
            }
        }
    }
}

# --- DLQ sanity check ------------------------------------------------------

Write-Step 'Checking the containment DLQ'
$dlqAttrs = aws sqs get-queue-attributes --queue-url $dlqUrl --attribute-names ApproximateNumberOfMessages --output json | ConvertFrom-Json
$dlqCount = [int]$dlqAttrs.Attributes.ApproximateNumberOfMessages
if ($dlqCount -eq 0) {
    Write-Pass 'DLQ empty'
}
else {
    Write-Fail "DLQ has $dlqCount message(s) - a containment event was not delivered"
    $exitCode = 1
}

exit $exitCode
