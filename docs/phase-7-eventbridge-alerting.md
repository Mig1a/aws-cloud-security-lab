# Phase 7 — Near-Real-Time Alerting via EventBridge

**Date:** 2026-08-16
**Objective:** Wire GuardDuty → Security Hub → EventBridge → Lambda, so a
high-severity finding produces a log alert within seconds instead of waiting
for the next manual scan.
**Status:** Complete
**Depends on:** [Phase 4 — Detection Services](phase-4-detection-services.md),
[Phase 6 — Incident #2](phase-6-incident-02.md)

```
GuardDuty  →  Security Hub  →  EventBridge  →  Lambda  →  CloudWatch Logs
```

Both prior incidents converged on this gap. INC-01 found that GuardDuty raised
nothing for a denied-IAM-actions pattern that needed a purpose-built rule.
INC-02 found a 2m23s public-bucket exposure that a manual `s3-posture-check.ps1`
run happened to catch quickly — detection there was a scan, not a subscription.
This phase is the first piece of infrastructure in the lab that reacts to an
event instead of waiting to be run.

Infrastructure: [terraform/response/](../terraform/response/).
Handler: [lambda/securityhub_alert/handler.py](../lambda/securityhub_alert/handler.py).
Self-test: [detections/test-high-severity-alert.ps1](../detections/test-high-severity-alert.ps1).

---

## 1. Why a fourth Terraform stack

The obvious place for this was `terraform/detection/`, next to Security Hub.
It went into a new `terraform/response/` stack instead, for the same reason
`environment/` is separate from `detection/`: different lifecycle. `detection/`
holds account posture (CloudTrail, GuardDuty, Security Hub subscriptions) that
should essentially never change. `response/` holds application logic — a
Lambda function, an event pattern, a DLQ — that will be edited and redeployed
repeatedly as the response side of the lab grows. Bundling them would mean
every Lambda iteration re-plans the account's core detection posture.

Both stacks are long-lived; only `environment/` is destroyed between sessions.

---

## 2. Nothing to enable, only something to filter

Security Hub already publishes every new and updated finding to the
EventBridge **default bus**, from any source — GuardDuty, standards controls,
Inspector, Macie, anything delivered through `BatchImportFindings`. There is no
subscription step. The entire phase is one rule that picks the interesting
findings off a bus that was already carrying them.

```hcl
event_pattern = jsonencode({
  source        = ["aws.securityhub"]
  "detail-type" = ["Security Hub Findings - Imported"]
  detail = {
    findings = {
      Severity    = { Label = var.alert_severity_labels }  # ["HIGH", "CRITICAL"]
      RecordState = ["ACTIVE"]
      Workflow    = { Status = ["NEW", "NOTIFIED"] }
    }
  }
})
```

Three filters, not one:

- **`Severity.Label`** is the actual point of the rule. Default is
  `["HIGH", "CRITICAL"]`, not `["HIGH"]` alone — the brief said HIGH, but a
  rule matching HIGH only would silently ignore everything worse than HIGH.
  Set `alert_severity_labels = ["HIGH"]` to match the brief literally.
- **`RecordState = ["ACTIVE"]`** exists because Security Hub re-publishes a
  finding to EventBridge when it's archived. Without this, resolving a finding
  fires a second alert for the exact event that closed it.
- **`Workflow.Status = ["NEW", "NOTIFIED"]`** exists because Security Hub also
  re-publishes on workflow changes. An analyst who marks a known finding
  `RESOLVED` or `SUPPRESSED` should not keep being paged by it on every touch.

---

## 3. The event pattern doesn't do what it looks like it does

`findings` in the ASFF envelope is an array — Security Hub batches up to 100
findings per event. EventBridge array matching is **ANY-element**, not
all-element: a batch containing one CRITICAL finding and ninety-nine
INFORMATIONAL ones matches the rule, and the *whole batch* is delivered to the
Lambda.

That means the event pattern is a coarse pre-filter, not the actual filter. The
handler re-filters every finding in the batch against the same severity set
before logging anything:

```python
def _matching(findings):
    kept = []
    for finding in findings:
        label = (finding.get("Severity") or {}).get("Label", "").upper()
        if label in ALERT_SEVERITIES:
            kept.append(finding)
    return kept
```

`ALERT_SEVERITIES` is read from an environment variable that Terraform sets
from the exact same `alert_severity_labels` list that builds the event
pattern, so the two cannot drift apart:

```hcl
environment {
  variables = { ALERT_SEVERITIES = join(",", var.alert_severity_labels) }
}
```

[`lambda/tests/test_handler.py`](../lambda/tests/test_handler.py) covers this
directly — `test_mixed_batch_reports_only_high` asserts that a four-finding
batch with one CRITICAL and three low-severity siblings produces exactly one
alert, not four.

---

## 4. Undelivered alerts go somewhere, not nowhere

EventBridge retries a failing Lambda invocation, then **drops the event**. For
most integrations that's an acceptable trade-off; for a security alert it is
not — a silently dropped alert is indistinguishable from no alert at all.

```hcl
retry_policy {
  maximum_event_age_in_seconds = 3600
  maximum_retry_attempts       = 3
}

dead_letter_config {
  arn = aws_sqs_queue.alert_dlq.arn
}
```

Failed deliveries land in an SQS dead-letter queue instead. The queue should
stay empty; anything appearing in it is itself a finding — an alert that never
reached a log. Verified empty after every test run in this phase.

---

## 5. IAM: no `AWSLambdaBasicExecutionRole`

The standard managed policy grants `logs:CreateLogGroup` plus write access to
**every** log group in the account. The role here gets a hand-written policy
scoped to one log group ARN, and `logs:CreateLogGroup` is withheld entirely:

```hcl
resource "aws_cloudwatch_log_group" "alert" {
  name              = "/aws/lambda/${local.function_name}"
  retention_in_days = var.log_retention_days
}
```

The group is created by Terraform, not implicitly by Lambda's first
invocation. An implicitly created log group has **no retention policy** — logs
accumulate forever — and survives `terraform destroy` as an orphan, since
Lambda creating it out-of-band means Terraform never claimed ownership of it.
Explicit creation plus withheld `CreateLogGroup` means a function rename can't
silently recreate an unmanaged, unbounded log group.

---

## 6. Deploying the function requires the deploy to actually change

```hcl
data "archive_file" "alert" {
  type        = "zip"
  source_dir  = "${path.module}/../../lambda/securityhub_alert"
  output_path = "${path.module}/.build/securityhub_alert.zip"
}

resource "aws_lambda_function" "alert" {
  filename         = data.archive_file.alert.output_path
  source_code_hash = data.archive_file.alert.output_base64sha256
  ...
}
```

Without `source_code_hash`, Terraform considers the function converged once
the zip exists at that path — editing `handler.py` and re-applying would leave
the *deployed* function unchanged while the stack reports no drift. The hash
ties deployment to content, so a code change always produces a new version.

`lambda/tests/` sits outside `lambda/securityhub_alert/` for the same reason:
anything under that directory is zipped verbatim into the deployment package.

---

## 7. Verification — the disk ran out mid-deploy

`terraform init` failed here with "There is not enough space on the disk," not
from a config error. Three existing stacks (`detection`, `incident-01`,
`incident-02`) each held an independent 865 MB copy of the AWS provider,
because no shared plugin cache was configured — 2.6 GB of duplication for one
provider used four times. Deleting the three `.terraform/` directories (cache
only; state files live outside them and were untouched) recovered most of it,
and clearing residual download temp files
(`%TEMP%\terraform-provider*`, left behind by the failed installs) recovered
the rest.

An attempt to fix this permanently — a `~/.terraformrc` with
`plugin_cache_dir` — did nothing on Windows: Terraform on Windows reads
`%APPDATA%\terraform.rc`, not the Unix-style dotfile path. Left uncorrected,
that file would have sat there implying a cache was active when it never took
effect. Removed rather than fixed, since setting up the Windows-correct path is
out of scope for this phase.

### End-to-end test

`aws events put-events` cannot be used to test this pipeline: EventBridge
rejects any custom event whose `source` begins with `aws.` — reserved for AWS
services — so a hand-crafted `aws.securityhub` event can never be injected
onto the bus. [`detections/test-high-severity-alert.ps1`](../detections/test-high-severity-alert.ps1)
instead calls `securityhub batch-import-findings` with a synthetic finding,
which is the supported way to get a genuine Security Hub finding event onto
the bus, exercising the real event pattern rather than an approximation of it.

Three bugs surfaced and were fixed during this verification, all in the test
script rather than the infrastructure:

**A BOM broke JSON detection.** `Set-Content -Encoding utf8` on Windows
PowerShell 5.1 writes a UTF-8 byte-order mark. The AWS CLI decides whether
`file://` content is JSON by checking whether it starts with `{` or `[`; a BOM
in front of that character makes it fall back to shorthand `key=value` parsing
and fail with `Expected: '='` — a genuinely confusing error for what is really
an encoding problem. Fixed with `[System.IO.File]::WriteAllText` and a
BOM-less `UTF8Encoding`.

**A masking bug hid the first failure.** The import step checked
`$import.FailedCount -gt 0` without first checking `$LASTEXITCODE`. When the
CLI call above failed outright, `$import` was `$null`, and PowerShell
evaluates `$null.FailedCount -gt 0` as `$false` — so the script printed
`PASS imported` for a call that had never imported anything. The wait loop
then correctly found nothing and failed for the right reason, but the wrong
step got blamed. `$LASTEXITCODE` is now checked immediately after every `aws`
invocation in the script, before any output is parsed.

**`--record-state` isn't a real parameter.** `batch-update-findings` has no
`--record-state` option — `RecordState` can only be set through
`batch-import-findings`. Archiving the synthetic test finding now re-imports it
with `RecordState=ARCHIVED`, which is also a better test: it re-publishes the
finding to EventBridge with the archived state, proving the rule's
`RecordState` filter actually drops it rather than firing a second alert.

### Result

```
==> Importing synthetic HIGH finding
    PASS  imported id=lab-phase7-selftest-...

==> Waiting for the alert Lambda
...
==> Result
    PASS  alert logged for HIGH

SECURITY INCIDENT DETECTED

  Finding:   SYNTHETIC LAB FINDING - Phase 7 pipeline self-test (HIGH)
  Resource:  arn:aws:securityhub:us-east-1:<account-id>:lab/synthetic-test-resource
  Severity:  HIGH
  Account:   <account-id>
  Region:    us-east-1
  Timestamp: 2026-08-16T18:43:30.114Z

==> Archiving the synthetic finding
    PASS  archived
```

Negative case, run with `-Severity LOW -ExpectNoAlert`:

```
==> Result
    PASS  no alert for LOW - the rule filters as intended
```

DLQ confirmed empty after both runs. `lambda/tests/test_handler.py` — 13 unit
tests covering the severity filter, the mixed-batch re-filter, missing-field
handling, and the environment-variable path — all pass independently of any
deployment.

---

## 8. Cost

| Item | Cost |
| --- | --- |
| EventBridge rule matching an AWS-service event | $0.00 — free |
| Lambda invocations, lab volume | $0.00 — well inside the permanent 1M request / 400,000 GB-second free tier |
| SQS DLQ, empty | $0.00 — well inside the permanent 1M request free tier |
| CloudWatch Logs | bounded by `log_retention_days` (default 14) |

Nothing here is trial-based. Unlike GuardDuty and Security Hub, none of this
stack's cost stops being free after 2026-09-08.

---

## 9. Teardown

Long-lived, like `detection/` — not destroyed between sessions.

```powershell
cd terraform/response
terraform destroy
```

Removes the Lambda, its role and log group, the EventBridge rule and target,
and the DLQ. Security Hub and EventBridge's default bus are untouched — they
belong to `detection/` and to the account respectively.

---

## Next phase

The pipeline logs; it does not act. The two detection-backlog items this phase
was built to eventually serve —
[denied `iam:CreateAccessKey`](../detections/README.md#backlog) (INC-01) and
[near-real-time `PutBucketPolicy`](../detections/README.md#backlog) (INC-02) —
are GuardDuty/custom findings, not something GuardDuty raises today, so they
still need either a purpose-built detector or a CloudTrail-driven EventBridge
rule ahead of this one. The natural Phase 8 is turning `securityhub_alert`
from a logger into a responder: revoke a session, tighten a bucket policy, or
open a ticket, gated behind the same `harden`-style explicit trigger used in
Phase 6 rather than acting automatically on day one.
