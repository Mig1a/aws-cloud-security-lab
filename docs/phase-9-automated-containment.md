# Phase 9 — Automated Containment

**Date:** 2026-08-16 (postmortem addendum: 2026-10-06, see §11)
**Objective:** Turn the Phase 8 handler from observer into responder, for
exactly one known finding type against exactly one known resource — not
"any HIGH finding → act."
**Status:** Complete — **with a postmortem.** This phase's first real exercise
(Phase 10) found the deployment silently non-functional. See §11 and
[incidents/incident-03-automated-containment.md](../incidents/incident-03-automated-containment.md).
**Depends on:** [Phase 8 — The Incident Handler](phase-8-incident-handler.md),
[Phase 6 — Incident #2 (insecure S3 configuration)](phase-6-incident-02.md)

Handler: [lambda/incident_containment/containment_handler.py](../lambda/incident_containment/containment_handler.py).
Tests: [lambda/tests/test_containment_handler.py](../lambda/tests/test_containment_handler.py).
Terraform: [terraform/response/containment_lambda.tf](../terraform/response/containment_lambda.tf),
[terraform/response/containment_eventbridge.tf](../terraform/response/containment_eventbridge.tf).
Self-test: [detections/test-automated-containment.ps1](../detections/test-automated-containment.ps1).

---

## 1. The scope decision

Phase 7's "Next phase" note and the Phase 8 backlog item both described this
the same loose way: act on a finding instead of just logging it. Read
literally, the easiest version is "every HIGH/CRITICAL finding the alert
Lambda already sees → try to fix it." That's also the version that turns one
Lambda into the single most dangerous thing in the account — a function with
standing write access to an unbounded set of resources, triggered by
whatever Security Hub happens to import next.

This phase is deliberately the opposite shape:

```
known finding type  +  known lab resource  +  approved remediation  →  Lambda
```

Each of those three is a hard boundary, not a convention:

- **Known finding type** — one ASFF `Types` value,
  `TTPs/Policy:S3-BucketAnonymousAccessGranted`. This is GuardDuty's native
  `Policy:S3/BucketAnonymousAccessGranted` as it actually renders once
  imported into Security Hub — verified against a real finding already
  present in this account, not guessed from documentation. The `/` inside
  `Policy:S3` becomes `-`, and the whole type is namespaced under `TTPs/`.
- **Known lab resource** — an explicit bucket-ARN allowlist
  (`containable_resource_arns`), defaulting to this lab's own INC-02 exercise
  bucket. Not a prefix. A finding against a bucket not on this exact list is
  logged and skipped, never acted on — a hypothetical `incident-03` bucket
  does not inherit this permission just by sharing a naming convention.
- **Approved remediation** — one idempotent call,
  `s3:PutPublicAccessBlock` with all four settings `true`. Not a policy
  rewrite, not a delete, nothing that can destroy data. It restores the
  specific control Phase 6 hardened and this finding type reports as
  missing — nothing more.

---

## 2. Architecture

A second EventBridge rule, not a branch inside the existing one:

```
GuardDuty finding
      │
      ▼
Security Hub (import)
      │
      ├──────────────────────────────┐
      ▼                              ▼
 alert rule                   containment rule
 (HIGH/CRITICAL, any type)    (exact Types match only)
      │                              │
      ▼                              ▼
 incident_handler.py          containment_handler.py
 (Phase 7/8 — logs only)      (Phase 9 — examine → act)
                                      │
                               ┌──────┴──────┐
                               ▼             ▼
                        allow-listed?   AUTO_CONTAIN_ENABLED?
                               │             │
                               └──────┬──────┘
                                      ▼ (only if both yes)
                          s3:PutPublicAccessBlock
                                      │
                                      ▼
                            structured log line
                           (every branch, always)
```

The alert rule stays broad on purpose — it only logs, so a wide net costs
nothing. The containment rule is scoped down to the one `Types` value this
Lambda is built to act on. The Lambda re-checks that same type (and the
resource allowlist) in code — defense in depth, same reasoning as the
severity re-filter in `incident_handler.py` (Phase 7 §3) — but a finding of
any other type never even reaches this Lambda's invocation count, which is a
stronger guarantee than a code-level check that could have a bug in it.

---

## 3. Two independent gates, not one

`enable_auto_containment` (a boolean) and `containable_resource_arns` (an
allowlist) are deliberately separate Terraform variables rather than one
combined "is this safe" flag:

| `enable_auto_containment` | `containable_resource_arns` | Result |
| --- | --- | --- |
| `false` | anything | Every check runs, every decision is logged, no API call is ever made |
| `true` | `[]` | The role has **no S3 permissions at all** (see §4) — physically cannot act on anything |
| `true` | `[bucket-arn]` | Acts only on that bucket, only for the one known finding type |

Either gate alone being restrictive is not enough by design — both must agree
before anything is touched. The default is `false` / the lab's own INC-02
bucket, so a fresh `terraform apply` deploys in dry-run mode: the function
runs on every matching finding, examines the real resource, and logs exactly
what it *would* do, with no mutating call made. The intended operator
sequence is: deploy with the switch off, review a few
`would_contain_but_disabled` log lines, and only then flip
`enable_auto_containment = true` in `terraform.tfvars`.

---

## 4. IAM: the only write permission in the lab

Every other identity in this repo either reads, or writes only through
Terraform's own execution. `aws_iam_role.containment` is the one exception,
and its policy is scoped as tightly as the job allows:

```hcl
actions   = ["s3:GetPublicAccessBlock", "s3:PutPublicAccessBlock"]
resources = local.containable_resource_arns   # exact ARNs, never a wildcard
```

Two details worth calling out:

- **`GetPublicAccessBlock` is granted alongside `PutPublicAccessBlock`.** The
  handler's "examine resource" step (see the flow diagram in the Phase 9
  brief) calls `get_public_access_block` before ever considering a write, so
  a re-delivered EventBridge event (at-least-once delivery) produces
  `already_contained` instead of a second, indistinguishable `contained`
  log line. Without the read permission, that idempotency check itself would
  fail closed in the wrong way — as `examine_failed`, not as a clean skip.
- **The policy document has `count = length(...) > 0 ? 1 : 0`.** If an
  operator sets `containable_resource_arns = []`, the role gets *no S3
  statement attached at all*, not a policy with an empty `resources` list.
  Some providers reject an empty resource list outright, and an empty list
  is a confusing way to represent "nothing is allowed" even when accepted —
  no permissions attached is the unambiguous version.

---

## 5. What the handler actually checks, in order

`_handle_one()` in `containment_handler.py` runs five checks per finding,
every one of them logged regardless of outcome:

1. **Type match** — `finding.Types` intersects `CONTAINABLE_FINDING_TYPES`.
   Fails → `skipped_unknown_type`.
2. **Resource present** — the finding carries an `AwsS3Bucket` resource.
   Deliberately *not* `Resources[0]`: a real GuardDuty S3 finding in this
   account lists the IAM principal that made the API call before the
   affected bucket, so indexing `[0]` would silently act on whichever
   resource happened to be listed first. Missing → `skipped_no_s3_resource`.
3. **Resource allow-listed** — the bucket ARN is in
   `CONTAINABLE_RESOURCE_ARNS`, checked as exact membership. Fails →
   `skipped_resource_not_allowlisted`.
4. **Already contained?** — `get_public_access_block` on the real bucket.
   All four settings already `true` → `already_contained`, no write
   attempted. This is also what makes a duplicate EventBridge delivery safe.
5. **Switch check** — `AUTO_CONTAIN_ENABLED`. Off → logs
   `would_contain_but_disabled` and stops. On → calls
   `put_public_access_block` with all four settings `true`, then logs
   `contained`.

Every branch, including the five skip/no-op outcomes, writes one structured
JSON line via `LOG.warning()` — finding ID, matched types, bucket ARN, the
live value of `AUTO_CONTAIN_ENABLED`, and a free-text detail. A containment
function that stays silent when it decides *not* to act is unauditable on
exactly the occasions that matter most for reviewing whether its judgment
was right — so every path through `_handle_one()` is equally visible in
CloudWatch Logs, not just the one that calls a mutating API.

The handler never raises: every failure mode (a malformed finding, an S3 API
error on either the read or the write) is caught, logged as its own named
action (`examine_failed`, `contain_failed`), and returned per-finding, so one
bad record in a batch can't take the rest of the batch down with it.

---

## 6. Delivery guarantees

Same DLQ pattern as the alert rule (Phase 7 §4), on its own queue:

```hcl
retry_policy {
  maximum_event_age_in_seconds = 3600
  maximum_retry_attempts       = 3
}
dead_letter_config {
  arn = aws_sqs_queue.containment_dlq.arn
}
```

A dropped containment event is a worse outcome here than a dropped alert
log line — it means a real exposure went uncontained with no record of why —
so the same three retries plus dead-letter-on-exhaustion applies, into a
dedicated `cloudsec-lab-s3-containment-dlq` rather than sharing the alert
Lambda's queue. A message landing there is always worth investigating; it
should be empty in steady state.

---

## 7. Deployment

```hcl
# versions.tf
Phase = "7-9" # alerting (7), field extraction (8), containment (9)
```

Applied against the already-live `terraform/response/` stack — new resources
added alongside the existing alert pipeline, nothing in it touched:

```
+ aws_cloudwatch_event_rule.s3_anonymous_access
+ aws_cloudwatch_event_target.containment_lambda
+ aws_cloudwatch_log_group.containment
+ aws_iam_role.containment
+ aws_iam_role_policy.containment_logs
+ aws_iam_role_policy.containment_s3[0]
+ aws_lambda_function.containment
+ aws_lambda_permission.allow_eventbridge_containment
+ aws_sqs_queue.containment_dlq
+ aws_sqs_queue_policy.containment_dlq
```

Re-confirmed while writing this doc: `terraform plan` against the live
account reports **no changes** — the deployed stack still matches this
configuration exactly, and `terraform fmt -check -recursive` /
`terraform validate` both pass clean. Current live settings, read back via
`terraform output`:

```
auto_containment_enabled  = false
containable_finding_types = ["TTPs/Policy:S3-BucketAnonymousAccessGranted"]
containable_resource_arns = ["arn:aws:s3:::cloudsec-lab-incident-02-<account-id>"]
```

— i.e. deployed in dry-run mode, as intended, against this lab's own INC-02
bucket.

---

## 8. Testing

`lambda/tests/test_containment_handler.py` — 14 tests, independent of any
deployment (mocked S3 client, no network calls): the three skip conditions
(unknown type, no S3 resource, resource not allow-listed), the
`Resources[0]`-is-not-assumed-to-be-the-bucket regression case, the
already-blocked no-op, examine/contain failure handling, the disabled-switch
path making no API call, the enabled path calling `put_public_access_block`
with all four settings, multi-finding independence, and that every branch
logs valid JSON. Combined with Phase 8's 17, the full `lambda/tests/` suite
is 31 tests, all passing:

```
$ python -m pytest lambda/tests/ -q
...............................                                          [100%]
31 passed in 2.34s
```

[`detections/test-automated-containment.ps1`](../detections/test-automated-containment.ps1)
is the end-to-end counterpart, exercising the real path — a genuine
`PutPublicAccessBlock` precondition, a synthetic `BatchImportFindings`
finding, and a real wait on CloudWatch Logs — in three scenarios:

- **`Contain`** (default) — flips Block Public Access off on the real
  allow-listed bucket, imports a finding matching both the known type and
  the known resource, and verifies against the live S3 API that the Lambda
  restored it (or, with the switch off, that it correctly did *not* touch
  the bucket and logged the dry-run line instead).
- **`WrongResource`** — same finding type, against a bucket ARN that isn't
  on the allowlist. Proves the resource check, not just the type check.
- **`WrongType`** — the real bucket, but a finding type the EventBridge rule
  doesn't match. Expects *no invocation at all* — proves the rule itself is
  the first line of defense, not only the Lambda's internal logic.

This script's current form includes a fix (committed alongside this phase)
for a PowerShell-specific bug found while running it for real: a
backtick-escaped or single-quoted embedded `"..."` is silently dropped when
PowerShell hands the argument to the `aws` CLI's native exe, confirmed via
`aws --debug` — the API received `filterPattern` with no quotes at all.
`test-high-severity-alert.ps1`'s multi-word phrase happened to still match
every word independently even split apart, which is why Phase 7/8 never
surfaced this; a hyphenated, single-token finding ID does not, which is how
this script caught it. Both scripts now use the backslash-escaped form
(`\"...\"`) that survives the PowerShell-to-argv boundary intact.

The `containment_log_group`'s 14-day retention (same `log_retention_days`
default as the alert Lambda) means the evidence from that run has since
rolled off. **Re-running `test-automated-containment.ps1` end to end — all
three scenarios — is the concrete next step**, both to re-confirm the live
path and to capture the screenshots listed in
[screenshots/README.md](../screenshots/README.md#phase-9--automated-containment).

---

## 9. Cost

- Containment Lambda: same free-tier math as the alert Lambda (Phase 7 §6) —
  $0.00 at lab invocation volume.
- One additional CloudWatch log group, 14-day retention: negligible.
- One additional SQS queue: free tier covers this volume indefinitely.
- No new always-on compute. The only resource this phase can ever modify
  (the INC-02 bucket's public access block) is a metadata flag, not billed
  storage or compute.

---

## 10. Teardown

No separate teardown. `terraform destroy` in `terraform/response/` (Phase 7
§9) removes the containment Lambda, its role, its EventBridge rule, and its
DLQ along with everything else in that stack. If a `Contain`-scenario test
run is ever interrupted with `enable_auto_containment = false`, the INC-02
bucket is left with Block Public Access off until either the switch is
turned on and the rule re-fires, or it's restored manually:

```powershell
aws s3api put-public-access-block --bucket <bucket> --public-access-block-configuration `
  BlockPublicAcls=true,IgnorePublicAcls=true,BlockPublicPolicy=true,RestrictPublicBuckets=true
```

---

## Next phase

The containment Lambda can act on exactly one finding type against exactly
one resource. The backlog items in
[detections/README.md](../detections/README.md#backlog) — a CloudTrail-driven
rule that doesn't depend on Security Hub, denied-IAM-action detectors, root
account usage — are all still open, and none of them currently has a
containment path the way this phase's S3 finding does. Extending this
pattern to a second finding type means adding a second explicit entry to
both `containable_finding_types` and a matching remediation branch in the
handler — never widening the existing match to "any HIGH finding," for the
same reason this phase started narrow.

---

## 11. Postmortem (added 2026-10-06)

**This phase's own verification (§8) never actually exercised the real
failure path.** The unit tests passed, `terraform plan`/`validate` were
clean, and the live account matched configuration — all true, and all
insufficient. The first time this Lambda was exercised against a real,
live-fire GuardDuty detection (Phase 10), it crashed on every invocation and
the bucket it was supposed to protect sat publicly exposed for **about 94
hours** before anyone noticed. Full incident writeup:
[incidents/incident-03-automated-containment.md](../incidents/incident-03-automated-containment.md).

Two independent bugs, each hiding the other:

1. **Wrong IAM action names.** §4 above granted `s3:GetPublicAccessBlock` /
   `s3:PutPublicAccessBlock` — the boto3/botocore *client method* names, not
   the actual IAM *action* names (`s3:GetBucketPublicAccessBlock` /
   `s3:PutBucketPublicAccessBlock` — note "Bucket", confirmed from the real
   `AccessDenied` error and matching CloudTrail `eventName`). Every real
   invocation was denied at the IAM layer before it could do anything.
2. **The examine step's own exception handling crashed instead of
   degrading.** `except _s3_client().exceptions.NoSuchPublicAccessBlockConfiguration`
   evaluates that attribute fresh every time any exception needs matching —
   and on this Lambda runtime's bundled botocore version, that attribute
   doesn't exist, so the attempt to check it raised its own `AttributeError`.
   That error is not caught by the `except Exception` immediately below it
   (it happens while evaluating the *first* except clause's type, not inside
   the `try`), so it escaped as an unhandled crash instead of the intended
   `examine_failed` log line.

**Why §8's "31/31 tests pass" didn't catch either one.** The unit test suite
used a hand-rolled fake S3 client whose `exceptions.NoSuchPublicAccessBlockConfiguration`
*always existed*, because the test author wrote it to exist — it modeled the
interface the code expected, not the version-dependent reality of a real
botocore client. And no unit test exercises IAM at all; that category of bug
is invisible to a test suite that never makes a real AWS call, by
construction. Neither gap was a testing mistake exactly — it's what *every*
offline unit test suite is structurally blind to. The lesson carried forward:
mocks that are too accommodating are a false negative waiting to happen, and
dry-run/`terraform plan` confidence is not the same claim as "this actually
works against the real API."

**Why the dead-letter queue didn't catch it either.** §6's DLQ only covers
EventBridge failing to *invoke* the Lambda. Here, EventBridge invoked it
successfully three times (Lambda's own default two automatic retries on an
async invocation error) and the function itself failed all three — a
distinct failure mode that needs the function's *own*
`dead_letter_config`, which did not exist until this postmortem added one.
The exact gap Phase 9 §5 warned about in prose — "a containment function
that stays silent... is unauditable" — existed in the infrastructure too,
not just the application code.

**Fixed, same day, verified against the real deployed pipeline:**

- `terraform/response/containment_lambda.tf` — corrected action names;
  added a function-level `dead_letter_config` (shares the existing DLQ) plus
  the `sqs:SendMessage` permission it needs.
- `lambda/incident_containment/containment_handler.py` — replaced the
  dynamic `.exceptions.X` lookup with a `botocore.exceptions.ClientError` +
  string error-code check, which is stable across botocore versions.
- `lambda/tests/test_containment_handler.py` — the fake client now raises a
  real `botocore.exceptions.ClientError` instead of a hand-rolled stand-in,
  and a new regression test (`test_access_denied_on_examine_is_logged_not_crashed`)
  reproduces the exact production failure.
- Re-verified with [`detections/test-automated-containment.ps1`](../detections/test-automated-containment.ps1)
  against the live, redeployed pipeline — all three scenarios (`Contain`,
  `WrongResource`, `WrongType`) pass, with the `Contain` scenario confirming
  via the real S3 API that the Lambda's own `PutPublicAccessBlock` call
  restored Block Public Access, not just that a log line said so.
