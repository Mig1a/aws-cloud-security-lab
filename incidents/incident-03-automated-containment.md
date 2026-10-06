# Incident 03 — Automated Containment's Live Fire-Drill

| Field | Value |
| --- | --- |
| **Incident ID** | INC-03 |
| **Type** | Data exposure (public S3 read) **and** a silent failure in the automation built to stop it |
| **Introduced** | 2026-10-02 20:53:53 UTC |
| **Detected (GuardDuty, automated)** | 2026-10-02 21:01:12 UTC |
| **Automated remediation attempted** | 2026-10-02 21:16:36 – 21:19:34 UTC (failed, ×3) |
| **Discovered (by the operator)** | 2026-10-06 ~19:08 UTC |
| **Remediated (manual)** | 2026-10-06 19:13:14 UTC |
| **Automation root-caused, fixed, re-verified** | 2026-10-06 19:24:20 UTC |
| **Exposure window** | **~94h19m** — the automated path never completed |
| **Analyst** | mella-admin, with Claude (Sonnet 5) driving the live exercise |
| **Account** | 089110987191 (us-east-1) |
| **Status** | Closed — remediated, root-caused, fixed, and re-verified against the real pipeline |

> **Training exercise, with an unplanned result.** The misconfiguration was
> introduced deliberately, against the same synthetic INC-02 exercise bucket
> used in [Incident 02](incident-02-s3.md), by flipping its `harden`
> Terraform variable to `false` — exactly as before. Public **read** only;
> public **write** was never configured. What was *not* planned: the
> [Phase 9](../docs/phase-9-automated-containment.md) automation built to
> contain this exact finding type crashed on every attempt and the exposure
> ran for days before a human noticed. That failure, not the misconfiguration
> itself, is the real subject of this report.

---

## Flow

```
Controlled event   CloudTrail        GuardDuty         EventBridge→Lambda    Containment attempted
  (PutBucketPolicy)  (records it)     (real detection)   (alert fires)         (crashes ×3, silently)
    20:53:53           20:53:53         21:01:12            21:16:36              21:16:36–21:19:34
                                                                                         │
                                                                              ~94 hours, undetected
                                                                                         │
                                                                                         ▼
                                                                          Operator discovers   19:08 (10-06)
                                                                          Manual remediation    19:13:14
                                                                          Root cause + fix      19:13–19:24
                                                                          Re-verified, live     19:24:20
```

---

## 1. The controlled security event

The INC-02 bucket (`cloudsec-lab-incident-02-089110987191`) was purpose-built
in [Phase 6](../docs/phase-6-incident-02.md) for exactly this: one bucket
whose every control reads `var.harden ? secure : insecure`, so reproducing
the misconfiguration is a one-line, reviewable Terraform diff rather than a
sequence of console clicks.

```
cd terraform/incident-02
terraform apply -var harden=false -auto-approve
```

This is a materially different, and more realistic, trigger than
[Phase 9](../docs/phase-9-automated-containment.md)'s own self-test, which
only ever toggles Block Public Access directly via `s3api
put-public-access-block`. This exercise instead reproduced the **actual**
original attack: `PutBucketPolicy` adding a public-read `Allow` statement
back — the same API call GuardDuty's finding already named as the cause of
the original INC-02 incident (`AccountId` `089110987191`, actor
`mella-admin`, finding ID `66cff41a3cd156e2591849cf30f0cfb1`, first raised
2026-08-09). Running this again against the same bucket reactivated the same
finding rather than minting a new one — GuardDuty aggregates repeat
occurrences of the same finding type against the same resource by
incrementing a counter on the existing finding, not by creating a new ID.

Confirmed exposed immediately after the apply:

```
GET https://cloudsec-lab-incident-02-089110987191.s3.amazonaws.com/internal/api-notes.txt
HTTP 200 — publicly readable, no AWS credentials sent
```

---

## 2. Real-time detection — this part worked

| Time (UTC) | Event | Source |
| --- | --- | --- |
| 20:53:46.229 | `terraform apply -var harden=false` started | Terraform / mella-admin |
| **20:53:53** | **`PutBucketPolicy`** — public read granted | CloudTrail, event `db633095-ee0f-4f6a-b03f-f78abddd6363` |
| 20:53:55.522 | Apply complete; anonymous `GET` confirmed `HTTP 200` | Manual verification |
| **21:01:12.184** | **GuardDuty finding updated** — `Policy:S3/BucketAnonymousAccessGranted`, `Count` 1→2, `EventLastSeen` = 20:53:53 | GuardDuty `get-findings` |
| 21:16:36.094 | **`SECURITY INCIDENT DETECTED`** logged by the Phase 7/8 alert Lambda | CloudWatch Logs, `cloudsec-lab-securityhub-alert` |

**GuardDuty's real detection latency was ~7m19s** (20:53:53 → 21:01:12) — a
genuine, useful data point against Phase 9's synthetic self-tests, which
skip this entirely via `BatchImportFindings` and report sub-second EventBridge
latency instead.

**A measurement gap worth naming explicitly:** Security Hub's own
`get-findings` response for this finding showed `UpdatedAt: 2026-10-02T21:01:12.184Z`
— identical to GuardDuty's own timestamp. Security Hub carries GuardDuty's
`UpdatedAt` through verbatim rather than stamping its own ingestion time, so
**that field cannot be used to measure how long Security Hub itself took to
import the finding.** The ~15-minute gap between GuardDuty's update
(21:01:12) and the alert Lambda actually firing (21:16:36) is real — the
alert Lambda's own invocation timestamp is the only reliable evidence of
when the finding actually reached EventBridge — but nothing in Security
Hub's finding record explains *where* in that chain the time went. Logged as
remediation item 5.

---

## 3. Automated containment — this part didn't

The Phase 9 containment Lambda (`cloudsec-lab-s3-containment`) was invoked
within the same second as the alert Lambda, off the same Security Hub event.
It then crashed, identically, three times:

| Invocation | Started (UTC) | Result |
| --- | --- | --- |
| 1 (initial) | 21:16:36.394 | Crash after 2676ms — `AttributeError` |
| 2 (Lambda's automatic async retry, ~59s later) | 21:17:35.244 | Crash after 205ms |
| 3 (Lambda's automatic async retry, ~2m later) | 21:19:34.592 | Crash after 257ms |

```
[ERROR] AttributeError: <botocore.errorfactory.S3Exceptions object at 0x...>
object has no attribute NoSuchPublicAccessBlockConfiguration. Valid exceptions
are: AccessDenied, BucketAlreadyExists, BucketAlreadyOwnedByYou,
EncryptionTypeMismatch, IdempotencyParameterMismatch, InvalidObjectState,
InvalidRequest, InvalidWriteOffset, NoSuchBucket, NoSuchKey, NoSuchUpload,
ObjectAlreadyInActiveTierError, ObjectNotInActiveTierError, TooManyParts
Traceback (most recent call last):
  File "/var/task/containment_handler.py", line 204, in lambda_handler
    results = [_handle_one(finding) for finding in findings]
  File "/var/task/containment_handler.py", line 165, in _handle_one
    except _s3_client().exceptions.NoSuchPublicAccessBlockConfiguration:
  File "/var/lang/.../botocore/errorfactory.py", line 51, in __getattr__
    raise AttributeError(...)
```

### Root cause: two independent bugs, each hiding the other

**Bug 1 — the deployed IAM policy granted the wrong action names.**
`terraform/response/containment_lambda.tf` granted
`s3:GetPublicAccessBlock` / `s3:PutPublicAccessBlock` — the boto3/botocore
*client method* names. The real IAM *action* names are
`s3:GetBucketPublicAccessBlock` / `s3:PutBucketPublicAccessBlock` (note
"Bucket"), confirmed directly from CloudTrail:

```
EventName:    GetBucketPublicAccessBlock
errorCode:    AccessDenied
errorMessage: User: arn:aws:sts::089110987191:assumed-role/cloudsec-lab-s3-containment-role/
              cloudsec-lab-s3-containment is not authorized to perform:
              s3:GetBucketPublicAccessBlock on resource:
              "arn:aws:s3:::cloudsec-lab-incident-02-089110987191" because no
              identity-based policy allows the s3:GetBucketPublicAccessBlock action
```

Every real invocation was denied at the IAM layer before the handler's logic
ever ran — the examine step's `get_public_access_block()` call always failed.

**Bug 2 — the handler's own exception matching crashed instead of
degrading.** The examine step was written to treat "no public access block
configured yet" as a clean, expected case:

```python
except _s3_client().exceptions.NoSuchPublicAccessBlockConfiguration:
    already_blocked = False
```

Python evaluates `except <expr>:` fresh, every time *any* exception needs
matching — and on this Lambda runtime's bundled botocore version, that
specific attribute does not exist. Evaluating it raised its own
`AttributeError`, which is **not** caught by the `except Exception` clause
written immediately below for exactly this kind of situation — because the
new error occurs while Python is still evaluating the *first* clause's type,
never inside the `try`. The result: any exception at all from the examine
step — this `AccessDenied`, or anything else — became an unhandled crash
instead of the intended `examine_failed` log line.

**Why neither bug was caught before this.** Phase 9's 31 unit tests all
passed, and `terraform plan`/`validate` were clean, because:

- The unit test suite's hand-rolled fake S3 client defined
  `exceptions.NoSuchPublicAccessBlockConfiguration` as a real class, always —
  because the test author wrote it to exist. It modeled the interface the
  code *expected*, not the version-dependent reality of a real botocore
  client. A test double that is too accommodating is a false negative
  waiting to happen.
- No unit test makes a real AWS call, by design (`lambda/README.md`'s own
  stated reasoning) — so an IAM action-name typo is structurally invisible
  to that suite, regardless of how thorough it is otherwise.
- `terraform plan`/`validate` check the *shape* of a policy document, not
  whether its action strings are real IAM actions AWS will actually honor.

**Why the dead-letter queue didn't catch it either.** The containment DLQ
built in Phase 9 is attached to the EventBridge rule *target* — it only
catches EventBridge failing to invoke the Lambda at all (e.g. a missing
`lambda:InvokeFunction` permission). Here, EventBridge successfully invoked
the Lambda all three times; the function was invoked fine and then failed
internally every time, after exhausting its own default two automatic
asynchronous-invocation retries. That is a distinct AWS failure mode,
governed by the **function's own** `dead_letter_config` — which did not
exist until this incident's fix. Confirmed: `ApproximateNumberOfMessages: 0`
on the DLQ throughout, despite three real failures.

---

## 4. The exposure window

With the automated path silently failing, the bucket remained publicly
readable from the original `PutBucketPolicy` call until a human checked:

```
2026-10-02 20:53:53 UTC  →  2026-10-06 19:13:14 UTC   =  ~94h19m
```

Nothing in the account surfaced this independently. Security Hub's own
console would have kept showing the finding as `NEW`/`ACTIVE` the entire
time — Security Hub has no concept of "a response was attempted and failed,"
only whether a finding itself is active. The gap was found only because this
exercise's own operator returned to the session days later and manually
re-checked the bucket's state rather than trusting the automation had
handled it. In a production account with no one watching, this is an
indefinite exposure, not a 2-minute one.

---

## 5. Remediation

**Manual, immediate, on discovery** — restoring the bucket's full hardened
posture (bucket policy, Block Public Access, versioning, object ownership),
same mechanism as the original misconfiguration:

```
cd terraform/incident-02
terraform apply -var harden=true -auto-approve
# Plan: 2 to add, 5 to change, 0 to destroy
```

Confirmed at 2026-10-06 19:13:14 UTC (`PutBucketPolicy`, CloudTrail event
`ec654174-5910-44df-802d-1f810667429f`):

```
aws s3api get-public-access-block  ->  all four settings true
GET .../internal/api-notes.txt     ->  HTTP 403 AccessDenied
```

**Then the automation itself**, in `terraform/response/`:

1. `containment_lambda.tf` — corrected the IAM action names to
   `s3:GetBucketPublicAccessBlock` / `s3:PutBucketPublicAccessBlock`; added a
   function-level `dead_letter_config` (reusing the existing containment
   DLQ) plus the `sqs:SendMessage` permission it requires, so a future
   internal function failure is no longer invisible.
2. `containment_handler.py` — replaced the dynamic
   `_s3_client().exceptions.NoSuchPublicAccessBlockConfiguration` lookup with
   a `botocore.exceptions.ClientError` catch keyed on the error's string
   `Code` — stable across botocore versions, since error codes are part of
   the AWS API contract and generated Python class names are not.
3. `test_containment_handler.py` — the fake S3 client now raises a real
   `botocore.exceptions.ClientError`, not a hand-rolled stand-in that always
   matched; added `test_access_denied_on_examine_is_logged_not_crashed`,
   which reproduces this exact failure and asserts a clean `examine_failed`
   instead of a crash.

---

## 6. Verification

Unit suite, 32/32 (31 prior + the new regression test), independent of any
deployment:

```
$ python -m pytest lambda/tests/ -q
................................                                         [100%]
32 passed in 1.62s
```

Redeployed via `terraform apply` (1 to add, 2 to change, 0 to destroy —
exactly the IAM policy, the new SQS-send permission, and the function's code
+ `dead_letter_config`). Then re-verified against the **live, real** pipeline
with [`detections/test-automated-containment.ps1`](../detections/test-automated-containment.ps1),
all three scenarios:

```
Contain:
  PASS  logged 'contained' as expected
  PASS  S3 confirms Block Public Access is restored - the Lambda actually
        made the API call
  PASS  DLQ empty

WrongResource:
  PASS  correctly skipped - skipped_resource_not_allowlisted
  PASS  DLQ empty

WrongType:
  PASS  no invocation for a non-matching finding type - the rule filters
        as intended
  PASS  DLQ empty
```

`contained` logged at 2026-10-06 19:24:20.259Z, confirmed against the real
S3 API, not just the log line — the same verification standard
[Incident 02](incident-02-s3.md) used for its own remediation.

---

## 7. Severity

### As executed — **Medium**

Synthetic bucket, public **read** only, no real data, and the exposure was
eventually caught and closed within the same operator session that
discovered it. Nothing indicates the exposure was found or used by anyone
else in the ~94-hour window (S3 data events remain enabled for this bucket
prefix per Phase 5 and show no anonymous `GetObject` beyond this exercise's
own verification requests).

### If genuine — **Critical**

| Factor | Assessment |
| --- | --- |
| Confidentiality | **High** — same as INC-02's assessment, now sustained for days instead of minutes |
| Availability of the control | **Critical** — the control an operator would reasonably trust to have closed this (automated containment) silently did not, with no alert that it hadn't |
| Discoverability | **High** — automated internet-wide bucket scanners operate continuously; days, not minutes, of exposure |
| Blast radius of the automation bug | Affects **every** future finding of this exact type against this exact bucket, not a one-time fluke — the fix was necessary, not optional |

A security control that fails open *and silently* is worse than having no
control at all, because it actively produces false confidence. That gap —
not the bucket policy — is the real finding of this incident.

---

## 8. Affected Resources

| Resource | Identifier | Impact |
| --- | --- | --- |
| S3 bucket | `cloudsec-lab-incident-02-089110987191` | Publicly readable for ~94h19m |
| Object | `internal/api-notes.txt` | Exposed; read only during this exercise's own verification |
| Lambda function | `cloudsec-lab-s3-containment` | Crashed on every real invocation until fixed in this incident |
| IAM role | `cloudsec-lab-s3-containment-role` | Policy corrected (action names) |
| SQS queue | `cloudsec-lab-s3-containment-dlq` | Gained a second producer (the function's own `dead_letter_config`), previously fed only by the EventBridge target |

Defined in [terraform/incident-02/](../terraform/incident-02/) and
[terraform/response/](../terraform/response/).

---

## 9. Lessons Learned

**Dry-run confidence and "it actually works" are different claims.**
Phase 9 shipped with passing unit tests, clean `terraform plan`/`validate`,
and a documented recommendation to re-verify live — and still shipped a
Lambda that could never once succeed against the real API, because none of
those checks exercise real IAM authorization.

**A mock that always provides what the code expects can't catch a bug in
that expectation.** The test suite's fake S3 client defined the exact
exception class the handler looked for, unconditionally — which is precisely
backwards from how a real, version-pinned botocore client behaves. The fix
reproduces this in the test suite itself, not just in the handler.

**`except <expression>:` is not free to evaluate.** An `except` clause's own
type expression can raise, and that new exception is not caught by sibling
`except` clauses on the same `try` — only by an enclosing one. Dynamic
attribute lookups (`client.exceptions.SomeName`) are exactly the kind of
expression this can bite, especially across SDK/runtime versions.

**A dead-letter queue attached to an EventBridge target does not cover the
function failing internally.** Those are two different AWS failure
boundaries. A Lambda meant to be the last line of defense for a security
finding needs its **own** `dead_letter_config`, not just one on the rule
that invokes it.

**An IAM action name and an SDK method name are not always the same
string.** `GetPublicAccessBlock`/`PutPublicAccessBlock` (botocore) vs.
`GetBucketPublicAccessBlock`/`PutBucketPublicAccessBlock` (IAM, and
CloudTrail's `eventName`) is an easy, silent typo with no error at
`terraform plan` time — only at the moment the policy is actually evaluated
against a real request.

**Automation that fails silently is worse than manual response.** INC-02's
manual exposure window was 2m23s because a human was actively watching.
INC-03's automated exposure window was ~94 hours because nothing was.
Automating a response raises, not lowers, the bar for making its *failure*
loud.

---

## 10. Remediation Items

| # | Action | Status |
| --- | --- | --- |
| 1 | Fix the containment IAM policy's action names | **Done** |
| 2 | Fix the brittle exception match in `containment_handler.py` | **Done** |
| 3 | Add a function-level `dead_letter_config` to the containment Lambda | **Done** |
| 4 | Re-verify all three self-test scenarios against the live pipeline | **Done** |
| 5 | Investigate what Security Hub's `UpdatedAt` field actually represents, and find a field (if one exists) that measures true Security Hub ingestion latency | Open |
| 6 | Alarm on the containment DLQ having any message > 0 (CloudWatch alarm → the account owner), rather than relying on someone reading this report | Open |
| 7 | Alarm on the containment Lambda's own `Errors` metric, independent of the DLQ, so a crash is visible within minutes, not days | Open |
| 8 | Decide whether unit tests for AWS-integrated handlers should assert against the real shape of `botocore.exceptions.ClientError` by convention, to prevent a recurrence of the Bug 1/Bug 2 pattern elsewhere in this repo | Open |

Items 6 and 7 matter most: this incident was found by luck — an operator
happening to recheck — not by anything the system itself surfaced. The whole
point of Phase 9 was to not depend on that.

---

## Related

- Build notes: [docs/phase-9-automated-containment.md](../docs/phase-9-automated-containment.md) (§11 postmortem)
- Build notes: [docs/phase-10-live-fire-drill.md](../docs/phase-10-live-fire-drill.md)
- Handler: [lambda/incident_containment/containment_handler.py](../lambda/incident_containment/containment_handler.py)
- Tests: [lambda/tests/test_containment_handler.py](../lambda/tests/test_containment_handler.py)
- Infrastructure: [terraform/response/containment_lambda.tf](../terraform/response/containment_lambda.tf)
- Self-test: [detections/test-automated-containment.ps1](../detections/test-automated-containment.ps1)
- Previous incident: [incident-02-s3.md](incident-02-s3.md)
