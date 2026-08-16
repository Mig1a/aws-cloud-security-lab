# Phase 6 — Incident #2: Insecure S3 Configuration

**Date:** 2026-08-09
**Objective:** Build a deliberately misconfigured S3 bucket, detect it, investigate
it, remediate it, and verify the fix — with remediation expressed as a reviewable
diff rather than console clicks.
**Status:** Complete
**Depends on:** [Phase 5 — Incident #1](phase-5-incident-01.md)

The investigation write-up is the real deliverable:
**[incidents/incident-02-s3.md](../incidents/incident-02-s3.md)**.
This document covers how it was built.

---

## 1. One bucket, two postures

The obvious build is two buckets — one insecure, one hardened — or a console
click-through that turns settings off and back on. Both were rejected.

Instead, [`terraform/incident-02/s3.tf`](../terraform/incident-02/s3.tf) declares
a single bucket whose every control reads `var.harden ? secure : insecure`:

```hcl
block_public_acls       = var.harden
object_ownership        = var.harden ? "BucketOwnerEnforced" : "ObjectWriter"
status                  = var.harden ? "Enabled" : "Suspended"
policy                  = var.harden ? data...hardened.json : data...insecure.json
```

Three consequences, all of which are the point of the exercise:

**Remediation becomes a diff.** `terraform apply -var=harden=true` produced
`Plan: 2 to add, 5 to change, 0 to destroy` — a reviewable, repeatable,
auditable change. A sequence of console clicks leaves nothing to review
afterwards.

**Before and after are the same resource.** Comparing two buckets would compare
two different ARNs; the anonymous `GET` that returns `200` and the one that
returns `403` here hit an identical URL.

**The insecure state is reachable by accident, not by default.** `harden`
defaults to `false` — deliberately, so that the exercise starts at the
misconfiguration — but the variable carries an inline safety block stating that
public **write** is never configured at any setting, contents are synthetic, and
the exposure window should be minutes.

A `project_name` validation enforces the `cloudsec-lab-incident-` prefix, same as
Phase 5, so the bucket cannot fall outside the CloudTrail data-event selector and
produce an uninvestigable exercise.

---

## 2. The finding that no longer exists

The classic teaching example is the unencrypted S3 bucket. It is **no longer
reproducible.**

Since January 2023 AWS applies SSE-S3 to every new bucket automatically.
`get-bucket-encryption` returned `AES256` against a bucket with no encryption
resource declared at all.

So the exercise models the weakness that does still exist: not *absent*
encryption but *undeclared* encryption posture — an implicit default, no bucket
key, no policy requiring encrypted uploads. That distinction propagated into the
detection, where S3-4 is rated **WARN** rather than **FAIL**. Flagging it as a
failure would have been teaching a control that AWS already guarantees.

Five controls were left genuinely absent: Block Public Access, wildcard-principal
policy, ACLs, versioning, TLS enforcement.

---

## 3. Security Hub detected nothing

Phase 4 enabled Security Hub with 98 AWS Foundational Security Best Practices
controls, including `S3.1`, `S3.2`, `S3.3`, `S3.5` and `S3.8` — every one of them
directly relevant to a world-readable bucket.

**Zero findings.**

Those controls are evaluated by AWS Config rules, and AWS Config was never
enabled — a deliberate Phase 4 cost decision, since Config has no free tier and
bills per configuration item. Verified during the exercise:

```
aws configservice describe-configuration-recorders  ->  (empty)
aws securityhub get-findings --filters ResourceType=AwsS3Bucket  ->  0
```

The controls report `ENABLED` while detecting nothing. This was not a planned
part of the phase; it was found by checking whether the managed service had
caught the misconfiguration before writing anything custom. **An enabled control
is not a working control**, and a compliance dashboard showing green is
indistinguishable from one that is not looking.

That gap is what justified writing a detection at all —
[`detections/s3-posture-check.ps1`](../detections/s3-posture-check.ps1), six
controls, documented in [detections/README.md](../detections/README.md) as a
compensating control for a known, accepted cost trade-off.

### Validated in both directions

| State | Result |
| --- | --- |
| Insecure baseline | 5 FAIL, 1 PASS |
| After remediation | 6 PASS, 0 FAIL, exit code 0 |

Testing that a detection can return a **pass** matters as much as testing that it
fires. A check that only ever fails looks identical to a broken one — so
verification in §5 of the report deliberately re-runs the same script that found
the problem.

---

## 4. Two ordering problems in the Terraform

**A public policy cannot be written while Block Public Policy is on.** S3 rejects
it. Applying the insecure baseline therefore requires the access block to settle
first, which Terraform will not infer on its own:

```hcl
depends_on = [
  aws_s3_bucket_public_access_block.target,
  aws_s3_bucket_ownership_controls.target,
]
```

**Lifecycle rules depend on versioning.** `noncurrent_version_expiration` is
meaningless until versioning exists, so the lifecycle resource takes an explicit
`depends_on` against the versioning resource.

Both are cases where the security control and the resource graph disagree about
ordering, and the graph has to be corrected by hand.

---

## 5. Problems found during the phase

**PowerShell's JSON parser silently truncated the investigation.** `ConvertFrom-Json`
on 5.1 rejects JSON containing keys that differ only by case, and CloudTrail's
`PutBucketOwnershipControls` records contain both `ownershipControls` and
`OwnershipControls`. Four events were dropped from the parsed timeline, including
the calls that enabled and later disabled ACLs.

The errors were visible rather than silent, but the resulting timeline was
incomplete and would have been accepted as complete had the errors been
suppressed. An investigation tool that loses evidence produces confident,
incomplete timelines. Logged as remediation item 4 — still open.

**Evidence capture re-opened the exposure.** The "before" screenshots were not
taken during the original 2m23s window; remediation had already completed. The
insecure baseline was re-applied at ~20:20 UTC for roughly 15 minutes to capture
them, then hardened and re-verified.

This is recorded in §2 of the report rather than quietly omitted, because an
incident report that hides a second exposure is inaccurate. It also illustrates a
real tension: reproducing a misconfiguration for documentation re-opens the risk
being documented. In a production account the answer is to capture evidence
*during* the original window, or to reproduce in an isolated account.

**Screenshots carried the account ID.** Redacted from both browser captures
before commit; the unredacted originals were discarded rather than kept
alongside.

---

## 6. Cost

| Item | Cost |
| --- | --- |
| S3 bucket, 3 synthetic objects | fractions of a cent |
| CloudTrail management events | $0.00 — first copy is free |
| CloudTrail S3 data events (scoped to the incident prefix) | negligible |
| Security Hub / GuardDuty | $0.00 during trial |
| AWS Config | **$0.00 — not enabled, which is why §3 happened** |

The Phase 3 EC2 environment stayed destroyed throughout.

---

## 7. Teardown

```powershell
cd terraform/incident-02
terraform destroy
```

`force_destroy = true` is set, so the bucket empties itself — including
noncurrent versions once hardening has enabled versioning.

> Leave the bucket **hardened** if it is kept between sessions. `terraform apply`
> with no arguments re-applies `harden = false` and re-opens public read, because
> that is the variable's default.

---

## Next phase

[Phase 7 — Near-Real-Time Alerting via EventBridge](phase-7-eventbridge-alerting.md).
Both incidents converged on the same gap: detection here was a manual scan,
and the 2m23s exposure window was that short only by luck. Phase 7 wires
Security Hub findings through EventBridge to a Lambda so a HIGH/CRITICAL
finding produces an alert within seconds — the general pipeline that the
specific rules in the [detection backlog](../detections/README.md#backlog)
(denied `iam:CreateAccessKey`, near-real-time `PutBucketPolicy`) still need to
be built on top of.
