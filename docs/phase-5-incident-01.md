# Phase 5 — Incident #1: IAM Investigation

**Date:** 2026-08-09
**Objective:** Create a deliberately limited IAM role, generate controlled
activity with it, and investigate that activity in CloudTrail.
**Status:** Complete
**Depends on:** [Phase 4 — Detection Services](phase-4-detection-services.md)

The investigation write-up is the real deliverable:
**[incidents/incident-01-iam.md](../incidents/incident-01-iam.md)**.
This document covers how it was built.

---

## 1. The problem found before starting

Phase 4 enabled CloudTrail with **management events only**, and explicitly
disabled data events to avoid a runaway bill.

That would have made this phase pointless. S3 `GetObject`, `PutObject`,
`DeleteObject`, and `ListObjects` are **data events**. With data events off,
an investigation into who read what from a bucket returns nothing.

### Fix, scoped for cost

`terraform/detection/cloudtrail.tf` now uses advanced event selectors: one for
management events, one for S3 data events **restricted by ARN prefix** to
`arn:aws:s3:::cloudsec-lab-incident-`.

```hcl
field_selector {
  field       = "resources.ARN"
  starts_with = var.s3_data_event_arn_prefixes
}
```

Only lab incident buckets are covered, so the per-event billing applies to a
handful of deliberate test actions rather than all account activity. Set
`s3_data_event_arn_prefixes = []` to turn it off.

A `project_name` validation in `terraform/incident-01/` enforces the matching
prefix, so a future incident stack cannot silently fall outside the selector
and produce an uninvestigable exercise.

---

## 2. A role, not a user with access keys

The brief allowed either. A role was chosen for two reasons:

**No long-lived credentials.** Assuming a role issues short-lived STS
credentials. Creating an IAM user with an access key would have written a
long-lived secret into Terraform state — recoverable, leakable, and needing
rotation.

**Better evidence.** Role assumption produces an `sts:AssumeRole` event and then
attributes every later action to
`assumed-role/<role>/<session-name>`. That session name is the single field an
analyst pivots on to reconstruct one actor's activity — which is precisely the
skill this phase practises.

### The permission boundary

| Allowed | Denied |
| --- | --- |
| `s3:ListBucket` where prefix matches `reports/*` | Everything else |
| `s3:GetObject` on `reports/*` | `restricted/*` — explicit `Deny` |
| | All writes, deletes, and all of IAM |

Session duration is capped at one hour.

The explicit `Deny` on `restricted/*` is redundant against an allow-list, but an
explicit deny cannot be overridden by a later grant and produces an unambiguous
denial in the logs.

---

## 3. Generating the activity

[`incidents/incident-01/generate-activity.ps1`](../incidents/incident-01/generate-activity.ps1)
assumes the role and runs 12 steps: 5 that should succeed and 7 that should be
refused.

The denials are the point. `AccessDenied` events record **intent** — what an
actor tried, independent of whether it worked. The script deliberately includes
IAM enumeration (`ListUsers`), a privilege-escalation attempt
(`CreateAccessKey` against the admin user), and lateral enumeration
(`ListAllMyBuckets`).

All 12 behaved as predicted. Temporary credentials are scoped to the script
process and cleared on exit.

---

## 4. Investigating

[`incidents/incident-01/investigate.ps1`](../incidents/incident-01/investigate.ps1)
follows the standard method: find the pivot, expand to the session, isolate the
denials, save evidence.

### Result: 4 of 11 actions visible

| Source | Events found |
| --- | --- |
| `lookup-events` (management) | 4 |
| S3 log files (data) | 7 |

`aws cloudtrail lookup-events` and the console's Event History return
**management events only**. Stopping there would have concluded the actor did
almost nothing — missing two file reads, an attempted read of a restricted file,
an attempted delete, and an attempted object plant.

Data events had to be pulled from the delivered log files in S3, decompressed,
and filtered on `eventCategory == "Data"`.

### Latency observed

Management events took **4–5 minutes** to appear in Event History; S3 log
delivery ran **5–15 minutes** behind. An investigation opened immediately after
an event sees an incomplete picture.

---

## 5. Two defects fixed during the phase

**Silent undercount in `investigate.ps1`.** PowerShell 5.1 returns nothing for
`.Count` on a single object, so the "allowed" tally rendered blank instead of
`1`. Wrapped the collections in `@()`. Worth noting because the failure mode was
a *quietly wrong number* in an investigation tool, not an error.

**Evidence contained sensitive values.** The raw CloudTrail JSON includes the
analyst's real public IP and, on the AssumeRole record, the issued session
token. `incidents/**/evidence/` is now gitignored, and the source IP is redacted
in the published report.

---

## 6. Cost

| Item | Cost |
| --- | --- |
| IAM role and policy | $0.00 |
| S3 test bucket, 3 small objects | fractions of a cent |
| CloudTrail data events (7 events, scoped) | negligible |
| GuardDuty / Security Hub | $0.00 during trial |

The Phase 3 EC2 environment stayed destroyed throughout, so the expensive
component was never running.

---

## 7. Teardown

```powershell
cd terraform/incident-01
terraform destroy
```

Removes the role, bucket, and test objects. The detection stack and its data
event selector stay in place for the next incident.

---

## Next phase

Phase 6 — turn finding 5 from the report into a detection: alert on denied IAM
actions, particularly `iam:CreateAccessKey`, and store the rule in
[detections/](../detections/). GuardDuty raised nothing for this activity, and
correctly so; catching it needs a purpose-built rule.
