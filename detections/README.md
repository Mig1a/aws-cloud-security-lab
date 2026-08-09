# Detections

Detection logic for this lab. Each entry states what it looks for, why it exists
rather than relying on a managed service, and how it was validated.

---

## Why custom detections at all

Security Hub is enabled with 98 AWS Foundational Security Best Practices
controls. Most of them are evaluated by **AWS Config rules**, and AWS Config is
**not enabled** in this account — a deliberate cost decision, since Config has no
free tier and bills per configuration item recorded.

The consequence, confirmed during [incident 02](../incidents/incident-02-s3.md):
controls report `ENABLED` while detecting nothing. A genuinely public S3 bucket
produced **zero** Security Hub findings.

The detections here provide equivalent coverage at no cost. They are a
compensating control for a known, accepted gap — not a replacement for managed
detection.

---

## Catalogue

### `s3-posture-check.ps1`

Evaluates every S3 bucket in the account against six controls.

| ID | Control | Severity | Rationale |
| --- | --- | --- | --- |
| S3-1 | Block Public Access — all four settings | **High** | The single most important S3 control |
| S3-2 | No `Allow` to a wildcard principal | **High** | Anonymous read/write grant |
| S3-3 | ACLs disabled (`BucketOwnerEnforced`) | Medium | Independent path to public objects |
| S3-4 | Explicit default encryption declared | Low (WARN) | See note below |
| S3-5 | Versioning enabled | Medium | Overwrite and deletion protection |
| S3-6 | Policy denies non-TLS requests | Medium | Prevents plaintext transport |

**Usage**

```powershell
./s3-posture-check.ps1                                      # whole account
./s3-posture-check.ps1 -BucketPrefix cloudsec-lab-incident- # scoped
./s3-posture-check.ps1 -FailOnFinding                       # exit 1 on FAIL, for CI
./s3-posture-check.ps1 -JsonOut results.json                # machine-readable
```

**Why S3-4 is a WARN, not a FAIL**

Since January 2023 AWS applies SSE-S3 to every new bucket automatically, so a
genuinely unencrypted bucket cannot be created and `get-bucket-encryption`
returns `AES256` even with nothing declared. The residual weakness is an
*undeclared* posture — no stated intent, no bucket key, no policy requiring
encrypted uploads. That is worth flagging but is not the same class of problem
as public access, so it does not fail the check.

**Validation**

Tested in both directions against a bucket deliberately configured insecurely:

| State | Result |
| --- | --- |
| Insecure baseline | 5 FAIL, 1 PASS — correctly identified every missing control |
| After remediation | 6 PASS, 0 FAIL — exit code 0 |

Testing that a detection can return a **pass** matters as much as testing that
it fires. A check that only ever fails is indistinguishable from a broken one.

**Known limitations**

- Point-in-time scan, not continuous. A bucket made public and reverted between
  runs is missed. Real-time coverage needs an EventBridge rule on
  `PutBucketPolicy` and `PutBucketPublicAccessBlock` — see the backlog.
- Does not inspect object-level ACLs, only bucket-level ownership settings.
- Does not evaluate cross-account access grants, only anonymous ones.
- Requires `s3:GetBucket*` across all buckets; runs as an administrative
  principal.

---

## Backlog

| Detection | Source incident | Priority |
| --- | --- | --- |
| Denied `iam:CreateAccessKey` / `iam:AttachUserPolicy` | [INC-01](../incidents/incident-01-iam.md) | **High** |
| Volume of denied IAM actions from one session | [INC-01](../incidents/incident-01-iam.md) | Medium |
| Near-real-time `PutBucketPolicy` / `PutBucketPublicAccessBlock` alert | [INC-02](../incidents/incident-02-s3.md) | **High** |
| Root account usage | — | Medium |
| CloudTrail `StopLogging` / trail deletion | — | **High** |

---

## Conventions

- One file per detection, named for what it detects.
- Every detection records: what it looks for, why it exists, how it was
  validated in both directions, and its limitations.
- Detections exit `0` when clean and support `-FailOnFinding` for CI use.
- Scripts must run on **Windows PowerShell 5.1** — no ternary operator, no
  `-AsHashtable`, and beware `ConvertFrom-Json` rejecting keys that differ only
  by case (it silently truncates CloudTrail analysis; see INC-02 §3).
