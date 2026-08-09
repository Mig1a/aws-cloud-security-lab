# Incident 02 — Insecure S3 Bucket Configuration

| Field | Value |
| --- | --- |
| **Incident ID** | INC-02 |
| **Type** | Data exposure — publicly readable S3 bucket |
| **Introduced** | 2026-08-09 20:08:07 UTC |
| **Detected** | 2026-08-09 20:08:44 UTC |
| **Remediated** | 2026-08-09 20:10:30 UTC |
| **Exposure window** | **2m23s** (plus a second, deliberate ~15m window for evidence capture — see §2) |
| **Analyst** | mella-admin |
| **Account** | 089110987191 (us-east-1) |
| **Status** | Closed — remediated and verified |

> **Training exercise.** The misconfiguration was introduced deliberately by the
> account owner against synthetic data. No real data was exposed. Public **read**
> was configured; public **write** was never configured at any point, since a
> publicly writable bucket is an abuse and cost vector rather than merely a
> confidentiality one.

---

## Flow

```
Misconfiguration  →  Detection  →  Investigation  →  Remediation  →  Verification
   20:08:07          20:08:44        20:09:39         20:10:30        20:11:30
```

---

## 1. Misconfiguration

A bucket, `cloudsec-lab-incident-02-089110987191`, was created with five
controls deliberately absent.

### Before

| Control | State | Consequence |
| --- | --- | --- |
| Block Public Access | **All four settings off** | Permits public policies and ACLs |
| Bucket policy | **`Allow s3:GetObject` to `Principal: *`** | Anonymous read of every object |
| Object ownership | `ObjectWriter` — **ACLs enabled** | Second, independent path to making objects public |
| Versioning | **Suspended** | No protection against overwrite or deletion |
| TLS enforcement | **None** | Objects readable over plaintext HTTP |
| Encryption | SSE-S3 (AWS default) | *See note below* |

Contents: three synthetic objects, including `internal/api-notes.txt` and
`internal/employees.csv` under a prefix whose name implies it should not be
public.

### Note on encryption

The classic "unencrypted S3 bucket" finding **is no longer reproducible**. Since
January 2023, AWS applies SSE-S3 to every new bucket automatically, and
`get-bucket-encryption` duly returned `AES256` even with no encryption resource
declared.

The realistic modern weakness is therefore not *absent* encryption but *undeclared*
encryption posture: relying on an implicit default, with no bucket key and no
policy requiring encrypted uploads. The detection reflects this by rating a
missing explicit configuration as **WARN**, not FAIL.

---

## 2. Detection

Detected by [`detections/s3-posture-check.ps1`](../detections/s3-posture-check.ps1),
which evaluates every bucket against six controls.

```
=== cloudsec-lab-incident-02-089110987191 ===
  S3-1   Block Public Access            FAIL  acls=False policy=False ignoreAcls=False restrict=False
  S3-2   No anonymous policy grant      FAIL  public Allow statement(s): PublicReadGetObject
  S3-3   ACLs disabled                  FAIL  objectOwnership=ObjectWriter
  S3-4   Explicit default encryption    PASS  sseAlgorithm=AES256
  S3-5   Versioning enabled             FAIL  status=Suspended
  S3-6   Denies plaintext requests      FAIL  no TLS-only deny statement

SUMMARY  buckets=1  checks=6  PASS=1  WARN=0  FAIL=5
```

### Why a custom detection rather than Security Hub

Security Hub is enabled with 98 AWS Foundational Security Best Practices
controls, including `S3.1`, `S3.2`, `S3.3`, `S3.5` and `S3.8` — all directly
relevant here.

**It produced zero findings.**

Those controls are evaluated by AWS Config rules, and **AWS Config is not
enabled** in this account — a deliberate cost decision from
[Phase 4](../docs/phase-4-detection-services.md), since Config has no free tier
and bills per configuration item. Verified during this exercise:

```
aws configservice describe-configuration-recorders  ->  (empty)
aws securityhub get-findings --filters ResourceType=AwsS3Bucket  ->  0
```

The controls report *enabled* while detecting nothing. **An enabled control is
not the same as a working control** — that gap is the most transferable lesson
in this incident.

### Exposure confirmed independently

Detection findings were corroborated with an unauthenticated request carrying no
AWS credentials:

```
GET https://cloudsec-lab-incident-02-<account-id>.s3.amazonaws.com/internal/api-notes.txt
HTTP 200 — PUBLICLY READABLE

GET http://...  (plaintext, no TLS)
HTTP 200 — readable over unencrypted transport
```

A browser with no AWS session reads the object directly:

![Anonymous read succeeds](../screenshots/06-s3-before-anonymous-read.png)

Console state at the time of detection:

| Block Public Access | Versioning |
| --- | --- |
| ![All four settings off](../screenshots/06-s3-before-block-public-access-off.png) | ![Suspended](../screenshots/06-s3-before-versioning-suspended.png) |

> **Second exposure window.** The "before" images above were not captured
> during the original 2m23s window — remediation had already completed. The
> insecure baseline was deliberately re-applied at ~20:20 UTC for roughly 15
> minutes to capture evidence, then hardened again and re-verified.
>
> Recorded here because an incident report that omits a second exposure is
> inaccurate, and because it illustrates a real tension: reproducing a
> misconfiguration for documentation re-opens the risk it documents. In a
> production account the correct answer is to capture evidence *during* the
> original window, or to reproduce it in an isolated account — not to re-expose
> the affected resource.

---

## 3. Investigation

Reconstructed from CloudTrail management events.

| Time (UTC) | Event | Principal | Significance |
| --- | --- | --- | --- |
| 20:08:06 | `CreateBucket` | mella-admin | Bucket created |
| 20:08:07 | `PutBucketVersioning` | mella-admin | Set to Suspended |
| **20:08:07** | **`PutBucketPolicy`** | mella-admin | **Public read granted — exposure begins** |
| **20:08:07** | **`PutBucketPublicAccessBlock`** | mella-admin | **All four protections disabled** |
| 20:08:44 | `GetBucketPublicAccessBlock` … | mella-admin | Detection scan |
| 20:09:31 | `GetBucketEncryption` | **resource-explorer-2** | AWS service, not the actor |
| 20:09:39 | `GetBucket*` sweep | mella-admin | Investigation |
| 20:10:29 | `PutBucketEncryption` | mella-admin | Remediation begins |
| **20:10:29** | **`PutBucketPublicAccessBlock`** | mella-admin | **Protections restored** |
| **20:10:30** | **`PutBucketPolicy`** | mella-admin | **Public grant removed — exposure ends** |
| 20:10:30 | `PutBucketLifecycle` | mella-admin | Lifecycle added |

### Findings

**Attribution is unambiguous.** All configuration changes trace to
`mella-admin` via the AWS CLI. In a real incident the follow-up question would
be whether that use was authorized.

**`resource-explorer-2` appears in the timeline but is not the actor.** An AWS
service-linked principal indexing the new bucket. Baseline noise an analyst must
recognise and exclude — mistaking it for actor activity would derail an
investigation.

**Exposure window is precisely bounded** by two `PutBucketPolicy` events:
20:08:07 to 20:10:30, **2 minutes 23 seconds**.

**No anonymous reads occurred.** S3 data events are enabled for this bucket
prefix (added in [Phase 5](../docs/phase-5-incident-01.md)), and no `GetObject`
by an anonymous principal was recorded other than the analyst's own verification
requests. Had data events been off, this question would have been unanswerable.

### A tooling defect found during the investigation

PowerShell 5.1's `ConvertFrom-Json` **rejects JSON containing keys that differ
only by case**, and CloudTrail's `PutBucketOwnershipControls` records contain
both `ownershipControls` and `OwnershipControls`:

```
ConvertFrom-Json : Cannot convert the JSON string because a dictionary that was
converted from the string contains the duplicated keys 'ownershipControls' and
'OwnershipControls'.
```

Four events were **dropped from the parsed timeline**, including the
`PutBucketOwnershipControls` calls that enabled and later disabled ACLs. The
errors were visible rather than silent, but the resulting timeline was
incomplete and would have been accepted as complete had the errors been
suppressed.

An investigation tool that quietly loses evidence is worse than no tool. Logged
as remediation item 4.

---

## 4. Remediation

Applied by flipping a single Terraform variable, so the fix is expressed as a
reviewable diff rather than a series of console clicks:

```powershell
terraform apply -var=harden=true
# Plan: 2 to add, 5 to change, 0 to destroy
```

### After

| Control | Before | After |
| --- | --- | --- |
| Block Public Access | all four **off** | **all four on** |
| Bucket policy | `Allow s3:GetObject` to `*` | **no public grant**; account-scoped read only |
| Object ownership | `ObjectWriter` (ACLs enabled) | **`BucketOwnerEnforced`** (ACLs disabled) |
| Versioning | Suspended | **Enabled** |
| TLS | not enforced | **`aws:SecureTransport=false` denied** |
| Encryption | implicit default | **explicit SSE-S3 + bucket key** |
| Upload encryption | not required | **unencrypted `PutObject` denied** |
| Lifecycle | none | noncurrent versions expire after 7 days |

The least-privilege grant replaces `Principal: *` with the account ID, so read
access requires an authenticated principal in this account.

---

## 5. Verification

Three independent checks, all after remediation.

**Detection re-run — clean:**

```
  S3-1   Block Public Access            PASS  all four settings enabled
  S3-2   No anonymous policy grant      PASS  no wildcard-principal Allow
  S3-3   ACLs disabled                  PASS  objectOwnership=BucketOwnerEnforced
  S3-4   Explicit default encryption    PASS  sseAlgorithm=AES256
  S3-5   Versioning enabled             PASS  status=Enabled
  S3-6   Denies plaintext requests      PASS  aws:SecureTransport=false denied

SUMMARY  buckets=1  checks=6  PASS=6  WARN=0  FAIL=0
exit code 0
```

**Anonymous access — denied:**

```
HTTPS GET  ->  403 Forbidden
HTTP  GET  ->  403 Forbidden
```

The same browser request now returns `AccessDenied`:

![Anonymous read denied](../screenshots/06-s3-after-access-denied.png)

Console state after remediation, same panels as §2:

| Block Public Access | Versioning |
| --- | --- |
| ![All four settings on](../screenshots/06-s3-after-block-public-access-on.png) | ![Enabled](../screenshots/06-s3-after-versioning-enabled.png) |

**Terraform state — converged:** `posture = "HARDENED"`.

Verifying by re-running the same detection that found the problem is deliberate:
it proves the detection is capable of returning a pass, not just a fail. A
detection that only ever fails is indistinguishable from one that is broken.

---

## 6. Severity

### As executed — **Informational**

Deliberate exercise, synthetic data, 2m23s exposure, no unauthorized access.

### If genuine — **High**

| Factor | Assessment |
| --- | --- |
| Confidentiality | **High** — anonymous read of an `internal/` prefix |
| Integrity | None — public write never granted |
| Availability | None |
| Discoverability | **High** — bucket enumeration is continuous and automated |
| Data sensitivity | Synthetic here; the prefix names simulate personnel and credential material |

Public S3 buckets are found by automated scanners within minutes. A 2-minute
window is small but not zero, and the correct assumption for a real bucket
holding real data is that anything publicly readable was read.

---

## 7. Affected Resources

| Resource | Identifier | Impact |
| --- | --- | --- |
| S3 bucket | `cloudsec-lab-incident-02-089110987191` | Publicly readable for 2m23s |
| Object | `public-brochure.txt` | Exposed (intended to be readable) |
| Object | `internal/employees.csv` | **Exposed** (synthetic) |
| Object | `internal/api-notes.txt` | **Exposed** (synthetic; read during verification) |

Defined in [terraform/incident-02/](../terraform/incident-02/).

---

## 8. Lessons Learned

**An enabled control is not a working control.** Security Hub reported five
relevant S3 controls as `ENABLED` and detected nothing, because their evaluation
engine — AWS Config — was not running. A compliance dashboard showing green can
mean "passing" or "not looking"; those are indistinguishable without checking.

**Cost decisions are security decisions.** Skipping AWS Config to protect a $10
budget silently removed the detection capability that would have caught this.
That is a legitimate trade-off, but it must be a *known* one, with compensating
control — here, the custom detection script.

**Detection must be verified in both directions.** Re-running the same check
after remediation proves it can return a pass. A check that only ever fails
looks identical to a broken one.

**Public Block Access is necessary but not sufficient.** Five separate controls
had to be fixed. Object ACLs and missing TLS enforcement are independent
exposure paths that survive turning on public access blocking alone.

**Expressing remediation as a diff beats console clicks.** `terraform apply
-var=harden=true` produced a reviewable, repeatable, auditable change —
`2 to add, 5 to change` — instead of a sequence of console actions no one can
review afterwards.

**Investigation tooling needs its own integrity checks.** PowerShell's JSON
parser dropped four CloudTrail events over case-differing duplicate keys. Tools
that lose evidence produce confident, incomplete timelines.

---

## 9. Remediation Items

| # | Action | Status |
| --- | --- | --- |
| 1 | Harden the bucket (5 controls) | **Done** |
| 2 | Add `s3-posture-check.ps1` to the detection catalogue | **Done** |
| 3 | Run the posture check before every commit that touches S3 | Open |
| 4 | Make the CloudTrail parser tolerate case-duplicate keys | Open |
| 5 | Decide on AWS Config — cost vs. losing Security Hub S3 coverage | Open |
| 6 | Alert on `PutBucketPolicy` and `PutBucketPublicAccessBlock` in near real time | Open |

Item 6 matters most: detection here was a manual scan. In a real account the
2m23s window would only have been that short by luck.

---

## Related

- Build notes: [docs/phase-6-incident-02.md](../docs/phase-6-incident-02.md)
- Detection: [detections/s3-posture-check.ps1](../detections/s3-posture-check.ps1)
- Infrastructure: [terraform/incident-02/](../terraform/incident-02/)
- Previous incident: [incident-01-iam.md](incident-01-iam.md)
