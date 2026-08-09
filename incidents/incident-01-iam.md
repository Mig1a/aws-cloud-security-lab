# Incident 01 — IAM Role Misuse Investigation

| Field | Value |
| --- | --- |
| **Incident ID** | INC-01 |
| **Type** | IAM — unauthorized privilege use / attempted escalation |
| **Detected** | 2026-08-09 19:10 UTC |
| **Closed** | 2026-08-09 19:35 UTC |
| **Analyst** | mella-admin |
| **Account** | 089110987191 (us-east-1) |
| **Status** | Closed — no compromise |

> **Training exercise.** All activity was generated deliberately by the account
> owner against synthetic data in an owned account. No real compromise occurred
> and no real data was involved. The report is written in operational form to
> practise the method; severity is assessed twice — once as simulated, once as
> if the activity had been genuine.

---

## 1. Incident Summary

At 19:10:44 UTC an IAM role, `cloudsec-lab-incident-01-analyst`, was assumed by
the IAM user `mella-admin`. Over the following 22 seconds the resulting session
performed **11 API actions** against a test S3 bucket and the account's IAM
service.

**Four actions succeeded**, all within the role's intended read-only scope.
**Seven were denied.** The denied set was not random: it followed a recognizable
progression from permitted reads, to probing the permission boundary, to an
attempt at privilege escalation, to lateral enumeration.

The most significant single event was a denied **`iam:CreateAccessKey` targeting
the administrative user `mella-admin`**. Had the role carried that permission,
the actor could have minted long-lived credentials for an administrator,
converting a one-hour session into durable account access.

The permission boundary held. Every out-of-scope action was refused, and all 11
actions were logged and attributable to a single session.

The investigation surfaced a **logging gap more consequential than the simulated
activity itself**: 7 of the 11 actions were not visible in CloudTrail Event
History and would have been entirely unrecorded under the account's prior
configuration.

---

## 2. Timeline

All times UTC, 2026-08-09.

| Time | Service | Action | Target | Result |
| --- | --- | --- | --- | --- |
| 19:10:44 | sts | **AssumeRole** | `cloudsec-lab-incident-01-analyst` | allowed |
| 19:10:45 | sts | GetCallerIdentity | — | allowed |
| 19:10:47 | s3 | ListObjects | `reports/` | allowed |
| 19:10:49 | s3 | GetObject | `reports/quarterly-summary.txt` | allowed |
| 19:10:51 | s3 | GetObject | `reports/runbook.txt` | allowed |
| 19:10:53 | s3 | GetObject | `restricted/payroll.txt` | **DENIED** |
| 19:10:55 | s3 | ListObjects | `restricted/` | **DENIED** |
| 19:10:57 | s3 | DeleteObject | `reports/runbook.txt` | **DENIED** |
| 19:10:59 | s3 | PutObject | `reports/implant.txt` | **DENIED** |
| 19:11:01 | iam | ListUsers | account | **DENIED** |
| 19:11:03 | iam | **CreateAccessKey** | user `mella-admin` | **DENIED** |
| 19:11:05 | s3 | ListBuckets | account | **DENIED** |
| 19:11:06 | — | Session credentials cleared | — | — |
| 20:10:44 | — | Session credentials expired naturally | — | — |

### Investigation timeline

| Time | Event |
| --- | --- |
| 19:11 | Activity concluded |
| 19:12 | First CloudTrail query — **0 events returned** (delivery lag) |
| 19:16 | Management events visible; 4 of 11 actions recovered |
| 19:20 | S3 log files retrieved and decompressed; remaining 7 actions recovered |
| 19:35 | Report completed |

**Observed latency:** management events took 4–5 minutes to appear in Event
History; S3 log file delivery ran 5–15 minutes behind. An investigation opened
immediately after an event sees an incomplete picture.

---

## 3. Evidence

### 3.1 Pivot event — role assumption

```
eventTime    : 2026-08-09T19:10:44Z
eventName    : AssumeRole
eventSource  : sts.amazonaws.com
userIdentity : arn:aws:iam::089110987191:user/mella-admin
sourceIP     : 50.211.153.xxx          (redacted — analyst's own address)
userAgent    : aws-cli/2.36.17 ... md/command#sts.assume-role
roleArn      : arn:aws:iam::089110987191:role/cloudsec-lab-incident-01-analyst
sessionName  : incident-01-test
expiration   : 2026-08-09T20:10:44Z
```

All subsequent actions are attributed to:

```
arn:aws:sts::089110987191:assumed-role/cloudsec-lab-incident-01-analyst/incident-01-test
```

The **session name is the thread the entire investigation hangs on.** A single
filter on `incident-01-test` reconstructs the actor's complete activity.

### 3.2 Privilege escalation attempt

```
eventTime : 2026-08-09T19:11:03Z
eventName : CreateAccessKey
errorCode : AccessDenied
errorMessage:
  User: arn:aws:sts::089110987191:assumed-role/cloudsec-lab-incident-01-analyst/incident-01-test
  is not authorized to perform: iam:CreateAccessKey on resource: user mella-admin
  because no identity-based policy allows the iam:CreateAccessKey action
```

### 3.3 Evidence sources

| Source | Events | Retrieval |
| --- | --- | --- |
| CloudTrail Event History (management) | 4 | `aws cloudtrail lookup-events` |
| CloudTrail S3 log files (data) | 7 | `aws s3 cp` from the trail bucket, then filter `eventCategory == "Data"` |

Data event retrieval:

```powershell
aws s3 cp s3://cloudsec-lab-cloudtrail-089110987191/AWSLogs/089110987191/CloudTrail/us-east-1/2026/08/09/ . --recursive
gunzip *.gz
# filter Records[] where eventCategory == "Data"
```

### 3.4 Evidence integrity

The trail has **log file validation enabled**, producing signed digest files.
Delivered logs can be verified as untampered with
`aws cloudtrail validate-logs`.

### 3.5 Evidence handling

Raw CloudTrail JSON is retained locally at `incidents/incident-01/evidence/`
and is **excluded from version control**. The records contain the analyst's real
public IP address and, on the AssumeRole record, the issued session token.

| File | Contents |
| --- | --- |
| `01-assume-role.json` | Pivot event |
| `02-session-activity.json` | All management events for the session |
| `03-denied-attempts.json` | Denied events only |

Reproduction:

```powershell
cd incidents/incident-01
./generate-activity.ps1
./investigate.ps1 -StartUtc 2026-08-09T19:09:00Z -EndUtc 2026-08-09T19:20:00Z
```

---

## 4. Root Cause

Two distinct root causes, only one of which is simulated.

### 4.1 Cause of the activity — simulated

The activity originated from the account owner running
`incidents/incident-01/generate-activity.ps1` as an authorized training
exercise. There was no external actor and no credential compromise.

Had this been genuine, the corresponding root cause question would be *how the
`mella-admin` credentials came to be used from that source* — the AssumeRole
event shows a standard AWS CLI user agent from the account owner's own address,
consistent with legitimate use.

### 4.2 Cause of the visibility gap — real

**CloudTrail was configured to record management events only.** S3 object-level
operations (`GetObject`, `PutObject`, `DeleteObject`, `ListObjects`) are
**data events**, a separate category that is not recorded unless explicitly
configured and that never appears in Event History even when it is.

This was a deliberate Phase 4 decision to avoid unbounded data-event billing,
but it meant 7 of 11 actions — including the attempted read of a restricted
file, the attempted delete, and the attempted object plant — would have left
**no record whatsoever**.

An investigation limited to Event History would have concluded the actor called
`GetCallerIdentity` and was denied three IAM/S3 listing operations. It would
have missed all data access entirely.

**This gap could not have been fixed after the fact.** Data events not recorded
at the time are unrecoverable.

---

## 5. Affected Resources

| Resource | Identifier | Impact |
| --- | --- | --- |
| IAM role | `cloudsec-lab-incident-01-analyst` | Assumed; used within and beyond intended scope |
| IAM user | `mella-admin` | **Target** of the escalation attempt; not modified |
| S3 bucket | `cloudsec-lab-incident-01-089110987191` | 2 objects read; 1 read attempt denied |
| S3 object | `reports/quarterly-summary.txt` | Read (synthetic data) |
| S3 object | `reports/runbook.txt` | Read; delete attempt denied |
| S3 object | `restricted/payroll.txt` | Read attempt **denied** |
| CloudTrail | `cloudsec-lab-trail` | Recorded the activity |
| S3 log bucket | `cloudsec-lab-cloudtrail-089110987191` | Evidence store |

**No resource was modified, deleted, or created by the actor.** No IAM
credentials were issued. No data left the account.

Resource definitions: [terraform/incident-01/](../terraform/incident-01/).

---

## 6. Severity

### As executed — **Informational**

Authorized training activity, synthetic data, no compromise, no impact.

### If genuine — **High**

| Factor | Assessment |
| --- | --- |
| Confidentiality | **Low impact** — 2 non-sensitive objects read; restricted file denied |
| Integrity | **None** — all write and delete attempts denied |
| Availability | **None** |
| **Intent** | **High** — deliberate escalation attempt against an admin user |
| **Potential impact** | **Critical if successful** — `iam:CreateAccessKey` on an administrator yields persistent full account access |

Rated **High** rather than Low on **demonstrated intent**, not achieved impact.
The actor attempted, in sequence, to read restricted data, destroy data, plant
an object, enumerate identities, and escalate to administrator. That the
controls held is a statement about the controls, not about the actor.

A single denied `iam:CreateAccessKey` against an administrative user warrants
escalation on its own.

---

## 7. Containment

### Actions taken

| Action | Time | Note |
| --- | --- | --- |
| Session credentials cleared from environment | 19:11:06 | Script scoped credentials to its own process |
| Session expired naturally | 20:10:44 | 1-hour `max_session_duration` cap |
| Scope confirmed — no other sessions of this role | 19:20 | CloudTrail review |
| Confirmed no access keys created | 19:20 | All `iam:CreateAccessKey` attempts denied |

### Pre-existing controls that contained it

**The role's permission boundary.** Only `s3:ListBucket` (prefix-limited) and
`s3:GetObject` on `reports/*` were granted. No IAM permissions, no write
actions.

**An explicit `Deny` on `restricted/*`.** Redundant against an allow-list, but
an explicit deny cannot be overridden by any later grant and produces an
unambiguous denial in the logs.

**A one-hour maximum session duration**, bounding the useful lifetime of a
leaked session credential.

### Containment that would have been required if genuine

Revoke the session immediately rather than waiting for expiry — attach a
`DenyAllExcept` inline policy with an `aws:TokenIssueTime` condition to the
role, since STS credentials cannot be individually revoked. Then audit
`mella-admin` for unauthorized access keys and rotate its credentials.

---

## 8. Remediation

### Completed

**CloudTrail S3 data events enabled**, scoped by ARN prefix to lab incident
buckets:

```hcl
field_selector {
  field       = "resources.ARN"
  starts_with = ["arn:aws:s3:::cloudsec-lab-incident-"]
}
```

Scoping keeps per-event billing bounded to deliberate test activity instead of
all account traffic. Implemented in
[terraform/detection/cloudtrail.tf](../terraform/detection/cloudtrail.tf).

**Guardrail against recurrence of the gap.** A `project_name` validation in
[terraform/incident-01/variables.tf](../terraform/incident-01/variables.tf)
rejects any name outside the `cloudsec-lab-incident-` prefix, so a future
incident stack cannot silently fall outside the data-event selector and produce
an uninvestigable exercise.

**Evidence handling corrected.** `incidents/**/evidence/` added to
`.gitignore`; source IP redacted in this report.

### Outstanding

| # | Action | Priority |
| --- | --- | --- |
| 1 | Alert on denied `iam:CreateAccessKey` and `iam:AttachUserPolicy` | **High** |
| 2 | Alert on volume of denied IAM actions from a single session | Medium |
| 3 | Enforce meaningful session names via an `sts:RoleSessionName` trust-policy condition | Medium |
| 4 | Extend data events to other buckets holding sensitive data, before they are needed | Medium |
| 5 | Enable AWS Config so Security Hub controls evaluate rather than report "No data" | Low — cost decision |

Item 1 is the Phase 6 deliverable, stored in [detections/](../detections/).

---

## 9. Lessons Learned

**You cannot investigate what you did not log.** The single most important
finding. Data events had to be enabled *before* the activity occurred; there is
no retroactive recovery. Every logging decision is a decision about which future
investigations are possible.

**Event History is not the whole trail.** `lookup-events` and the console's
Event History return management events only. An analyst who treats Event History
as complete will reach confident, wrong conclusions — here, that an actor who
read two files and attempted four destructive operations "did almost nothing."

**Denials are the highest-signal evidence.** Successful actions show what an
actor *could* do; denied actions show what they *tried* to do. The denied
`iam:CreateAccessKey` was the most important event in the incident precisely
because it failed. Detections built only on successful actions miss the
intent that precedes a successful attack.

**Session names are the investigative pivot.** Because `incident-01-test` was
supplied at assumption time, one filter reconstructed the whole timeline.
Attribution should not be left to chance — enforce it in the trust policy.

**Cost controls and detection capability are in direct tension.** Data events,
AWS Config, and GuardDuty add-ons all improve investigability and all cost
money. The correct answer is not "enable everything" or "enable nothing" but
*scope deliberately* — here, data events on lab buckets only. Log what you would
need to investigate.

**Log delivery latency is an operational constraint.** The first query returned
zero events and looked like a misconfiguration. Knowing the expected 5–15 minute
lag prevents wasted time chasing a non-problem during a live response.

**GuardDuty correctly raised nothing.** A short burst of denied calls from the
account's own address is not threat-intel-worthy. This is a reminder that
managed detection covers known-bad patterns, and that account-specific
behaviours require purpose-built detections — the gap Phase 6 addresses.

---

## Related

- Build notes: [docs/phase-5-incident-01.md](../docs/phase-5-incident-01.md)
- Tooling: [incidents/incident-01/](incident-01/)
- Infrastructure: [terraform/incident-01/](../terraform/incident-01/)
- Detection config: [terraform/detection/](../terraform/detection/)
