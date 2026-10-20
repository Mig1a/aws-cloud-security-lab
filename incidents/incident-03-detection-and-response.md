# Incident 03 — Detection and Response Pipeline, Both Branches

| Field | Value |
| --- | --- |
| **Incident ID** | INC-03 |
| **Type** | Mixed — one remediable S3 misconfiguration, three unremediable GuardDuty findings |
| **Detected** | 2026-10-19 16:03:54 UTC (first finding) |
| **Closed** | 2026-10-19 16:10:16 UTC |
| **Analyst** | mella-admin |
| **Account** | 0891****7191 (us-east-1) |
| **Status** | Closed — contained and verified |

> **Training exercise.** All activity was generated deliberately by the
> account owner. The S3 exposure used synthetic data on a bucket this lab
> already owns; the three "malicious activity" findings were generated via
> GuardDuty's own official `create-sample-findings` API — real finding
> records, not fabricated ones, but representing activity that never
> actually occurred in this account. No real attacker, no real compromise.

---

## 1. Incident Summary

This exercise deliberately produced four findings in one run, specifically
to prove the detection/response pipeline's **severity- and type-based
branching** works correctly on real evidence, not just in code review:

- **One remediable finding** — the Incident 02 bucket was re-exposed
  (`terraform apply -var harden=false`), producing real AWS Config-backed
  Security Hub findings (`S3.8`, then `S3.3` and `S3.2`). The containment
  Lambda detected, judged, and **contained** it: a real
  `s3:PutBucketPublicAccessBlock` call, confirmed against the live API, not
  just a log line.
- **Three unremediable findings** — real GuardDuty finding records
  (`CredentialAccess:IAMUser/CompromisedCredentials`,
  `PrivilegeEscalation:IAMUser/AnomalousBehavior`,
  `Recon:IAMUser/TorIPCaller`), none of which match any trigger the
  containment Lambda recognizes. The correct behavior for these is
  **notify only** — and that is exactly what happened for one of them.

The other two did not alert at all, which turned out to be the most
interesting result in the whole exercise: both carried GuardDuty's own
severity score of `5.0`, which Security Hub labels `MEDIUM` — below this
pipeline's `HIGH`/`CRITICAL` alert threshold. They were correctly filtered
out, not missed. Only `CompromisedCredentials` (severity `8.0`, `HIGH`)
reached the alert Lambda and triggered an SNS notification.

**No finding of any kind reached the containment Lambda except the real S3
exposure** — confirmed directly by searching the containment log group for
any of the three sample finding types and finding zero matches. The
separation between "detect everything, act on almost nothing" held exactly
as designed.

---

## 2. Timeline

All times UTC, 2026-10-19.

| Time | Event | Branch |
| --- | --- | --- |
| 16:03:52 | Exercise starts (`incidents/incident-03/generate-activity.ps1`) | — |
| 16:03:54.935–966 | Three GuardDuty sample findings created | Unremediable |
| ~16:03:55 | `terraform apply -var harden=false` — bucket re-exposed | Remediable |
| 16:04:04 | Anonymous `GET` on the bucket confirmed `HTTP 200` | Remediable |
| 16:04:23 | Alert Lambda logs `SECURITY INCIDENT DETECTED` for `CompromisedCredentials` (HIGH) | Unremediable |
| 16:04:2x | SNS delivers the `CompromisedCredentials` alert | Unremediable |
| — | `PrivilegeEscalation` and `TorIPCaller` (both MEDIUM) never reach the alert rule's threshold — **no alert, correctly** | Unremediable |
| 16:07:14 | Security Hub `S3.8` finding transitions to `FAILED` | Remediable |
| 16:07:37 | Containment Lambda logs `"contained"` — real `PutBucketPublicAccessBlock` call | Remediable |
| 16:07:38–16:10:16 | `S3.3` and `S3.2` findings also arrive `FAILED→` already-fixed state; Lambda logs `"already_contained"` each time — idempotency holding across multiple control IDs for the same resource | Remediable |
| (later) | `terraform apply -var harden=true` — bucket fully re-hardened (policy, versioning, TLS) beyond what containment alone restores | Remediable |

**Exposure window (remediable path): ~16:03:55 → 16:07:14, roughly 3 minutes
19 seconds** from re-exposure to a confirmed `FAILED` finding reaching the
Lambda — consistent with this lab's other measured AWS Config evaluation
latencies (2–7 minutes observed elsewhere).

---

## 3. Evidence

### 3.1 The three GuardDuty sample findings, as generated

```json
[
  {"Type": "CredentialAccess:IAMUser/CompromisedCredentials", "Severity": 8.0,
   "Title": "The IAM access key GeneratedFindingAccessKeyId was identified as potentially compromised..."},
  {"Type": "PrivilegeEscalation:IAMUser/AnomalousBehavior", "Severity": 5.0,
   "Title": "The user IAMUser : GeneratedFindingUserName is anomalously invoking APIs commonly used in PrivilegeEscalation tactics."},
  {"Type": "Recon:IAMUser/TorIPCaller", "Severity": 5.0,
   "Title": "The reconnaissance API GeneratedFindingAPIName was invoked from a Tor exit node."}
]
```

Verified via `aws guardduty get-findings` directly against this account's
detector — not assumed from the request, confirmed from the response.

### 3.2 The one finding that alerted

```
[WARNING] 2026-10-19T16:04:23.686Z  f31fa22b-41e0-42bf-bc72-9ab4ea1b9cbf

SECURITY INCIDENT DETECTED

  Finding ID:  arn:aws:guardduty:us-east-1:0891****7191:detector/d535937b.../finding/86c81f2c...
  Finding:     The IAM access key GeneratedFindingAccessKeyId was identified
               as potentially compromised by Amazon threat intelligence...
  Severity:    HIGH
```

### 3.3 The real containment action

```json
{"containment_action": "contained",
 "finding_id": "arn:aws:securityhub:us-east-1:0891****7191:security-control/S3.8/finding/7d54e8bc-...",
 "finding_types": ["Software and Configuration Checks/Industry and Regulatory Standards"],
 "bucket_arn": "arn:aws:s3:::cloudsec-lab-incident-02-0891****7191",
 "auto_contain_enabled": true,
 "detail": "PutPublicAccessBlock: all four settings enabled."}
```

Followed by two `already_contained` lines for `S3.3` and `S3.2` as those
controls' own evaluations caught up to the already-fixed resource — proof
the idempotency check (§5 of the Phase 9 design) behaves correctly when
multiple finding types describe the same underlying state.

### 3.4 Independent verification, not trusted from the log

```
$ aws s3api get-public-access-block --bucket cloudsec-lab-incident-02-...
{ "PublicAccessBlockConfiguration": { all four: true } }

$ curl anonymous GET (after containment) -> HTTP 403
```

### 3.5 SNS delivery

```
AWS/SNS NumberOfNotificationsDelivered: 1 (16:04 — CompromisedCredentials alert)
                                        3 (16:07 — contained action + ambient traffic)
NumberOfNotificationsFailed: 0 (entire window)
```

### 3.6 Confirming the containment Lambda was never invoked for the unremediable findings

```
$ aws logs filter-log-events --log-group-name .../cloudsec-lab-s3-containment \
    --filter-pattern "CompromisedCredentials OR PrivilegeEscalation OR TorIPCaller"
0 events
```

This is the actual proof of the branch boundary — not an assumption that
the EventBridge rule's `Types`/`Compliance.SecurityControlId` match would
exclude these, but a direct search of the containment Lambda's own
invocation history confirming it did not run.

---

## 4. Root Cause

Both halves of this incident were deliberately caused by the account owner,
for the explicit purpose of exercising the pipeline:

- **Remediable half:** `terraform apply -var harden=false` in
  `terraform/incident-02/`, the same toggle used throughout this lab.
- **Unremediable half:** `aws guardduty create-sample-findings`, GuardDuty's
  own supported mechanism for generating real finding records without
  real suspicious activity.

Nothing here reflects an actual attacker or actual compromised credentials.

---

## 5. Affected Resources

| Resource | Identifier | Impact |
| --- | --- | --- |
| S3 bucket | `cloudsec-lab-incident-02-0891****7191` | Publicly readable for ~3m19s; contained automatically, then fully re-hardened |
| GuardDuty detector | `d535937b...` | 3 sample findings created; 1 archived-equivalent (superseded by this report) |
| Containment Lambda | `cloudsec-lab-s3-containment` | Invoked 3 times (1 `contained`, 2 `already_contained`); never invoked for the unremediable findings |
| Alert Lambda | `cloudsec-lab-securityhub-alert` | Invoked for the `HIGH` finding only; correctly silent for the two `MEDIUM` ones |
| SNS topic | `cloudsec-lab-security-alerts` | Delivered notifications for both the alert and the containment outcome |

---

## 6. Severity

**As executed — Informational.** Authorized exercise, synthetic data,
real findings generated via GuardDuty's own sanctioned sample-finding
mechanism, no real attacker.

**If genuine — High for the credential-compromise finding specifically.**
A real `CredentialAccess:IAMUser/CompromisedCredentials` finding at severity
`8.0` would warrant immediate investigation regardless of what this lab's
automation does or doesn't do with it — this lab has no automated response
for compromised credentials at all, which is accurately reflected by the
pipeline doing exactly one thing: telling a human.

---

## 7. Containment

### Remediable path

The containment Lambda's existing, already-verified logic acted with no
changes needed: type/control-ID match → resource allow-listed → examine →
not yet blocked → `AUTO_CONTAIN_ENABLED` true → `PutBucketPublicAccessBlock`
→ logged and notified.

### Unremediable path

There is, correctly, no containment action available. "Contain" for a
compromised-credentials finding would mean something like disabling the
access key or forcing a credential rotation — actions this lab has
deliberately never built, since doing so safely requires knowing which key,
confirming it's actually compromised (not a false positive), and having a
rollback plan if it's wrong. Notifying a human is the entire, correct
response here, not a placeholder for a future automated one.

---

## 8. Remediation

| # | Action | Status |
| --- | --- | --- |
| 1 | Contain the real S3 exposure | **Done** — automatic, ~3m19s |
| 2 | Fully re-harden the bucket (policy, versioning, TLS) | **Done** — `terraform apply -var harden=true` |
| 3 | Confirm no cross-contamination between the two branches | **Done** — §3.6 |
| 4 | Build an actual response for compromised-credential findings (key disable, forced rotation) | Open — same backlog item as denied `iam:CreateAccessKey` detection (INC-01); still no detector *or* response for this class of finding |

---

## 9. Lessons Learned

**Severity filtering is itself part of the system under test, not a given.**
Two of three "attack-shaped" findings never alerted — correctly — because
they scored below the HIGH threshold. A test that only checks "did
something fire" would have missed verifying the *other* direction: that
the pipeline also correctly stays quiet on sub-threshold findings, on real
GuardDuty-scored evidence rather than a synthetic severity value chosen to
make the test pass.

**The absence of an invocation is something you can prove, not just
assume.** Confirming the containment Lambda never ran for the unremediable
findings meant searching its own log group directly for zero matches — the
same rigor this lab applies to confirming something *did* happen, turned
around to confirm something correctly *didn't*.

**Running both branches together is a stronger test than running them
separately.** Had only the S3 exposure been tested (as in earlier
exercises), the "notify-only" path would still be unverified in practice.
Running them in the same window, then independently confirming no
cross-talk, is what actually proves the branch boundary rather than just
the two paths individually.

**Idempotency matters even within a single incident.** Three separate
finding types (`S3.8`, `S3.3`, `S3.2`) all described the same underlying
resource state at slightly different times. The Lambda correctly contained
once and correctly no-opped twice more, rather than calling
`PutPublicAccessBlock` redundantly or, worse, miscounting the incident as
three separate containments.

---

## Related

- Activity script: [incidents/incident-03/generate-activity.ps1](incident-03/generate-activity.ps1)
- Containment design: [docs/phase-9-automated-containment.md](../docs/phase-9-automated-containment.md),
  specifically [§11](../docs/phase-9-automated-containment.md#11-extension--a-second-trigger-family-and-notification)
- Related incident: [incident-02-s3.md](incident-02-s3.md) (the same bucket's
  original misconfiguration)
- Detection backlog: [detections/README.md#backlog](../detections/README.md#backlog)
  (item 4 above is the same open gap as the denied `iam:CreateAccessKey`
  detector from INC-01)
