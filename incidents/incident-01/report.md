# Incident 01 — IAM Role Activity Investigation

| Field | Value |
| --- | --- |
| **Incident ID** | INC-01 |
| **Date** | 2026-08-09 |
| **Classification** | Training exercise — authorized activity in an owned account |
| **Severity** | N/A (simulated) |
| **Analyst** | mella-admin |
| **Status** | Closed |

> **This is a lab exercise.** All activity was generated deliberately by the
> account owner against synthetic data. No real compromise occurred and no real
> data was involved. The narrative below is written as a genuine investigation
> would be, to practise the method.

---

## 1. Summary

A limited IAM role, `cloudsec-lab-incident-01-analyst`, was assumed and used to
perform 11 actions against a test S3 bucket over a 22-second window. Four
actions succeeded within the role's intended permissions. **Seven were denied**,
including two attempts at IAM reconnaissance and one at privilege escalation.

The permission boundary held. Every action outside the role's intended scope was
refused, and all 11 actions were recorded and attributable to a single session.

---

## 2. Timeline (UTC)

| Time | Source | Action | Target | Result |
| --- | --- | --- | --- | --- |
| 19:10:44 | sts | **AssumeRole** | `cloudsec-lab-incident-01-analyst` | **allowed** |
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

---

## 3. Actor attribution

The investigation pivots on the role assumption:

```
eventTime    : 2026-08-09T19:10:44Z
userIdentity : arn:aws:iam::089110987191:user/mella-admin
sourceIP     : 50.211.153.xxx        (redacted - analyst's own address)
userAgent    : aws-cli/2.36.17 ... md/command#sts.assume-role
roleArn      : arn:aws:iam::089110987191:role/cloudsec-lab-incident-01-analyst
sessionName  : incident-01-test
expiration   : 2026-08-09T20:10:44Z
```

Everything afterwards is attributed to:

```
arn:aws:sts::089110987191:assumed-role/cloudsec-lab-incident-01-analyst/incident-01-test
```

**The session name is the thread the whole investigation hangs on.** Because
`incident-01-test` was supplied at assumption time, every downstream action
carries it, so a single filter reconstructs the actor's complete activity. A
generic or attacker-chosen session name would make this materially harder —
which is why enforcing meaningful session names via `sts:RoleSessionName`
conditions is worth doing in real environments.

Note the user agent also records the exact CLI command (`md/command#sts.assume-role`),
which is useful corroboration.

---

## 4. What the denials reveal

Denied events are the most informative part of this incident. They record
**intent** — what the actor tried, regardless of success.

Three stand out:

**`iam:ListUsers` (19:11:01)** — enumeration. An actor mapping the account's
identities.

**`iam:CreateAccessKey` on `mella-admin` (19:11:03)** — attempted privilege
escalation. This is the single most alarming event in the timeline. Had the
role carried `iam:CreateAccessKey`, the actor could have minted long-lived
credentials for an administrator, converting a one-hour session into permanent
access. In a real incident this event alone would justify escalation.

**`s3:ListAllMyBuckets` (19:11:05)** — enumeration beyond the one permitted
bucket, probing for lateral targets.

The pattern — read permitted data, probe the boundary, attempt escalation,
enumerate laterally — is a recognizable progression rather than random error.

The full denial message is explicit about the cause:

```
User: arn:aws:sts::089110987191:assumed-role/cloudsec-lab-incident-01-analyst/incident-01-test
is not authorized to perform: iam:CreateAccessKey on resource: user mella-admin
because no identity-based policy allows the iam:CreateAccessKey action
```

---

## 5. The logging gap this exercise exposed

**Only 4 of the 11 actions appeared in CloudTrail Event History.**

`aws cloudtrail lookup-events` — and the console's Event History view — return
**management events only**. The seven S3 object-level actions are **data
events**, which are not recorded at all unless explicitly configured, and never
appear in Event History even when they are.

Had the investigation stopped at Event History, it would have concluded the
actor did nothing but call `GetCallerIdentity` and get denied three times. The
actual data access — including reading two files and attempting to read a
restricted one, delete a file, and plant a new object — would have been
invisible.

Two lessons:

1. **You cannot investigate what you did not log.** Data events had to be
   enabled *before* the activity occurred. There is no retroactive fix.
2. **Event History is not the whole trail.** Data events live only in the
   delivered S3 log files and must be read from there.

Retrieval used for this incident:

```powershell
aws s3 cp s3://cloudsec-lab-cloudtrail-089110987191/AWSLogs/089110987191/CloudTrail/us-east-1/2026/08/09/ . --recursive
gunzip *.gz
# then filter Records[] where eventCategory == "Data"
```

### Delivery latency

Management events took roughly **4–5 minutes** to appear in Event History. S3
log file delivery ran **5–15 minutes** behind. An investigation started
immediately after an event will see an incomplete picture — a real operational
consideration when responding to something live.

---

## 6. Findings

| # | Finding | Assessment |
| --- | --- | --- |
| 1 | Permission boundary held — all 7 out-of-scope actions denied | Working as intended |
| 2 | Privilege escalation attempt (`iam:CreateAccessKey`) was blocked and logged | Working as intended |
| 3 | Data events were required to see 7 of 11 actions | **Configuration gap, now closed** |
| 4 | Session name made attribution trivial | Good practice to enforce |
| 5 | Explicit `Deny` on `restricted/` produced unambiguous denial | Good practice |

---

## 7. Recommendations

**Enable CloudTrail data events on buckets holding sensitive data — before you
need them.** Scope by ARN prefix to control cost rather than enabling
account-wide. This lab now does exactly that.

**Alert on `iam:CreateAccessKey` and `iam:AttachUserPolicy`.** These are
high-signal privilege-escalation primitives. A denied attempt is arguably a
stronger alert than a successful one, because success may be legitimate
administration while a denial is almost never routine.

**Enforce meaningful role session names.** An `sts:RoleSessionName` condition in
the trust policy keeps attribution cheap.

**Keep session durations short.** This role is capped at one hour, bounding the
usefulness of a leaked session credential.

**Consider GuardDuty coverage.** GuardDuty raised no finding here — correctly,
since this was a single short burst from the account's own address. Detecting
this pattern would need a custom detection on denied-IAM-action volume, which
is a candidate for [detections/](../../detections/).

---

## 8. Evidence

Raw CloudTrail records are saved locally under `evidence/` and are **excluded
from version control** — they contain the analyst's real source IP and, on the
AssumeRole record, the issued session token.

| File | Contents |
| --- | --- |
| `evidence/01-assume-role.json` | The pivot event |
| `evidence/02-session-activity.json` | All management events for the session |
| `evidence/03-denied-attempts.json` | Denied events only |

Reproduce with:

```powershell
./generate-activity.ps1
./investigate.ps1 -StartUtc 2026-08-09T19:09:00Z -EndUtc 2026-08-09T19:20:00Z
```

---

## 9. Resources involved

| Resource | Identifier |
| --- | --- |
| Test role | `cloudsec-lab-incident-01-analyst` |
| Test bucket | `cloudsec-lab-incident-01-089110987191` |
| Trail | `cloudsec-lab-trail` |
| Log bucket | `cloudsec-lab-cloudtrail-089110987191` |

Defined in [terraform/incident-01/](../../terraform/incident-01/).
