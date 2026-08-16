# Screenshots — shot list and redaction checklist

Evidence images for the README and phase docs.

**Read [§3 Redaction](#3-redaction--do-this-before-committing) before committing
anything here.** Console screenshots leak the account ID and your public IP by
default, and this is a public repository.

---

## 1. Timing constraints

Three things bound when these can be captured:

| Constraint | Deadline | Affects |
| --- | --- | --- |
| GuardDuty / Security Hub free trials end | **~2026-09-08** | All detection screenshots |
| EC2 environment costs ~$8/month while up | — | All VPC / EC2 screenshots |
| Security Hub controls take hours to populate | — | Control pass/fail views |

**Batch the work.** Bring the environment up, capture everything in one sitting,
then tear it down. Twenty minutes of `t3.micro` runtime costs well under a cent.

```powershell
cd terraform/environment
terraform apply          # ~$0.011/hour while up
# ... capture every shot below ...
terraform destroy
```

---

## 2. Shot list

### Phase 2 — Cost guardrails

| # | File | Where | Shows |
| --- | --- | --- | --- |
| 1 | `02-budget-overview.png` | Billing → Budgets | The $10 monthly budget |
| 2 | `02-budget-alerts.png` | Budgets → budget → Alerts | All four thresholds: $5, $8, $10 actual + forecast |

### Phase 3 — Base environment

Requires `terraform apply` in `terraform/environment/`.

| # | File | Where | Shows |
| --- | --- | --- | --- |
| 3 | `03-vpc-resource-map.png` | VPC → your VPC → Resource map | Subnet, route table, IGW in one view |
| 4 | `03-security-group-inbound.png` | EC2 → Security Groups → Inbound rules | **Empty inbound list** — the no-open-ports decision |
| 5 | `03-ec2-imdsv2.png` | EC2 → instance → Details → IMDSv2 | `Required` |
| 6 | `03-ssm-session.png` | Terminal running `aws ssm start-session` | Shell access with no SSH key |
| 7 | `03-s3-block-public-access.png` | S3 → log bucket → Permissions | All four blocks on |

### Phase 4 — Detection services

Capture before the trials end.

| # | File | Where | Shows |
| --- | --- | --- | --- |
| 8 | `04-guardduty-enabled.png` | GuardDuty → Settings | Detector active, 15-minute frequency |
| 9 | `04-guardduty-features.png` | GuardDuty → Settings → Protection plans | Malware + runtime monitoring **disabled** — the cost decision |
| 10 | `04-securityhub-controls.png` | Security Hub → Controls | 98 controls; also honestly shows "No data" without AWS Config |
| 11 | `04-cloudtrail-trail-config.png` | CloudTrail → trail | Multi-region + log file validation on |

### Phase 5 — Incident 01

The most valuable images in the repo.

| # | File | Where | Shows |
| --- | --- | --- | --- |
| 12 | `05-cloudtrail-assumerole.png` | CloudTrail → Event History → `AssumeRole` | The pivot event with session name `incident-01-test` |
| 13 | **`05-denied-createaccesskey.png`** | Event History → `CreateAccessKey` → expanded | **The privilege-escalation attempt, denied.** Single best image here |
| 14 | `05-data-event-selectors.png` | CloudTrail → trail → Data events | ARN-prefix scoping — the cost-controlled fix |
| 15 | `05-investigate-output.png` | Terminal running `investigate.ps1` | Allowed vs denied breakdown |

### Phase 6 — Incident 02 (captured)

Six images, before/after pairs. Account ID redacted with solid boxes in both
browser shots.

| File | Shows |
| --- | --- |
| `06-s3-before-block-public-access-off.png` | Block all public access: **Off** |
| `06-s3-before-versioning-suspended.png` | Versioning: **Suspended** |
| `06-s3-before-anonymous-read.png` | Browser with no AWS session reading the object, `HTTP 200` |
| `06-s3-after-block-public-access-on.png` | Block all public access: **On** |
| `06-s3-after-versioning-enabled.png` | Versioning: **Enabled** |
| `06-s3-after-access-denied.png` | Same request returning `AccessDenied` |

### Phase 7 — EventBridge alerting (partially captured)

No timing constraint — `terraform/response/` is long-lived, not torn down
between sessions. Run
[`detections/test-high-severity-alert.ps1`](../detections/test-high-severity-alert.ps1)
first so the Lambda has actually fired before capturing 21–23.

Item 18 is captured, no redaction needed.

| # | File | Where | Shows |
| --- | --- | --- | --- |
| 18 | `07-eventbridge-rule-pattern.png` **(captured, no redaction needed)** | EventBridge → Rules → `cloudsec-lab-securityhub-high-severity` → Event pattern | The three filters: `Severity.Label` HIGH/CRITICAL, `RecordState` ACTIVE, `Workflow.Status` NEW/NOTIFIED |
| 19 | `07-eventbridge-rule-targets.png` | Same rule → Targets tab | Lambda target with a dead-letter queue configured |
| 20 | `07-lambda-trigger.png` | Lambda → `cloudsec-lab-securityhub-alert` → Configuration → Triggers | EventBridge rule listed as the trigger |
| 21 | `07-lambda-monitor-invocations.png` | Lambda → Monitor tab | Invocation graph showing the self-test's real invocations |
| 22 | `07-dlq-empty.png` | SQS → `cloudsec-lab-securityhub-alert-dlq` → Monitoring | `Messages available: 0` — proof a failed delivery isn't silently vanishing |
| 23 | `07-self-test-output.png` | Terminal running `test-high-severity-alert.ps1` | `PASS alert logged for HIGH`, and a second run with `-Severity LOW -ExpectNoAlert` showing `PASS no alert for LOW` |

### Phase 8 — Incident handler

**The two alert-block screenshots sent earlier in this session are now
stale — do not save them.** They were captured before this phase's field
extraction landed, so their log block only shows the five original fields
(Finding/Resource/Severity/Account/Region/Timestamp). The deployed function
now emits eight (Finding ID, Finding, Type, Description, Resource, Severity,
Account, Region, Timestamp), and the filenames below moved to a `08-` prefix
to match. Re-run the self-test against the redeployed function and capture
fresh.

| # | File | Where | Shows |
| --- | --- | --- | --- |
| 24 | **`08-security-incident-detected.png`** | CloudWatch Logs → log group → latest stream, expanded `[WARNING]` row, after re-running the self-test against the redeployed function | **The full alert block — all eight fields. Single best image for this phase, same role as #13 in Phase 5.** Account ID appears in the `Finding ID:` ARN, the `Resource:` ARN, and the `Account:` line — box out all three. |
| 25 | `08-security-incident-detected-structured.png` | Same log stream, expanded `[INFO]` row directly below | The compact JSON line for CloudWatch Logs Insights, now including `types` and `description`. Account ID appears in `"account"`, possibly inside `"id"`, and inside `"resources"` — box out all three. |

### Tooling

| # | File | Where | Shows |
| --- | --- | --- | --- |
| 26 | `00-terraform-apply.png` | Terminal | `Apply complete! Resources: 19 added` |
| 27 | `00-terraform-destroy.png` | Terminal | `Destroy complete! Resources: 19 destroyed` |

---

## 3. Redaction — do this before committing

Every console page carries identifiers worth removing from a public repo.

| Redact | Appears in | Notes |
| --- | --- | --- |
| **Account ID `089110987191`** | Console header, every ARN, bucket names | Most common leak |
| **Your public IP** | CloudTrail event details `sourceIPAddress` | Same value redacted from the incident report |
| **Session tokens / access key IDs** | AssumeRole `responseElements` | Never screenshot an expanded AssumeRole response |
| Email address | Budget alert subscribers | |
| Instance IDs, VPC IDs | Various | Low risk — fine to leave |

Practical method: crop the browser chrome and the account menu, then draw solid
boxes (not blur — blur is sometimes reversible) over the remaining IDs. Save as
PNG.

**Phase 7 specifically:** the `SECURITY INCIDENT DETECTED` log block (#21)
prints the account ID as plain text in its `Account:` line and inside the
`Resource:` ARN — not console chrome, the literal log message. Redact both
before committing, same as any other account ID.

A quick pre-commit grep will not catch text inside images, so this step is
manual. Check each file before `git add`.

---

## 4. Conventions

- **Format:** PNG. Crop tight to the relevant panel; no full desktop captures.
- **Naming:** `<phase>-<subject>.png`, e.g. `05-denied-createaccesskey.png`
- **Reference from docs** with relative links:
  `![Denied CreateAccessKey](../screenshots/05-denied-createaccesskey.png)`

> **Note:** this repo lives under OneDrive, so files added here upload to
> OneDrive as well as GitHub. Keep unredacted originals outside the repo.
