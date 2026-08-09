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

### Tooling

| # | File | Where | Shows |
| --- | --- | --- | --- |
| 16 | `00-terraform-apply.png` | Terminal | `Apply complete! Resources: 19 added` |
| 17 | `00-terraform-destroy.png` | Terminal | `Destroy complete! Resources: 19 destroyed` |

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
