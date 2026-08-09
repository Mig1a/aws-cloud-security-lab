# Phase 4 — Detection Services

**Date:** 2026-08-09
**Objective:** Enable CloudTrail, GuardDuty, and Security Hub.
**Status:** Complete — 15 resources applied and verified
**Depends on:** [Phase 3 — Base Environment](phase-3-base-environment.md)

> **Free trials started 2026-08-09 and end approximately 2026-09-08.**
> GuardDuty and Security Hub both bill continuously after that. The clock
> cannot be paused or reset. See [§6 Cost](#6-cost).
>
> **Do not `terraform destroy` this stack between sessions.** It is long-lived
> by design — see [§2](#2-why-cloudtrail-moved).

---

## 1. What was enabled

| Service | Configuration |
| --- | --- |
| **CloudTrail** | Multi-region trail, global service events, log file validation, delivering to a dedicated S3 bucket |
| **GuardDuty** | Detector enabled, 15-minute finding publication, S3 data-event analysis on, paid add-ons off |
| **Security Hub** | Enabled with AWS Foundational Security Best Practices (98 controls), GuardDuty findings routed in |

---

## 2. Why CloudTrail moved

Phase 3 put CloudTrail and its log bucket in `terraform/environment/`, the
stack that gets destroyed between sessions to avoid EC2 charges. That is the
wrong home for audit logging: tearing down the lab would also stop recording
API activity, and delete the logs already collected.

Phase 4 moves them into a new long-lived `terraform/detection/` stack alongside
GuardDuty and Security Hub. Audit and detection now keep running when the
ephemeral environment is gone — which is also what GuardDuty needs, since it
reads CloudTrail management events continuously.

The move needed no state surgery: the Phase 3 environment had already been
destroyed, so `terraform/environment/` held an empty state and only the `.tf`
files had to move (`git mv`, preserving history).

### Current layout

```
terraform/
├── budget/        # Phase 2 — long-lived. Cost guardrails.
├── detection/     # Phase 4 — long-lived. CloudTrail, GuardDuty, Security Hub.
└── environment/   # Phase 3 — ephemeral. VPC, EC2, IAM. Destroy between sessions.
```

Three states, three lifecycles. Only `environment/` should ever be destroyed
routinely.

---

## 3. GuardDuty

GuardDuty analyzes three foundational sources with no separate setup: CloudTrail
management events, VPC Flow Logs, and Route 53 DNS query logs. It reads them
from the AWS control plane directly — none need to be delivered anywhere first.

Finding publication is set to `FIFTEEN_MINUTES`, the fastest option, which
matters when running detection exercises. New findings always publish
immediately; this setting governs updates to existing ones.

### Paid add-ons declared explicitly

The three most expensive optional features are declared in code rather than
left to provider defaults, so the cost posture is visible:

| Feature | Status | Reason |
| --- | --- | --- |
| `S3_DATA_EVENTS` | **Enabled** | Cheap on an idle account; useful for the exercises ahead |
| `EBS_MALWARE_PROTECTION` | **Disabled** | Billed per GB scanned, creates snapshots — the priciest add-on |
| `RUNTIME_MONITORING` | **Disabled** | Billed per vCPU-hour |

### Features AWS enabled that were not declared

Verification showed several features on that this config never set:

```
EKS_AUDIT_LOGS     ENABLED
RDS_LOGIN_EVENTS   ENABLED
LAMBDA_NETWORK_LOGS ENABLED
```

These are AWS defaults for a new detector. They are billable in principle but
cost nothing here, because the account has no EKS clusters, no RDS instances,
and no Lambda functions for them to observe. Worth revisiting if a later phase
adds any of those — particularly Lambda, which [lambda/](../lambda/) is
scaffolded for.

---

## 4. Security Hub

Enabled with `enable_default_standards = false`, then a single standard
subscribed explicitly, so the set of billable checks is exactly what the config
says rather than whatever AWS defaults to.

**AWS Foundational Security Best Practices v1.0.0** — 98 controls enabled.
`auto_enable_controls = true` means controls AWS adds to the standard later turn
on automatically.

CIS 1.4 and PCI DSS are available via the `security_hub_standards` variable but
are not subscribed. Adding CIS roughly doubles check volume for heavily
overlapping coverage.

GuardDuty findings are routed into Security Hub through a product subscription,
so both services share one finding queue.

### The AWS Config dependency

**Most Security Hub controls are evaluated by AWS Config rules underneath, and
AWS Config is not enabled by this stack.** Without it, a large share of the 98
controls will report *No data* rather than pass or fail.

This is deliberate. AWS Config has no free tier and bills per configuration item
recorded. On an account with active `terraform apply` / `destroy` cycles, every
resource change records items — it is the most likely source of an unexpected
bill in this lab, and the phase docs have flagged it since Phase 1.

What still works without Config: GuardDuty findings flowing in, the Security Hub
finding format and console, and controls evaluated directly against API state.

Enabling Config is a conscious decision to make later, after confirming the
budget can absorb it.

---

## 5. Verification

Checked through the AWS CLI, independently of Terraform state:

| Check | Result |
| --- | --- |
| CloudTrail logging | `IsLogging=True`, no delivery error |
| GuardDuty detector | `ENABLED`, `FIFTEEN_MINUTES` |
| Malware protection | `DISABLED` |
| Runtime monitoring | `DISABLED` |
| S3 data events | `ENABLED` |
| Security Hub | `hub/default`, `AutoEnableControls=True` |
| Standard subscribed | AWS Foundational Security Best Practices |
| Controls enabled | 98 |

Standards status read `INCOMPLETE` immediately after subscribing. That is
expected — Security Hub takes time to activate controls and run the first
evaluation. Finding counts were 0 for both services at apply time, which is also
expected on a freshly enabled account.

### Where to look

```
GuardDuty    https://us-east-1.console.aws.amazon.com/guardduty/home?region=us-east-1#/findings
Security Hub https://us-east-1.console.aws.amazon.com/securityhub/home?region=us-east-1#/findings
CloudTrail   https://us-east-1.console.aws.amazon.com/cloudtrailv2/home?region=us-east-1#/events
```

---

## 6. Cost

### During the trial — through approximately 2026-09-08

| Service | Cost |
| --- | --- |
| CloudTrail management events, first copy | $0.00 |
| GuardDuty | $0.00 (30-day trial) |
| Security Hub | $0.00 (30-day trial) |
| S3 log storage (30-day expiry) | pennies |

### After the trial

| Service | Model | Estimate for this account |
| --- | --- | --- |
| GuardDuty | ~$4 per million CloudTrail events, plus per-GB flow and DNS logs | Well under $1/month while idle |
| Security Hub | Per security check, plus finding ingestion above the free allowance | A few dollars/month at 98 controls |

Rough steady state with the Phase 3 environment destroyed: **$2–5/month**.
Add roughly **$8/month** whenever the EC2 instance is left running.

### This changes the budget arithmetic

The Phase 2 budget is $10/month with alerts at $5, $8, and $10. Once the trials
end, the detection stack alone consumes a meaningful share of that before any
lab work happens. Options when the deadline approaches:

- Raise `monthly_budget_usd` in `terraform/budget/` and re-apply
- Drop Security Hub, keep GuardDuty — GuardDuty is the cheaper of the two and
  produces the more interesting findings for a detection lab
- Keep both and be strict about destroying `environment/` after every session

**Set a calendar reminder for early September 2026** to review actual spend in
Cost Explorer before the trials lapse.

---

## 7. Teardown

Only the ephemeral environment should be destroyed routinely:

```powershell
cd terraform/environment
terraform destroy
```

To decommission detection entirely — which stops all audit logging and deletes
collected CloudTrail logs via `force_destroy`:

```powershell
cd terraform/detection
terraform destroy
```

Note that disabling and re-enabling GuardDuty does not restart the free trial,
and archived findings are lost.

---

## Next phase

Phase 5 — generate findings and detect them: trigger GuardDuty detections
deliberately, capture the results in [detections/](../detections/), and write up
the investigations in [incidents/](../incidents/). The trial window is the right
time to do this.
