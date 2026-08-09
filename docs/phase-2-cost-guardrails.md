# Phase 2 — Cost Guardrails

**Date:** 2026-08-09
**Objective:** Put a spend ceiling and tiered alerting in place, as Terraform
code, before any billable security service is enabled.
**Status:** Complete — budget live and verified
**Depends on:** [Phase 1 — Environment Setup](phase-1-environment-setup.md)

---

## 1. Why this comes first

Nearly every service this lab needs bills continuously once switched on, and the
free trials start on **activation**, not on first use:

| Service | Cost model |
| --- | --- |
| GuardDuty | 30-day trial, then per-GB of logs analyzed |
| Security Hub | 30-day trial, then per-check and per-finding |
| AWS Config | No free tier — charges per configuration item recorded |
| CloudTrail | First copy of management events free; data events billed |

AWS Config is the classic surprise: it quietly records every resource change,
including ones Terraform makes. Building the alerting first means the first
billable mistake produces an email rather than a statement.

This also makes a good first Terraform exercise — a real `+ create` plan on a
resource that costs nothing to run.

---

## 2. What was built

A single `aws_budgets_budget` resource: a **$10 monthly cost budget** with four
notifications.

| Alert | Type | Condition |
| --- | --- | --- |
| 1 | ACTUAL | spend > $5.00 |
| 2 | ACTUAL | spend > $8.00 |
| 3 | ACTUAL | spend > $10.00 |
| 4 | FORECASTED | projected month-end spend > $10.00 |

All four deliver to the address in `alert_email`. Budget notifications go
straight to email and need no SNS topic or subscription confirmation.

### Files

```
terraform/budget/
├── versions.tf              # Terraform + AWS provider constraints, default tags
├── variables.tf             # Inputs with validation
├── budget.tf                # The budget resource
├── outputs.tf               # Budget name, limit, thresholds
├── terraform.tfvars.example # Committed template
└── terraform.tfvars         # Real values — gitignored
```

> These files lived directly in `terraform/` when this phase was written.
> [Phase 3](phase-3-base-environment.md) moved them into `terraform/budget/` so
> the ephemeral Phase 3 environment could be destroyed without taking the
> budget with it.

### Variables

| Variable | Type | Default | Purpose |
| --- | --- | --- | --- |
| `alert_email` | string | *(required)* | Alert recipient; regex-validated |
| `monthly_budget_usd` | number | `10` | Budget ceiling |
| `alert_thresholds_usd` | list(number) | `[5, 8, 10]` | Actual-spend trigger points |
| `enable_forecast_alert` | bool | `true` | Toggle the forecasted alert |
| `aws_region` | string | `us-east-1` | Provider region |

The three actual-spend alerts are generated from `alert_thresholds_usd` with a
`dynamic "notification"` block, so changing the list changes the alerts — no
copy-pasted resource blocks.

---

## 3. Design decisions

### Absolute values, not percentages

Thresholds use `threshold_type = "ABSOLUTE_VALUE"` so the config reads in the
same dollars as the requirement. The percentage equivalent (50/80/100) would
mean the same thing today but silently re-scale if the budget limit changed.

### `include_credit = false`

The budget tracks **gross usage cost**, not what reaches the card.

With promotional credits applied, a credit-inclusive budget reports $0 right up
until the credits are exhausted, then jumps. Excluding credits means alerts
reflect what is actually being consumed, which is the useful signal while
learning. `include_refund` is also false; `include_tax` is true.

### A fourth, unrequested alert

The specification called for three alerts at $5/$8/$10, all of which fire on
spend already incurred. A `FORECASTED` alert was added because actual-spend
alerts are inherently late — with Config recording continuously, $5 to $10 can
elapse in under a day. The forecast alert typically fires days earlier.

Set `enable_forecast_alert = false` to match the original three-alert spec
exactly.

### Default tags

The provider applies `Project` and `ManagedBy` tags to every taggable resource,
so lab resources stay distinguishable in Cost Explorer.

---

## 4. Commands run

```powershell
cd terraform
terraform fmt -recursive     # no changes needed
terraform init               # downloaded AWS provider v6.58.0
terraform validate           # Success! The configuration is valid.
terraform plan -out=tfplan   # 1 to add, 0 to change, 0 to destroy
terraform apply tfplan       # Apply complete! Resources: 1 added
```

Using `-out=tfplan` and then applying that saved file guarantees the applied
changes are exactly the reviewed ones. The plan file was deleted afterward and
`tfplan` added to `.gitignore`.

---

## 5. Verification

Confirmed independently of Terraform, through the AWS CLI, so the check does not
rely on Terraform's own view of state:

```powershell
aws budgets describe-budget --account-id <id> --budget-name lab-monthly-cost-budget
aws budgets describe-notifications-for-budget --account-id <id> --budget-name lab-monthly-cost-budget
```

Results:

```
lab-monthly-cost-budget   10.0   USD   MONTHLY   COST

ACTUAL       GREATER_THAN   10.0   ABSOLUTE_VALUE
ACTUAL       GREATER_THAN    5.0   ABSOLUTE_VALUE
ACTUAL       GREATER_THAN    8.0   ABSOLUTE_VALUE
FORECASTED   GREATER_THAN   10.0   ABSOLUTE_VALUE
```

Terraform outputs:

```
budget_name            = "lab-monthly-cost-budget"
budget_limit           = "10 USD"
alert_thresholds_usd   = [5, 8, 10]
forecast_alert_enabled = true
```

---

## 6. Secrets handling

`terraform.tfvars` contains the alert email and is excluded by the `*.tfvars`
rule in `.gitignore` — confirmed with `git check-ignore -v`, which reported the
matching rule and line. `terraform.tfvars.example` is committed in its place so
the required inputs are documented without exposing real values.

`terraform.tfstate` is likewise gitignored. State is currently local; moving it
to an S3 backend with DynamoDB locking is a candidate for a later phase.

---

## 7. What this costs

AWS provides the first two budgets per account at no charge, so this one is
free. Beyond that, AWS charges a small daily fee per budget.

---

## 8. Issue encountered — disk exhaustion

`terraform init` downloaded the ~700 MB AWS provider into `terraform/.terraform/`,
dropping free space on C: from 1.2 GB to **0.2 GB** — low enough to destabilize
Windows.

Resolved by clearing regenerable caches, which recovered ~5.2 GB:

| Cache | Reclaimed |
| --- | --- |
| npm | 2.87 GB |
| Windows temp | ~0.6 GB |
| pip | 0.07 GB |

`cleanmgr` was not used — the session was not elevated, and its system targets
were nearly empty anyway (`C:\Windows.old` absent, update cache 0.01 GB).

**Follow-up:** a plugin cache was configured before Phase 3 to stop the provider
being duplicated per directory. It did not help on Windows — see
[Phase 3 §8](phase-3-base-environment.md#8-issue--the-plugin-cache-did-not-save-disk).

---

## 9. Teardown

```powershell
cd terraform
terraform destroy
```

The budget itself is free, so there is no cost reason to destroy it — and good
reason to leave it running, since it protects against the phases that follow.

---

## Next phase

Phase 3 — enable logging and detection: CloudTrail with a dedicated S3 bucket,
then GuardDuty. These are the first genuinely billable services, which is
exactly why the guardrail in this phase exists.
