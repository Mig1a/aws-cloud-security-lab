# Phase 3 — Base AWS Environment

**Date:** 2026-08-09
**Objective:** Build the foundational lab environment with Terraform — VPC,
public subnet, security group, EC2 instance, S3, IAM, and CloudTrail.
**Status:** Complete — 19 resources applied and verified
**Depends on:** [Phase 2 — Cost Guardrails](phase-2-cost-guardrails.md)

> **This phase costs money.** Roughly **$8/month** if left running. See
> [§7 Cost](#7-cost) and run `terraform destroy` at the end of each session.

---

## 1. Architecture

```
AWS Account
│
├── VPC  10.0.0.0/16
│   ├── Internet Gateway
│   ├── Public subnet  10.0.1.0/24  (AZ us-east-1a, auto-assign public IP)
│   ├── Route table    0.0.0.0/0 → IGW
│   └── Security group (no inbound; egress all)
│       └── EC2  t3.micro  Amazon Linux 2023
│           └── Instance profile → IAM role → AmazonSSMManagedInstanceCore
│
├── S3  cloudsec-lab-cloudtrail-<account-id>
│   ├── Public access blocked (all four settings)
│   ├── Versioning + SSE-S3 + bucket keys
│   ├── Lifecycle: expire objects after 30 days
│   └── Bucket policy: CloudTrail write only, TLS required
│
└── CloudTrail  cloudsec-lab-trail
    └── Multi-region, global events, log file validation
```

---

## 2. Directory restructure

Phase 2 kept everything in `terraform/`. Phase 3 splits it:

```
terraform/
├── budget/        # Phase 2 — cost guardrails (own state)
└── environment/   # Phase 3 — this build (own state)
```

The reason is lifecycle, not tidiness. The Phase 3 environment should be
destroyed between sessions to avoid EC2 charges. With a single shared state,
`terraform destroy` would take the budget with it — removing the cost alerting
at exactly the moment spend from the month is still accruing. Separate states
let the environment come and go while the guardrail stays up.

The move was done with `git mv` for tracked files, and the local
`terraform.tfstate` was relocated by hand. Verified by re-running
`terraform init` and `terraform plan` in `terraform/budget/`, which reported no
infrastructure changes — confirming the budget resource was still correctly
tracked.

---

## 3. What was built

### Networking (`vpc.tf`)

| Resource | Detail |
| --- | --- |
| `aws_vpc` | `10.0.0.0/16`, DNS support and hostnames on |
| `aws_internet_gateway` | Public egress |
| `aws_subnet` | `10.0.1.0/24`, first available AZ, auto-assign public IP |
| `aws_route_table` | Default route to IGW, associated with the subnet |

The AZ comes from `data.aws_availability_zones` rather than a hardcoded
`us-east-1a`, so the config is portable across regions.

### Security group (`security_group.tf`)

**No inbound rules.** Egress is open, which the SSM agent, package updates, and
CloudTrail delivery all require.

Access to the instance is through **Systems Manager Session Manager**, which
works over an outbound connection from the agent rather than an inbound port.
No open port 22, no key pair to lose, no bastion, and every session is logged.

SSH remains available behind two variables (`enable_ssh`, `allowed_ssh_cidr`),
off by default. A variable validation rejects `0.0.0.0/0` outright, and a
`precondition` blocks enabling SSH without supplying a source CIDR.

### IAM (`iam.tf`)

An EC2 role carrying only `AmazonSSMManagedInstanceCore` — the managed policy
Session Manager needs — plus an instance profile binding it to the instance.

No S3 access, no admin. If a later exercise compromises the instance, the
credentials reachable from its metadata service are deliberately near-useless.

### EC2 (`ec2.tf`)

| Setting | Value | Why |
| --- | --- | --- |
| AMI | Amazon Linux 2023, via SSM public parameter | Always current; no hardcoded AMI ID to rot |
| Type | `t3.micro` | Smallest practical |
| `http_tokens` | `required` | **Forces IMDSv2** |
| `http_put_response_hop_limit` | `1` | Blocks container-to-metadata pivots |
| Root volume | 8 GB gp3, **encrypted** | Encryption at rest |

Forcing IMDSv2 is the highest-value single setting here. Under IMDSv1, any
server-side request forgery bug on the instance can read the role's temporary
credentials with a plain GET. IMDSv2's token requirement closes that path.

### S3 (`s3.tf`)

Log bucket named `cloudsec-lab-cloudtrail-<account-id>` — the account ID
supplies global uniqueness without needing a random provider.

Hardening applied: all four public-access-block settings, versioning, SSE-S3
with bucket keys, `BucketOwnerEnforced` ownership (ACLs disabled), and a
lifecycle rule expiring objects after `log_retention_days` (default 30) so
storage cost stays bounded.

The bucket policy grants `s3:GetBucketAcl` and `s3:PutObject` to
`cloudtrail.amazonaws.com`, scoped with an `aws:SourceArn` condition so only
*this account's* trail can write — this is the guard against the confused-deputy
problem. A third statement denies all requests where
`aws:SecureTransport` is false, rejecting plaintext HTTP.

`force_destroy = true` is set so `terraform destroy` can remove the bucket with
logs still in it. Appropriate for a lab, never for a bucket that matters.

### CloudTrail (`cloudtrail.tf`)

Multi-region trail with global service events and **log file validation**
enabled, producing signed digests so tampering with delivered logs is
detectable. Logs an attacker can silently edit are not evidence.

**Data events are deliberately not enabled.** S3 object-level and Lambda
invocation events bill per event and are the usual cause of surprise CloudTrail
bills. Enable them scoped to a single bucket when an exercise needs them.

#### The dependency cycle, and how it is avoided

CloudTrail will not accept a bucket until the bucket policy allows it, but the
policy needs the trail ARN for its `aws:SourceArn` condition. Referencing
`aws_cloudtrail.lab.arn` from the policy creates a cycle.

The trail ARN is instead constructed in a `local` from known values:

```hcl
trail_arn = "arn:aws:cloudtrail:${var.aws_region}:${account_id}:trail/${var.project_name}-trail"
```

with `depends_on = [aws_s3_bucket_policy.cloudtrail]` on the trail to force
ordering.

---

## 4. Commands run

```powershell
cd terraform/environment
terraform fmt -recursive
terraform init                # AWS provider v6.58.0
terraform validate            # Success!
terraform plan -out=tfplan    # Plan: 19 to add, 0 to change, 0 to destroy
terraform apply tfplan        # Apply complete! Resources: 19 added
```

---

## 5. Verification

Checked through the AWS CLI, independently of Terraform's state:

| Check | Command | Result |
| --- | --- | --- |
| Instance running, IMDSv2 enforced | `aws ec2 describe-instances` | `running  t3.micro  required  attached` |
| CloudTrail actively logging | `aws cloudtrail get-trail-status` | `IsLogging=True`, no delivery error |
| Multi-region + validation | `aws cloudtrail describe-trails` | `True  True` |
| S3 public access blocked | `aws s3api get-public-access-block` | `True True True True` |
| No inbound SG rules | `aws ec2 describe-security-group-rules` | count `0` |
| Session Manager reachable | `aws ssm describe-instance-information` | `Online  Amazon Linux 2023  agent 3.3.4624.0` |

### Connecting to the instance

```powershell
aws ssm start-session --target <instance-id> --region us-east-1
```

No SSH key, no open port.

---

## 6. Resource inventory

| Type | Count |
| --- | --- |
| VPC / IGW / subnet / route table / association | 5 |
| Security group + egress rule | 2 |
| IAM role, policy attachment, instance profile | 3 |
| EC2 instance | 1 |
| S3 bucket + 6 configuration resources | 7 |
| CloudTrail trail | 1 |
| **Total** | **19** |

---

## 7. Cost

| Item | Approximate monthly cost if left running |
| --- | --- |
| EC2 t3.micro (us-east-1, on-demand) | ~$7.50 |
| EBS 8 GB gp3 | ~$0.65 |
| CloudTrail management events, first copy | $0.00 |
| S3 storage for logs (30-day expiry) | pennies |
| VPC, IGW, subnet, security group, IAM | $0.00 |
| **Total** | **~$8.20/month** |

That is above the $8 alert threshold and just under the $10 ceiling set in
Phase 2 — so leaving this running for a full month will trigger alerts. That is
the guardrail working as designed, not a misconfiguration.

If the account still has free-tier EC2 hours or signup credits, actual charges
may be lower. Do not rely on it.

**Run `terraform destroy` in `terraform/environment/` at the end of each
session.** The budget in `terraform/budget/` is free and should be left alone.

---

## 8. Issue — the plugin cache did not save disk

`TF_PLUGIN_CACHE_DIR` was configured in `%APPDATA%\terraform.rc` before this
phase, expecting it to stop the ~840 MB AWS provider being duplicated per
directory.

**It did not work as intended on Windows.** Terraform shares cached providers
via symlinks, which need privileges Windows does not grant by default, so it
falls back to copying. Measured afterwards:

| Location | Size |
| --- | --- |
| Plugin cache | 0.84 GB |
| `terraform/budget/.terraform` | 0.84 GB |
| `terraform/environment/.terraform` | 0.84 GB |

Three copies, 2.5 GB total — the cache made disk usage *worse* by adding a third
copy. It still saves re-download time.

Options: enable Windows Developer Mode so Terraform can create symlinks, or
delete the cache directory and remove the `terraform.rc` entry to reclaim
0.84 GB.

A related note: writing `terraform.rc` with PowerShell 5.1's
`Set-Content -Encoding utf8` added a UTF-8 BOM, which Terraform's HCL parser
rejects with `At 1:1: illegal char`. It had to be rewritten BOM-free via
`[System.IO.File]::WriteAllText`.

---

## 9. Teardown

```powershell
cd terraform/environment
terraform destroy
```

Removes all 19 resources. `force_destroy` on the log bucket means CloudTrail
logs are deleted with it — export anything worth keeping into `incidents/`
first.

---

## Next phase

Phase 4 — enable GuardDuty and begin generating and detecting findings. Note
that GuardDuty's 30-day free trial starts the moment it is enabled, so plan the
exercises before switching it on.
