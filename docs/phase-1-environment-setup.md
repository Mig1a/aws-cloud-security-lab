# Phase 1 — Environment Setup

**Date:** 2026-08-09
**Objective:** Stand up an empty GitHub repository and get AWS CLI and Terraform
authenticating against a personal AWS account from a local Windows workstation.
**Status:** Complete

---

## 1. Workstation baseline

| Item | Value |
| --- | --- |
| OS | Windows 11 Home (10.0.22621) |
| Shell | PowerShell 5.1 |
| Editor | VS Code 1.131.0 |
| Repo location | `C:\Users\mella\OneDrive\Desktop\GMU\aws-cloud-security-lab` |

---

## 2. Repository setup

### Problem found

The git repository root was the parent `GMU` folder, not the lab folder. That
folder held 71 untracked personal files — resumes, an academic transcript, and
tax documents. A `git add .` from the root would have staged all of them and
pushed them to a public GitHub repository.

### Resolution

Moved the `.git` directory from `GMU\` into `aws-cloud-security-lab\`, which
made the lab folder the repository root. Commit history and the `origin` remote
were preserved, so no force-push was needed. The parent folder is no longer a
git repository, so personal documents are now structurally unreachable by git.

### Directory structure created

```
aws-cloud-security-lab/
├── terraform/      # Infrastructure as code
├── lambda/         # Automated response function source
├── detections/     # Detection rules and queries
├── incidents/      # Incident write-ups
├── diagrams/       # Architecture diagrams
├── screenshots/    # Console evidence
├── docs/           # Phase documentation
├── .gitignore
└── README.md
```

Empty directories carry a `.gitkeep` placeholder so git tracks them.

### .gitignore

Written to exclude, in particular:

- Terraform state (`*.tfstate`, `*.tfstate.*`) and variable files (`*.tfvars`)
- Credentials and keys (`*.pem`, `*.key`, `.env`)
- Lambda build artifacts (`*.zip`, `__pycache__/`, `.venv/`)

`.terraform.lock.hcl` is deliberately **not** ignored — the provider lock file
should be committed so provider versions resolve identically across machines.

### Remote

`origin` → `https://github.com/Mig1a/aws-cloud-security-lab.git`, branch `main`.

---

## 3. Toolchain installation

Verified what was present, then installed what was missing via `winget`.

| Tool | Version | Action |
| --- | --- | --- |
| Git | 2.49.0 | Already present |
| VS Code | 1.131.0 | Already present |
| AWS CLI | 2.36.17 | Installed (`winget install --id Amazon.AWSCLI -e`) |
| Terraform | 1.15.8 | Installed (`winget install --id Hashicorp.Terraform -e`) |
| Python | 3.13.15 | Already present; made default (see below) |

### Python PATH correction

Bare `python` resolved to a Microsoft Store Python **3.9** shim in
`%LOCALAPPDATA%\Microsoft\WindowsApps`, which is past end-of-life and is not a
valid Lambda runtime. Four interpreters were installed (3.14, 3.13, 3.11, 3.9)
but only the Store shim was on `PATH`.

Fixed by prepending Python 3.13 to the **user** PATH in the registry:

```
C:\Users\mella\AppData\Local\Programs\Python\Python313\Scripts
C:\Users\mella\AppData\Local\Programs\Python\Python313
```

The registry value was read and written unexpanded and its `ExpandString` type
preserved, so no `%VAR%` references were flattened into literals. The original
value is backed up at `C:\Users\mella\user-path-backup.txt`. Python 3.9 remains
reachable via `py -3.9` for other coursework.

Lambda code in this lab targets **Python 3.13**, matching the `python3.13`
Lambda runtime.

---

## 4. AWS account setup

Used a personal AWS account rather than AWS Educate, because Educate provides
only a sandbox — it does not permit the IAM, GuardDuty, and Terraform access
this lab requires.

Steps performed in the console:

1. Signed in as root user
2. Created IAM user `mella-admin` with `AdministratorAccess` and console access
3. Generated a CLI access key for that user
4. Configured the CLI locally with `aws configure` (region `us-east-1`,
   output `json`)

Root credentials are not used for day-to-day work, and no root access keys were
created.

---

## 5. Verification

Both tools were verified by actually reaching AWS, not just by version string.

### AWS CLI

```powershell
aws sts get-caller-identity
```

Returned `arn:aws:iam::0891****7191:user/mella-admin` — confirming
authentication as the IAM user rather than root.

### Terraform

Applied a throwaway configuration containing only a read-only data source, so
no infrastructure was created:

```hcl
data "aws_caller_identity" "current" {}
output "arn" { value = data.aws_caller_identity.current.arn }
```

`terraform init` downloaded AWS provider v6.58.0; `terraform apply` returned the
same ARN with `0 added, 0 changed, 0 destroyed`. This confirms Terraform picks
up the CLI credentials automatically. The scratch directory was then deleted.

---

## 6. Issues encountered

### Disk exhaustion

`terraform init` failed with `There is not enough space on the disk`. The C:
drive had **0.47 GB free of 457 GB**; the AWS provider binary needs roughly
700 MB.

Clearing `%TEMP%` reclaimed ~880 MB, which was enough to complete verification.
This is a stopgap, not a fix — see outstanding items.

### Duplicate commit subject

Two commits share the subject "Scaffold lab structure and relocate repo root"
because the scaffold had been partially committed in an earlier session.
Cosmetic only; can be squashed.

---

## 7. Outstanding items

| Item | Why it matters |
| --- | --- |
| **Free up disk space** | ~1.2 GB free. The AWS provider is re-downloaded per project by default; the next `terraform init` may fail again. |
| **Set `TF_PLUGIN_CACHE_DIR`** | Makes Terraform download each provider once and share it across projects — directly mitigates the disk problem. |
| **Confirm MFA on root user** | Instructed but not independently verified. A root account with only a password is a single credential leak from account takeover. |
| **Create a zero-spend budget alert** | Instructed but not independently verified. GuardDuty, Security Hub, and Config bill continuously once enabled. |
| **Move repo out of OneDrive** | OneDrive sync can conflict with git internals, and `screenshots/` will sync-upload evidence images. |

---

## 8. Cost awareness

Most services this lab needs are **not** free tier:

| Service | Cost model |
| --- | --- |
| GuardDuty | 30-day trial, then per-GB analyzed |
| Security Hub | 30-day trial, then per-check and per-finding |
| AWS Config | No free tier — per configuration item recorded |
| CloudTrail | First copy of management events free; data events billed |

Trials start when the service is enabled, not when it is first used. Practice
running `terraform destroy` at the end of each working session.

---

## Next phase

Phase 2 — write the first real Terraform configuration in `terraform/`:
a zero-spend budget alert and billing alarm. Chosen deliberately as the first
build because it costs nothing to run and provides a guardrail before any
billable security service is enabled.
