# AWS Cloud Security Lab

A hands-on lab for building and exercising detection and response capabilities in AWS.

## Layout

| Directory | Contents |
| --- | --- |
| `terraform/` | Infrastructure as code for the lab environment |
| `lambda/` | Lambda function source for automated response actions |
| `detections/` | Detection rules and queries |
| `incidents/` | Incident write-ups and investigation notes |
| `diagrams/` | [Architecture and data-flow diagrams](diagrams/architecture.md) |
| `screenshots/` | Console evidence captured during exercises |
| `docs/` | Phase-by-phase build documentation |

## Documentation

| Phase | Document | Status |
| --- | --- | --- |
| 1 | [Environment Setup](docs/phase-1-environment-setup.md) | Complete |
| 2 | [Cost Guardrails](docs/phase-2-cost-guardrails.md) | Complete |
| 3 | [Base AWS Environment](docs/phase-3-base-environment.md) | Complete |
| 4 | [Detection Services](docs/phase-4-detection-services.md) | Complete |
| 5 | [Incident #1 — IAM Investigation](docs/phase-5-incident-01.md) | Complete |
| 6 | [Incident #2 — Insecure S3 Configuration](docs/phase-6-incident-02.md) | Complete |
| 7 | [Near-Real-Time Alerting via EventBridge](docs/phase-7-eventbridge-alerting.md) | Complete |
| 8 | [The Incident Handler](docs/phase-8-incident-handler.md) | Complete |
| 9 | [Automated Containment](docs/phase-9-automated-containment.md) | Complete — postmortem in §11 |
| 10 | [Live Fire-Drill](docs/phase-10-live-fire-drill.md) | Complete |

## Incidents

| ID | Report | Summary |
| --- | --- | --- |
| INC-01 | [IAM Role Misuse Investigation](incidents/incident-01-iam.md) | 11 actions from one assumed role; 7 denied including a privilege-escalation attempt. Exposed that 7 of 11 were invisible without CloudTrail data events. |
| INC-02 | [Insecure S3 Configuration](incidents/incident-02-s3.md) | Bucket made publicly readable, detected, investigated, and remediated in a 2m23s exposure window. Exposed that Security Hub's S3 controls detect nothing without AWS Config. |
| INC-03 | [Automated Containment's Live Fire-Drill](incidents/incident-03-automated-containment.md) | A real GuardDuty detection reached the Phase 9 containment Lambda, which then crashed on every invocation — wrong IAM action names, masked by a second bug in its own error handling. ~94h exposure before discovery; root-caused, fixed, and re-verified live. |

### INC-02 evidence — before and after remediation

Anonymous request carrying no AWS credentials, against the same object:

| Before — `HTTP 200`, world-readable | After — `HTTP 403 AccessDenied` |
| --- | --- |
| ![Anonymous read succeeds](screenshots/06-s3-before-anonymous-read.png) | ![Anonymous read denied](screenshots/06-s3-after-access-denied.png) |

Bucket configuration, same console panels:

| Before | After |
| --- | --- |
| ![Block public access off](screenshots/06-s3-before-block-public-access-off.png) | ![Block public access on](screenshots/06-s3-after-block-public-access-on.png) |
| ![Versioning suspended](screenshots/06-s3-before-versioning-suspended.png) | ![Versioning enabled](screenshots/06-s3-after-versioning-enabled.png) |

Remediation was a single Terraform variable — `terraform apply -var=harden=true`,
`Plan: 2 to add, 5 to change` — rather than a sequence of console clicks. Full
write-up in [incidents/incident-02-s3.md](incidents/incident-02-s3.md).

## Architecture

Module-by-module detail below. For the simplified, whole-lab view, see
[diagrams/architecture.md](diagrams/architecture.md).

```mermaid
flowchart TB
    subgraph budget["terraform/budget/ &nbsp;·&nbsp; long-lived"]
        BUD["<b>AWS Budgets</b><br/>$10/month ceiling<br/>alerts at $5 · $8 · $10 + forecast"]
    end

    subgraph detection["terraform/detection/ &nbsp;·&nbsp; long-lived"]
        CT["<b>CloudTrail</b><br/>multi-region · log file validation<br/>management + scoped S3 data events"]
        S3L["<b>S3 log bucket</b><br/>SSE-S3 · versioned · public access blocked<br/>TLS-only policy · 30-day expiry"]
        GD["<b>GuardDuty</b><br/>CloudTrail + VPC Flow + DNS logs<br/>paid add-ons disabled"]
        SH["<b>Security Hub</b><br/>AWS Foundational Best Practices<br/>98 controls"]
    end

    subgraph response["terraform/response/ &nbsp;·&nbsp; long-lived"]
        EB["<b>EventBridge rule</b><br/>default bus · Severity HIGH/CRITICAL<br/>RecordState ACTIVE · Workflow NEW/NOTIFIED"]
        LAM["<b>Lambda</b> securityhub_alert<br/>python3.13 · logs only, no remediation"]
        DLQ["<b>SQS DLQ</b><br/>catches undelivered alerts"]
        EB2["<b>EventBridge rule</b><br/>exact Types match only:<br/>S3 anonymous access"]
        CLAM["<b>Lambda</b> s3_containment<br/>allow-listed bucket only · dry-run by default"]
        CDLQ["<b>SQS DLQ</b><br/>catches undelivered containment events"]
    end

    subgraph env["terraform/environment/ &nbsp;·&nbsp; ephemeral, ~$8/mo"]
        VPC["<b>VPC</b> 10.0.0.0/16"]
        SUB["<b>Public subnet</b> 10.0.1.0/24<br/>+ IGW · route table"]
        SG["<b>Security group</b><br/>no inbound rules"]
        EC2["<b>EC2</b> t3.micro · AL2023<br/>IMDSv2 required · encrypted EBS"]
        ROLE["<b>IAM role</b> + instance profile<br/>AmazonSSMManagedInstanceCore only"]
    end

    subgraph inc["terraform/incident-01/ &nbsp;·&nbsp; exercise"]
        TROLE["<b>Test role</b><br/>read-only on reports/<br/>explicit deny on restricted/"]
        TB["<b>Test bucket</b><br/>reports/ · restricted/"]
    end

    subgraph inc2["terraform/incident-02/ &nbsp;·&nbsp; exercise"]
        INC2B["<b>INC-02 bucket</b><br/>hardened policy · the one resource<br/>the containment Lambda may touch"]
    end

    OP(["Operator"]) -->|"SSM Session Manager<br/>no open port, no key pair"| EC2
    VPC --> SUB --> SG --> EC2
    ROLE -.attached.-> EC2

    EC2 -->|API activity| CT
    TROLE -->|"assumed · allowed + denied actions"| TB
    TB -->|data events| CT
    TROLE -->|management events| CT

    CT --> S3L
    CT ==>|"management, flow & DNS logs"| GD
    GD ==>|findings| SH
    SH ==>|"Findings - Imported"| EB
    EB ==>|invoke| LAM
    EB -.->|"failed delivery"| DLQ
    LAM -->|"SECURITY INCIDENT DETECTED"| CWL[("CloudWatch Logs")]
    SH ==>|"Findings - Imported<br/>(S3 anonymous access only)"| EB2
    EB2 ==>|invoke| CLAM
    EB2 -.->|"failed delivery"| CDLQ
    CLAM -->|"PutPublicAccessBlock<br/>(if allow-listed + enabled)"| INC2B
    CLAM -->|"every decision, logged"| CWL

    BUD -.->|"email alerts on spend"| OP
    SH -.->|findings| OP

    classDef longlived fill:#e8f4ea,stroke:#3d7a4f,color:#1a3d28
    classDef ephemeral fill:#fdf1e3,stroke:#b5711f,color:#5c3a0c
    classDef exercise fill:#eceaf7,stroke:#5b4b9e,color:#2c2456
    class BUD,CT,S3L,GD,SH,EB,LAM,DLQ,EB2,CLAM,CDLQ,CWL longlived
    class VPC,SUB,SG,EC2,ROLE ephemeral
    class TROLE,TB,INC2B exercise
```

Green is long-lived and always on. Orange is destroyed between sessions to
avoid EC2 charges. Purple is per-exercise.

## Terraform layout

Separate state per lifecycle. Only `environment/` should be destroyed routinely.

| Directory | Lifecycle |
| --- | --- |
| [terraform/budget/](terraform/budget/) | Long-lived. Cost guardrails — leave running. |
| [terraform/detection/](terraform/detection/) | Long-lived. CloudTrail, GuardDuty, Security Hub — leave running. |
| [terraform/response/](terraform/response/) | Long-lived. EventBridge rules, alert Lambda, containment Lambda, DLQs — leave running. |
| [terraform/environment/](terraform/environment/) | Ephemeral. **Run `terraform destroy` between sessions** — roughly $8/month if left up. |
| [terraform/incident-01/](terraform/incident-01/), [terraform/incident-02/](terraform/incident-02/) | Exercise. Destroy once the incident write-up is complete. |

> **Free trials for GuardDuty and Security Hub end approximately 2026-09-08.**
> Review spend in Cost Explorer before then — see [Phase 4 §6](docs/phase-4-detection-services.md#6-cost).

## Prerequisites

| Tool | Purpose |
| --- | --- |
| [AWS CLI v2](https://docs.aws.amazon.com/cli/latest/userguide/getting-started-install.html) | Authenticating to the lab account and querying resources |
| [Terraform](https://developer.hashicorp.com/terraform/install) | Provisioning and tearing down lab infrastructure |
| [Git](https://git-scm.com/downloads) | Version control |
| [VS Code](https://code.visualstudio.com/) | Editing, with the HashiCorp Terraform and AWS Toolkit extensions |
| [Python 3.12+](https://www.python.org/downloads/) | Lambda function runtime and helper scripts |

On Windows, install the first two with:

```powershell
winget install --id Amazon.AWSCLI -e
winget install --id Hashicorp.Terraform -e
```

Verify each is on `PATH` in a fresh terminal:

```powershell
aws --version; terraform version; git --version; python --version
```

> **Python note:** Lambda code targets **3.13**, matching the `python3.13` Lambda
> runtime. Create the virtualenv with `py -3.13 -m venv .venv` so the interpreter
> is pinned explicitly regardless of what bare `python` resolves to.

## Getting started

_TBD — document AWS account setup, credential profile, and `terraform apply` steps here._
