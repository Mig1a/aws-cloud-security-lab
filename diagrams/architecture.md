# Architecture

The big picture: one AWS account, three resource pillars feeding one
detection pipeline, ending in one narrowly-scoped automated response.

For the detailed, module-by-module diagram (every Terraform directory,
lifecycle color-coding, exact EventBridge filter criteria) see
[README.md § Architecture](../README.md#architecture) instead — this one is
deliberately the simplified, whole-lab view.

```mermaid
flowchart TB
    IAM0["<b>Operator</b><br/>mella-admin"]
    ACCT["<b>AWS Account</b><br/>0891****7191 · us-east-1"]
    BUD["<b>AWS Budgets</b><br/>$10/month ceiling"]

    IAM0 --> ACCT
    ACCT -.->|"guardrail"| BUD

    ACCT --> EC2G
    ACCT --> S3G
    ACCT --> IAMG

    subgraph EC2G["EC2 — ephemeral, ~$8/mo"]
        EC2["t3.micro · SSM Session Manager only<br/>no SSH key, no open inbound ports"]
    end

    subgraph S3G["S3"]
        S3LOG["CloudTrail log bucket<br/>long-lived"]
        S3EX["Exercise buckets<br/>incident-01 · incident-02"]
    end

    subgraph IAMG["IAM"]
        ROLES["Roles & policies<br/>EC2 instance · test role (INC-01)<br/>alert Lambda · containment Lambda"]
    end

    EC2G --> CT
    S3G --> CT
    IAMG --> CT

    CT["<b>CloudTrail</b><br/>multi-region · log file validation<br/>management + scoped S3 data events"]
    CT --> GD["<b>GuardDuty</b><br/>CloudTrail + VPC Flow + DNS logs"]
    CFG["<b>AWS Config</b><br/>scoped to AWS::S3::Bucket only"]
    S3G --> CFG
    GD --> SH["<b>Security Hub</b><br/>98 AWS Foundational Security<br/>Best Practices controls"]
    CFG --> SH
    SH --> EB["<b>EventBridge</b><br/>alert rule — any HIGH/CRITICAL finding<br/>2 containment rules — 4 verified finding types"]
    EB --> LAM["<b>Lambda</b><br/>securityhub_alert — logs + notifies every finding<br/>s3_containment — acts on 4 known types, notifies"]
    LAM --> AR["<b>Automated Response</b><br/>PutBucketPublicAccessBlock on one<br/>explicitly allow-listed S3 bucket"]
    LAM -.->|"SNS"| OP2(["Operator inbox"])

    classDef longlived fill:#e8f4ea,stroke:#3d7a4f,color:#1a3d28
    classDef ephemeral fill:#fdf1e3,stroke:#b5711f,color:#5c3a0c
    classDef pillar fill:#eef1fb,stroke:#3a4d8f,color:#1b2550
    class BUD,CT,GD,CFG,SH,EB,LAM,AR longlived
    class EC2 ephemeral
    class S3LOG,S3EX,ROLES pillar
```

**Reading the shape:** everything above `CloudTrail` is *what the account
does* — three independent pillars (compute, storage, identity) that all
produce activity. Everything from `CloudTrail` down is *one linear
pipeline* that turns that activity into a decision: log it and, for any
actionable outcome, notify a human via SNS (always), or, for two
independently-verified trigger families against exactly one known resource,
also fix it. That narrowing — three sources, one pipeline, one
narrow action at the end, widened only after each new trigger is verified
against a real finding — is deliberate; see
[docs/phase-9-automated-containment.md §1](../docs/phase-9-automated-containment.md#1-the-scope-decision)
and [§11](../docs/phase-9-automated-containment.md#11-extension--a-second-trigger-family-and-notification)
for how "fix it" grew from one case to four without widening the action
itself.

**What actually went live:** both trigger families have been proven against
the real account, not just unit-tested — GuardDuty's anonymous-access
finding, and the AWS Config-backed `S3.1`/`S3.2`/`S3.3`/`S3.8` "block public
access" family, each confirmed with a real or synthetic finding, a real
`PutBucketPublicAccessBlock` call, and the bucket's resulting state
independently re-checked via the live S3 API — see
[docs/phase-9-automated-containment.md §11](../docs/phase-9-automated-containment.md#11-extension--a-second-trigger-family-and-notification).
