# Phase 10 — Live Fire-Drill

**Date:** 2026-10-02 (event) / 2026-10-06 (discovery, fix, and re-verification)
**Objective:** Run the full chain in anger, once, against the real account —
a genuine misconfiguration, real GuardDuty detection, real Security Hub
import, real EventBridge delivery, real (attempted) automated containment —
and record the entire incident with real timestamps, not synthetic ones.
**Status:** Complete — the drill found a real bug, which is the point of
running a drill.
**Depends on:** [Phase 9 — Automated Containment](phase-9-automated-containment.md),
[Phase 6 — Incident #2](phase-6-incident-02.md)

The incident write-up is the real deliverable:
**[incidents/incident-03-automated-containment.md](../incidents/incident-03-automated-containment.md)**.
This document covers how the exercise was built and run.

---

## 1. Why a real attack, not another synthetic one

Phases 7–9 all verify the pipeline with a synthetic finding via
`BatchImportFindings` — deliberately, for speed and determinism (see
`detections/test-automated-containment.ps1`'s own docstring). That's the
right choice for a unit-of-work self-test, and the wrong choice for this
phase specifically: the brief asked for the *whole* chain, CloudTrail through
GuardDuty through Security Hub, with real timestamps — and GuardDuty's real
detection latency, Security Hub's real import behavior, and the full
EventBridge-to-Lambda path under real conditions were exactly the things a
synthetic finding skips past.

The trigger chosen was `terraform apply -var harden=false` in
`terraform/incident-02/` — the same mechanism [Incident 02](incident-02-s3.md)
used, reapplied to the same purpose-built exercise bucket. Not a new
misconfiguration invented for this phase: reusing INC-02's bucket and its
`harden` variable meant the "attack" was a one-line, reviewable Terraform
diff, the resulting GuardDuty finding was the **same finding ID** reactivated
(not a new one — GuardDuty aggregates repeats by resource+type), and the
whole exercise closed a loop the repo had already opened: INC-02 was handled
manually in 2m23s; this phase asked the Phase 9 automation to handle the
same class of event on its own.

---

## 2. What "enable the automation for real" required

Phase 9 deployed with `enable_auto_containment = false` by default —
deliberately, so a fresh deploy starts in dry-run. Running this phase's
"Automated Containment" box as a genuine `PutPublicAccessBlock` call, not a
logged intent, required a `terraform.tfvars` (gitignored, not committed)
setting it `true`:

```hcl
enable_auto_containment = true
```

`terraform plan` showed exactly the one expected change (the Lambda's
`AUTO_CONTAIN_ENABLED` environment variable) before applying it.

---

## 3. The drill found a bug, live

The short version — full root-cause analysis in
[incidents/incident-03-automated-containment.md §3](../incidents/incident-03-automated-containment.md#3-automated-containment--this-part-didnt):
the containment Lambda's IAM policy granted the wrong action names
(`s3:GetPublicAccessBlock` instead of the real `s3:GetBucketPublicAccessBlock`),
and a separate bug in the handler's own exception handling turned the
resulting `AccessDenied` into an unhandled crash instead of a graceful log
line. Neither the DLQ nor the 31-test unit suite caught it, for reasons the
incident report explains. The bucket was publicly exposed for roughly 94
hours before anyone noticed, since the drill's operator stepped away from
the session for several days in the middle of it — an accident that, in
hindsight, made the exercise more realistic, not less: a real automated
control that fails does not politely wait for someone to be watching.

Fixed, redeployed, and re-verified against the live pipeline the same day
the gap was found. See the incident report for the full fix and
verification evidence, and
[docs/phase-9-automated-containment.md §11](phase-9-automated-containment.md#11-postmortem-added-2026-10-06)
for the postmortem addendum to Phase 9's own documentation.

---

## 4. Cost

One real `terraform apply` cycle in `terraform/incident-02/` (toggled
`false` then back to `true`) and one in `terraform/response/` (the
`enable_auto_containment` toggle, then the bug fix) — no new always-on
resources. A few extra GuardDuty/Security Hub/Lambda invocations at
negligible volume.

---

## 5. Teardown

No separate teardown. `enable_auto_containment` is left as a deliberate,
operator-level decision (see the incident report) rather than reset
automatically by this phase.

---

## Next phase

Remediation items 6 and 7 in the incident report — alarming on the
containment DLQ and the Lambda's own `Errors` metric — are the next concrete
step: this phase's bug was found by an operator returning to the session by
chance, which is exactly the failure mode automated containment was built to
remove from the *detection* side. The same principle now needs to apply to
monitoring the automation itself.
