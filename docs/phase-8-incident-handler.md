# Phase 8 — The Incident Handler

**Date:** 2026-08-16
**Objective:** Broaden the Phase 7 alert Lambda so it extracts everything an
analyst needs to triage a finding — not just enough to prove the pipeline
works — without a console trip.
**Status:** Complete
**Depends on:** [Phase 7 — Near-Real-Time Alerting via EventBridge](phase-7-eventbridge-alerting.md)

Handler: [lambda/securityhub_alert/incident_handler.py](../lambda/securityhub_alert/incident_handler.py).
Tests: [lambda/tests/test_incident_handler.py](../lambda/tests/test_incident_handler.py).

---

## 1. What changed

Phase 7's field list was five values plus a title — enough to prove
GuardDuty → Security Hub → EventBridge → Lambda actually worked:
Finding (title), Resource, Severity, Account, Region, Timestamp.

This phase's brief asked for eight: **Finding ID, Finding type, Severity,
Resource, Account, Region, Timestamp, Description.** The three new ones —
Finding ID, Type, Description — are the ones an analyst actually needs to act
rather than just notice:

- **Finding ID** is how you look the finding back up in Security Hub, or
  reference it in a ticket, without hunting by title text.
- **Finding type** (ASFF `Types`, e.g.
  `Software and Configuration Checks/AWS Security Best Practices/S3.1`) says
  *which control or detector fired* — the difference between "something about
  S3" and "specifically S3.1, Block Public Access."
- **Description** is the free-text explanation Security Hub already wrote.
  Printing it means an analyst doesn't open the console just to find out what
  a control name means.

Title is kept alongside Finding ID, even though the brief's list doesn't name
it separately — it's the one field of the nine that's actually meant for a
human to read at a glance, and dropping it to match the list literally would
have made the block harder to triage, not easier.

---

## 2. Same function, not a new one

The obvious reading of "create `incident_handler.py`" is a new file. It
became the *same* Lambda instead, renamed.

Phase 7's `handler.py` was already deployed, wired to the real EventBridge
rule, and verified end to end against live Security Hub findings. Standing up
a second, near-identical function alongside it — its own IAM role, its own
log group, maybe its own EventBridge target — would have meant two logging
Lambdas to keep in sync for the rest of the lab's life, for a difference that
is entirely about *what fields get extracted*, not about *when the function
runs* or *what it's allowed to touch*. Extending beats duplicating here.

```hcl
resource "aws_lambda_function" "alert" {
  handler = "incident_handler.lambda_handler"  # was "handler.lambda_handler"
  ...
}
```

`terraform/response/lambda.tf` didn't otherwise change — same role, same log
group, same EventBridge target, same DLQ. Only the entry point and the
deployed code moved. `source_code_hash` (see Phase 7 §6) meant this alone was
enough to force a real redeploy, not a silent no-op.

---

## 3. Two fields needed defensive handling the first five didn't

**`Description` can contain embedded newlines.** ASFF descriptions are free
text, and nothing stops one from arriving with a line break. Printed
directly, that would visually split into what looks like an extra field in
the aligned block below it. Collapsed to one line first:

```python
def _description(finding):
    text = finding.get("Description")
    if not text:
        return UNKNOWN
    return " ".join(str(text).split())
```

**`Types` is a list, like `Resources`.** A finding can carry more than one
type. Reused the same one-line-plus-count pattern Phase 7 already had for
`_resources()`, rather than inventing a second convention:

```python
def _types(finding):
    types = finding.get("Types") or []
    if not types:
        return UNKNOWN
    if len(types) == 1:
        return types[0]
    return f"{types[0]} (+{len(types) - 1} more)"
```

---

## 4. The alignment stopped being hand-counted

Phase 7's block had six lines, each with manually-counted trailing spaces so
the colons lined up:

```python
f"  Finding:   {finding.get('Title', UNKNOWN)}",
f"  Resource:  {_resources(finding)}",
```

Adding three fields meant re-counting every existing line by hand, and the
longest new label (`Description:`) is longer than anything before it — silent
misalignment is an easy way to get this wrong without it being visibly wrong.
Replaced with a list of `(label, value)` pairs and a computed width:

```python
fields = [
    ("Finding ID", finding.get("Id", UNKNOWN)),
    ("Finding", finding.get("Title", UNKNOWN)),
    ("Type", _types(finding)),
    ("Description", _description(finding)),
    ("Resource", _resources(finding)),
    ("Severity", severity),
    ("Account", finding.get("AwsAccountId", UNKNOWN)),
    ("Region", finding.get("Region", UNKNOWN)),
    ("Timestamp", timestamp),
]
width = max(len(label) for label, _ in fields) + 1  # +1 for the colon
lines = [f"  {(label + ':').ljust(width + 1)}{value}" for label, value in fields]
```

A ninth field next phase means adding one tuple, not re-spacing nine lines by
hand.

The structured JSON line (§3 of Phase 7 — the second, compact `LOG.info()`
call meant for CloudWatch Logs Insights) grew the same three keys:
`"types"`, `"description"`. `"id"` already existed there, since Phase 7's
version used it for the finding ID under a different key name than the human
block used.

---

## 5. Verification

Redeployed via `terraform apply` against the already-live `terraform/response/`
stack — one resource changed, not created:

```
~ resource "aws_lambda_function" "alert" {
    ~ handler          = "handler.lambda_handler" -> "incident_handler.lambda_handler"
    ~ source_code_hash = "cTcQ..." -> "LjcT..."
    ~ description      = "Phase 7 - logs ..." -> "Phase 8 - extracts and logs ..."
}

Plan: 0 to add, 1 to change, 0 to destroy.
```

Then re-ran [`detections/test-high-severity-alert.ps1`](../detections/test-high-severity-alert.ps1)
against the redeployed function — same self-test built in Phase 7, no changes
needed, since it only asserts on the presence of `SECURITY INCIDENT DETECTED`
and the severity label, not the full field list.

```
==> Importing synthetic HIGH finding
    PASS  imported id=lab-phase7-selftest-b589504d42df

==> Result
    PASS  alert logged for HIGH

SECURITY INCIDENT DETECTED

  Finding ID:  lab-phase7-selftest-b589504d42df
  Finding:     SYNTHETIC LAB FINDING - Phase 7 pipeline self-test (HIGH)
  Type:        Software and Configuration Checks/Lab/SelfTest
  Description: Generated by detections/test-high-severity-alert.ps1 to verify the Security Hub -> EventBridge -> Lambda path. Not a real security finding.
  Resource:    arn:aws:securityhub:us-east-1:089110987191:lab/synthetic-test-resource
  Severity:    HIGH
  Account:     089110987191
  Region:      us-east-1
  Timestamp:   2026-08-16T20:45:55.223Z

==> Archiving the synthetic finding
    PASS  archived
```

Negative case (`-Severity LOW -ExpectNoAlert`) still passed — the severity
re-filter (Phase 7 §3) is untouched by this phase. DLQ confirmed empty after
both runs.

![SECURITY INCIDENT DETECTED — all eight fields](../screenshots/08-security-incident-detected.png)

![The structured log line for the same finding](../screenshots/08-security-incident-detected-structured.png)

`lambda/tests/test_incident_handler.py` — 17 tests (renamed and extended from
Phase 7's 13): the existing severity-filter and structured-JSON coverage,
plus new cases for `_types()`, `_description()` (including the newline-collapse
case), and a `test_contains_every_required_field` assertion listing all nine
labels. All pass independent of any deployment.

---

## 6. Cost

No change from Phase 7 — same function, same role, same log group, same DLQ.
A slightly larger deployment package (more code) and marginally larger log
lines are not a meaningfully different cost at lab volume.

---

## 7. Teardown

No separate teardown. This phase didn't add resources — `terraform destroy`
in `terraform/response/` (see Phase 7 §9) removes this handler along with
everything else in that stack.

---

## Next phase

The handler still only logs. Turning it from observer into responder — acting
on a finding instead of describing it — remains the open item from Phase 7's
"Next phase" section: revoke a session, tighten a bucket policy, open a
ticket, gated behind an explicit trigger rather than acting automatically.
The extraction this phase built (Finding ID to reference the finding, Type to
decide *what kind* of response applies, Resource to know *what* to act on) is
what that response logic would consume.
