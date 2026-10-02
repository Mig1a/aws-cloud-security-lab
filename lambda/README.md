# Lambda

Function source for automated response and alerting. Each function lives in
its own subdirectory, zipped verbatim by the Terraform stack that deploys it —
so only handler code and its runtime dependencies belong inside a function's
directory. Tests live in [tests/](tests/), outside every function directory,
for exactly that reason.

---

## Catalogue

### `securityhub_alert/` — entry point `incident_handler.py`

**Deployed by:** [terraform/response/](../terraform/response/)
**Trigger:** EventBridge rule on Security Hub findings at `HIGH`/`CRITICAL`
severity (configurable — see `var.alert_severity_labels`)
**Build notes:** [docs/phase-7-eventbridge-alerting.md](../docs/phase-7-eventbridge-alerting.md)
(wiring), [docs/phase-8-incident-handler.md](../docs/phase-8-incident-handler.md)
(field extraction)

Logs `SECURITY INCIDENT DETECTED` with finding ID, finding, type, description,
resource, severity, account, region, and timestamp — everything an analyst
needs to triage without a console trip. **Read-only — does not remediate
anything.** This is the notification half of detect-and-respond; automated
response for one known finding type now exists (see `incident_containment/`
below) — the rest of the [detection backlog](../detections/README.md#backlog)
is still log-only.

Re-filters every finding in the batch it receives against its own severity
threshold rather than trusting the EventBridge event pattern alone — see
[incident_handler.py](securityhub_alert/incident_handler.py) and Phase 7 §3
for why the pattern alone lets low-severity findings through.

```powershell
aws logs tail /aws/lambda/cloudsec-lab-securityhub-alert --follow
```

### `incident_containment/` — entry point `containment_handler.py`

**Deployed by:** [terraform/response/](../terraform/response/)
**Trigger:** a second, narrower EventBridge rule matching one exact ASFF
`Types` value — GuardDuty's `Policy:S3/BucketAnonymousAccessGranted` as
Security Hub renders it (configurable — see `var.containable_finding_types`)
**Build notes:** [docs/phase-9-automated-containment.md](../docs/phase-9-automated-containment.md)

**The only Lambda in this repo authorized to write to a real resource.**
Examines a finding's bucket against an explicit ARN allowlist
(`var.containable_resource_arns`) and, only if both that allowlist and the
`enable_auto_containment` kill switch agree, calls
`s3:PutPublicAccessBlock` to restore all four Block Public Access settings.
With the switch off (the default), every check still runs and is still
logged as `would_contain_but_disabled` — nothing is ever silently skipped
without a trace. Never acts on "any HIGH finding" — see the handler's module
docstring and Phase 9 §1 for why the scope stays this narrow.

```powershell
aws logs tail /aws/lambda/cloudsec-lab-s3-containment --follow
```

---

## Testing

```powershell
py -3.13 lambda/tests/test_incident_handler.py
py -3.13 lambda/tests/test_containment_handler.py
```

No pytest dependency to run them this way — plain `unittest`, run directly
(`requirements-dev.txt` adds `pytest` only for `python -m pytest lambda/tests/`,
which runs both files in one pass). Exercises the severity filter, the
mixed-batch re-filter, missing-field handling, and the `ALERT_SEVERITIES`
environment override for the alert Lambda; the three skip conditions, the
`Resources[0]`-is-not-the-bucket regression case, the already-blocked no-op,
and the enabled/disabled switch paths for the containment Lambda — all 31
tests independent of any deployment.

For end-to-end tests against the real deployed pipeline (Security Hub →
EventBridge → Lambda → CloudWatch Logs), see
[detections/test-high-severity-alert.ps1](../detections/test-high-severity-alert.ps1)
and [detections/test-automated-containment.ps1](../detections/test-automated-containment.ps1).
