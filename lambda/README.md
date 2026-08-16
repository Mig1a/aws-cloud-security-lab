# Lambda

Function source for automated response and alerting. Each function lives in
its own subdirectory, zipped verbatim by the Terraform stack that deploys it —
so only handler code and its runtime dependencies belong inside a function's
directory. Tests live in [tests/](tests/), outside every function directory,
for exactly that reason.

---

## Catalogue

### `securityhub_alert/`

**Deployed by:** [terraform/response/](../terraform/response/)
**Trigger:** EventBridge rule on Security Hub findings at `HIGH`/`CRITICAL`
severity (configurable — see `var.alert_severity_labels`)
**Build notes:** [docs/phase-7-eventbridge-alerting.md](../docs/phase-7-eventbridge-alerting.md)

Logs `SECURITY INCIDENT DETECTED` with the finding, resource, severity,
account, region, and timestamp. **Read-only — does not remediate anything.**
This is the notification half of detect-and-respond; automated response is
still open, tracked in the [detection backlog](../detections/README.md#backlog).

Re-filters every finding in the batch it receives against its own severity
threshold rather than trusting the EventBridge event pattern alone — see
[handler.py](securityhub_alert/handler.py) and Phase 7 §3 for why the pattern
alone lets low-severity findings through.

```powershell
aws logs tail /aws/lambda/cloudsec-lab-securityhub-alert --follow
```

---

## Testing

```powershell
py -3.13 lambda/tests/test_handler.py
```

No pytest dependency — plain `unittest`, run directly. Exercises the severity
filter, the mixed-batch re-filter, missing-field handling, and the
`ALERT_SEVERITIES` environment override, independent of any deployment.

For an end-to-end test against the real deployed pipeline (Security Hub →
EventBridge → Lambda → CloudWatch Logs), see
[detections/test-high-severity-alert.ps1](../detections/test-high-severity-alert.ps1).
