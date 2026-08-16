"""Log high-severity Security Hub findings delivered by EventBridge.

Phase 7. This function deliberately does NOT remediate anything. It is the
notification half of the detect -> respond pipeline; automated response is a
later phase. Keeping it read-only means a bad event pattern produces noise in a
log group rather than an unwanted change to account state.

Event shape (EventBridge, detail-type "Security Hub Findings - Imported"):

    { "detail": { "findings": [ <ASFF finding>, ... ] } }

Note the plural. Security Hub batches findings, so one event can carry up to
100 of them -- see the re-filter in `_matching()` for why that matters.
"""

import json
import logging
import os

LOG = logging.getLogger()
LOG.setLevel(os.environ.get("LOG_LEVEL", "INFO"))

# Kept in sync with the EventBridge event pattern by Terraform, which sets this
# variable from the same list it builds the pattern from.
ALERT_SEVERITIES = {
    s.strip().upper()
    for s in os.environ.get("ALERT_SEVERITIES", "HIGH,CRITICAL").split(",")
    if s.strip()
}

UNKNOWN = "<unknown>"


def _matching(findings):
    """Drop findings whose severity is below the alerting threshold.

    This filter is NOT redundant with the EventBridge event pattern.

    EventBridge matches an array if ANY element matches. A batch containing one
    CRITICAL finding and ninety-nine INFORMATIONAL ones matches the rule, and
    the whole batch is delivered. Without this second pass the function would
    announce "SECURITY INCIDENT DETECTED" for every low-severity finding that
    happened to travel alongside a real one.
    """
    kept = []
    for finding in findings:
        label = (finding.get("Severity") or {}).get("Label", "").upper()
        if label in ALERT_SEVERITIES:
            kept.append(finding)
    return kept


def _resources(finding):
    """Flatten the ASFF Resources array to a readable one-liner."""
    ids = [r.get("Id", UNKNOWN) for r in finding.get("Resources") or []]
    if not ids:
        return UNKNOWN
    if len(ids) == 1:
        return ids[0]
    return f"{ids[0]} (+{len(ids) - 1} more)"


def _report(finding):
    """Render one finding as the human-readable alert block."""
    severity = (finding.get("Severity") or {}).get("Label", UNKNOWN)

    # UpdatedAt is when Security Hub last saw the finding; CreatedAt is when it
    # first appeared. For a NEW finding they are equal, so preferring UpdatedAt
    # costs nothing and is more accurate on re-imports.
    timestamp = finding.get("UpdatedAt") or finding.get("CreatedAt") or UNKNOWN

    return "\n".join(
        [
            "",
            "SECURITY INCIDENT DETECTED",
            "",
            f"  Finding:   {finding.get('Title', UNKNOWN)}",
            f"  Resource:  {_resources(finding)}",
            f"  Severity:  {severity}",
            f"  Account:   {finding.get('AwsAccountId', UNKNOWN)}",
            f"  Region:    {finding.get('Region', UNKNOWN)}",
            f"  Timestamp: {timestamp}",
            "",
        ]
    )


def lambda_handler(event, context):
    findings = (event.get("detail") or {}).get("findings") or []
    alerting = _matching(findings)

    if findings and not alerting:
        # Reaching here means the event pattern passed a batch through on the
        # strength of a finding this function then discarded. Expected
        # behaviour, but worth a line: a flood of these means the pattern and
        # ALERT_SEVERITIES have drifted apart.
        LOG.info(
            "No finding at or above %s in batch of %d; nothing to report.",
            "/".join(sorted(ALERT_SEVERITIES)),
            len(findings),
        )
        return {"received": len(findings), "alerted": 0}

    for finding in alerting:
        LOG.warning(_report(finding))

        # Second, compact line for machine consumption. The block above is for
        # a human reading the log stream; this one is what CloudWatch Logs
        # Insights and any future metric filter can actually parse.
        LOG.info(
            json.dumps(
                {
                    "alert": "securityhub_high_severity",
                    "id": finding.get("Id"),
                    "title": finding.get("Title"),
                    "severity": (finding.get("Severity") or {}).get("Label"),
                    "account": finding.get("AwsAccountId"),
                    "region": finding.get("Region"),
                    "product": (finding.get("ProductFields") or {}).get(
                        "aws/securityhub/ProductName"
                    ),
                    "resources": [
                        r.get("Id") for r in finding.get("Resources") or []
                    ],
                    "updated_at": finding.get("UpdatedAt"),
                }
            )
        )

    return {"received": len(findings), "alerted": len(alerting)}
