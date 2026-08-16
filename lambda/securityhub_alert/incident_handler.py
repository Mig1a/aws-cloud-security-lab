"""Extract and log the fields an incident responder needs from a Security Hub
finding delivered by EventBridge.

Phase 7 built the minimal version of this function - severity/resource/
account/region/timestamp, enough to prove GuardDuty -> Security Hub ->
EventBridge -> Lambda actually worked end to end. Phase 8 extends the same
function with the fields an analyst (or a future automated responder) needs to
actually act on a finding rather than just notice one: Finding ID (to look it
up or suppress it later), Finding type (which control or detector fired), and
Description (what the finding means without a console trip).

Still deliberately read-only. It is the notification half of the detect ->
respond pipeline; automated remediation is a later phase. Keeping it read-only
means a bad event pattern produces noise in a log group rather than an
unwanted change to account state.

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


def _types(finding):
    """Flatten the ASFF Types array to a readable one-liner.

    Types is a taxonomy path such as
    "Software and Configuration Checks/AWS Security Best Practices/S3.1" - the
    one field that tells an analyst *which control or detector* fired without
    opening the console. Same one-line-plus-count treatment as _resources,
    since a finding can carry more than one.
    """
    types = finding.get("Types") or []
    if not types:
        return UNKNOWN
    if len(types) == 1:
        return types[0]
    return f"{types[0]} (+{len(types) - 1} more)"


def _description(finding):
    """ASFF descriptions are free text and occasionally arrive with embedded
    newlines. Collapsed to one line so a single finding can't be mistaken for
    multiple fields in the human-readable block below."""
    text = finding.get("Description")
    if not text:
        return UNKNOWN
    return " ".join(str(text).split())


def _report(finding):
    """Render one finding as the human-readable alert block.

    Fields and label widths are computed together so the colons stay aligned
    without hand-counting spaces - the Phase 7 version did that by hand and it
    already needed re-spacing once for one new field.
    """
    severity = (finding.get("Severity") or {}).get("Label", UNKNOWN)

    # UpdatedAt is when Security Hub last saw the finding; CreatedAt is when it
    # first appeared. For a NEW finding they are equal, so preferring UpdatedAt
    # costs nothing and is more accurate on re-imports.
    timestamp = finding.get("UpdatedAt") or finding.get("CreatedAt") or UNKNOWN

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

    lines = ["", "SECURITY INCIDENT DETECTED", ""]
    lines += [f"  {(label + ':').ljust(width + 1)}{value}" for label, value in fields]
    lines.append("")
    return "\n".join(lines)


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
                    "types": finding.get("Types") or [],
                    "description": finding.get("Description"),
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
