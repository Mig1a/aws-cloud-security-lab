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

Extension: every alerted finding also publishes a short message to
NOTIFY_TOPIC_ARN via SNS. Unlike the containment handler's narrow,
four-outcome notification list, every finding that reaches this function is
already the thing worth a human's attention - that is what ALERT_SEVERITIES
and the EventBridge pattern upstream are for - so there is no separate
notify-worthy subset to compute here. This exists specifically to cover
finding types (like Incident 01's denied iam:CreateAccessKey pattern) that
reach HIGH/CRITICAL severity but have no automated remedy at all: a human
being told is the entire response. A notify failure is caught and logged,
never raised, the same discipline containment_handler.py already follows.

Event shape (EventBridge, detail-type "Security Hub Findings - Imported"):

    { "detail": { "findings": [ <ASFF finding>, ... ] } }

Note the plural. Security Hub batches findings, so one event can carry up to
100 of them -- see the re-filter in `_matching()` for why that matters.
"""

import json
import logging
import os

import boto3

LOG = logging.getLogger()
LOG.setLevel(os.environ.get("LOG_LEVEL", "INFO"))

# Kept in sync with the EventBridge event pattern by Terraform, which sets this
# variable from the same list it builds the pattern from.
ALERT_SEVERITIES = {
    s.strip().upper()
    for s in os.environ.get("ALERT_SEVERITIES", "HIGH,CRITICAL").split(",")
    if s.strip()
}

# Extension: where every alerted finding gets published. Empty string (not
# None) is the safe default - _notify() treats a blank topic ARN as "not
# configured" and skips the publish call rather than letting boto3 raise on
# an empty resource, same convention containment_handler.py uses.
NOTIFY_TOPIC_ARN = os.environ.get("NOTIFY_TOPIC_ARN", "").strip()

UNKNOWN = "<unknown>"

_sns = None


def _sns_client():
    """Lazy, module-level client - built once per execution environment,
    and easy to replace with a fake in tests by setting the module's `_sns`
    global directly. Same pattern as containment_handler.py's _sns_client()."""
    global _sns
    if _sns is None:
        _sns = boto3.client("sns")
    return _sns


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


def _notify(finding):
    """Publish a short message to NOTIFY_TOPIC_ARN for one alerted finding.
    Never raises - a notification failure must not turn an already-logged
    alert into a crashed invocation."""
    if not NOTIFY_TOPIC_ARN:
        return

    severity = (finding.get("Severity") or {}).get("Label", UNKNOWN)
    subject = f"[cloudsec-lab] {severity} finding: {finding.get('Title', UNKNOWN)}"
    message = "\n".join(
        [
            f"Finding ID:  {finding.get('Id', UNKNOWN)}",
            f"Finding:     {finding.get('Title', UNKNOWN)}",
            f"Type:        {_types(finding)}",
            f"Resource:    {_resources(finding)}",
            f"Severity:    {severity}",
        ]
    )

    try:
        _sns_client().publish(
            TopicArn=NOTIFY_TOPIC_ARN,
            Subject=subject[:100],  # SNS subject is capped at 100 characters
            Message=message,
        )
    except Exception as exc:  # noqa: BLE001 - notification must not crash the handler
        LOG.warning(
            json.dumps(
                {
                    "alert": "notify_failed",
                    "id": finding.get("Id"),
                    "detail": str(exc),
                }
            )
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
        _notify(finding)

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
