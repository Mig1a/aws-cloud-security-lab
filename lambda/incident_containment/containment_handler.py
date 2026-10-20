"""Contain one specific, narrowly-scoped S3 misconfiguration when GuardDuty
or an AWS Config-backed Security Hub standards control reports it against a
resource this lab explicitly allow-lists.

Phase 9. This is the one function in the lab authorized to write to a real
AWS resource, and every axis of that authorization is deliberately narrow:

  Trigger   Two EventBridge rules, each matching an exact, verified ASFF
            field - GuardDuty's Policy:S3/BucketAnonymousAccessGranted (via
            Types, see CONTAINABLE_FINDING_TYPES) and, separately, a Config-
            backed standards control such as S3.1 (via
            Compliance.SecurityControlId, see
            CONTAINABLE_SECURITY_CONTROL_IDS below). Not "any HIGH finding".
  Resource  An explicit allowlist of bucket ARNs (CONTAINABLE_RESOURCE_ARNS).
            Not a prefix. A finding against a bucket not on this exact list
            is logged and skipped, never acted on.
  Action    One idempotent API call - s3:PutPublicAccessBlock, all four
            settings True. Not a policy rewrite, not a delete, nothing that
            can destroy data.
  Switch    AUTO_CONTAIN_ENABLED must be explicitly "true". Off by default.
            With it off, every check below still runs and is still logged -
            this function always reports what it WOULD have done, whether
            or not it was allowed to actually do it.

None of these checks are redundant with each other, or with the EventBridge
event patterns that invoke this function - see the Phase 9 build notes for
why each one exists independently and what happens if any one is removed.

Extension: every actionable outcome (contained, would_contain_but_disabled,
contain_failed, examine_failed) also publishes a short message to
NOTIFY_TOPIC_ARN via SNS - the first thing in this lab that reaches a human
directly rather than only writing a CloudWatch Logs line someone has to go
looking for. A failure to publish is caught and logged, never raised; it
must not be able to turn a successful containment decision into a crashed
invocation.

Event shape - the same Security Hub finding-imported envelope
incident_handler.py reads, just delivered by narrower rules:

    { "detail": { "findings": [ <ASFF finding>, ... ] } }
"""

import json
import logging
import os

import boto3
from botocore.exceptions import ClientError

LOG = logging.getLogger()
LOG.setLevel(os.environ.get("LOG_LEVEL", "INFO"))

# The only finding type(s) this function ever acts on. Verified against a
# real finding already present in this account, not guessed from
# documentation: GuardDuty's native type "Policy:S3/BucketAnonymousAccessGranted"
# arrives in Security Hub's ASFF Types field as
# "TTPs/Policy:S3-BucketAnonymousAccessGranted" - the "/" inside the
# Policy:S3 segment becomes "-", and the whole thing is namespaced under
# "TTPs/".
CONTAINABLE_FINDING_TYPES = {
    t.strip()
    for t in os.environ.get(
        "CONTAINABLE_FINDING_TYPES", "TTPs/Policy:S3-BucketAnonymousAccessGranted"
    ).split(",")
    if t.strip()
}

# The only resources this function is ever allowed to touch. Populated by
# Terraform from an explicit variable - never derived from a prefix or
# wildcard match against the finding itself.
CONTAINABLE_RESOURCE_ARNS = {
    a.strip() for a in os.environ.get("CONTAINABLE_RESOURCE_ARNS", "").split(",") if a.strip()
}

# Extension: Compliance.SecurityControlId values from Config-backed Security
# Hub standards findings (e.g. "S3.1") - a second, independent match path
# alongside CONTAINABLE_FINDING_TYPES above, because standards findings
# identify which control fired through a different ASFF field than
# GuardDuty findings do. Empty by default - populated only once a real value
# has been verified against a live finding, same discipline as
# CONTAINABLE_FINDING_TYPES's own docstring note above.
CONTAINABLE_SECURITY_CONTROL_IDS = {
    c.strip()
    for c in os.environ.get("CONTAINABLE_SECURITY_CONTROL_IDS", "").split(",")
    if c.strip()
}

# Off unless explicitly turned on. Terraform's var.enable_auto_containment
# defaults to false; this mirrors that default so a missing or malformed env
# var fails closed, not open.
AUTO_CONTAIN_ENABLED = os.environ.get("AUTO_CONTAIN_ENABLED", "false").strip().lower() == "true"

# Extension: where actionable outcomes get published. Empty string (rather
# than None) is the safe default if this is ever missing - _notify() treats
# a blank topic ARN as "notification not configured" and skips the publish
# call entirely rather than letting boto3 raise on an empty resource.
NOTIFY_TOPIC_ARN = os.environ.get("NOTIFY_TOPIC_ARN", "").strip()

# Outcomes worth a human's attention: a real action, a real decision not to
# act (because the switch is off), or a real failure. Deliberately excludes
# the routine skip_* outcomes and already_contained - those happen on every
# finding Security Hub imports that isn't relevant here, and paging a human
# for "not relevant" would make the signal worth reading disappear into
# noise.
_NOTIFY_ACTIONS = {
    "contained",
    "would_contain_but_disabled",
    "contain_failed",
    "examine_failed",
}

_BLOCK_KEYS = (
    "BlockPublicAcls",
    "IgnorePublicAcls",
    "BlockPublicPolicy",
    "RestrictPublicBuckets",
)

_s3 = None
_sns = None


def _s3_client():
    """Lazy, module-level client - built once per execution environment
    rather than once per invocation, and easy to replace with a fake client
    in tests by setting the module's `_s3` global directly."""
    global _s3
    if _s3 is None:
        _s3 = boto3.client("s3")
    return _s3


def _sns_client():
    """Same lazy, replaceable-in-tests pattern as _s3_client() above."""
    global _sns
    if _sns is None:
        _sns = boto3.client("sns")
    return _sns


def _s3_bucket_resource(finding):
    """The finding's AwsS3Bucket resource, if any - deliberately NOT
    Resources[0].

    A GuardDuty S3 finding's Resources array carries the IAM principal that
    made the API call as one entry and the affected bucket as another; in a
    real finding pulled from this account the access key came first, not the
    bucket. Taking Resources[0] here would silently act on whatever resource
    happened to be listed first.
    """
    for resource in finding.get("Resources") or []:
        if resource.get("Type") == "AwsS3Bucket":
            return resource
    return None


def _bucket_name(bucket_arn):
    # arn:aws:s3:::my-bucket -> my-bucket
    return bucket_arn.rsplit(":", 1)[-1]


def _log(action, finding, bucket_arn=None, detail=None):
    """One structured line per decision, whichever branch was taken.

    Every branch logs, not only the ones that acted. A containment function
    that stays silent when it decides NOT to act is unauditable on exactly
    the occasions that matter most for reviewing whether its judgment was
    right.
    """
    LOG.warning(
        json.dumps(
            {
                "containment_action": action,
                "finding_id": finding.get("Id"),
                "finding_types": finding.get("Types"),
                "bucket_arn": bucket_arn,
                "auto_contain_enabled": AUTO_CONTAIN_ENABLED,
                "detail": detail,
                "timestamp": finding.get("UpdatedAt") or finding.get("CreatedAt"),
            }
        )
    )
    _notify(action, finding, bucket_arn=bucket_arn, detail=detail)


def _notify(action, finding, bucket_arn=None, detail=None):
    """Publish a short message to NOTIFY_TOPIC_ARN for actionable outcomes
    only (see _NOTIFY_ACTIONS). Never raises - a notification failure must
    not turn an already-decided containment outcome into a crashed
    invocation, the same "must not crash the handler" discipline every
    other step in this file follows.

    Deliberately called from _log() rather than scattered across each
    return point in _handle_one() - every call to _log() already carries
    exactly the fields a message needs, and it keeps "which outcomes get
    logged" and "which outcomes get notified" impossible to let drift out
    of sync with each other by construction.
    """
    if action not in _NOTIFY_ACTIONS or not NOTIFY_TOPIC_ARN:
        return

    control_id = (finding.get("Compliance") or {}).get("SecurityControlId")
    subject = f"[cloudsec-lab] S3 containment: {action}"
    message = "\n".join(
        [
            f"Action:      {action}",
            f"Finding ID:  {finding.get('Id', 'unknown')}",
            f"Type/Control:{' ' + control_id if control_id else ' ' + str(finding.get('Types'))}",
            f"Bucket:      {bucket_arn or 'unknown'}",
            f"Auto-contain:{' enabled' if AUTO_CONTAIN_ENABLED else ' disabled (dry-run)'}",
            f"Detail:      {detail or ''}",
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
                    "containment_action": "notify_failed",
                    "finding_id": finding.get("Id"),
                    "original_action": action,
                    "detail": str(exc),
                }
            )
        )


def _handle_one(finding):
    """Decide and, if allowed, act on a single finding. Never raises - every
    failure mode is caught, logged, and returned as its own named action, so
    one bad finding in a batch can't take the rest down with it."""

    finding_types = set(finding.get("Types") or [])
    security_control_id = (finding.get("Compliance") or {}).get("SecurityControlId")

    type_matches = bool(finding_types & CONTAINABLE_FINDING_TYPES)
    control_matches = security_control_id in CONTAINABLE_SECURITY_CONTROL_IDS

    if not (type_matches or control_matches):
        _log("skipped_unknown_type", finding)
        return "skipped_unknown_type"

    resource = _s3_bucket_resource(finding)
    if resource is None:
        _log("skipped_no_s3_resource", finding)
        return "skipped_no_s3_resource"

    bucket_arn = resource.get("Id", "")
    if bucket_arn not in CONTAINABLE_RESOURCE_ARNS:
        _log("skipped_resource_not_allowlisted", finding, bucket_arn=bucket_arn)
        return "skipped_resource_not_allowlisted"

    bucket_name = _bucket_name(bucket_arn)

    # "Examine resource": decide whether there is anything to do before doing
    # it, so a re-delivered or duplicate event (EventBridge is at-least-once)
    # produces "already_contained" instead of an indistinguishable second
    # "contained" line.
    try:
        config = _s3_client().get_public_access_block(Bucket=bucket_name)
        already_blocked = all(
            config.get("PublicAccessBlockConfiguration", {}).get(key, False)
            for key in _BLOCK_KEYS
        )
    except ClientError as exc:
        # Checked by ASFF error *code*, not by a dynamically-generated
        # `_s3_client().exceptions.NoSuchPublicAccessBlockConfiguration`
        # class - that attribute does not exist on every botocore version
        # (the Lambda runtime's bundled version omits it), and accessing a
        # missing attribute on the exceptions factory raises its own
        # AttributeError that is NOT caught by the `except Exception` below,
        # since it happens while Python is still evaluating *this* except
        # clause's type, not inside the try block - a real AccessDenied (or
        # any other ClientError) would then escape as an unhandled crash
        # instead of a graceful examine_failed log line. Matching on the
        # string error code instead is stable across botocore versions
        # because it's part of the AWS API contract, not generated Python.
        if exc.response.get("Error", {}).get("Code") == "NoSuchPublicAccessBlockConfiguration":
            already_blocked = False
        else:
            _log("examine_failed", finding, bucket_arn=bucket_arn, detail=str(exc))
            return "examine_failed"
    except Exception as exc:  # noqa: BLE001 - the examine step must not crash the handler
        _log("examine_failed", finding, bucket_arn=bucket_arn, detail=str(exc))
        return "examine_failed"

    if already_blocked:
        _log("already_contained", finding, bucket_arn=bucket_arn)
        return "already_contained"

    if not AUTO_CONTAIN_ENABLED:
        _log(
            "would_contain_but_disabled",
            finding,
            bucket_arn=bucket_arn,
            detail="AUTO_CONTAIN_ENABLED is false - no API call made.",
        )
        return "would_contain_but_disabled"

    try:
        _s3_client().put_public_access_block(
            Bucket=bucket_name,
            PublicAccessBlockConfiguration={key: True for key in _BLOCK_KEYS},
        )
    except Exception as exc:  # noqa: BLE001 - the contain step must not crash the handler
        _log("contain_failed", finding, bucket_arn=bucket_arn, detail=str(exc))
        return "contain_failed"

    _log(
        "contained",
        finding,
        bucket_arn=bucket_arn,
        detail="PutPublicAccessBlock: all four settings enabled.",
    )
    return "contained"


def lambda_handler(event, context):
    findings = (event.get("detail") or {}).get("findings") or []
    results = [_handle_one(finding) for finding in findings]
    return {"received": len(findings), "results": results}
