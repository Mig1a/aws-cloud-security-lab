"""Unit tests for the Phase 9 containment handler.

Deliberately outside lambda/incident_containment/ - that directory is zipped
verbatim by the archive_file data source in terraform/response/containment_lambda.tf,
so anything placed there ships to production inside the deployment package.

No pytest dependency, no real AWS calls - a hand-written fake S3 client
stands in for boto3. Run directly:

    py -3.13 lambda/tests/test_containment_handler.py
"""

import json
import logging
import os
import sys
import unittest
from unittest.mock import patch

from botocore.exceptions import ClientError

sys.path.insert(
    0,
    os.path.join(
        os.path.dirname(os.path.abspath(__file__)), "..", "incident_containment"
    ),
)

import containment_handler as handler  # noqa: E402

ALLOWED_ARN = "arn:aws:s3:::test-lab-allowlisted-bucket"
OTHER_ARN = "arn:aws:s3:::not-on-the-allowlist"
KNOWN_TYPE = "TTPs/Policy:S3-BucketAnonymousAccessGranted"


def client_error(code, operation="GetPublicAccessBlock", message="boom"):
    """A real botocore.exceptions.ClientError, not a hand-rolled stand-in -
    see the regression test below for why that distinction matters: a fake
    that defines whatever attribute the code expects, unconditionally,
    hides exactly the version-dependent bugs a real client would surface."""
    return ClientError({"Error": {"Code": code, "Message": message}}, operation)


class FakeS3Client:
    """Enough of boto3's S3 client surface for this handler, nothing more.

    No network calls, no real AWS credentials required to run this suite.
    """

    def __init__(self, blocked_buckets=None, raise_on_get=None, raise_on_put=None):
        self.blocked_buckets = set(blocked_buckets or ())
        self.raise_on_get = raise_on_get
        self.raise_on_put = raise_on_put
        self.get_calls = []
        self.put_calls = []

    def get_public_access_block(self, Bucket):
        self.get_calls.append(Bucket)
        if self.raise_on_get:
            raise self.raise_on_get
        if Bucket not in self.blocked_buckets:
            raise client_error("NoSuchPublicAccessBlockConfiguration")
        return {
            "PublicAccessBlockConfiguration": {
                "BlockPublicAcls": True,
                "IgnorePublicAcls": True,
                "BlockPublicPolicy": True,
                "RestrictPublicBuckets": True,
            }
        }

    def put_public_access_block(self, Bucket, PublicAccessBlockConfiguration):
        self.put_calls.append((Bucket, PublicAccessBlockConfiguration))
        if self.raise_on_put:
            raise self.raise_on_put
        self.blocked_buckets.add(Bucket)


def finding(
    types,
    resources,
    finding_id="finding-1",
    updated_at="2026-08-16T12:00:00.000Z",
    security_control_id=None,
):
    result = {"Id": finding_id, "Types": types, "Resources": resources, "UpdatedAt": updated_at}
    if security_control_id is not None:
        result["Compliance"] = {"SecurityControlId": security_control_id}
    return result


def iam_key_resource(key_id="AKIAEXAMPLE"):
    return {"Type": "AwsIamAccessKey", "Id": f"AWS::IAM::AccessKey:{key_id}"}


def s3_bucket_resource(arn):
    return {"Type": "AwsS3Bucket", "Id": arn}


def event(*findings):
    return {"detail": {"findings": list(findings)}}


class FakeSNSClient:
    """Enough of boto3's SNS client surface for this handler, nothing more -
    same minimal, real-exception philosophy as FakeS3Client above:
    raise_on_publish is a real ClientError, never a hand-rolled stand-in, so
    a test asserting the handler survives an SNS failure actually proves
    that against the real exception shape."""

    def __init__(self, raise_on_publish=None):
        self.raise_on_publish = raise_on_publish
        self.publish_calls = []

    def publish(self, TopicArn, Subject, Message):
        self.publish_calls.append((TopicArn, Subject, Message))
        if self.raise_on_publish:
            raise self.raise_on_publish


def use_fake_s3(test, **kwargs):
    """Install a fresh FakeS3Client as the module's client and guarantee it's
    torn down even if the test raises."""
    fake = FakeS3Client(**kwargs)
    handler._s3 = fake
    test.addCleanup(setattr, handler, "_s3", None)
    return fake


def use_fake_sns(test, **kwargs):
    """Same pattern as use_fake_s3 above, for the SNS client."""
    fake = FakeSNSClient(**kwargs)
    handler._sns = fake
    test.addCleanup(setattr, handler, "_sns", None)
    return fake


class ContainmentTestCase(unittest.TestCase):
    """Base class fixing CONTAINABLE_RESOURCE_ARNS/AUTO_CONTAIN_ENABLED to
    known values for the duration of each test, restored afterwards.

    NOTIFY_TOPIC_ARN is left at its real, parsed-from-environment value
    (empty string outside Lambda) rather than fixed here - tests that care
    about notification behaviour set it explicitly, so every other test in
    this file is proof that nothing about containment itself depends on
    notification being configured at all.
    """

    def setUp(self):
        self._patches = [
            patch.object(handler, "CONTAINABLE_RESOURCE_ARNS", {ALLOWED_ARN}),
            patch.object(handler, "AUTO_CONTAIN_ENABLED", True),
        ]
        for p in self._patches:
            p.start()
            self.addCleanup(p.stop)


class TestGatingChecks(ContainmentTestCase):
    """Each gate is independent - failing any one must skip, not fall
    through to the next, and must never call the S3 API."""

    def test_unknown_type_is_skipped(self):
        fake = use_fake_s3(self)
        result = handler.lambda_handler(
            event(finding(["Some/Other-Type"], [s3_bucket_resource(ALLOWED_ARN)])), None
        )
        self.assertEqual(result["results"], ["skipped_unknown_type"])
        self.assertEqual(fake.get_calls, [])
        self.assertEqual(fake.put_calls, [])

    def test_no_s3_resource_is_skipped(self):
        """A matching finding type whose Resources array never mentions an
        S3 bucket at all - e.g. an IAM-only finding that happened to share a
        type string. Must not guess at a target."""
        fake = use_fake_s3(self)
        result = handler.lambda_handler(
            event(finding([KNOWN_TYPE], [iam_key_resource()])), None
        )
        self.assertEqual(result["results"], ["skipped_no_s3_resource"])
        self.assertEqual(fake.get_calls, [])

    def test_resource_not_on_allowlist_is_skipped(self):
        fake = use_fake_s3(self)
        result = handler.lambda_handler(
            event(finding([KNOWN_TYPE], [s3_bucket_resource(OTHER_ARN)])), None
        )
        self.assertEqual(result["results"], ["skipped_resource_not_allowlisted"])
        self.assertEqual(fake.get_calls, [])

    def test_resources_0_is_not_assumed_to_be_the_bucket(self):
        """Regression test for the real-world ordering observed in this
        account: the IAM access key that made the API call is listed before
        the affected bucket."""
        fake = use_fake_s3(self, blocked_buckets=set())
        result = handler.lambda_handler(
            event(
                finding(
                    [KNOWN_TYPE],
                    [iam_key_resource(), s3_bucket_resource(ALLOWED_ARN)],
                )
            ),
            None,
        )
        self.assertEqual(result["results"], ["contained"])
        self.assertEqual(fake.put_calls[0][0], "test-lab-allowlisted-bucket")


class TestExamineStep(ContainmentTestCase):
    def test_already_blocked_is_a_noop(self):
        fake = use_fake_s3(self, blocked_buckets={"test-lab-allowlisted-bucket"})
        result = handler.lambda_handler(
            event(finding([KNOWN_TYPE], [s3_bucket_resource(ALLOWED_ARN)])), None
        )
        self.assertEqual(result["results"], ["already_contained"])
        self.assertEqual(fake.put_calls, [])

    def test_examine_failure_is_logged_and_skipped(self):
        fake = use_fake_s3(self, raise_on_get=RuntimeError("access denied"))
        result = handler.lambda_handler(
            event(finding([KNOWN_TYPE], [s3_bucket_resource(ALLOWED_ARN)])), None
        )
        self.assertEqual(result["results"], ["examine_failed"])
        self.assertEqual(fake.put_calls, [])

    def test_access_denied_on_examine_is_logged_not_crashed(self):
        """A real AccessDenied on the examine step (e.g. from a misconfigured
        IAM policy) must produce a graceful `examine_failed` log line, not an
        unhandled crash. The handler's exception matching is deliberately
        `except ClientError` + a string error-code check rather than
        `except _s3_client().exceptions.NoSuchPublicAccessBlockConfiguration`
        - that dynamically-generated attribute is not guaranteed to exist on
        every botocore version bundled with a given Lambda runtime, and
        accessing a missing one raises its own AttributeError that `except
        Exception` cannot catch (it happens while evaluating the except
        clause's type, not inside the try). A hand-rolled fake exception
        class that always defines the exact attribute the code expects would
        never catch a regression here - which is why this suite's fakes
        raise a real `botocore.exceptions.ClientError` instead."""
        fake = use_fake_s3(self, raise_on_get=client_error("AccessDenied"))
        result = handler.lambda_handler(
            event(finding([KNOWN_TYPE], [s3_bucket_resource(ALLOWED_ARN)])), None
        )
        self.assertEqual(result["results"], ["examine_failed"])
        self.assertEqual(fake.put_calls, [])


class TestKillSwitch(ContainmentTestCase):
    def test_disabled_does_not_call_put(self):
        fake = use_fake_s3(self)
        with patch.object(handler, "AUTO_CONTAIN_ENABLED", False):
            result = handler.lambda_handler(
                event(finding([KNOWN_TYPE], [s3_bucket_resource(ALLOWED_ARN)])), None
            )
        self.assertEqual(result["results"], ["would_contain_but_disabled"])
        self.assertEqual(fake.put_calls, [])

    def test_enabled_calls_put_with_all_four_settings_true(self):
        fake = use_fake_s3(self)
        result = handler.lambda_handler(
            event(finding([KNOWN_TYPE], [s3_bucket_resource(ALLOWED_ARN)])), None
        )
        self.assertEqual(result["results"], ["contained"])
        self.assertEqual(len(fake.put_calls), 1)
        bucket, config = fake.put_calls[0]
        self.assertEqual(bucket, "test-lab-allowlisted-bucket")
        self.assertTrue(all(config.values()))
        self.assertEqual(
            set(config.keys()),
            {
                "BlockPublicAcls",
                "IgnorePublicAcls",
                "BlockPublicPolicy",
                "RestrictPublicBuckets",
            },
        )

    def test_contain_failure_is_logged_not_raised(self):
        fake = use_fake_s3(self, raise_on_put=RuntimeError("throttled"))
        result = handler.lambda_handler(
            event(finding([KNOWN_TYPE], [s3_bucket_resource(ALLOWED_ARN)])), None
        )
        self.assertEqual(result["results"], ["contain_failed"])


class TestBatch(ContainmentTestCase):
    def test_multiple_findings_are_independent(self):
        """One bad finding in a batch must not stop the others from being
        evaluated and, where appropriate, acted on."""
        use_fake_s3(self)
        result = handler.lambda_handler(
            event(
                finding(["Some/Other-Type"], [s3_bucket_resource(ALLOWED_ARN)], "f-1"),
                finding([KNOWN_TYPE], [s3_bucket_resource(OTHER_ARN)], "f-2"),
                finding([KNOWN_TYPE], [s3_bucket_resource(ALLOWED_ARN)], "f-3"),
            ),
            None,
        )
        self.assertEqual(result["received"], 3)
        self.assertEqual(
            result["results"],
            ["skipped_unknown_type", "skipped_resource_not_allowlisted", "contained"],
        )

    def test_empty_event_is_not_an_error(self):
        self.assertEqual(handler.lambda_handler({}, None), {"received": 0, "results": []})


class TestLogging(ContainmentTestCase):
    def test_every_branch_logs_valid_json(self):
        """A containment function that only logs when it acts is unauditable
        on the occasions that matter most - every branch must produce a
        parseable line."""
        use_fake_s3(self)
        with patch.object(handler.LOG, "warning") as warn:
            handler.lambda_handler(
                event(finding([KNOWN_TYPE], [s3_bucket_resource(ALLOWED_ARN)])), None
            )
        self.assertEqual(len(warn.call_args_list), 1)
        payload = json.loads(warn.call_args_list[0].args[0])
        self.assertEqual(payload["containment_action"], "contained")
        self.assertEqual(payload["bucket_arn"], ALLOWED_ARN)
        self.assertIs(payload["auto_contain_enabled"], True)


class TestSecurityControlIdMatch(ContainmentTestCase):
    """Extension: a Config-backed standards finding identifies its control
    via Compliance.SecurityControlId, a completely different ASFF field
    from the GuardDuty-sourced Types this handler already matched on - this
    is the second, independent match path, not a replacement for the first.
    """

    def setUp(self):
        super().setUp()
        p = patch.object(handler, "CONTAINABLE_SECURITY_CONTROL_IDS", {"S3.1"})
        p.start()
        self.addCleanup(p.stop)

    def test_matching_security_control_id_is_contained_without_a_types_match(self):
        fake = use_fake_s3(self)
        result = handler.lambda_handler(
            event(
                finding(
                    ["Software and Configuration Checks/Industry and Regulatory Standards"],
                    [s3_bucket_resource(ALLOWED_ARN)],
                    security_control_id="S3.1",
                )
            ),
            None,
        )
        self.assertEqual(result["results"], ["contained"])
        self.assertEqual(len(fake.put_calls), 1)

    def test_unlisted_security_control_id_with_unrelated_types_is_skipped(self):
        fake = use_fake_s3(self)
        result = handler.lambda_handler(
            event(
                finding(
                    ["Software and Configuration Checks/Industry and Regulatory Standards"],
                    [s3_bucket_resource(ALLOWED_ARN)],
                    security_control_id="S3.2",
                )
            ),
            None,
        )
        self.assertEqual(result["results"], ["skipped_unknown_type"])
        self.assertEqual(fake.get_calls, [])


class TestNotifications(ContainmentTestCase):
    """Extension: the only part of this lab's pipeline that ever reaches a
    human directly rather than only CloudWatch Logs. Notification must be
    exactly as narrow as the containment decision itself - fired for real
    outcomes, silent for routine skips, and never able to crash the
    handler on its own.
    """

    TOPIC_ARN = "arn:aws:sns:us-east-1:123456789012:test-security-alerts"

    def setUp(self):
        super().setUp()
        p = patch.object(handler, "NOTIFY_TOPIC_ARN", self.TOPIC_ARN)
        p.start()
        self.addCleanup(p.stop)

    def test_contained_publishes_one_notification(self):
        use_fake_s3(self)
        fake_sns = use_fake_sns(self)
        handler.lambda_handler(
            event(finding([KNOWN_TYPE], [s3_bucket_resource(ALLOWED_ARN)])), None
        )
        self.assertEqual(len(fake_sns.publish_calls), 1)
        topic_arn, subject, message = fake_sns.publish_calls[0]
        self.assertEqual(topic_arn, self.TOPIC_ARN)
        self.assertIn("contained", subject)
        self.assertIn(ALLOWED_ARN, message)

    def test_would_contain_but_disabled_publishes(self):
        use_fake_s3(self)
        fake_sns = use_fake_sns(self)
        with patch.object(handler, "AUTO_CONTAIN_ENABLED", False):
            handler.lambda_handler(
                event(finding([KNOWN_TYPE], [s3_bucket_resource(ALLOWED_ARN)])), None
            )
        self.assertEqual(len(fake_sns.publish_calls), 1)

    def test_contain_failed_publishes(self):
        use_fake_s3(self, raise_on_put=RuntimeError("throttled"))
        fake_sns = use_fake_sns(self)
        handler.lambda_handler(
            event(finding([KNOWN_TYPE], [s3_bucket_resource(ALLOWED_ARN)])), None
        )
        self.assertEqual(len(fake_sns.publish_calls), 1)

    def test_examine_failed_publishes(self):
        use_fake_s3(self, raise_on_get=RuntimeError("boom"))
        fake_sns = use_fake_sns(self)
        handler.lambda_handler(
            event(finding([KNOWN_TYPE], [s3_bucket_resource(ALLOWED_ARN)])), None
        )
        self.assertEqual(len(fake_sns.publish_calls), 1)

    def test_routine_skips_do_not_publish(self):
        """Paging a human for every irrelevant finding Security Hub imports
        would make the signal worth reading disappear into noise."""
        use_fake_s3(self)
        fake_sns = use_fake_sns(self)
        handler.lambda_handler(
            event(finding(["Some/Other-Type"], [s3_bucket_resource(ALLOWED_ARN)])), None
        )
        self.assertEqual(fake_sns.publish_calls, [])

    def test_already_contained_does_not_publish(self):
        use_fake_s3(self, blocked_buckets={"test-lab-allowlisted-bucket"})
        fake_sns = use_fake_sns(self)
        handler.lambda_handler(
            event(finding([KNOWN_TYPE], [s3_bucket_resource(ALLOWED_ARN)])), None
        )
        self.assertEqual(fake_sns.publish_calls, [])

    def test_unconfigured_topic_arn_never_calls_publish(self):
        """Default state outside any test override: NOTIFY_TOPIC_ARN is the
        empty string. _notify() must treat that as "not configured", not
        attempt a publish call with an empty TopicArn."""
        use_fake_s3(self)
        fake_sns = use_fake_sns(self)
        with patch.object(handler, "NOTIFY_TOPIC_ARN", ""):
            handler.lambda_handler(
                event(finding([KNOWN_TYPE], [s3_bucket_resource(ALLOWED_ARN)])), None
            )
        self.assertEqual(fake_sns.publish_calls, [])

    def test_publish_failure_is_caught_and_does_not_raise(self):
        """A notification failure must not be able to turn an already-decided
        containment outcome into a crashed invocation - the same discipline
        every other step in this handler already follows."""
        use_fake_s3(self)
        use_fake_sns(self, raise_on_publish=client_error("Throttling", operation="Publish"))
        result = handler.lambda_handler(
            event(finding([KNOWN_TYPE], [s3_bucket_resource(ALLOWED_ARN)])), None
        )
        # The containment outcome itself is unaffected by the notify failure.
        self.assertEqual(result["results"], ["contained"])


class TestEnvironmentWiring(unittest.TestCase):
    """Proves CONTAINABLE_FINDING_TYPES, CONTAINABLE_RESOURCE_ARNS, and
    AUTO_CONTAIN_ENABLED are actually parsed from the environment Terraform
    sets them from - not just that the module-level defaults happen to work
    in isolation.

    Same reload-after-patch-restore ordering established in
    test_incident_handler.py: the module must be reloaded while the patched
    environment is active, and reloaded again AFTER patch.dict restores the
    real environment, or the override leaks into every test that runs after
    this one.
    """

    def test_env_vars_are_honoured(self):
        import importlib

        try:
            with patch.dict(
                os.environ,
                {
                    "CONTAINABLE_FINDING_TYPES": "Type/A, Type/B",
                    "CONTAINABLE_RESOURCE_ARNS": f"{ALLOWED_ARN}, {OTHER_ARN}",
                    "AUTO_CONTAIN_ENABLED": "TRUE",
                    "CONTAINABLE_SECURITY_CONTROL_IDS": "S3.1, S3.2",
                    "NOTIFY_TOPIC_ARN": " arn:aws:sns:us-east-1:123456789012:topic ",
                },
            ):
                importlib.reload(handler)
                self.assertEqual(handler.CONTAINABLE_FINDING_TYPES, {"Type/A", "Type/B"})
                self.assertEqual(
                    handler.CONTAINABLE_RESOURCE_ARNS, {ALLOWED_ARN, OTHER_ARN}
                )
                self.assertTrue(handler.AUTO_CONTAIN_ENABLED)
                self.assertEqual(
                    handler.CONTAINABLE_SECURITY_CONTROL_IDS, {"S3.1", "S3.2"}
                )
                self.assertEqual(
                    handler.NOTIFY_TOPIC_ARN, "arn:aws:sns:us-east-1:123456789012:topic"
                )
        finally:
            importlib.reload(handler)

        # Guard the restore itself.
        self.assertEqual(
            handler.CONTAINABLE_FINDING_TYPES, {"TTPs/Policy:S3-BucketAnonymousAccessGranted"}
        )
        self.assertEqual(handler.CONTAINABLE_RESOURCE_ARNS, set())
        self.assertFalse(handler.AUTO_CONTAIN_ENABLED)
        self.assertEqual(handler.CONTAINABLE_SECURITY_CONTROL_IDS, set())
        self.assertEqual(handler.NOTIFY_TOPIC_ARN, "")

    def test_missing_auto_contain_env_var_fails_closed(self):
        import importlib

        try:
            with patch.dict(os.environ, {}, clear=False):
                os.environ.pop("AUTO_CONTAIN_ENABLED", None)
                importlib.reload(handler)
                self.assertFalse(handler.AUTO_CONTAIN_ENABLED)
        finally:
            importlib.reload(handler)


if __name__ == "__main__":
    logging.disable(logging.CRITICAL)
    unittest.main(verbosity=2)
