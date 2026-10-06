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
    see the regression test below for why that distinction is the whole
    point: Phase 10's live fire-drill was silently broken by code that
    assumed a different, hand-rolled fake's shape rather than this one."""
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


def finding(types, resources, finding_id="finding-1", updated_at="2026-08-16T12:00:00.000Z"):
    return {"Id": finding_id, "Types": types, "Resources": resources, "UpdatedAt": updated_at}


def iam_key_resource(key_id="AKIAEXAMPLE"):
    return {"Type": "AwsIamAccessKey", "Id": f"AWS::IAM::AccessKey:{key_id}"}


def s3_bucket_resource(arn):
    return {"Type": "AwsS3Bucket", "Id": arn}


def event(*findings):
    return {"detail": {"findings": list(findings)}}


def use_fake_s3(test, **kwargs):
    """Install a fresh FakeS3Client as the module's client and guarantee it's
    torn down even if the test raises."""
    fake = FakeS3Client(**kwargs)
    handler._s3 = fake
    test.addCleanup(setattr, handler, "_s3", None)
    return fake


class ContainmentTestCase(unittest.TestCase):
    """Base class fixing CONTAINABLE_RESOURCE_ARNS/AUTO_CONTAIN_ENABLED to
    known values for the duration of each test, restored afterwards."""

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
        """Regression test for Phase 10's live fire-drill: the deployed IAM
        policy granted the wrong action names (s3:GetPublicAccessBlock
        instead of the real s3:GetBucketPublicAccessBlock), so every real
        invocation hit AccessDenied here. The handler's own exception
        matching made this worse, not better - `except
        _s3_client().exceptions.NoSuchPublicAccessBlockConfiguration` raised
        its own AttributeError on this runtime's botocore (see
        containment_handler.py), which is not caught by `except Exception`
        and crashed the whole invocation instead of logging
        examine_failed. The bucket sat publicly exposed for about four days
        before anyone (anything) noticed - a crash neither EventBridge's
        target-level DLQ nor the function's own retries made visible,
        because the Lambda WAS successfully invoked each time; it just
        failed once inside. A hand-rolled fake exception class previously
        in this file could never have caught this - it always defined the
        exact attribute the code expected, which is exactly backwards from
        what a real, version-dependent botocore client does."""
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
                },
            ):
                importlib.reload(handler)
                self.assertEqual(handler.CONTAINABLE_FINDING_TYPES, {"Type/A", "Type/B"})
                self.assertEqual(
                    handler.CONTAINABLE_RESOURCE_ARNS, {ALLOWED_ARN, OTHER_ARN}
                )
                self.assertTrue(handler.AUTO_CONTAIN_ENABLED)
        finally:
            importlib.reload(handler)

        # Guard the restore itself.
        self.assertEqual(
            handler.CONTAINABLE_FINDING_TYPES, {"TTPs/Policy:S3-BucketAnonymousAccessGranted"}
        )
        self.assertEqual(handler.CONTAINABLE_RESOURCE_ARNS, set())
        self.assertFalse(handler.AUTO_CONTAIN_ENABLED)

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
