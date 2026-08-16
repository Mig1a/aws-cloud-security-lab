"""Unit tests for the Phase 7 alert handler.

Deliberately outside lambda/securityhub_alert/ - that directory is zipped
verbatim by the archive_file data source in terraform/response/lambda.tf, so
anything placed there ships to production inside the deployment package.

No pytest dependency; run it directly:

    py -3.13 lambda/tests/test_handler.py
"""

import json
import logging
import os
import sys
import unittest
from unittest.mock import patch

sys.path.insert(
    0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "securityhub_alert")
)

import handler  # noqa: E402


def finding(severity, title="t", resources=None, account="111122223333"):
    return {
        "Id": f"finding-{severity}-{title}",
        "Title": title,
        "Severity": {"Label": severity},
        "AwsAccountId": account,
        "Region": "us-east-1",
        "UpdatedAt": "2026-08-16T12:00:00.000Z",
        "CreatedAt": "2026-08-16T11:00:00.000Z",
        "Resources": resources if resources is not None else [{"Id": "arn:aws:s3:::b"}],
    }


def event(*findings):
    return {"detail": {"findings": list(findings)}}


class TestSeverityFilter(unittest.TestCase):
    def test_high_alerts(self):
        result = handler.lambda_handler(event(finding("HIGH")), None)
        self.assertEqual(result, {"received": 1, "alerted": 1})

    def test_critical_alerts(self):
        result = handler.lambda_handler(event(finding("CRITICAL")), None)
        self.assertEqual(result["alerted"], 1)

    def test_low_does_not_alert(self):
        result = handler.lambda_handler(event(finding("LOW")), None)
        self.assertEqual(result, {"received": 1, "alerted": 0})

    def test_mixed_batch_reports_only_high(self):
        """The reason the handler re-filters at all.

        EventBridge matches an array if ANY element matches, so this whole
        batch is delivered on the strength of one CRITICAL finding. Reporting
        all four would mean three false 'SECURITY INCIDENT DETECTED' banners.
        """
        result = handler.lambda_handler(
            event(
                finding("INFORMATIONAL", "noise-1"),
                finding("CRITICAL", "the-real-one"),
                finding("LOW", "noise-2"),
                finding("MEDIUM", "noise-3"),
            ),
            None,
        )
        self.assertEqual(result, {"received": 4, "alerted": 1})

    def test_severity_label_is_case_insensitive(self):
        result = handler.lambda_handler(event(finding("high")), None)
        self.assertEqual(result["alerted"], 1)

    def test_empty_event_is_not_an_error(self):
        self.assertEqual(
            handler.lambda_handler({}, None), {"received": 0, "alerted": 0}
        )

    def test_missing_severity_does_not_raise(self):
        f = finding("HIGH")
        del f["Severity"]
        self.assertEqual(handler.lambda_handler(event(f), None)["alerted"], 0)


class TestReportFormat(unittest.TestCase):
    def test_contains_every_required_field(self):
        block = handler._report(finding("HIGH", "Public S3 bucket"))

        self.assertIn("SECURITY INCIDENT DETECTED", block)
        for label in ("Finding:", "Resource:", "Severity:", "Account:", "Region:", "Timestamp:"):
            self.assertIn(label, block)

        self.assertIn("Public S3 bucket", block)
        self.assertIn("111122223333", block)
        self.assertIn("us-east-1", block)
        self.assertIn("2026-08-16T12:00:00.000Z", block)

    def test_missing_fields_render_as_unknown_not_keyerror(self):
        block = handler._report({"Severity": {"Label": "HIGH"}})
        self.assertIn("<unknown>", block)

    def test_multiple_resources_are_summarised(self):
        text = handler._resources(
            finding("HIGH", resources=[{"Id": "arn:a"}, {"Id": "arn:b"}, {"Id": "arn:c"}])
        )
        self.assertEqual(text, "arn:a (+2 more)")

    def test_no_resources(self):
        self.assertEqual(handler._resources(finding("HIGH", resources=[])), "<unknown>")

    def test_structured_line_is_valid_json(self):
        """The compact line must stay parseable for Logs Insights."""
        with patch.object(handler.LOG, "info") as info:
            handler.lambda_handler(event(finding("HIGH", "parse me")), None)

        payloads = [
            json.loads(c.args[0])
            for c in info.call_args_list
            if c.args and isinstance(c.args[0], str) and c.args[0].startswith("{")
        ]
        self.assertEqual(len(payloads), 1)
        self.assertEqual(payloads[0]["severity"], "HIGH")
        self.assertEqual(payloads[0]["title"], "parse me")
        self.assertEqual(payloads[0]["resources"], ["arn:aws:s3:::b"])


class TestEnvironmentOverride(unittest.TestCase):
    def test_alert_severities_env_var_is_honoured(self):
        """Terraform sets this from the same list that builds the event
        pattern; if the env var were ignored the two could silently drift.

        ALERT_SEVERITIES is read once at module scope, so exercising it means
        reloading the module. The restoring reload must happen AFTER patch.dict
        has put the environment back - reloading while the patch is still
        active rebuilds the module from the patched value and leaks the
        override into every test that runs later.
        """
        import importlib

        try:
            with patch.dict(os.environ, {"ALERT_SEVERITIES": "MEDIUM,HIGH,CRITICAL"}):
                importlib.reload(handler)
                self.assertEqual(
                    handler.lambda_handler(event(finding("MEDIUM")), None)["alerted"], 1
                )
        finally:
            importlib.reload(handler)

        # Guard the restore itself, so a future edit that re-breaks the
        # ordering fails here rather than as a confusing failure elsewhere.
        self.assertEqual(handler.ALERT_SEVERITIES, {"HIGH", "CRITICAL"})
        self.assertEqual(handler.lambda_handler(event(finding("MEDIUM")), None)["alerted"], 0)


if __name__ == "__main__":
    logging.disable(logging.CRITICAL)
    unittest.main(verbosity=2)
