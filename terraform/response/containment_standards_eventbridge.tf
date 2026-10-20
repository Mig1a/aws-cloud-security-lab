# Extension - a second, narrow rule feeding the SAME Phase 9 containment
# Lambda, for findings that come from AWS Config-backed Security Hub
# standards controls (e.g. S3.1) rather than from GuardDuty.
#
# Mirrors containment_eventbridge.tf's shape deliberately: a separate rule
# rather than an EventBridge $or pattern combining two different fields, for
# the same reason Phase 9 gave for not branching inside the alert rule - a
# finding matching neither rule never reaches this Lambda's invocation count
# at all, which is a stronger guarantee than a code-level check alone.
#
# Standards-control findings identify which control fired via
# Compliance.SecurityControlId (e.g. "S3.1"), not via the GuardDuty-style
# Types string containment_eventbridge.tf matches on - a different ASFF
# field entirely, which is why this needed its own rule rather than an added
# value in the existing one's Types list.

resource "aws_cloudwatch_event_rule" "s3_standards_containment" {
  count = length(var.containable_security_control_ids) > 0 ? 1 : 0

  name        = "${var.project_name}-s3-standards-containment"
  description = "AWS Config-backed Security Hub standards control (e.g. S3.1) -> containment Lambda. Same Lambda as the GuardDuty-sourced containment rule."
  state       = "ENABLED"

  event_pattern = jsonencode({
    source        = ["aws.securityhub"]
    "detail-type" = ["Security Hub Findings - Imported"]
    detail = {
      findings = {
        Compliance = {
          SecurityControlId = var.containable_security_control_ids
        }
        RecordState = ["ACTIVE"]
      }
    }
  })
}

resource "aws_cloudwatch_event_target" "containment_lambda_standards" {
  count = length(var.containable_security_control_ids) > 0 ? 1 : 0

  rule      = aws_cloudwatch_event_rule.s3_standards_containment[0].name
  target_id = "containment-lambda-standards"
  arn       = aws_lambda_function.containment.arn

  # Same reasoning as the GuardDuty-sourced rule's target
  # (containment_eventbridge.tf): a dropped containment event here is worse
  # than a dropped log line, so failed deliveries land in the same DLQ
  # rather than nowhere.
  retry_policy {
    maximum_event_age_in_seconds = 3600
    maximum_retry_attempts       = 3
  }

  dead_letter_config {
    arn = aws_sqs_queue.containment_dlq.arn
  }
}

resource "aws_lambda_permission" "allow_eventbridge_containment_standards" {
  count = length(var.containable_security_control_ids) > 0 ? 1 : 0

  statement_id  = "AllowExecutionFromEventBridgeStandards"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.containment.function_name
  principal     = "events.amazonaws.com"
  source_arn    = aws_cloudwatch_event_rule.s3_standards_containment[0].arn
}
