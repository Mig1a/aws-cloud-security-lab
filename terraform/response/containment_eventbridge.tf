# Phase 9 - a second, deliberately narrower EventBridge rule.
#
# The alert rule (eventbridge.tf) matches every HIGH/CRITICAL Security Hub
# finding on purpose - it only logs, so a broad trigger costs nothing. This
# rule feeds a function that can write to a real resource, so it is scoped
# down to the exact Types value the containment Lambda is built to act on.
# The Lambda re-checks this itself (defense in depth, same reasoning as the
# severity re-filter in incident_handler.py) - but a finding of any other
# type never reaches this Lambda's invocation count at all, which is a
# stronger guarantee than a code-level check that could have a bug in it.

resource "aws_cloudwatch_event_rule" "s3_anonymous_access" {
  name        = "${var.project_name}-s3-anonymous-access-containment"
  description = "GuardDuty: S3 bucket anonymous access granted -> containment Lambda. One known finding type, one known resource class."
  state       = "ENABLED"

  event_pattern = jsonencode({
    source        = ["aws.securityhub"]
    "detail-type" = ["Security Hub Findings - Imported"]
    detail = {
      findings = {
        Types       = var.containable_finding_types
        RecordState = ["ACTIVE"]
      }
    }
  })
}

resource "aws_cloudwatch_event_target" "containment_lambda" {
  rule      = aws_cloudwatch_event_rule.s3_anonymous_access.name
  target_id = "containment-lambda"
  arn       = aws_lambda_function.containment.arn

  # Same reasoning as the alert rule's target (eventbridge.tf): a dropped
  # containment event is worse here than a dropped log line, since it means
  # a real exposure went uncontained with no record of why.
  retry_policy {
    maximum_event_age_in_seconds = 3600
    maximum_retry_attempts       = 3
  }

  dead_letter_config {
    arn = aws_sqs_queue.containment_dlq.arn
  }
}

resource "aws_lambda_permission" "allow_eventbridge_containment" {
  statement_id  = "AllowExecutionFromEventBridge"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.containment.function_name
  principal     = "events.amazonaws.com"
  source_arn    = aws_cloudwatch_event_rule.s3_anonymous_access.arn
}

# --- Dead letter queue -------------------------------------------------------

resource "aws_sqs_queue" "containment_dlq" {
  name = "${var.project_name}-s3-containment-dlq"

  message_retention_seconds = 1209600 # 14 days, the SQS maximum
  sqs_managed_sse_enabled   = true

  tags = {
    Name = "${var.project_name}-s3-containment-dlq"
  }
}

data "aws_iam_policy_document" "containment_dlq" {
  statement {
    sid     = "AllowEventBridgeToDeadLetter"
    effect  = "Allow"
    actions = ["sqs:SendMessage"]

    principals {
      type        = "Service"
      identifiers = ["events.amazonaws.com"]
    }

    resources = [aws_sqs_queue.containment_dlq.arn]

    condition {
      test     = "ArnEquals"
      variable = "aws:SourceArn"
      values   = [aws_cloudwatch_event_rule.s3_anonymous_access.arn]
    }
  }
}

resource "aws_sqs_queue_policy" "containment_dlq" {
  queue_url = aws_sqs_queue.containment_dlq.id
  policy    = data.aws_iam_policy_document.containment_dlq.json
}
