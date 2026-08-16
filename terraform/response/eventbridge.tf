# EventBridge - routes Security Hub findings to the alert Lambda.
#
#   GuardDuty -> Security Hub -> EventBridge -> Lambda
#
# Security Hub publishes every new and updated finding to the EventBridge
# default bus automatically. There is nothing to enable and no subscription to
# create: the findings are already on the bus, and this stack is only the rule
# that picks the interesting ones off it.
#
# That also means the rule works for findings from ANY Security Hub source, not
# just GuardDuty - standards controls, Inspector, Macie, and anything imported
# through BatchImportFindings all arrive in the same ASFF envelope.
#
# COST: rules matching AWS-service events are free, and so are their
# invocations. The billable component of this stack is Lambda, which is inside
# the permanent free tier at lab volumes.

resource "aws_cloudwatch_event_rule" "high_severity_findings" {
  name        = "${var.project_name}-securityhub-high-severity"
  description = "Security Hub findings at severity ${join(" or ", var.alert_severity_labels)} -> alert Lambda"
  state       = "ENABLED"

  # Three filters, not one:
  #
  #   Severity.Label   the actual point of the rule.
  #
  #   RecordState      ARCHIVED findings are re-published when Security Hub
  #                    archives them. Without this, resolving a finding fires
  #                    the alert a second time.
  #
  #   Workflow.Status  RESOLVED and SUPPRESSED findings are also re-published
  #                    on update. An analyst who suppresses a known-accepted
  #                    finding should not keep being paged by it.
  #
  # Matching on findings[] is an ANY-element match: a batch containing one HIGH
  # finding is delivered in full, low-severity siblings included. The Lambda
  # re-filters for that reason.
  event_pattern = jsonencode({
    source        = ["aws.securityhub"]
    "detail-type" = ["Security Hub Findings - Imported"]
    detail = {
      findings = {
        Severity    = { Label = var.alert_severity_labels }
        RecordState = ["ACTIVE"]
        Workflow    = { Status = ["NEW", "NOTIFIED"] }
      }
    }
  })
}

resource "aws_cloudwatch_event_target" "alert_lambda" {
  rule      = aws_cloudwatch_event_rule.high_severity_findings.name
  target_id = "alert-lambda"
  arn       = aws_lambda_function.alert.arn

  # EventBridge retries a failing invocation, then drops the event. A dropped
  # security alert is indistinguishable from no alert, so undeliverable events
  # go to the DLQ instead of disappearing.
  retry_policy {
    maximum_event_age_in_seconds = 3600
    maximum_retry_attempts       = 3
  }

  dead_letter_config {
    arn = aws_sqs_queue.alert_dlq.arn
  }
}

# Resource-based policy on the function. Without it EventBridge is denied and
# every event dead-letters.
resource "aws_lambda_permission" "allow_eventbridge" {
  statement_id  = "AllowExecutionFromEventBridge"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.alert.function_name
  principal     = "events.amazonaws.com"
  source_arn    = aws_cloudwatch_event_rule.high_severity_findings.arn
}

# --- Dead letter queue -------------------------------------------------------
#
# COST: SQS free tier is 1M requests/month, permanently. An empty queue is free.

resource "aws_sqs_queue" "alert_dlq" {
  name = "${var.project_name}-securityhub-alert-dlq"

  message_retention_seconds = 1209600 # 14 days, the SQS maximum
  sqs_managed_sse_enabled   = true

  tags = {
    Name = "${var.project_name}-securityhub-alert-dlq"
  }
}

data "aws_iam_policy_document" "alert_dlq" {
  statement {
    sid     = "AllowEventBridgeToDeadLetter"
    effect  = "Allow"
    actions = ["sqs:SendMessage"]

    principals {
      type        = "Service"
      identifiers = ["events.amazonaws.com"]
    }

    resources = [aws_sqs_queue.alert_dlq.arn]

    # Scoped to this rule, so the queue is not a write target for every
    # EventBridge rule in the account.
    condition {
      test     = "ArnEquals"
      variable = "aws:SourceArn"
      values   = [aws_cloudwatch_event_rule.high_severity_findings.arn]
    }
  }
}

resource "aws_sqs_queue_policy" "alert_dlq" {
  queue_url = aws_sqs_queue.alert_dlq.id
  policy    = data.aws_iam_policy_document.alert_dlq.json
}
