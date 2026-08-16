# Alert Lambda - logs high-severity Security Hub findings.
#
# COST: the Lambda free tier is 1M requests and 400,000 GB-seconds per month,
# permanently, not just during a trial. At lab finding volumes this is $0.00.
# The only line item that can grow is CloudWatch Logs, bounded by
# var.log_retention_days.

locals {
  function_name = "${var.project_name}-securityhub-alert"
  source_dir    = "${path.module}/../../lambda/securityhub_alert"
}

# Zipped at plan time from the source tree. source_code_hash below means a code
# change produces a new deployment on `terraform apply` - without it, editing
# handler.py leaves the deployed function untouched and the stack lies about
# being converged.
data "archive_file" "alert" {
  type        = "zip"
  source_dir  = local.source_dir
  output_path = "${path.module}/.build/securityhub_alert.zip"
}

# --- Logging -----------------------------------------------------------------

# Created explicitly rather than left to Lambda's implicit creation, for two
# reasons: an implicitly created group has NO retention policy and keeps logs
# forever, and it survives `terraform destroy` as an orphan.
resource "aws_cloudwatch_log_group" "alert" {
  name              = "/aws/lambda/${local.function_name}"
  retention_in_days = var.log_retention_days
}

# --- Execution role ----------------------------------------------------------

data "aws_iam_policy_document" "assume_role" {
  statement {
    effect  = "Allow"
    actions = ["sts:AssumeRole"]

    principals {
      type        = "Service"
      identifiers = ["lambda.amazonaws.com"]
    }
  }
}

resource "aws_iam_role" "alert" {
  name               = "${local.function_name}-role"
  assume_role_policy = data.aws_iam_policy_document.assume_role.json
}

# Written by hand instead of attaching AWSLambdaBasicExecutionRole, which grants
# logs:CreateLogGroup plus write access to every log group in the account.
#
# logs:CreateLogGroup is deliberately NOT granted. The group is Terraform's, and
# withholding the permission means a rename cannot silently recreate it without
# a retention policy.
data "aws_iam_policy_document" "alert_logs" {
  statement {
    sid    = "WriteOwnLogStream"
    effect = "Allow"

    actions = [
      "logs:CreateLogStream",
      "logs:PutLogEvents",
    ]

    resources = ["${aws_cloudwatch_log_group.alert.arn}:*"]
  }
}

resource "aws_iam_role_policy" "alert_logs" {
  name   = "write-own-logs"
  role   = aws_iam_role.alert.id
  policy = data.aws_iam_policy_document.alert_logs.json
}

# --- Function ----------------------------------------------------------------

resource "aws_lambda_function" "alert" {
  function_name = local.function_name
  description   = "Phase 7 - logs ${join("/", var.alert_severity_labels)} Security Hub findings. Read-only; does not remediate."

  role    = aws_iam_role.alert.arn
  handler = "handler.lambda_handler"
  runtime = var.lambda_runtime

  filename         = data.archive_file.alert.output_path
  source_code_hash = data.archive_file.alert.output_base64sha256

  timeout     = var.lambda_timeout_seconds
  memory_size = 128

  environment {
    variables = {
      # Same list that builds the event pattern, so the function's second-pass
      # filter cannot drift from the rule that invoked it.
      ALERT_SEVERITIES = join(",", var.alert_severity_labels)
    }
  }

  # Without this the function's first invocation races Terraform and creates
  # the log group itself, with no retention.
  depends_on = [
    aws_cloudwatch_log_group.alert,
    aws_iam_role_policy.alert_logs,
  ]
}
