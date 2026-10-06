# Phase 9 - the containment Lambda and its permissions.
#
# This is the only IAM identity in the whole lab that is ever granted write
# access to a real resource outside Terraform's own execution. Every
# permission below is scoped as narrowly as it can be while still doing the
# job - see docs/phase-9-automated-containment.md for the reasoning behind
# each restriction, and lambda/incident_containment/containment_handler.py
# for the code-level checks that don't trust this scoping alone.
#
# COST: same free-tier math as the alert Lambda (lambda.tf) - $0.00 at lab
# invocation volume, permanently, not just during a trial.

locals {
  containment_function_name = "${var.project_name}-s3-containment"

  # Empty var.containable_resource_arns means "use this lab's own INC-02
  # exercise bucket" - computed from the live account ID rather than a
  # hardcoded literal, so no real account ID is ever committed to this file.
  # A variable default cannot reference data.aws_caller_identity (Terraform
  # requires variable defaults to be constant), which is exactly why this is
  # a local instead of living directly on the variable.
  containable_resource_arns = length(var.containable_resource_arns) > 0 ? var.containable_resource_arns : [
    "arn:aws:s3:::cloudsec-lab-incident-02-${data.aws_caller_identity.current.account_id}"
  ]
}

data "archive_file" "containment" {
  type        = "zip"
  source_dir  = "${path.module}/../../lambda/incident_containment"
  output_path = "${path.module}/.build/incident_containment.zip"
}

# --- Logging -----------------------------------------------------------------
# Same rationale as the alert Lambda's log group (lambda.tf): created
# explicitly so it has a retention policy and isn't orphaned by
# `terraform destroy`, and logs:CreateLogGroup is withheld from the role
# below so a rename can't silently recreate an unmanaged, unbounded group.

resource "aws_cloudwatch_log_group" "containment" {
  name              = "/aws/lambda/${local.containment_function_name}"
  retention_in_days = var.log_retention_days
}

# --- Execution role ------------------------------------------------------

data "aws_iam_policy_document" "containment_assume_role" {
  statement {
    effect  = "Allow"
    actions = ["sts:AssumeRole"]

    principals {
      type        = "Service"
      identifiers = ["lambda.amazonaws.com"]
    }
  }
}

resource "aws_iam_role" "containment" {
  name               = "${local.containment_function_name}-role"
  assume_role_policy = data.aws_iam_policy_document.containment_assume_role.json
}

data "aws_iam_policy_document" "containment_logs" {
  statement {
    sid    = "WriteOwnLogStream"
    effect = "Allow"

    actions = [
      "logs:CreateLogStream",
      "logs:PutLogEvents",
    ]

    resources = ["${aws_cloudwatch_log_group.containment.arn}:*"]
  }
}

resource "aws_iam_role_policy" "containment_logs" {
  name   = "write-own-logs"
  role   = aws_iam_role.containment.id
  policy = data.aws_iam_policy_document.containment_logs.json
}

# --- Function-level dead letter queue ---------------------------------------
#
# Distinct from containment_eventbridge.tf's rule-target DLQ, which only
# catches EventBridge failing to INVOKE this function at all (e.g. the
# lambda:InvokeFunction permission below being missing). Phase 10's live
# fire-drill found the gap this closes: the function WAS invoked
# successfully three times (EventBridge's retry_policy below) and crashed
# inside all three - a failure mode the rule-target DLQ cannot see, because
# from EventBridge's point of view the invoke succeeded every time. Lambda's
# own asynchronous-invocation dead_letter_config is what catches "invoked
# fine, then the function itself errored out after every retry" - the one
# this phase actually hit, which until now went to the same place every
# `would_contain_but_disabled` dry-run log line goes when nothing is wrong:
# nowhere visible.
data "aws_iam_policy_document" "containment_dlq_send" {
  statement {
    sid       = "SendFailedInvocationsToOwnDLQ"
    effect    = "Allow"
    actions   = ["sqs:SendMessage"]
    resources = [aws_sqs_queue.containment_dlq.arn]
  }
}

resource "aws_iam_role_policy" "containment_dlq_send" {
  name   = "send-failed-invocations-to-dlq"
  role   = aws_iam_role.containment.id
  policy = data.aws_iam_policy_document.containment_dlq_send.json
}

# The one write permission this entire lab grants outside of Terraform
# itself. `resources` is local.containable_resource_arns - an explicit
# allowlist, never a wildcard, never a prefix. `count` means an operator who
# explicitly sets containable_resource_arns = [] gets a role with NO S3
# permissions at all, not a policy with an empty resource list (which some
# providers reject outright, and which would be a confusing way to represent
# "nothing is allowed").
#
# Action names are s3:Get/PutBucketPublicAccessBlock - WITH "Bucket" in the
# name. This is the actual IAM action name AWS exposes for this API (matching
# the CloudTrail eventName and what shows up in an AccessDenied message), NOT
# the boto3/botocore client method name (s3api get/put-public-access-block,
# no "Bucket"). The two were out of sync here for the whole life of Phase 9 -
# every real invocation of this role got AccessDenied, invisibly, because the
# policy granted an action name that doesn't exist. Found during Phase 10's
# live fire-drill: see docs/phase-9-automated-containment.md's postmortem
# note and incidents/incident-03-automated-containment.md.
data "aws_iam_policy_document" "containment_s3" {
  count = length(local.containable_resource_arns) > 0 ? 1 : 0

  statement {
    sid    = "ExamineAndBlockPublicAccessOnAllowlistedBuckets"
    effect = "Allow"

    actions = [
      "s3:GetBucketPublicAccessBlock",
      "s3:PutBucketPublicAccessBlock",
    ]

    resources = local.containable_resource_arns
  }
}

resource "aws_iam_role_policy" "containment_s3" {
  count  = length(local.containable_resource_arns) > 0 ? 1 : 0
  name   = "contain-allowlisted-s3-buckets"
  role   = aws_iam_role.containment.id
  policy = data.aws_iam_policy_document.containment_s3[0].json
}

# --- Function --------------------------------------------------------------

resource "aws_lambda_function" "containment" {
  function_name = local.containment_function_name
  description   = "Phase 9 - contains S3 public access exposure on an explicit resource allowlist. enable_auto_containment=${var.enable_auto_containment}."

  role    = aws_iam_role.containment.arn
  handler = "containment_handler.lambda_handler"
  runtime = var.lambda_runtime

  filename         = data.archive_file.containment.output_path
  source_code_hash = data.archive_file.containment.output_base64sha256

  timeout     = var.lambda_timeout_seconds
  memory_size = 128

  environment {
    variables = {
      # All three read by the same names the EventBridge rule
      # (containment_eventbridge.tf) is built from, so the rule that invokes
      # this function and the checks inside it cannot silently drift apart -
      # same defense-in-depth pattern as the alert Lambda's ALERT_SEVERITIES.
      CONTAINABLE_FINDING_TYPES = join(",", var.containable_finding_types)
      CONTAINABLE_RESOURCE_ARNS = join(",", local.containable_resource_arns)
      AUTO_CONTAIN_ENABLED      = tostring(var.enable_auto_containment)
    }
  }

  # Catches the function itself erroring out after Lambda's own built-in
  # async-invocation retries are exhausted - distinct from, and not covered
  # by, the EventBridge rule target's retry_policy/dead_letter_config in
  # containment_eventbridge.tf (that one only fires if EventBridge can't
  # invoke this function at all). See the IAM policy above this resource for
  # why this phase needed to learn that distinction the hard way.
  dead_letter_config {
    target_arn = aws_sqs_queue.containment_dlq.arn
  }

  depends_on = [
    aws_cloudwatch_log_group.containment,
    aws_iam_role_policy.containment_logs,
    aws_iam_role_policy.containment_dlq_send,
  ]
}
