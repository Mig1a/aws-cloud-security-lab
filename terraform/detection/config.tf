# AWS Config - the evaluation engine most Security Hub standards controls
# depend on. Off by default (var.enable_config), for the reason documented at
# length in securityhub.tf and incidents/incident-02-s3.md: Config has no free
# tier and bills per configuration item recorded, which on an account with
# active Terraform apply/destroy cycles is the single most likely source of an
# unexpected bill in this lab.
#
# Scoped to S3 buckets ONLY (recording_group below) rather than "all supported
# resource types" - the expensive default that would record every change to
# every EC2/VPC/IAM/etc. resource too. This lab only ever needed Config to make
# the S3 standards controls (S3.1, S3.2, S3.3, S3.5, S3.8) actually evaluate
# something, so that is all it is scoped to record.
#
# Delivers to the EXISTING CloudTrail log bucket (s3.tf), under its own
# "config/" prefix, rather than standing up a second bucket - one more long-
# lived, hardened bucket to manage would cost nothing extra in dollars but adds
# a resource this lab does not need.

locals {
  config_recorder_name = "${var.project_name}-config-recorder"
}

# --- IAM role Config assumes to read resource state and write snapshots ------

data "aws_iam_policy_document" "config_assume_role" {
  count = var.enable_config ? 1 : 0

  statement {
    effect  = "Allow"
    actions = ["sts:AssumeRole"]

    principals {
      type        = "Service"
      identifiers = ["config.amazonaws.com"]
    }
  }
}

resource "aws_iam_role" "config" {
  count = var.enable_config ? 1 : 0

  name               = "${local.config_recorder_name}-role"
  assume_role_policy = data.aws_iam_policy_document.config_assume_role[0].json
}

# AWS-managed policy granting Config read access to describe the resource
# types it records. Grants no write access of its own - the inline policy
# below is what lets this role deliver snapshots to this lab's own bucket.
resource "aws_iam_role_policy_attachment" "config_managed" {
  count = var.enable_config ? 1 : 0

  role       = aws_iam_role.config[0].name
  policy_arn = "arn:aws:iam::aws:policy/service-role/AWS_ConfigRole"
}

# Scoped narrowly to this lab's own CloudTrail bucket, under the config/
# prefix only - never the whole bucket, and never a wildcard resource.
data "aws_iam_policy_document" "config_s3_delivery" {
  count = var.enable_config ? 1 : 0

  statement {
    sid       = "AllowGetBucketAcl"
    effect    = "Allow"
    actions   = ["s3:GetBucketAcl"]
    resources = [aws_s3_bucket.cloudtrail.arn]
  }

  statement {
    sid       = "AllowPutConfigSnapshots"
    effect    = "Allow"
    actions   = ["s3:PutObject"]
    resources = ["${aws_s3_bucket.cloudtrail.arn}/${var.config_s3_key_prefix}/*"]

    condition {
      test     = "StringEquals"
      variable = "s3:x-amz-acl"
      values   = ["bucket-owner-full-control"]
    }
  }
}

resource "aws_iam_role_policy" "config_s3_delivery" {
  count = var.enable_config ? 1 : 0

  name   = "deliver-snapshots-to-cloudtrail-bucket"
  role   = aws_iam_role.config[0].id
  policy = data.aws_iam_policy_document.config_s3_delivery[0].json
}

# --- Recorder, scoped to S3 buckets only --------------------------------------

resource "aws_config_configuration_recorder" "lab" {
  count = var.enable_config ? 1 : 0

  name     = local.config_recorder_name
  role_arn = aws_iam_role.config[0].arn

  recording_group {
    all_supported                 = false
    include_global_resource_types = false
    resource_types                = ["AWS::S3::Bucket"]
  }
}

resource "aws_config_delivery_channel" "lab" {
  count = var.enable_config ? 1 : 0

  name           = "${local.config_recorder_name}-channel"
  s3_bucket_name = aws_s3_bucket.cloudtrail.id
  s3_key_prefix  = var.config_s3_key_prefix

  depends_on = [aws_iam_role_policy.config_s3_delivery]
}

# Config requires the delivery channel to exist before recording can start -
# this resource is the explicit "turn it on" switch, split out from the
# recorder itself so Terraform orders it correctly.
resource "aws_config_configuration_recorder_status" "lab" {
  count = var.enable_config ? 1 : 0

  name       = aws_config_configuration_recorder.lab[0].name
  is_enabled = true

  depends_on = [aws_config_delivery_channel.lab]
}
