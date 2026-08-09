# Deliberately limited test role.
#
# A ROLE, not a user with access keys. Two reasons:
#
#   1. No long-lived credentials. Assuming a role issues short-lived STS
#      credentials, so nothing durable is created that could leak, and no
#      secret lands in Terraform state.
#   2. Better evidence. Role assumption produces an sts:AssumeRole event and
#      then attributes every subsequent action to
#      `assumed-role/<role>/<session-name>`. That session name is the thread an
#      analyst pulls to reconstruct a single actor's activity - exactly the
#      investigation this phase practises.

locals {
  trusted_principal = coalesce(var.trusted_principal_arn, data.aws_caller_identity.current.arn)
}

data "aws_iam_policy_document" "assume_role" {
  statement {
    sid     = "AllowSpecificPrincipalToAssume"
    effect  = "Allow"
    actions = ["sts:AssumeRole"]

    principals {
      type        = "AWS"
      identifiers = [local.trusted_principal]
    }
  }
}

resource "aws_iam_role" "test_analyst" {
  name               = "${var.project_name}-analyst"
  description        = "Phase 5 test role - read-only access to one S3 prefix. Intentionally limited."
  assume_role_policy = data.aws_iam_policy_document.assume_role.json

  # Short sessions. Shrinks the window a leaked session credential is useful
  # for, and forces re-assumption, which leaves more evidence in CloudTrail.
  max_session_duration = 3600

  tags = {
    Name    = "${var.project_name}-analyst"
    Purpose = "incident-01-investigation-target"
  }
}

# The permission boundary being tested.
#
# Allowed:  list the bucket, read objects under reports/
# Denied:   everything else, including restricted/, writes, deletes, and all IAM
#
# Nothing here grants iam:*, s3:Delete*, or s3:Put*. Attempts at those produce
# AccessDenied events, which is the point.
data "aws_iam_policy_document" "analyst_permissions" {
  statement {
    sid       = "ListBucketRestrictedToReportsPrefix"
    effect    = "Allow"
    actions   = ["s3:ListBucket"]
    resources = [aws_s3_bucket.lab_data.arn]

    condition {
      test     = "StringLike"
      variable = "s3:prefix"
      values   = ["reports/*", "reports", ""]
    }
  }

  statement {
    sid       = "ReadOnlyReportsPrefix"
    effect    = "Allow"
    actions   = ["s3:GetObject"]
    resources = ["${aws_s3_bucket.lab_data.arn}/reports/*"]
  }

  # Explicit deny on the restricted prefix. Redundant given the allow-list
  # above, but an explicit deny cannot be overridden by a later grant, and it
  # produces an unambiguous denial in the logs.
  statement {
    sid       = "ExplicitDenyRestrictedPrefix"
    effect    = "Deny"
    actions   = ["s3:*"]
    resources = ["${aws_s3_bucket.lab_data.arn}/restricted/*"]
  }
}

resource "aws_iam_role_policy" "analyst" {
  name   = "${var.project_name}-analyst-permissions"
  role   = aws_iam_role.test_analyst.id
  policy = data.aws_iam_policy_document.analyst_permissions.json
}
