# Extension - the first thing in this whole lab that actively notifies a
# human, rather than only writing a CloudWatch Logs line someone has to go
# looking for. Every Lambda before this one (Phase 7's alert handler, Phase
# 9's containment handler) only ever logged; nothing paged anyone.
#
# One shared topic for both Lambdas: the alert handler publishes on every
# HIGH/CRITICAL finding it sees (broad, by design - that is already the
# filtered set), and the containment handler publishes on its own narrower
# four actionable outcomes. Covers the case Incident 01 exposed: a finding
# type with no automated remedy at all (denied iam:CreateAccessKey, if a
# detector for it is ever built) still reaches a human, because "notify" is
# the correct response when there is nothing to automate.
#
# COST: SNS email delivery is free at any volume relevant to this lab (free
# tier is 1,000 email notifications/month, permanently, not just during a
# trial). No SMS subscription here - that has a real per-message cost and
# needs a verified phone number; email mirrors the mechanism AWS Budgets
# (terraform/budget/) already uses for cost alerts.

resource "aws_sns_topic" "security_alerts" {
  name = "${var.project_name}-security-alerts"
}

# Email subscriptions require a one-time manual confirmation click in the
# recipient's inbox after apply. Terraform cannot complete that step - the
# subscription exists but delivers nothing until confirmed. Check
# `terraform output sns_subscription_arn`; it reads "PendingConfirmation"
# until the link is clicked.
resource "aws_sns_topic_subscription" "email" {
  topic_arn = aws_sns_topic.security_alerts.arn
  protocol  = "email"
  endpoint  = var.notify_email
}

# Scoped to exactly this one topic ARN - same "exact resource, never a
# wildcard" posture as every other permission the containment role holds
# (containment_lambda.tf).
data "aws_iam_policy_document" "containment_notify" {
  statement {
    sid       = "PublishSecurityAlerts"
    effect    = "Allow"
    actions   = ["sns:Publish"]
    resources = [aws_sns_topic.security_alerts.arn]
  }
}

resource "aws_iam_role_policy" "containment_notify" {
  name   = "publish-security-alerts"
  role   = aws_iam_role.containment.id
  policy = data.aws_iam_policy_document.containment_notify.json
}

# Same grant, same topic, for the alert Lambda's own role (lambda.tf) - it
# publishes on every HIGH/CRITICAL finding it alerts on, independent of
# containment.
resource "aws_iam_role_policy" "alert_notify" {
  name   = "publish-security-alerts"
  role   = aws_iam_role.alert.id
  policy = data.aws_iam_policy_document.containment_notify.json
}
