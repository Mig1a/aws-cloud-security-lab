# Security Hub - aggregates findings and runs standards-based posture checks.
#
# COST: 30-day free trial, then billed per security check and per finding
# ingested beyond the monthly free allowance.
#
# IMPORTANT DEPENDENCY: most controls in the standards below are evaluated by
# AWS Config rules under the hood, not by Security Hub itself - Security Hub
# only aggregates findings that something else (Config, for these controls;
# GuardDuty, for behavioral ones) already produced and handed to it. See
# config.tf: Config is OFF by default (var.enable_config) and has no free
# tier - it bills per configuration item recorded. Without it, a large share
# of controls report "No data" rather than pass or fail, confirmed directly
# in incidents/incident-02-s3.md (zero findings against a genuinely public
# bucket) and closed out in that same report's addendum once Config was
# turned on, scoped to AWS::S3::Bucket only.
#
# What still works without Config: GuardDuty findings flowing into Security Hub,
# the Security Hub finding format itself, and controls evaluated directly
# against API state.

locals {
  standard_arns = {
    aws_foundational = "arn:aws:securityhub:${data.aws_region.current.region}::standards/aws-foundational-security-best-practices/v/1.0.0"
    cis_1_4          = "arn:aws:securityhub:${data.aws_region.current.region}::standards/cis-aws-foundations-benchmark/v/1.4.0"
    pci_dss          = "arn:aws:securityhub:${data.aws_region.current.region}::standards/pci-dss/v/3.2.1"
  }
}

resource "aws_securityhub_account" "lab" {
  enable_default_standards  = false
  auto_enable_controls      = var.security_hub_auto_enable_controls
  control_finding_generator = "SECURITY_CONTROL"
}

# Standards are subscribed explicitly rather than via enable_default_standards,
# so the set of billable checks is what this file says it is.
resource "aws_securityhub_standards_subscription" "enabled" {
  for_each = toset(var.security_hub_standards)

  standards_arn = local.standard_arns[each.value]
  depends_on    = [aws_securityhub_account.lab]
}

# Route GuardDuty findings into Security Hub so both services share one queue.
resource "aws_securityhub_product_subscription" "guardduty" {
  product_arn = "arn:aws:securityhub:${data.aws_region.current.region}::product/aws/guardduty"

  depends_on = [
    aws_securityhub_account.lab,
    aws_guardduty_detector.lab,
  ]
}
