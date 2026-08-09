# Security Hub - aggregates findings and runs standards-based posture checks.
#
# COST: 30-day free trial, then billed per security check and per finding
# ingested beyond the monthly free allowance.
#
# IMPORTANT DEPENDENCY: most controls in the standards below are evaluated by
# AWS Config rules under the hood. AWS Config is NOT enabled by this stack and
# has no free tier - it bills per configuration item recorded. Without it, a
# large share of controls report "No data" rather than pass or fail.
#
# That is a deliberate choice: Config on an account with active Terraform
# apply/destroy cycles records an item for every resource change and is the
# most likely source of an unexpected bill in this lab. Enable it consciously,
# after deciding the budget can absorb it.
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
