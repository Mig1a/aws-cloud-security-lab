# Monthly cost budget with tiered email alerts.
#
# This is deliberately the first thing built in the lab: GuardDuty, Security Hub,
# and AWS Config all bill continuously once enabled, and their free trials start
# on activation rather than on first use. The guardrail goes up before anything
# billable does.

resource "aws_budgets_budget" "monthly_cost" {
  name         = "lab-monthly-cost-budget"
  budget_type  = "COST"
  limit_amount = tostring(var.monthly_budget_usd)
  limit_unit   = "USD"
  time_unit    = "MONTHLY"

  # Track gross usage cost rather than what lands on the card. With promotional
  # credits applied, a credit-inclusive budget reads $0 right up until the
  # credits run dry, which hides the spend that is actually accumulating.
  cost_types {
    include_credit = false
    include_refund = false
    include_tax    = true
    use_amortized  = false
  }

  # Alert on spend that has already been incurred.
  dynamic "notification" {
    for_each = toset(var.alert_thresholds_usd)

    content {
      notification_type          = "ACTUAL"
      comparison_operator        = "GREATER_THAN"
      threshold                  = notification.value
      threshold_type             = "ABSOLUTE_VALUE"
      subscriber_email_addresses = [var.alert_email]
    }
  }

  # Alert on spend AWS projects for month end, before it is incurred.
  dynamic "notification" {
    for_each = var.enable_forecast_alert ? [1] : []

    content {
      notification_type          = "FORECASTED"
      comparison_operator        = "GREATER_THAN"
      threshold                  = var.monthly_budget_usd
      threshold_type             = "ABSOLUTE_VALUE"
      subscriber_email_addresses = [var.alert_email]
    }
  }
}
