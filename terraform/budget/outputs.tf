output "budget_name" {
  description = "Name of the monthly cost budget."
  value       = aws_budgets_budget.monthly_cost.name
}

output "budget_limit" {
  description = "Monthly ceiling enforced by the budget."
  value       = "${aws_budgets_budget.monthly_cost.limit_amount} ${aws_budgets_budget.monthly_cost.limit_unit}"
}

output "alert_thresholds_usd" {
  description = "Actual-spend amounts that trigger an email alert."
  value       = var.alert_thresholds_usd
}

output "forecast_alert_enabled" {
  description = "Whether a forecasted-overrun alert is configured."
  value       = var.enable_forecast_alert
}
