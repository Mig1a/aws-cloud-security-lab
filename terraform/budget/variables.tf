variable "aws_region" {
  description = "Region for the AWS provider. Budgets is a global service, but the provider still needs a region."
  type        = string
  default     = "us-east-1"
}

variable "alert_email" {
  description = "Email address that receives budget alerts."
  type        = string

  validation {
    condition     = can(regex("^[^@\\s]+@[^@\\s]+\\.[^@\\s]+$", var.alert_email))
    error_message = "alert_email must be a valid email address."
  }
}

variable "monthly_budget_usd" {
  description = "Monthly cost budget ceiling, in USD."
  type        = number
  default     = 10

  validation {
    condition     = var.monthly_budget_usd > 0
    error_message = "monthly_budget_usd must be greater than zero."
  }
}

variable "alert_thresholds_usd" {
  description = "Dollar amounts of actual spend at which to send an alert."
  type        = list(number)
  default     = [5, 8, 10]

  validation {
    condition     = length(var.alert_thresholds_usd) > 0
    error_message = "Provide at least one alert threshold."
  }
}

variable "enable_forecast_alert" {
  description = <<-EOT
    Also alert when AWS *forecasts* month-end spend will exceed the budget.
    This fires days before the actual overrun, which is the difference between
    catching a runaway GuardDuty bill early and reading about it on your card.
  EOT
  type        = bool
  default     = true
}
