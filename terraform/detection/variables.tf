variable "aws_region" {
  description = "Region for the detection stack. GuardDuty and Security Hub are regional; findings elsewhere will not appear."
  type        = string
  default     = "us-east-1"
}

variable "project_name" {
  description = "Name prefix applied to resources and tags."
  type        = string
  default     = "cloudsec-lab"
}

variable "log_retention_days" {
  description = "Days to retain CloudTrail objects in S3 before expiry. Bounds storage cost."
  type        = number
  default     = 30

  validation {
    condition     = var.log_retention_days >= 1
    error_message = "log_retention_days must be at least 1."
  }
}

variable "guardduty_finding_frequency" {
  description = <<-EOT
    How often GuardDuty publishes updates to existing findings.
    FIFTEEN_MINUTES is the fastest and is what you want while actively running
    detection exercises; new findings are always published immediately.
  EOT
  type        = string
  default     = "FIFTEEN_MINUTES"

  validation {
    condition     = contains(["FIFTEEN_MINUTES", "ONE_HOUR", "SIX_HOURS"], var.guardduty_finding_frequency)
    error_message = "Must be FIFTEEN_MINUTES, ONE_HOUR, or SIX_HOURS."
  }
}

variable "guardduty_s3_protection" {
  description = <<-EOT
    Analyze S3 data events for suspicious access patterns.
    Billed per million events. Cheap on an idle lab account.
  EOT
  type        = bool
  default     = true
}

variable "guardduty_malware_protection" {
  description = <<-EOT
    Scan EBS volumes when GuardDuty raises certain EC2 findings.

    Off by default: this is billed per GB scanned and creates snapshots, which
    is the most expensive GuardDuty add-on and the least useful on an
    intentionally small lab.
  EOT
  type        = bool
  default     = false
}

variable "guardduty_runtime_monitoring" {
  description = <<-EOT
    Agent-based runtime visibility for EC2, ECS, and EKS.
    Off by default - billed per vCPU-hour.
  EOT
  type        = bool
  default     = false
}

variable "security_hub_standards" {
  description = <<-EOT
    Security Hub standards to subscribe to.

    Each enabled control is a billable check. Start with the AWS Foundational
    Security Best Practices standard alone; adding CIS roughly doubles the
    check volume for heavily overlapping coverage.

    Valid keys: "aws_foundational", "cis_1_4", "pci_dss"
  EOT
  type        = list(string)
  default     = ["aws_foundational"]

  validation {
    condition = alltrue([
      for s in var.security_hub_standards : contains(["aws_foundational", "cis_1_4", "pci_dss"], s)
    ])
    error_message = "Allowed values: aws_foundational, cis_1_4, pci_dss."
  }
}

variable "security_hub_auto_enable_controls" {
  description = "Automatically enable new controls as AWS adds them to a subscribed standard."
  type        = bool
  default     = true
}
