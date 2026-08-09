variable "aws_region" {
  description = "Region for incident 01 test resources."
  type        = string
  default     = "us-east-1"
}

variable "project_name" {
  description = "Name prefix. Must keep the cloudsec-lab-incident- prefix so the bucket falls inside the CloudTrail data-event selector configured in terraform/detection/."
  type        = string
  default     = "cloudsec-lab-incident-01"

  validation {
    condition     = startswith(var.project_name, "cloudsec-lab-incident-")
    error_message = "project_name must start with 'cloudsec-lab-incident-', otherwise CloudTrail will not record S3 data events for the bucket and the investigation will find nothing."
  }
}

variable "trusted_principal_arn" {
  description = <<-EOT
    ARN permitted to assume the test role. Defaults to the caller, so the role
    is assumable only by the identity that created it.
  EOT
  type        = string
  default     = null
}
