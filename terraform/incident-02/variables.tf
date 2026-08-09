variable "aws_region" {
  description = "Region for incident 02 test resources."
  type        = string
  default     = "us-east-1"
}

variable "project_name" {
  description = "Name prefix. Must keep the cloudsec-lab-incident- prefix so the bucket falls inside the CloudTrail data-event selector in terraform/detection/."
  type        = string
  default     = "cloudsec-lab-incident-02"

  validation {
    condition     = startswith(var.project_name, "cloudsec-lab-incident-")
    error_message = "project_name must start with 'cloudsec-lab-incident-', otherwise CloudTrail will not record S3 data events for the bucket."
  }
}

variable "harden" {
  description = <<-EOT
    Switches the bucket between the two states this exercise compares.

      false -> the deliberately insecure baseline (the "misconfiguration")
      true  -> the remediated, hardened configuration

    Flipping this variable and running `terraform plan` shows the remediation
    as an explicit diff, which is the point of the exercise.

    SAFETY NOTES for the insecure state:
      * Public READ only. Public WRITE is never configured, at any setting.
        A publicly writable bucket can be used to host malware and to run up
        transfer charges against the account owner.
      * Objects are synthetic placeholders. No real data is ever placed here.
      * The exposure window should be minutes. Remediate in the same session.
  EOT
  type        = bool
  default     = false
}
