variable "aws_region" {
  description = <<-EOT
    Region for the response stack.

    Must match the region of the detection stack. Security Hub is regional and
    publishes findings to the EventBridge default bus in its own region only -
    a rule in another region will never fire.
  EOT
  type        = string
  default     = "us-east-1"
}

variable "project_name" {
  description = "Name prefix applied to resources and tags."
  type        = string
  default     = "cloudsec-lab"
}

variable "alert_severity_labels" {
  description = <<-EOT
    Security Hub severity labels that trigger the alert Lambda.

    The brief for this phase said HIGH. CRITICAL is included by default because
    a rule matching HIGH alone silently ignores everything worse than HIGH -
    the exact failure mode this lab keeps running into, where a control looks
    enabled and covers less than it appears to.

    Set to ["HIGH"] to match the brief literally.

    Valid labels: INFORMATIONAL, LOW, MEDIUM, HIGH, CRITICAL
  EOT
  type        = list(string)
  default     = ["HIGH", "CRITICAL"]

  validation {
    condition = length(var.alert_severity_labels) > 0 && alltrue([
      for s in var.alert_severity_labels :
      contains(["INFORMATIONAL", "LOW", "MEDIUM", "HIGH", "CRITICAL"], s)
    ])
    error_message = "Must be a non-empty subset of INFORMATIONAL, LOW, MEDIUM, HIGH, CRITICAL."
  }
}

variable "log_retention_days" {
  description = <<-EOT
    Retention for the Lambda's CloudWatch log group.

    CloudWatch Logs bills for ingestion and storage. Left unset, a log group
    retains forever, which is the standard way a free-tier lab starts costing
    money months later.
  EOT
  type        = number
  default     = 14

  validation {
    condition     = contains([1, 3, 5, 7, 14, 30, 60, 90, 120, 150, 180, 365, 400, 545, 731, 1096, 1827, 2192, 2557, 2922, 3288, 3653], var.log_retention_days)
    error_message = "Must be a retention value CloudWatch Logs accepts (1, 3, 5, 7, 14, 30, 60, 90, ...)."
  }
}

variable "lambda_runtime" {
  description = "Python runtime for the alert function. Matches the version documented in the repo README."
  type        = string
  default     = "python3.13"
}

variable "lambda_timeout_seconds" {
  description = "Function timeout. The function only formats and logs, so this is generous."
  type        = number
  default     = 30
}

# --- Phase 9: automated containment ------------------------------------------

variable "enable_auto_containment" {
  description = <<-EOT
    Master kill switch for the Phase 9 containment Lambda.

    false (default): the Lambda still runs on every matching finding, still
    checks the resource allowlist, still examines the resource's current
    state, and still logs exactly what it would have done - it just never
    calls the mutating S3 API. Deploy with this off first, review a few
    "would_contain_but_disabled" log lines, and only then turn it on.

    true: the Lambda actually calls s3:PutPublicAccessBlock on an
    allow-listed bucket when a matching finding arrives.

    This is deliberately a second, independent gate from
    containable_resource_arns below - either one alone being restrictive is
    not enough; both must agree before anything is touched.
  EOT
  type        = bool
  default     = false
}

variable "containable_finding_types" {
  description = <<-EOT
    The exact ASFF Types values the containment Lambda is allowed to act on.

    Default is GuardDuty's Policy:S3/BucketAnonymousAccessGranted as it
    appears once imported into Security Hub - verified against a real
    finding already present in this account (GuardDuty's "/" becomes "-",
    and the whole type is namespaced under "TTPs/"), not guessed from
    documentation.

    Deliberately a short, explicit list, never "any HIGH finding" - see
    docs/phase-9-automated-containment.md for why that distinction matters.
  EOT
  type        = list(string)
  default     = ["TTPs/Policy:S3-BucketAnonymousAccessGranted"]

  validation {
    condition     = length(var.containable_finding_types) > 0
    error_message = "Must list at least one finding type - an empty list here would leave the EventBridge rule matching nothing, silently disabling containment."
  }
}

variable "containable_resource_arns" {
  description = <<-EOT
    The exact S3 bucket ARNs the containment Lambda is allowed to touch.

    Empty list (the variable's own default) means "compute the fallback
    below" - this lab's INC-02 exercise bucket, built from the current
    account ID rather than a hardcoded literal, since a real AWS account ID
    must never be committed to this repo's Terraform. Override to point
    elsewhere, or to list more than one bucket, in terraform.tfvars.

    NOT a prefix match, anywhere in this stack. A future incident-03 bucket
    does not inherit this permission just by sharing a naming convention -
    it has to be added here deliberately. Empty list = nothing is ever
    contained, regardless of enable_auto_containment; this is the second,
    independent gate alongside the kill switch above.
  EOT
  type        = list(string)
  default     = []
}
