variable "aws_region" {
  description = "Region to build the lab environment in."
  type        = string
  default     = "us-east-1"
}

variable "project_name" {
  description = "Name prefix applied to resources and tags."
  type        = string
  default     = "cloudsec-lab"
}

variable "vpc_cidr" {
  description = "CIDR block for the lab VPC."
  type        = string
  default     = "10.0.0.0/16"
}

variable "public_subnet_cidr" {
  description = "CIDR block for the public subnet."
  type        = string
  default     = "10.0.1.0/24"
}

variable "instance_type" {
  description = <<-EOT
    EC2 instance type. t3.micro runs roughly $7.50/month if left on around the
    clock, which alone would consume most of the $10 budget from Phase 2.
    Destroy or stop the instance when not actively working.
  EOT
  type        = string
  default     = "t3.micro"
}

variable "enable_ssh" {
  description = <<-EOT
    Open inbound TCP 22 to `allowed_ssh_cidr`.

    Left off by default. The instance is reachable through AWS Systems Manager
    Session Manager, which needs no inbound port, no key pair, and no bastion,
    and logs every session. Enable SSH only if an exercise specifically calls
    for it.
  EOT
  type        = bool
  default     = false
}

variable "allowed_ssh_cidr" {
  description = "Source CIDR permitted to reach port 22 when enable_ssh is true. Use your own address as a /32."
  type        = string
  default     = null

  validation {
    condition     = var.allowed_ssh_cidr == null || can(cidrnetmask(coalesce(var.allowed_ssh_cidr, "10.0.0.0/8")))
    error_message = "allowed_ssh_cidr must be a valid CIDR block, e.g. 203.0.113.4/32."
  }

  validation {
    condition     = var.allowed_ssh_cidr != "0.0.0.0/0"
    error_message = "Refusing 0.0.0.0/0 for SSH. Exposing port 22 to the internet invites credential-stuffing within minutes. Use your own address as a /32, or leave enable_ssh false and use Session Manager."
  }
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
