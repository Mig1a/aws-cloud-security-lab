output "cloudtrail_bucket" {
  description = "S3 bucket receiving CloudTrail logs."
  value       = aws_s3_bucket.cloudtrail.id
}

output "cloudtrail_arn" {
  description = "ARN of the CloudTrail trail."
  value       = aws_cloudtrail.lab.arn
}

output "guardduty_detector_id" {
  description = "GuardDuty detector ID."
  value       = aws_guardduty_detector.lab.id
}

output "guardduty_paid_features" {
  description = "Status of the optional, separately billed GuardDuty features."
  value = {
    s3_data_events         = aws_guardduty_detector_feature.s3_data_events.status
    ebs_malware_protection = aws_guardduty_detector_feature.ebs_malware_protection.status
    runtime_monitoring     = aws_guardduty_detector_feature.runtime_monitoring.status
  }
}

output "security_hub_standards" {
  description = "Subscribed Security Hub standards."
  value       = [for s in aws_securityhub_standards_subscription.enabled : s.standards_arn]
}

output "console_links" {
  description = "Where to review findings."
  value = {
    guardduty    = "https://${var.aws_region}.console.aws.amazon.com/guardduty/home?region=${var.aws_region}#/findings"
    security_hub = "https://${var.aws_region}.console.aws.amazon.com/securityhub/home?region=${var.aws_region}#/findings"
    cloudtrail   = "https://${var.aws_region}.console.aws.amazon.com/cloudtrailv2/home?region=${var.aws_region}#/events"
  }
}

output "cost_note" {
  description = "Standing cost reminder for the detection stack."
  value       = "GuardDuty and Security Hub free trials both start on enable and run 30 days. This stack is long-lived by design - do NOT destroy it between sessions, but do review spend before the trials end."
}
