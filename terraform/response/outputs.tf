output "function_name" {
  description = "Alert Lambda."
  value       = aws_lambda_function.alert.function_name
}

output "log_group" {
  description = "Where alerts land. Tail with: aws logs tail <this> --follow"
  value       = aws_cloudwatch_log_group.alert.name
}

output "rule_name" {
  description = "EventBridge rule matching Security Hub findings."
  value       = aws_cloudwatch_event_rule.high_severity_findings.name
}

output "alerting_on" {
  description = "Severity labels that trigger an alert."
  value       = var.alert_severity_labels
}

output "dlq_url" {
  description = "Dead letter queue. Should always be empty; a message here is an alert that was never delivered."
  value       = aws_sqs_queue.alert_dlq.url
}

output "self_test_command" {
  description = "Import a synthetic HIGH finding to prove the pipeline end to end."
  value       = "./detections/test-high-severity-alert.ps1"
}

output "console_links" {
  description = "Where to inspect the pipeline."
  value = {
    rule      = "https://${var.aws_region}.console.aws.amazon.com/events/home?region=${var.aws_region}#/eventbus/default/rules/${aws_cloudwatch_event_rule.high_severity_findings.name}"
    function  = "https://${var.aws_region}.console.aws.amazon.com/lambda/home?region=${var.aws_region}#/functions/${aws_lambda_function.alert.function_name}"
    log_group = "https://${var.aws_region}.console.aws.amazon.com/cloudwatch/home?region=${var.aws_region}#logsV2:log-groups/log-group/${replace(aws_cloudwatch_log_group.alert.name, "/", "$252F")}"
  }
}

# --- Phase 9: automated containment ------------------------------------------

output "containment_function_name" {
  description = "Containment Lambda."
  value       = aws_lambda_function.containment.function_name
}

output "containment_log_group" {
  description = "Where containment decisions land, including every skip. Tail with: aws logs tail <this> --follow"
  value       = aws_cloudwatch_log_group.containment.name
}

output "containment_rule_name" {
  description = "EventBridge rule matching only the containable finding type(s)."
  value       = aws_cloudwatch_event_rule.s3_anonymous_access.name
}

output "containment_dlq_url" {
  description = "Dead letter queue for the containment rule. Should always be empty; a message here is a containable finding that never reached the Lambda."
  value       = aws_sqs_queue.containment_dlq.url
}

output "auto_containment_enabled" {
  description = "Whether the Lambda is actually allowed to call the mutating S3 API right now, or is running in log-only dry-run mode."
  value       = var.enable_auto_containment
}

output "containable_finding_types" {
  description = "ASFF Types the containment Lambda acts on."
  value       = var.containable_finding_types
}

output "containable_resource_arns" {
  description = "The only resources the containment Lambda is permitted to touch."
  value       = local.containable_resource_arns
}

output "containment_self_test_command" {
  description = "Flip the allow-listed bucket's Block Public Access off, import a synthetic matching finding, and verify the Lambda restores it."
  value       = "./detections/test-automated-containment.ps1"
}
