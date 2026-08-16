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
