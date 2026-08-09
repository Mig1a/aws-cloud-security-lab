output "bucket_name" {
  description = "Test data bucket."
  value       = aws_s3_bucket.lab_data.id
}

output "role_arn" {
  description = "ARN of the deliberately limited test role."
  value       = aws_iam_role.test_analyst.arn
}

output "role_name" {
  description = "Name of the test role, as it appears in CloudTrail userIdentity."
  value       = aws_iam_role.test_analyst.name
}

output "trusted_principal" {
  description = "Identity permitted to assume the test role."
  value       = local.trusted_principal
}

output "assume_command" {
  description = "Assume the role manually."
  value       = "aws sts assume-role --role-arn ${aws_iam_role.test_analyst.arn} --role-session-name incident-01-test"
}
