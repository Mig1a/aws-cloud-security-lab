output "vpc_id" {
  description = "Lab VPC ID."
  value       = aws_vpc.lab.id
}

output "public_subnet_id" {
  description = "Public subnet ID."
  value       = aws_subnet.public.id
}

output "security_group_id" {
  description = "Instance security group ID."
  value       = aws_security_group.instance.id
}

output "instance_id" {
  description = "Lab EC2 instance ID."
  value       = aws_instance.lab.id
}

output "instance_public_ip" {
  description = "Public IP of the lab instance."
  value       = aws_instance.lab.public_ip
}

output "instance_private_ip" {
  description = "Private IP of the lab instance."
  value       = aws_instance.lab.private_ip
}

output "instance_role_name" {
  description = "IAM role attached to the instance."
  value       = aws_iam_role.instance.name
}

output "session_manager_command" {
  description = "Connect to the instance without SSH or an open inbound port."
  value       = "aws ssm start-session --target ${aws_instance.lab.id} --region ${var.aws_region}"
}

output "estimated_monthly_cost_note" {
  description = "Reminder that this environment bills while it exists."
  value       = "~$8/month if left running (t3.micro + 8GB gp3). Run 'terraform destroy' when done."
}
