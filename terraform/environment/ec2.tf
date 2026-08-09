# Lab EC2 instance.
#
# COST: t3.micro is roughly $7.50/month left running, plus about $0.65 for the
# EBS volume. That is most of the $10 budget from Phase 2. Run `terraform
# destroy` when you finish a session.

data "aws_ssm_parameter" "al2023_ami" {
  name = "/aws/service/ami-amazon-linux-latest/al2023-ami-kernel-default-x86_64"
}

resource "aws_instance" "lab" {
  ami                    = data.aws_ssm_parameter.al2023_ami.value
  instance_type          = var.instance_type
  subnet_id              = aws_subnet.public.id
  vpc_security_group_ids = [aws_security_group.instance.id]
  iam_instance_profile   = aws_iam_instance_profile.instance.name

  # Require IMDSv2. IMDSv1 lets any SSRF bug on the instance read the role's
  # temporary credentials with a plain GET; IMDSv2's token requirement blocks
  # that. This is the single highest-value EC2 hardening setting.
  metadata_options {
    http_endpoint               = "enabled"
    http_tokens                 = "required"
    http_put_response_hop_limit = 1
  }

  root_block_device {
    volume_type           = "gp3"
    volume_size           = 8
    encrypted             = true
    delete_on_termination = true
  }

  monitoring = false

  tags = {
    Name = "${var.project_name}-instance"
  }
}
