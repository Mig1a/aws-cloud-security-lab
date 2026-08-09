# Security group for the lab instance.
#
# No inbound rules by default. Access is via Systems Manager Session Manager,
# which reaches the instance through an outbound connection from the SSM agent
# rather than an inbound port. That removes the usual open-22 attack surface
# and gives auditable session logs.

resource "aws_security_group" "instance" {
  name_prefix = "${var.project_name}-instance-"
  description = "Lab EC2 instance - egress only unless SSH is explicitly enabled"
  vpc_id      = aws_vpc.lab.id

  tags = {
    Name = "${var.project_name}-instance-sg"
  }

  lifecycle {
    create_before_destroy = true
  }
}

resource "aws_vpc_security_group_egress_rule" "all_outbound" {
  security_group_id = aws_security_group.instance.id
  description       = "Required for SSM agent, package updates, and CloudTrail delivery"
  ip_protocol       = "-1"
  cidr_ipv4         = "0.0.0.0/0"
}

# Optional, off by default. Guarded so enable_ssh cannot be set without also
# supplying a source CIDR.
resource "aws_vpc_security_group_ingress_rule" "ssh" {
  count = var.enable_ssh ? 1 : 0

  security_group_id = aws_security_group.instance.id
  description       = "SSH from operator address"
  ip_protocol       = "tcp"
  from_port         = 22
  to_port           = 22
  cidr_ipv4         = var.allowed_ssh_cidr

  lifecycle {
    precondition {
      condition     = var.allowed_ssh_cidr != null
      error_message = "enable_ssh is true but allowed_ssh_cidr is not set. Set it to your own address as a /32."
    }
  }
}
