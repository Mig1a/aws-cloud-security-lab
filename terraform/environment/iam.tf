# Instance role.
#
# Carries only AmazonSSMManagedInstanceCore - the AWS-managed policy that lets
# Systems Manager reach the instance. No S3, no admin, nothing broader. If the
# instance is later compromised in an exercise, the blast radius of its
# credentials is deliberately small.

data "aws_iam_policy_document" "ec2_assume_role" {
  statement {
    effect  = "Allow"
    actions = ["sts:AssumeRole"]

    principals {
      type        = "Service"
      identifiers = ["ec2.amazonaws.com"]
    }
  }
}

resource "aws_iam_role" "instance" {
  name_prefix        = "${var.project_name}-instance-"
  description        = "Lab EC2 instance role - Session Manager access only"
  assume_role_policy = data.aws_iam_policy_document.ec2_assume_role.json
}

resource "aws_iam_role_policy_attachment" "ssm_core" {
  role       = aws_iam_role.instance.name
  policy_arn = "arn:aws:iam::aws:policy/AmazonSSMManagedInstanceCore"
}

resource "aws_iam_instance_profile" "instance" {
  name_prefix = "${var.project_name}-instance-"
  role        = aws_iam_role.instance.name
}
