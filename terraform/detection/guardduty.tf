# GuardDuty - continuous threat detection.
#
# GuardDuty analyzes three foundational sources at no extra charge beyond the
# per-volume pricing: CloudTrail management events, VPC Flow Logs, and Route 53
# DNS query logs. It reads them directly from the AWS control plane, so none of
# them need to be separately enabled or delivered anywhere.
#
# COST: 30-day free trial from the moment the detector is created. After that,
# roughly $4 per million CloudTrail events plus per-GB charges for flow and DNS
# logs. On an idle lab account this is typically well under $1/month - the
# optional add-on features below are what make it expensive.

resource "aws_guardduty_detector" "lab" {
  enable                       = true
  finding_publishing_frequency = var.guardduty_finding_frequency

  tags = {
    Name = "${var.project_name}-guardduty"
  }
}

# Optional paid features are declared explicitly rather than left to the
# provider default, so the cost posture is visible in code.

resource "aws_guardduty_detector_feature" "s3_data_events" {
  detector_id = aws_guardduty_detector.lab.id
  name        = "S3_DATA_EVENTS"
  status      = var.guardduty_s3_protection ? "ENABLED" : "DISABLED"
}

resource "aws_guardduty_detector_feature" "ebs_malware_protection" {
  detector_id = aws_guardduty_detector.lab.id
  name        = "EBS_MALWARE_PROTECTION"
  status      = var.guardduty_malware_protection ? "ENABLED" : "DISABLED"
}

resource "aws_guardduty_detector_feature" "runtime_monitoring" {
  detector_id = aws_guardduty_detector.lab.id
  name        = "RUNTIME_MONITORING"
  status      = var.guardduty_runtime_monitoring ? "ENABLED" : "DISABLED"
}
