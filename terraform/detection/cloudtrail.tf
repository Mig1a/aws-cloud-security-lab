# Multi-region CloudTrail recording management events.
#
# COST: the first copy of management events per account is free. Data events
# (S3 object-level and Lambda invocations) are billed per event and are NOT
# enabled here - they are the usual source of surprise CloudTrail bills. Turn
# them on deliberately, scoped to one bucket, when an exercise needs them.
#
# Log file validation is on, producing signed digest files so tampering with
# delivered logs is detectable. That matters for a detection lab: logs an
# attacker can silently edit are not evidence.

resource "aws_cloudtrail" "lab" {
  name           = "${var.project_name}-trail"
  s3_bucket_name = aws_s3_bucket.cloudtrail.id

  is_multi_region_trail         = true
  include_global_service_events = true
  enable_log_file_validation    = true
  enable_logging                = true

  tags = {
    Name = "${var.project_name}-trail"
  }

  # The bucket policy must exist before CloudTrail will accept the bucket.
  depends_on = [aws_s3_bucket_policy.cloudtrail]
}
