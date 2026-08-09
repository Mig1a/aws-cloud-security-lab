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

  # Management events - the free copy. Always on.
  advanced_event_selector {
    name = "Management events"

    field_selector {
      field  = "eventCategory"
      equals = ["Management"]
    }
  }

  # S3 object-level (data) events, scoped by ARN prefix.
  #
  # Phase 5 needs these: S3 GetObject and ListObjects are data events, not
  # management events, so without this an investigation into who read what
  # from a bucket finds nothing. "You cannot investigate what you did not log."
  #
  # Scoped deliberately. Data events bill per event, and enabling them
  # account-wide is the classic source of a runaway CloudTrail bill. This
  # matches only lab incident buckets.
  dynamic "advanced_event_selector" {
    for_each = length(var.s3_data_event_arn_prefixes) > 0 ? [1] : []

    content {
      name = "S3 data events for lab incident buckets"

      field_selector {
        field  = "eventCategory"
        equals = ["Data"]
      }

      field_selector {
        field  = "resources.type"
        equals = ["AWS::S3::Object"]
      }

      field_selector {
        field       = "resources.ARN"
        starts_with = var.s3_data_event_arn_prefixes
      }
    }
  }

  tags = {
    Name = "${var.project_name}-trail"
  }

  # The bucket policy must exist before CloudTrail will accept the bucket.
  depends_on = [aws_s3_bucket_policy.cloudtrail]
}
