# Test data for the investigation.
#
# Two prefixes with different sensitivity, so the role's permission boundary
# can be exercised in both directions: reads that succeed and reads that are
# denied. The denied ones are the more interesting CloudTrail evidence.
#
# Contents are entirely synthetic. Nothing here is real data.

resource "aws_s3_bucket" "lab_data" {
  bucket        = "${var.project_name}-${data.aws_caller_identity.current.account_id}"
  force_destroy = true

  tags = {
    Name = "${var.project_name}-data"
  }
}

resource "aws_s3_bucket_public_access_block" "lab_data" {
  bucket = aws_s3_bucket.lab_data.id

  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_server_side_encryption_configuration" "lab_data" {
  bucket = aws_s3_bucket.lab_data.id

  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "AES256"
    }
  }
}

# Readable by the test role.
resource "aws_s3_object" "public_notes" {
  bucket       = aws_s3_bucket.lab_data.id
  key          = "reports/quarterly-summary.txt"
  content      = "SYNTHETIC LAB DATA - quarterly summary placeholder.\nNo real information.\n"
  content_type = "text/plain"
}

resource "aws_s3_object" "runbook" {
  bucket       = aws_s3_bucket.lab_data.id
  key          = "reports/runbook.txt"
  content      = "SYNTHETIC LAB DATA - operations runbook placeholder.\n"
  content_type = "text/plain"
}

# Outside the role's permitted prefix. Reading this should be denied, and that
# denial is the signal the investigation looks for.
resource "aws_s3_object" "restricted" {
  bucket       = aws_s3_bucket.lab_data.id
  key          = "restricted/payroll.txt"
  content      = "SYNTHETIC LAB DATA - stand-in for a file the test role must not read.\n"
  content_type = "text/plain"
}
