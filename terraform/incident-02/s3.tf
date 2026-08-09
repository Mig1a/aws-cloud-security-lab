# Incident 02 - insecure S3 configuration, and its remediation.
#
# One bucket, two postures, selected by var.harden. Everything below that reads
# `var.harden ? X : Y` is a control that the insecure baseline omits.
#
# The whole file is written so that `terraform plan` after flipping the toggle
# reads as a remediation plan.

resource "aws_s3_bucket" "target" {
  bucket        = "${var.project_name}-${data.aws_caller_identity.current.account_id}"
  force_destroy = true

  tags = {
    Name     = "${var.project_name}-target"
    Posture  = var.harden ? "hardened" : "INSECURE"
    Exercise = "incident-02"
  }
}

# --- Control 1: Block Public Access ------------------------------------------
# The single most important S3 control. All four settings off in the insecure
# baseline, which is what permits the public policy below to take effect.
resource "aws_s3_bucket_public_access_block" "target" {
  bucket = aws_s3_bucket.target.id

  block_public_acls       = var.harden
  block_public_policy     = var.harden
  ignore_public_acls      = var.harden
  restrict_public_buckets = var.harden
}

# --- Control 2: Object ownership / ACLs --------------------------------------
# BucketOwnerEnforced disables ACLs entirely. The insecure baseline leaves ACLs
# usable, which is a second, independent path to making objects public.
resource "aws_s3_bucket_ownership_controls" "target" {
  bucket = aws_s3_bucket.target.id

  rule {
    object_ownership = var.harden ? "BucketOwnerEnforced" : "ObjectWriter"
  }
}

# --- Control 3: Versioning ---------------------------------------------------
# Protects against overwrite and deletion, including ransomware-style
# destruction. Absent in the insecure baseline.
resource "aws_s3_bucket_versioning" "target" {
  bucket = aws_s3_bucket.target.id

  versioning_configuration {
    status = var.harden ? "Enabled" : "Suspended"
  }
}

# --- Control 4: Encryption ---------------------------------------------------
# NOTE: since January 2023 S3 applies SSE-S3 to all new buckets automatically,
# so a genuinely unencrypted bucket can no longer be created. The realistic
# weakness is therefore not "no encryption" but "no EXPLICIT encryption
# posture": relying on an implicit default, with no bucket key.
#
# The hardened state declares the intent and enables bucket keys, which also
# cuts request costs.
resource "aws_s3_bucket_server_side_encryption_configuration" "target" {
  count = var.harden ? 1 : 0

  bucket = aws_s3_bucket.target.id

  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "AES256"
    }
    bucket_key_enabled = true
  }
}

# --- Control 5: Lifecycle ----------------------------------------------------
resource "aws_s3_bucket_lifecycle_configuration" "target" {
  count = var.harden ? 1 : 0

  bucket     = aws_s3_bucket.target.id
  depends_on = [aws_s3_bucket_versioning.target]

  rule {
    id     = "expire-noncurrent"
    status = "Enabled"

    filter {}

    noncurrent_version_expiration {
      noncurrent_days = 7
    }

    abort_incomplete_multipart_upload {
      days_after_initiation = 7
    }
  }
}

# --- Bucket policy -----------------------------------------------------------

# INSECURE: anonymous read of every object.
#
# Read only. s3:PutObject is deliberately never granted to a wildcard
# principal - a publicly writable bucket is an abuse and cost problem, not
# just a confidentiality one.
data "aws_iam_policy_document" "insecure" {
  statement {
    sid     = "PublicReadGetObject"
    effect  = "Allow"
    actions = ["s3:GetObject"]

    principals {
      type        = "*"
      identifiers = ["*"]
    }

    resources = ["${aws_s3_bucket.target.arn}/*"]
  }
}

# HARDENED: no public grant at all, plus an explicit deny on plaintext HTTP
# and a least-privilege read grant scoped to this account only.
data "aws_iam_policy_document" "hardened" {
  statement {
    sid     = "DenyInsecureTransport"
    effect  = "Deny"
    actions = ["s3:*"]

    principals {
      type        = "*"
      identifiers = ["*"]
    }

    resources = [
      aws_s3_bucket.target.arn,
      "${aws_s3_bucket.target.arn}/*",
    ]

    condition {
      test     = "Bool"
      variable = "aws:SecureTransport"
      values   = ["false"]
    }
  }

  statement {
    sid     = "DenyUnencryptedObjectUploads"
    effect  = "Deny"
    actions = ["s3:PutObject"]

    principals {
      type        = "*"
      identifiers = ["*"]
    }

    resources = ["${aws_s3_bucket.target.arn}/*"]

    condition {
      test     = "StringNotEquals"
      variable = "s3:x-amz-server-side-encryption"
      values   = ["AES256", "aws:kms"]
    }
  }

  # Least privilege: read access limited to principals in this account.
  statement {
    sid     = "AllowThisAccountReadOnly"
    effect  = "Allow"
    actions = ["s3:GetObject", "s3:ListBucket"]

    principals {
      type        = "AWS"
      identifiers = [data.aws_caller_identity.current.account_id]
    }

    resources = [
      aws_s3_bucket.target.arn,
      "${aws_s3_bucket.target.arn}/*",
    ]
  }
}

resource "aws_s3_bucket_policy" "target" {
  bucket = aws_s3_bucket.target.id
  policy = var.harden ? data.aws_iam_policy_document.hardened.json : data.aws_iam_policy_document.insecure.json

  # A public policy is rejected while BlockPublicPolicy is on, so the access
  # block must be settled before the policy is written.
  depends_on = [
    aws_s3_bucket_public_access_block.target,
    aws_s3_bucket_ownership_controls.target,
  ]
}

# --- Synthetic contents ------------------------------------------------------
resource "aws_s3_object" "sample" {
  for_each = {
    "public-brochure.txt"    = "SYNTHETIC LAB DATA - a file intended to be readable.\n"
    "internal/employees.csv" = "SYNTHETIC LAB DATA - name,role\nplaceholder,placeholder\n"
    "internal/api-notes.txt" = "SYNTHETIC LAB DATA - stand-in for a file that must never be public.\n"
  }

  bucket       = aws_s3_bucket.target.id
  key          = each.key
  content      = each.value
  content_type = "text/plain"

  depends_on = [aws_s3_bucket_ownership_controls.target]
}
