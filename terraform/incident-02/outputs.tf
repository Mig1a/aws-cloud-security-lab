output "bucket_name" {
  description = "Target bucket for the exercise."
  value       = aws_s3_bucket.target.id
}

output "posture" {
  description = "Which configuration is currently applied."
  value       = var.harden ? "HARDENED" : "INSECURE"
}

output "public_object_url" {
  description = "URL that anonymous callers can fetch while the insecure posture is applied. Should return 403 once hardened."
  value       = "https://${aws_s3_bucket.target.id}.s3.amazonaws.com/internal/api-notes.txt"
}

output "remediation_command" {
  description = "Apply the fix."
  value       = var.harden ? "already hardened" : "terraform apply -var harden=true"
}
