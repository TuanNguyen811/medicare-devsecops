output "db_endpoint" {
  description = "PostgreSQL endpoint (private)"
  value       = aws_db_instance.medicare.address
}

output "imaging_bucket" {
  description = "Bucket storing medical imaging files"
  value       = aws_s3_bucket.imaging.bucket
}
