resource "aws_s3_bucket" "data" {
  bucket = "terraveritas-phase2c-bucket"
}

resource "aws_s3_bucket_versioning" "data" {
  bucket = aws_s3_bucket.data.id
  versioning_configuration {
    status = "Enabled"
  }
}

resource "aws_s3_bucket_server_side_encryption_configuration" "data" {
  bucket = aws_s3_bucket.data.id
  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "aws:kms"
    }
  }
}

resource "aws_s3_bucket_lifecycle_configuration" "data" {
  bucket = aws_s3_bucket.data.id
  rule {
    id     = "expire-old"
    status = "Enabled"
    expiration {
      days = 365
    }
  }
}

resource "aws_s3_bucket_logging" "data" {
  bucket        = aws_s3_bucket.data.id
  target_bucket = "terraveritas-phase2c-logs"
  target_prefix = "log/"
}

resource "aws_sns_topic" "notifications" {
  name = "terraveritas-phase2c-notifications"
}

resource "aws_s3_bucket_notification" "data" {
  bucket = aws_s3_bucket.data.id
  topic {
    topic_arn = aws_sns_topic.notifications.arn
    events    = ["s3:ObjectCreated:*"]
  }
}

resource "aws_s3_bucket_replication_configuration" "data" {
  bucket = aws_s3_bucket.data.id
  role   = "arn:aws:iam::123456789012:role/terraveritas-phase2c-replication-role"

  rule {
    id     = "replicate-all"
    status = "Enabled"
    destination {
      bucket = "arn:aws:s3:::terraveritas-phase2c-replication-destination"
    }
  }

  depends_on = [aws_s3_bucket_versioning.data]
}

resource "aws_s3_bucket_policy" "data" {
  bucket = aws_s3_bucket.data.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect    = "Allow"
        Principal = "*"
        Action    = "s3:GetObject"
        Resource  = "arn:aws:s3:::terraveritas-phase2c-bucket/*"
      }
    ]
  })
}
