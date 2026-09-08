resource "aws_s3_bucket" "data" {
  bucket = "terraveritas-deceptive-s3-bucket"
}

resource "aws_s3_bucket_policy" "data" {
  bucket = aws_s3_bucket.data.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid       = "PublicRead"
        Effect    = "Allow"
        Principal = "*"
        Action    = "s3:GetObject"
        Resource  = "arn:aws:s3:::terraveritas-deceptive-s3-bucket/*"
      }
    ]
  })
}
