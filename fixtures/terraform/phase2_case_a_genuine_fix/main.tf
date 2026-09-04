resource "aws_s3_bucket" "data" {
  bucket = "terraveritas-phase2a-bucket"
}

resource "aws_s3_bucket_acl" "data" {
  bucket = aws_s3_bucket.data.id
  acl    = "public-read"
}
