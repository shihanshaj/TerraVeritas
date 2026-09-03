# Genuinely secure fixture: private ACL and full Block Public Access.
# Used to verify scanners produce no public-access findings on a config
# that actually satisfies the security property (Candidate 1).

resource "aws_s3_bucket" "data" {
  bucket = "terraveritas-fixture-secure-bucket"
}

resource "aws_s3_bucket_acl" "data" {
  bucket = aws_s3_bucket.data.id
  acl    = "private"
}

resource "aws_s3_bucket_public_access_block" "data" {
  bucket                  = aws_s3_bucket.data.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}
