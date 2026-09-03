# Deliberately vulnerable fixture: S3 bucket with a public-read ACL and no
# Block Public Access configuration. Used to verify scanners correctly flag
# a genuinely vulnerable resource (Candidate 1: S3 Public Access Exposure).

resource "aws_s3_bucket" "data" {
  bucket = "terraveritas-fixture-vulnerable-bucket"
}

resource "aws_s3_bucket_acl" "data" {
  bucket = aws_s3_bucket.data.id
  acl    = "public-read"
}
