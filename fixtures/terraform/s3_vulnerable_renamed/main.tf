# Same vulnerability as s3_vulnerable (public-read ACL, no Block Public
# Access), but the resource label is renamed from "data" to "archive" and
# the bucket name changed too. Used to prove the differential engine's
# relocation-candidate matching against real Checkov output, not just
# synthetic Finding construction.

resource "aws_s3_bucket" "archive" {
  bucket = "terraveritas-fixture-vulnerable-bucket-renamed"
}

resource "aws_s3_bucket_acl" "archive" {
  bucket = aws_s3_bucket.archive.id
  acl    = "public-read"
}
