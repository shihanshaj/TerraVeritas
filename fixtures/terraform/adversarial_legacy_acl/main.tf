# Adversarial fixture: public access declared via the legacy pre-v4 AWS
# provider inline `acl` attribute on aws_s3_bucket itself, rather than the
# separate aws_s3_bucket_acl resource. Real Checkov catches this (verified
# empirically). This project's S3_PUBLIC_ACCESS_EXPOSURE invariant does
# not — a disclosed gap since the Prompt 6 design pass, exercised for real
# here as adversarial test #1.

resource "aws_s3_bucket" "data" {
  bucket = "terraveritas-adversarial-legacy-acl"
  acl    = "public-read"
}
