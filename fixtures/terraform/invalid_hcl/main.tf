# Deliberately invalid HCL (unclosed block) to verify scanners/parsers fail
# safely rather than crashing or silently reporting an empty clean scan.

resource "aws_s3_bucket" "broken" {
  bucket = "terraveritas-fixture-invalid"
  # missing closing brace below on purpose
