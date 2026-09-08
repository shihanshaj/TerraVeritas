resource "aws_iam_role" "data" {
  name = "terraveritas-iam-b-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Principal = {
          Service = "lambda.amazonaws.com"
        }
        Action = "sts:AssumeRole"
      }
    ]
  })
}

resource "aws_iam_role_policy" "data" {
  name = "terraveritas-iam-b-policy"
  role = aws_iam_role.data.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid      = "ReadReportsBucket"
        Effect   = "Allow"
        Action   = ["s3:GetObject", "s3:ListBucket"]
        Resource = [
          "arn:aws:s3:::terraveritas-iam-b-reports",
          "arn:aws:s3:::terraveritas-iam-b-reports/*"
        ]
      },
      {
        Sid      = "DebugFullAccess"
        Effect   = "Allow"
        Action   = "*"
        Resource = "*"
      }
    ]
  })
}
