resource "aws_iam_role" "data" {
  name = "terraveritas-iam-c-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Principal = {
          Service = "ec2.amazonaws.com"
        }
        Action = "sts:AssumeRole"
      }
    ]
  })
}

resource "aws_iam_role_policy" "data" {
  name = "terraveritas-iam-c-policy"
  role = aws_iam_role.data.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid      = "LegacyAdminAccess"
        Effect   = "Allow"
        Action   = "*"
        Resource = "*"
      },
      {
        Sid      = "TempDebugAccess"
        Effect   = "Allow"
        Action   = "*"
        Resource = "*"
      }
    ]
  })
}
