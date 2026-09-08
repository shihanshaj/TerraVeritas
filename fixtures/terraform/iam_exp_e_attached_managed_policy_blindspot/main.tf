resource "aws_iam_role" "data" {
  name = "terraveritas-iam-e-role"

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

resource "aws_iam_policy" "admin" {
  name = "terraveritas-iam-e-managed-admin-policy"

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid      = "ManagedFullAccess"
        Effect   = "Allow"
        Action   = "*"
        Resource = "*"
      }
    ]
  })
}

resource "aws_iam_role_policy_attachment" "data" {
  role       = aws_iam_role.data.name
  policy_arn = aws_iam_policy.admin.arn
}
