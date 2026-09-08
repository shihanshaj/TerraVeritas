resource "aws_iam_role" "data" {
  name = "terraveritas-iam-d-role"

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
  name = "terraveritas-iam-d-policy"
  role = aws_iam_role.data.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid      = "FullAccess-${aws_iam_role.data.unique_id}"
        Effect   = "Allow"
        Action   = "*"
        Resource = "*"
      }
    ]
  })
}
