resource "aws_security_group" "data" {
  name        = "terraveritas-fixture-sg"
  description = "fixture"

  ingress {
    description = "SSH from anywhere"
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
}
