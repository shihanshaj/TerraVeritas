resource "aws_security_group" "data" {
  name        = "terraveritas-fixture-sg"
  description = "fixture"

  ingress {
    description = "SSH from office"
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["203.0.113.0/24"]
  }
}
