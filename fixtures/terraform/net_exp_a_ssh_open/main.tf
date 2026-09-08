resource "aws_security_group" "data" {
  name        = "terraveritas-net-a-sg"
  description = "application servers"

  ingress {
    description = "SSH for admin access"
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
}
