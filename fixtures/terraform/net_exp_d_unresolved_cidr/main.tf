resource "aws_eip" "ops" {
  domain = "vpc"
}

resource "aws_security_group" "data" {
  name        = "terraveritas-net-d-sg"
  description = "application servers"

  ingress {
    description = "SSH restricted to the operations team's floating IP"
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["${aws_eip.ops.public_ip}/32"]
  }
}
