resource "aws_security_group" "data" {
  name        = "terraveritas-net-c-sg"
  description = "bastion and remote-management host"

  ingress {
    description = "SSH for admin access"
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  ingress {
    description = "RDP for Windows admin access"
    from_port   = 3389
    to_port     = 3389
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
}
