resource "aws_security_group" "data" {
  name        = "terraveritas-net-b-sg"
  description = "database servers"

  ingress {
    description = "MySQL access for the reporting service"
    from_port   = 3306
    to_port     = 3306
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
}
