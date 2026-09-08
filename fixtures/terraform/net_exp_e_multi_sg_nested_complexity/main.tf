resource "aws_security_group" "web" {
  name        = "terraveritas-net-e-web-sg"
  description = "public web tier -- already restricted, should not be touched"

  ingress {
    description = "HTTPS from the internet"
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
}

resource "aws_security_group" "data" {
  name        = "terraveritas-net-e-app-sg"
  description = "application tier"

  ingress {
    description = "HTTPS from the load balancer tier"
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  ingress {
    description = "SSH for admin access"
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  ingress {
    description = "MySQL access restricted to the corporate network"
    from_port   = 3306
    to_port     = 3306
    protocol    = "tcp"
    cidr_blocks = ["203.0.113.0/24"]
  }
}
