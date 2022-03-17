terraform {
  required_providers {
    aws = {
      source = "hashicorp/aws"
      version = "~> 2.70"
    }
  }
}

provider "aws" {
  region = "us-east-2"
}

# Default security group to access the instances via WinRM over HTTP and HTTPS
resource "aws_security_group" "linux-httpd" {
  name        = "linux-httpd"
  description = "Used in the terraform"

  # WinRM access from anywhere
  ingress {
    from_port   = 80
    to_port     = 80
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  ingress {
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  # outbound internet access
  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
}

resource "aws_instance" "linux_httpd" {
  ami = "ami-03d64741867e7bb94"
  instance_type = "t2.micro"
  tags = {
    Name = "RHEL-HTTPD"
    owner = "cmays"
    AOC_DEMO_ROLE = "httpd"
    DemoID = "cmays"
  }
  key_name = "deployer-key-linux"

  # Our Security group to allow WinRM access
  vpc_security_group_ids = [aws_security_group.linux-httpd.id]
}

resource "aws_key_pair" "deployer" {
  key_name = "deployer-key-linux"
  public_key = var.public_key
}
