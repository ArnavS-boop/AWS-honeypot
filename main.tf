terraform {
  required_providers {
    aws = {
      source = "hashicorp/aws"
    }
  }
}

provider "aws" {
  region = "us-east-1"
}

resource "aws_instance" "decoy" {
  ami           = "ami-61ad6e59d7b0"
  instance_type = "t3.micro"

  user_data = file("${path.module}/scripts/decoy-init.sh")

  tags = {
    Name = "honeypot-decoy"
    Role = "decoy"
  }
}

resource "aws_instance" "captor" {
  ami           = "ami-61ad6e59d7b0"
  instance_type = "t3.micro"

  tags = {
    Name = "honeypot-captor"
    Role = "captor"
  }
}

resource "aws_instance" "risk_assessment" {
  ami           = "ami-61ad6e59d7b0"
  instance_type = "t3.micro"

  tags = {
    Name = "honeypot-risk-assessment"
    Role = "risk-assessment"
  }
}

resource "aws_instance" "orchestrator" {
  ami           = "ami-61ad6e59d7b0"
  instance_type = "t3.micro"

  tags = {
    Name = "honeypot-orchestrator"
    Role = "orchestrator"
  }
}