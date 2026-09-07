###############################################################################
# TKH Final Capstone - Milestone 1: Infrastructure
# Author: Dwayne Saxton
#
# Builds a minimal, secure public web stack on AWS:
#   VPC -> Public Subnet -> Internet Gateway -> Route Table -> Security Group
#   -> EC2 web server (Apache/httpd) bootstrapped via user_data
#
# NOTE: Code only. Do NOT run `terraform apply` for this milestone.
###############################################################################

terraform {
  required_version = ">= 1.5.0"

  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
  }
}

provider "aws" {
  region = var.aws_region
}

###############################################################################
# AMI LOOKUP
# Pull the current Amazon Linux 2023 AMI from the AWS-managed SSM Parameter
# Store instead of hardcoding one. Hardcoded AMI IDs are region-specific and
# go stale, and a stale AMI means unpatched CVEs.
###############################################################################
data "aws_ssm_parameter" "al2023" {
  name = "/aws/service/ami-amazon-linux-latest/al2023-ami-kernel-default-x86_64"
}

###############################################################################
# THE NETWORK
###############################################################################

# The VPC - our isolated private network space (10.0.0.0/16).
resource "aws_vpc" "main" {
  cidr_block           = var.vpc_cidr
  enable_dns_support   = true
  enable_dns_hostnames = true

  tags = {
    Name = "${var.project_name}-vpc"
  }
}

# Public subnet (10.0.1.0/24) - where the web server lives.
resource "aws_subnet" "public" {
  vpc_id                  = aws_vpc.main.id
  cidr_block              = var.public_subnet_cidr
  availability_zone       = var.availability_zone
  map_public_ip_on_launch = true

  tags = {
    Name = "${var.project_name}-public-subnet"
  }
}

# The Internet Gateway - the VPC's door to the public internet.
resource "aws_internet_gateway" "main" {
  vpc_id = aws_vpc.main.id

  tags = {
    Name = "${var.project_name}-igw"
  }
}

# Route table: send all non-local traffic (0.0.0.0/0) out through the IGW.
resource "aws_route_table" "public" {
  vpc_id = aws_vpc.main.id

  route {
    cidr_block = "0.0.0.0/0"
    gateway_id = aws_internet_gateway.main.id
  }

  tags = {
    Name = "${var.project_name}-public-rt"
  }
}

# Bind the route table to the subnet. Without this association the subnet
# silently falls back to the default route table and has no internet path.
resource "aws_route_table_association" "public" {
  subnet_id      = aws_subnet.public.id
  route_table_id = aws_route_table.public.id
}

###############################################################################
# THE FIREWALL
# Port 80 open to the world (it is a public web server).
# Port 22 locked to a single /32 - my home IP only. Never 0.0.0.0/0 on SSH.
###############################################################################
resource "aws_security_group" "web" {
  name        = "${var.project_name}-web-sg"
  description = "Allow HTTP from anywhere and SSH from my home IP only"
  vpc_id      = aws_vpc.main.id

  ingress {
    description = "HTTP from the public internet"
    from_port   = 80
    to_port     = 80
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  ingress {
    description = "SSH restricted to my home IP address only"
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = [var.my_home_ip]
  }

  egress {
    description = "Allow all outbound (needed for yum package installs)"
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = {
    Name = "${var.project_name}-web-sg"
  }
}

###############################################################################
# THE SERVER
###############################################################################
resource "aws_instance" "web" {
  ami                    = data.aws_ssm_parameter.al2023.value
  instance_type          = var.instance_type
  subnet_id              = aws_subnet.public.id
  vpc_security_group_ids = [aws_security_group.web.id]

  # Enforce IMDSv2 - blocks the SSRF-to-credential-theft path behind the
  # Capital One breach.
  metadata_options {
    http_endpoint = "enabled"
    http_tokens   = "required"
  }

  root_block_device {
    volume_size = 8
    volume_type = "gp3"
    encrypted   = true
  }

  # Bootstrap script - runs once, as root, on first boot.
  user_data = <<-EOT
    #!/bin/bash
    yum update -y
    yum install -y httpd
    systemctl start httpd
    systemctl enable httpd
    echo "<h1>TKH Final Capstone - Deployed via Terraform</h1>" > /var/www/html/index.html
  EOT

  tags = {
    Name = "${var.project_name}-web-server"
  }
}
