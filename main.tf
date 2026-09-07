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
# tfsec AVD-AWS-0164 is an accepted risk, not a defect. This subnet exists to
# host an internet-facing web server, so a routable public IP is the
# requirement. The compensating control is the security group below, which
# exposes only :80 to the world and restricts :22 to a single /32.
#tfsec:ignore:aws-ec2-no-public-ip-subnet
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

  # tfsec AVD-AWS-0107 is an accepted risk. A public web server must accept
  # traffic from the public internet on :80. The exposure is bounded: only :80
  # is open to 0.0.0.0/0, and :22 is limited to one address.
  #tfsec:ignore:aws-ec2-no-public-ingress-sgr
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

  # tfsec AVD-AWS-0104 is an accepted risk. The bootstrap script must reach the
  # Amazon Linux package repositories, whose address space is not a fixed CIDR
  # that can be enumerated in this security group.
  # TEMPORARILY DISABLED - proving the quality gate breaks the build
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


###############################################################################
# VPC FLOW LOGS
#
# The one tfsec finding that was a genuine gap rather than an accepted risk
# (AVD-AWS-0178). Without flow logs there is no record of traffic in or out of
# the VPC, so a security incident cannot be reconstructed after the fact.
###############################################################################

data "aws_caller_identity" "current" {}

# Customer-managed KMS key for the log group. A CMK rather than the default
# AWS-owned key means rotation and access are auditable and controlled by this
# account - AVD-AWS-0017.
resource "aws_kms_key" "flow_logs" {
  description             = "Encrypts VPC flow logs for ${var.project_name}"
  deletion_window_in_days = 10
  enable_key_rotation     = true
  policy                  = data.aws_iam_policy_document.flow_logs_kms.json

  tags = {
    Name = "${var.project_name}-flow-logs-key"
  }
}

data "aws_iam_policy_document" "flow_logs_kms" {
  # Account root retains administrative control of the key.
  statement {
    effect    = "Allow"
    actions   = ["kms:*"]
    resources = ["*"]

    principals {
      type        = "AWS"
      identifiers = ["arn:aws:iam::${data.aws_caller_identity.current.account_id}:root"]
    }
  }

  # CloudWatch Logs must be able to encrypt and decrypt log data with this key.
  statement {
    effect = "Allow"

    actions = [
      "kms:Encrypt",
      "kms:Decrypt",
      "kms:ReEncrypt*",
      "kms:GenerateDataKey*",
      "kms:DescribeKey",
    ]

    resources = ["*"]

    principals {
      type        = "Service"
      identifiers = ["logs.${var.aws_region}.amazonaws.com"]
    }
  }
}

resource "aws_cloudwatch_log_group" "vpc_flow_logs" {
  name              = "/aws/vpc/${var.project_name}-flow-logs"
  retention_in_days = var.flow_log_retention_days
  kms_key_id        = aws_kms_key.flow_logs.arn

  tags = {
    Name = "${var.project_name}-flow-logs"
  }
}

# Trust policy - lets the VPC Flow Logs service assume this role.
data "aws_iam_policy_document" "flow_logs_assume_role" {
  statement {
    effect  = "Allow"
    actions = ["sts:AssumeRole"]

    principals {
      type        = "Service"
      identifiers = ["vpc-flow-logs.amazonaws.com"]
    }
  }
}

data "aws_iam_policy_document" "flow_logs_permissions" {
  statement {
    effect = "Allow"

    actions = [
      "logs:CreateLogStream",
      "logs:PutLogEvents",
      "logs:DescribeLogStreams",
    ]

    # tfsec AVD-AWS-0057 is an accepted risk. The ":*" suffix is the log-stream
    # wildcard AWS documents for this role - flow logs create one stream per
    # ENI, so streams cannot be enumerated ahead of time. The policy is still
    # scoped to this single log group and never to "*".
    #tfsec:ignore:aws-iam-no-policy-wildcards
    resources = ["${aws_cloudwatch_log_group.vpc_flow_logs.arn}:*"]
  }
}

resource "aws_iam_role" "flow_logs" {
  name               = "${var.project_name}-flow-logs-role"
  assume_role_policy = data.aws_iam_policy_document.flow_logs_assume_role.json

  tags = {
    Name = "${var.project_name}-flow-logs-role"
  }
}

resource "aws_iam_role_policy" "flow_logs" {
  name   = "${var.project_name}-flow-logs-policy"
  role   = aws_iam_role.flow_logs.id
  policy = data.aws_iam_policy_document.flow_logs_permissions.json
}

resource "aws_flow_log" "main" {
  vpc_id          = aws_vpc.main.id
  traffic_type    = "ALL"
  iam_role_arn    = aws_iam_role.flow_logs.arn
  log_destination = aws_cloudwatch_log_group.vpc_flow_logs.arn

  tags = {
    Name = "${var.project_name}-flow-log"
  }
}
