variable "project_name" {
  description = "Prefix applied to the Name tag of every resource."
  type        = string
  default     = "tkh-capstone"
}

variable "aws_region" {
  description = "AWS region to deploy into."
  type        = string
  default     = "us-east-1"
}

variable "availability_zone" {
  description = "Availability Zone for the public subnet."
  type        = string
  default     = "us-east-1a"
}

variable "vpc_cidr" {
  description = "CIDR block for the VPC."
  type        = string
  default     = "10.0.0.0/16"
}

variable "public_subnet_cidr" {
  description = "CIDR block for the public subnet."
  type        = string
  default     = "10.0.1.0/24"
}

variable "instance_type" {
  description = "EC2 instance type for the web server."
  type        = string
  default     = "t2.micro"
}

# No default on purpose. Terraform refuses to plan until this is supplied,
# which makes it impossible to accidentally ship an open SSH port.
variable "my_home_ip" {
  description = "Public IP in CIDR /32 notation. SSH is allowed from this address only."
  type        = string

  validation {
    condition     = can(cidrhost(var.my_home_ip, 0)) && endswith(var.my_home_ip, "/32")
    error_message = "my_home_ip must be a single address in CIDR form ending in /32."
  }
}
