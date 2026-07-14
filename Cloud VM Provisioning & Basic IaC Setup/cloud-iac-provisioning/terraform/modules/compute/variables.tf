variable "project_name" {
  description = "Name of the project"
  type        = string
}

variable "environment" {
  description = "Environment (dev, staging, prod)"
  type        = string
}

variable "instance_type" {
  description = "EC2 instance type (e.g. t3.micro)"
  type        = string
  default     = "t3.micro"
}

variable "subnet_id" {
  description = "The Subnet ID to deploy the instance into"
  type        = string
}

variable "vpc_security_group_ids" {
  description = "A list of security group IDs to associate with the instance"
  type        = list(string)
}

variable "key_name" {
  description = "Name of the AWS key pair to use for SSH access"
  type        = string
}

variable "user_data" {
  description = "The user data script to run on boot (e.g. bootstrap.sh)"
  type        = string
}
