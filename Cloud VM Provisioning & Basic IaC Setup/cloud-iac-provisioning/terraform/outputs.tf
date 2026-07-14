output "public_ip" {
  description = "The public IP address of the provisioned VM"
  value       = module.compute.public_ip
}

output "instance_id" {
  description = "The ID of the EC2 instance"
  value       = module.compute.instance_id
}

output "security_group_id" {
  description = "The ID of the Security Group attached to the instance"
  value       = module.security.security_group_id
}

output "ssh_command" {
  description = "Ready-to-copy SSH command to connect to the instance"
  value       = "ssh -i ~/.ssh/sre_iac_rsa adminuser@${module.compute.public_ip}"
}

output "project_name" {
  description = "The project name (used by teardown.sh for AWS CLI tag filters)"
  value       = var.project_name
}

output "aws_region" {
  description = "The AWS region (used by teardown.sh for AWS CLI queries)"
  value       = var.aws_region
}
