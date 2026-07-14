output "instance_id" {
  description = "The EC2 instance ID"
  value       = aws_instance.vm.id
}

output "public_ip" {
  description = "The public IP address of the EC2 instance"
  value       = aws_instance.vm.public_ip
}
