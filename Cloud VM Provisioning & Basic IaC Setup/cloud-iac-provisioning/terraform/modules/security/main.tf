resource "aws_security_group" "vm_sg" {
  name        = "${var.project_name}-sg-${var.environment}"
  description = "Security group for the provisioned VM"
  vpc_id      = var.vpc_id

  # Allow SSH from the allowed CIDR block
  ingress {
    description = "SSH Access"
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = [var.allowed_ssh_cidr]
  }

  # Allow node_exporter traffic (usually port 9100) from the allowed CIDR block for testing
  # In a real production setup, this would be restricted to the Prometheus server's CIDR or VPC internal CIDR
  ingress {
    description = "Node Exporter Access"
    from_port   = 9100
    to_port     = 9100
    protocol    = "tcp"
    cidr_blocks = [var.allowed_ssh_cidr] 
  }

  # Allow outbound internet access
  egress {
    description = "Allow all outbound traffic"
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = {
    Name        = "${var.project_name}-sg-${var.environment}"
    Environment = var.environment
    Project     = var.project_name
    ManagedBy   = "terraform"
  }
}
