environment      = "dev"
project_name     = "sre-iac-demo"
aws_region       = "us-east-1"
instance_type    = "t3.micro"  # Free tier eligible (if t2.micro is preferred, change here)

# SECURITY WARNING: You must set allowed_ssh_cidr to your actual IP (e.g. "203.0.113.1/32")
# DO NOT leave this as 0.0.0.0/0 unless you know what you're doing.
# You can override this at runtime: `terraform apply -var-file="environments/dev.tfvars" -var="allowed_ssh_cidr=$(curl -s ifconfig.me)/32"`
allowed_ssh_cidr = "0.0.0.0/0" # Change this!
