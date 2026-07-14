# ------------------------------------------------------------------------------
# Local Variables & Data Sources
# ------------------------------------------------------------------------------
locals {
  # We read the bootstrap script from the scripts directory
  bootstrap_script = file("${path.module}/../scripts/bootstrap.sh")
}

# ------------------------------------------------------------------------------
# SSH Key Pair
# ------------------------------------------------------------------------------
# Create a new SSH key pair for accessing the instance.
# IMPORTANT: Generate this locally first using: `ssh-keygen -t rsa -b 4096 -f ~/.ssh/sre_iac_rsa`
resource "aws_key_pair" "vm_key" {
  key_name   = "${var.project_name}-key-${var.environment}"
  public_key = file(pathexpand("~/.ssh/sre_iac_rsa.pub"))
}

# ------------------------------------------------------------------------------
# Modules
# ------------------------------------------------------------------------------

module "network" {
  source = "./modules/network"

  project_name = var.project_name
  environment  = var.environment
}

module "security" {
  source = "./modules/security"

  project_name     = var.project_name
  environment      = var.environment
  vpc_id           = module.network.vpc_id
  allowed_ssh_cidr = var.allowed_ssh_cidr
}

module "compute" {
  source = "./modules/compute"

  project_name           = var.project_name
  environment            = var.environment
  instance_type          = var.instance_type
  subnet_id              = module.network.public_subnet_id
  vpc_security_group_ids = [module.security.security_group_id]
  key_name               = aws_key_pair.vm_key.key_name
  user_data              = local.bootstrap_script
}
