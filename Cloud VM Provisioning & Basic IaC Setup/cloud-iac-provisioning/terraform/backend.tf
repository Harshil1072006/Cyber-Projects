# ------------------------------------------------------------------------------
# Terraform Backend Configuration
# ------------------------------------------------------------------------------
# By default, we use local state so this project is immediately runnable without
# needing to pre-provision an S3 bucket and DynamoDB table.
#
# FOR PRODUCTION: Uncomment the block below and replace the bucket/table names
# with your actual AWS resources. This ensures state is shared securely among 
# team members and prevents concurrent runs from corrupting the state file via 
# DynamoDB locking.
# ------------------------------------------------------------------------------

# terraform {
#   backend "s3" {
#     bucket         = "my-sre-terraform-state-bucket"
#     key            = "cloud-iac-provisioning/terraform.tfstate"
#     region         = "us-east-1"
#     encrypt        = true
#     dynamodb_table = "terraform-state-lock"
#   }
# }
