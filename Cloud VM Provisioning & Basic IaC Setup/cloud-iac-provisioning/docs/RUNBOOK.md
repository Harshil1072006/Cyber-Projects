# SRE Runbook — Cloud VM Provisioning (Terraform)

> **Audience:** On-call SRE / Infrastructure Engineer  
> This runbook covers fresh provisioning, handling failures, and safe teardown.

---

## Runbook 1: Fresh Provision Walkthrough

### Prerequisites

1. AWS CLI configured: `aws sts get-caller-identity` must return your account
2. SSH key generated: `ssh-keygen -t rsa -b 4096 -f ~/.ssh/sre_iac_rsa`
3. Terraform 1.5+ installed: `terraform version`
4. Your current public IP: `curl -s ifconfig.me`

### Steps

```bash
# 1. Navigate to the project
cd "c:/Cyber Project/Cloud VM Provisioning & Basic IaC Setup/cloud-iac-provisioning"

# 2. Review the plan (includes cost check)
./scripts/plan_and_show_cost.sh --env dev

# 3. Apply (replace with your actual IP)
terraform -chdir=terraform apply \
  -var-file=environments/dev.tfvars \
  -var="allowed_ssh_cidr=$(curl -s ifconfig.me)/32"

# 4. Copy the SSH command from the output
terraform -chdir=terraform output ssh_command

# 5. Wait ~2-3 minutes for cloud-init to finish, then verify
./scripts/verify_provision.sh
```

Expected successful output from `verify_provision.sh`:
```
  ✓ PASS  Bootstrap marker exists
  ✓ PASS  Admin user 'adminuser' exists
  ✓ PASS  node_exporter systemd service is active
  ✓ PASS  node_exporter HTTP on :9100 responding (18 metric families)
  ✓ PASS  SSH root login is disabled
  ✓ PASS  SSH password authentication is disabled
  ✓ PASS  System is up to date

VERIFICATION PASSED. The instance is healthy and monitoring-ready.
```

---

## Runbook 2: Handling a Partially-Failed Apply

### Scenario: terraform apply fails halfway through

Terraform is designed to be safe on partial failures. The state file records what was successfully created, so re-running `apply` is safe and will only attempt to create the missing resources.

```bash
# Simply re-run apply — Terraform will pick up from where it left off
terraform -chdir=terraform apply -var-file=environments/dev.tfvars ...
```

### Scenario: State drift (resource exists in AWS but not in Terraform state)

If someone manually created or deleted a resource outside of Terraform:

```bash
# See what Terraform thinks the state is
terraform -chdir=terraform state list

# Import an existing resource into Terraform state
# Example: import an existing security group
terraform -chdir=terraform import module.security.aws_security_group.vm_sg sg-0123456789abcdef0

# OR: mark a resource as tainted to force recreation on next apply
terraform -chdir=terraform taint module.compute.aws_instance.vm

# Then apply to reconcile
terraform -chdir=terraform apply -var-file=environments/dev.tfvars ...
```

### Scenario: Tainted resource (broken instance)

```bash
# Force the instance to be destroyed and recreated on next apply
terraform -chdir=terraform taint module.compute.aws_instance.vm
terraform -chdir=terraform apply -var-file=environments/dev.tfvars ...
```

---

## Runbook 3: Safe Re-Run of Apply

Terraform is idempotent — re-running `apply` on an unchanged configuration produces no changes. It is always safe to run:

```bash
terraform -chdir=terraform plan -var-file=environments/dev.tfvars ...
```

This will tell you exactly what *would* change before you commit. Only apply if the plan shows the expected delta.

---

## Runbook 4: Full Teardown

```bash
# Option A: Interactive (recommended)
./scripts/teardown.sh --env dev

# Option B: Non-interactive (CI/CD)
./scripts/teardown.sh --env dev --auto-approve
```

After teardown, the script will scan AWS for orphaned resources. If it exits with code `2`, orphans were found. Clean them up manually:

### Manual cleanup if teardown fails

```bash
# List all resources tagged with the project
aws resourcegroupstaggingapi get-resources \
  --tag-filters "Key=Project,Values=sre-iac-demo" \
  --region us-east-1

# Force-terminate any leftover instances
aws ec2 terminate-instances --instance-ids <INSTANCE_ID> --region us-east-1

# Delete any orphaned security groups
aws ec2 delete-security-group --group-id <SG_ID> --region us-east-1

# Release any orphaned EIPs (these cost money when unattached!)
aws ec2 release-address --allocation-id <EIP_ID> --region us-east-1
```

### Final AWS Console verification

1. Go to AWS Console → EC2 → Instances → Filter by tag `Project=sre-iac-demo` — should be empty
2. Go to EC2 → Security Groups → Filter same — should be empty (except default SG)
3. Go to EC2 → Elastic IPs — should show no allocated IPs for this project
4. Go to VPC → Your VPCs — the project VPC should be gone

---

## Orphan Resource Cleanup Reference

| Resource | Cost if left running | Cleanup command |
|----------|---------------------|-----------------|
| EC2 t3.micro | Free up to 750hrs/mo, then ~$0.0104/hr | `aws ec2 terminate-instances` |
| EBS gp3 volume | Free up to 30GB/mo, then $0.08/GB/mo | `aws ec2 delete-volume` |
| Elastic IP (unattached) | ~$0.005/hr | `aws ec2 release-address` |
| NAT Gateway | ~$0.045/hr + data | `aws ec2 delete-nat-gateway` |
| VPC | Free | `aws ec2 delete-vpc` |
| Security Group | Free | `aws ec2 delete-security-group` |
