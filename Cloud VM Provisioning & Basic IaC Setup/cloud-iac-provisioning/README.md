# 🏗️ Cloud VM Provisioning & Basic IaC Setup

> Terraform-based Infrastructure as Code that provisions a hardened, monitoring-ready Ubuntu 22.04 VM on AWS in under 5 minutes — reproducibly, securely, and for free within the AWS Free Tier.

---

## ⚡ Free Tier Safe

> [!IMPORTANT]
> This project is designed to stay within the **AWS Free Tier** when torn down promptly:
> - **EC2:** `t3.micro` — Free for 750 hours/month per account
> - **EBS:** 8GB `gp3` root volume — Free up to 30GB/month total
> - **VPC, Subnets, Security Groups, IGW:** Always free
> - **NAT Gateways, EIPs, ALBs:** NOT used — those are not free
>
> ⚠️ Always run `./scripts/teardown.sh` after testing to avoid charges.

---

## Architecture

```
 terraform apply
       │
       ├── modules/network   ──► VPC + Public Subnet + IGW + Route Table
       ├── modules/security  ──► Security Group (SSH: /32 CIDR only)
       └── modules/compute   ──► EC2 t3.micro, Ubuntu 22.04 LTS
                                       │
                                       └── user_data: bootstrap.sh
                                               ├── System update
                                               ├── Create adminuser (no root SSH)
                                               ├── Harden SSH config
                                               └── Install node_exporter :9100
                                                        │
                                                        └──► Prometheus (monitoring project)
                                                             can scrape immediately
```

---

## Project Structure

```
cloud-iac-provisioning/
├── terraform/
│   ├── main.tf               # Root module — wires network/security/compute
│   ├── variables.tf          # All input variables
│   ├── outputs.tf            # Public IP, instance ID, SSH command
│   ├── providers.tf          # AWS provider, version pinned to ~> 5.0
│   ├── backend.tf            # Local state (S3+DynamoDB documented, commented)
│   ├── terraform.tfvars.example
│   └── modules/
│       ├── network/          # VPC, Subnet, IGW, Route Table
│       ├── security/         # Security Group (SSH CIDR-restricted)
│       └── compute/          # EC2, AMI lookup, key pair
├── scripts/
│   ├── bootstrap.sh          # cloud-init: update, user, SSH hardening, node_exporter
│   ├── verify_provision.sh   # SSH-based smoke test (7 health checks)
│   ├── teardown.sh           # terraform destroy + orphan resource scan
│   └── plan_and_show_cost.sh # terraform plan with cost classification
├── environments/
│   ├── dev.tfvars
│   └── staging.tfvars
└── docs/
    ├── ARCHITECTURE.md       # Module design, tagging, state mgmt, OCI portability
    ├── RUNBOOK.md            # SRE guide: provision, fix partial failures, teardown
    ├── SECURITY_NOTES.md     # SSH CIDR policy, IAM least privilege, alternatives
    └── SCREENSHOTS.md        # Expected CLI output for all four scripts
```

---

## Quickstart

### Prerequisites

```bash
# 1. Install Terraform 1.5+
# https://developer.hashicorp.com/terraform/install

# 2. Configure AWS CLI
aws configure   # or set AWS_ACCESS_KEY_ID / AWS_SECRET_ACCESS_KEY env vars

# 3. Generate SSH key pair
ssh-keygen -t rsa -b 4096 -f ~/.ssh/sre_iac_rsa
```

### Provision

```bash
cd "cloud-iac-provisioning"

# Preview cost and resources first
./scripts/plan_and_show_cost.sh --env dev

# Apply — replace with your actual public IP
terraform -chdir=terraform apply \
  -var-file=environments/dev.tfvars \
  -var="allowed_ssh_cidr=$(curl -s ifconfig.me)/32"

# Wait ~3 minutes for cloud-init, then verify
./scripts/verify_provision.sh

# SSH in (command is in terraform output)
terraform -chdir=terraform output ssh_command
```

### Teardown (always do this after testing!)

```bash
./scripts/teardown.sh --env dev
```

---

## Adding a New Environment

1. Create `environments/production.tfvars`:
   ```hcl
   environment      = "production"
   project_name     = "sre-iac-demo"
   aws_region       = "us-east-1"
   instance_type    = "t3.micro"
   allowed_ssh_cidr = "YOUR_IP/32"
   ```

2. Create a new Terraform workspace (optional, for state isolation):
   ```bash
   terraform -chdir=terraform workspace new production
   ```

3. Apply:
   ```bash
   terraform -chdir=terraform apply -var-file=environments/production.tfvars
   ```

---

## OCI Portability

This project is structured for easy porting to Oracle Cloud Infrastructure (OCI). Changes required:

| File | AWS | OCI |
|------|-----|-----|
| `providers.tf` | `hashicorp/aws ~> 5.0` | `oracle/oci >= 4.0.0` |
| `network/main.tf` | `aws_vpc`, `aws_subnet`, `aws_internet_gateway` | `oci_core_vcn`, `oci_core_subnet`, `oci_core_internet_gateway` |
| `security/main.tf` | `aws_security_group` | `oci_core_network_security_group` |
| `compute/main.tf` | `aws_instance` + `data.aws_ami` | `oci_core_instance` + `oci_core_images` |

The module variable interface (`vpc_id`, `subnet_id`, `security_group_ids`) stays the same. Only the resource implementations inside each module change — this is the whole point of the module abstraction.

---

## Resource Tagging (FinOps)

Every resource provisioned by this project is tagged:

| Tag | Value | Purpose |
|-----|-------|---------|
| `Name` | `sre-iac-demo-vpc-dev` | Human identification |
| `Project` | `sre-iac-demo` | Filter in AWS Cost Explorer |
| `Environment` | `dev` / `staging` | Separate environment costs |
| `ManagedBy` | `terraform` | Distinguishes IaC vs. ClickOps resources |

Use AWS Cost Explorer → Filter by `Project=sre-iac-demo` to see exact cost attribution.

---

## Design Decisions

### Why Terraform over ClickOps or raw AWS CLI scripts?

| Approach | Problem |
|----------|---------|
| AWS Console (ClickOps) | Manual, error-prone, not reproducible, hard to peer-review |
| `aws ec2 run-instances` scripts | No state tracking, no drift detection, no dependency graph |
| **Terraform** | Declarative, stateful, diff-aware, idempotent, version-controlled |

Terraform's state file means if your VPC already exists, `apply` won't try to create a second one. That's the critical difference from scripting.

### Why modular structure?

- **Change boundaries match module boundaries**: networking rarely changes; compute changes often
- **Testability**: each module can be tested independently
- **Reuse**: the `network` module can be used by a database stack unchanged
- **Readability**: a reviewer can audit `modules/security` in isolation for the security group rules

### Why local state by default?

Remote state (S3 + DynamoDB) requires creating those AWS resources before you can run Terraform. For a single-developer demo/portfolio project, local state removes that chicken-and-egg problem. The production path (remote state + locking) is fully documented in `backend.tf` and `ARCHITECTURE.md` — one uncomment + `terraform init -migrate-state` away.

### Why modular bootstrap.sh instead of Ansible or Chef?

For a single VM provisioned by Terraform, `user_data` (cloud-init) requires zero additional tooling or network access to a configuration management server. It runs before the VM is even reachable over SSH. For a fleet of VMs that need ongoing configuration management, Ansible would be the right next step — and the `verify_provision.sh` smoke test gives you a hook point to wire that in.
