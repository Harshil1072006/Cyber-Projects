# Architecture — Cloud VM Provisioning & Basic IaC Setup

## Overview

This project provisions a hardened, monitoring-ready Ubuntu 22.04 VM on AWS using Terraform. Infrastructure is split into three reusable modules (network, security, compute) orchestrated by a root module, with a Bash bootstrap script applied via `user_data` (cloud-init) on first boot.

---

## Architecture Diagram

```
 Your Machine                    AWS
 ─────────────────────           ──────────────────────────────────────────
 terraform apply        ──────►  VPC (10.0.0.0/16)
   │                             │
   ├─ modules/network            ├── Public Subnet (10.0.1.0/24)
   │    VPC, Subnet,             │     │
   │    IGW, Route Table         │     └── EC2 Instance (t3.micro)
   │                             │           │
   ├─ modules/security           │           ├── user_data: bootstrap.sh
   │    Security Group           │           │     ├── apt-get update
   │    SSH :22 ← allowed_cidr   │           │     ├── create adminuser
   │    metrics :9100            │           │     ├── harden SSH
   │                             │           │     └── install node_exporter :9100
   └─ modules/compute            │           │
        EC2 Instance             │           └── Tags: Project/Environment/Owner/ManagedBy
        Ubuntu 22.04 LTS         │
        key_name (SSH key pair)  ├── Internet Gateway
                                 └── Route Table ──► 0.0.0.0/0

 After Apply:
   terraform output ssh_command   ──► ssh -i ~/.ssh/sre_iac_rsa adminuser@<IP>
   verify_provision.sh            ──► SSH in, check bootstrap_done + node_exporter
   Prometheus (other project)     ──► scrape http://<IP>:9100/metrics
```

---

## Module Breakdown & Design Rationale

### Why split into modules?

| Module | Responsibility | Why Separate? |
|--------|----------------|---------------|
| `network` | VPC, Subnet, IGW, Route Table | Network topology is environment-agnostic and reusable across staging/prod |
| `security` | Security Groups | Security policies evolve independently of compute; helps security team audit |
| `compute` | EC2, AMI lookup, key pair | Compute resources change most frequently (resizing, AMI updates) |

This mirrors how real infrastructure teams think: networking changes rarely, security policies change sometimes, compute changes often. The module boundary = the change boundary.

### Why a custom VPC instead of default VPC?

The default VPC in every AWS region is a shared blast radius. Any resource in it is on the same network as other experiments. A custom VPC with a single public subnet gives:
- Clear isolation per project
- Explicit control over CIDR ranges
- Clean teardown (`terraform destroy` removes everything including the VPC)

---

## Tagging Strategy (FinOps)

Every resource gets four tags:

| Tag | Value | Purpose |
|-----|-------|---------|
| `Name` | `{project}-{resource}-{env}` | Human-readable identification |
| `Project` | `sre-iac-demo` | Cost allocation — filter billing by project |
| `Environment` | `dev` / `staging` | Separate dev and staging costs in Cost Explorer |
| `ManagedBy` | `terraform` | Quickly identify Terraform-managed vs. manually-created resources |
| `Owner` | (from tfvars) | Who to contact about this resource |

This is a **FinOps best practice**: you can go to AWS Cost Explorer, filter by `Project=sre-iac-demo`, and immediately see what this project costs.

---

## State Management

| Scenario | Backend | Reason |
|----------|---------|--------|
| Local development / demo | Local (`.terraform/terraform.tfstate`) | Zero extra setup; safe for single person |
| Team collaboration | S3 + DynamoDB | Shared, encrypted state; DynamoDB prevents concurrent `apply` from corrupting state |

The S3 + DynamoDB config is in `backend.tf`, commented out. To enable:
1. Create an S3 bucket (with versioning + encryption) and DynamoDB table
2. Uncomment the `backend "s3"` block in `backend.tf`
3. Run `terraform init -migrate-state`

---

## OCI Portability

This project is structured so porting to Oracle Cloud Infrastructure (OCI) requires minimal changes:

| Component | AWS | OCI Equivalent |
|-----------|-----|----------------|
| `providers.tf` | `hashicorp/aws ~> 5.0` | `oracle/oci >= 4.0.0` |
| `modules/network/main.tf` | `aws_vpc`, `aws_subnet`, `aws_internet_gateway` | `oci_core_vcn`, `oci_core_subnet`, `oci_core_internet_gateway` |
| `modules/security/main.tf` | `aws_security_group` | `oci_core_security_list` or `oci_core_network_security_group` |
| `modules/compute/main.tf` | `aws_instance` + `data.aws_ami` | `oci_core_instance` + `oci_core_images` data source |
| `variables.tf` | `aws_region` | `oci_region` / `oci_tenancy_ocid` |

The module variable contracts (`vpc_id`, `subnet_id`, `security_group_ids`) remain the same — only the resource implementations inside each module change.
