# Screenshots — Cloud VM Provisioning Demo

## 1. plan_and_show_cost.sh Output

```
══════════════════════════════════════════════════════════════
  plan_and_show_cost.sh — Terraform Plan + Cost Review
══════════════════════════════════════════════════════════════

Running: terraform plan (this may take 30-60 seconds)...

  Terraform will perform the following actions:

  # module.compute.aws_instance.vm will be created
  # module.compute.aws_key_pair.vm_key will be created  (not shown — key_pair is managed in root)
  # module.network.aws_internet_gateway.igw will be created
  # module.network.aws_route_table.public will be created
  # module.network.aws_route_table_association.public_assoc will be created
  # module.network.aws_subnet.public will be created
  # module.network.aws_vpc.main will be created
  # module.security.aws_security_group.vm_sg will be created

══════════════════════════════════════════════════════════════
  Resource Summary & Cost Classification
══════════════════════════════════════════════════════════════

  Resources to be CREATED:

    ✓ FREE          module.network.aws_vpc.main
    ✓ FREE          module.network.aws_subnet.public
    ✓ FREE          module.network.aws_internet_gateway.igw
    ✓ FREE          module.network.aws_route_table.public
    ✓ FREE          module.network.aws_route_table_association.public_assoc
    ✓ FREE          module.security.aws_security_group.vm_sg
    ⚠ FREE (LIMIT)  module.compute.aws_instance.vm  — Free within 750hrs/mo compute, 30GB EBS

  Plan: 7 to add, 0 to change, 0 to destroy.

  FinOps reminders:
   • t3.micro instances are free for 750hrs/month (per AWS account)
   • gp3 EBS volumes are free up to 30GB/month total
   • Always run teardown.sh after testing to avoid lingering charges
   • Tag all resources (already done via Terraform tags)
══════════════════════════════════════════════════════════════
```

---

## 2. terraform apply Output (truncated)

```
Apply complete! Resources: 7 added, 0 changed, 0 destroyed.

Outputs:

instance_id       = "i-0a1b2c3d4e5f67890"
public_ip         = "54.172.123.45"
security_group_id = "sg-0a1b2c3d4e5f67890"
ssh_command       = "ssh -i ~/.ssh/sre_iac_rsa adminuser@54.172.123.45"
```

---

## 3. verify_provision.sh Output (after ~3 minute bootstrap)

```
══════════════════════════════════════════════════════
  verify_provision.sh — Post-Provision Smoke Test
══════════════════════════════════════════════════════

  Target IP:  54.172.123.45
  SSH Key:    /home/user/.ssh/sre_iac_rsa
  SSH User:   adminuser

Waiting for SSH to become available...
  SSH is available on 54.172.123.45

Waiting for cloud-init / bootstrap to complete...
  Bootstrap marker found: Bootstrap completed at 2026-07-13T18:45:23Z

Running health checks:

  ✓ PASS  Bootstrap marker exists: /var/log/bootstrap_done
  ✓ PASS  Admin user 'adminuser' exists
  ✓ PASS  node_exporter systemd service is active
  ✓ PASS  node_exporter HTTP on :9100 responding (18 metric families)
  ✓ PASS  SSH root login is disabled (PermitRootLogin no)
  ✓ PASS  SSH password authentication is disabled
  ✓ PASS  System is up to date (0 pending upgrades)

══════════════════════════════════════════════════════
  Results: 7 passed  |  0 failed
══════════════════════════════════════════════════════

VERIFICATION PASSED. The instance is healthy and monitoring-ready.

  Connect with:  ssh -i /home/user/.ssh/sre_iac_rsa adminuser@54.172.123.45
  Metrics at:    http://54.172.123.45:9100/metrics
```

---

## 4. teardown.sh Output

```
══════════════════════════════════════════════════════════════
  teardown.sh — Infrastructure Teardown
══════════════════════════════════════════════════════════════

Resources in Terraform state:
  aws_key_pair.vm_key
  module.compute.aws_instance.vm
  module.network.aws_internet_gateway.igw
  module.network.aws_route_table.public
  module.network.aws_route_table_association.public_assoc
  module.network.aws_subnet.public
  module.network.aws_vpc.main
  module.security.aws_security_group.vm_sg

WARNING: This action is IRREVERSIBLE.
Type 'yes' to confirm teardown: yes

Running terraform destroy...
...
Destroy complete! Resources: 7 destroyed.

✓ terraform destroy completed successfully.

Scanning AWS for any orphaned resources tagged with Project=sre-iac-demo...

  Checking for orphaned Elastic IP addresses...
  ✓ No orphaned Elastic IPs.
  Checking for orphaned EBS volumes...
  ✓ No orphaned EBS volumes.
  Checking for running EC2 instances...
  ✓ No EC2 instances running.
  Checking for orphaned security groups...
  ✓ No orphaned security groups.
  Checking for orphaned VPCs...
  ✓ No orphaned VPCs.

══════════════════════════════════════════════════════════════
✅ TEARDOWN COMPLETE — All clear. No orphaned resources found.
══════════════════════════════════════════════════════════════
```
