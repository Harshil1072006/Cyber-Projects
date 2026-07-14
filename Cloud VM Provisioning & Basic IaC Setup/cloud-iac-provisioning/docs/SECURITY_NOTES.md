# Security Notes — Cloud VM Provisioning

## SSH Access: Why We Don't Default to 0.0.0.0/0

The `allowed_ssh_cidr` variable has **no secure default**. You must explicitly pass your IP address. This is intentional.

**Why open SSH to the world is dangerous:**
- Port 22 is constantly probed by automated scanners (Shodan, Masscan)
- Without key-based auth, brute-force attacks against password-protected accounts take seconds
- Even with key-based auth, open port 22 creates unnecessary exposure
- If your private key is compromised, any attacker worldwide can attempt access

**What we do instead:**
```hcl
# In the security module:
ingress {
  from_port   = 22
  to_port     = 22
  protocol    = "tcp"
  cidr_blocks = [var.allowed_ssh_cidr]  # Must be set explicitly — e.g. "203.0.113.1/32"
}
```

Get your IP at apply time: `$(curl -s ifconfig.me)/32`

---

## What You'd Use in Real Production

| Approach | How it works | Why it's better |
|----------|-------------|-----------------|
| **AWS SSM Session Manager** | Browser/CLI shell into EC2 with no open ports | Zero exposed SSH; audit trail in CloudTrail; no key management |
| **Bastion Host** | One hardened jump box with SSH; all other VMs unreachable from internet | Minimal attack surface; all SSH traffic goes through one auditable point |
| **AWS VPN (Client VPN)** | SSH over VPN; port 22 not exposed to internet | Strong authentication; corporate network access |
| **EC2 Instance Connect** | Temporary SSH public keys pushed by AWS IAM | No long-lived keys; IAM-managed access |

For this portfolio project, explicit CIDR restriction (`/32` for your single IP) is the right balance between demoability and security.

---

## IAM Least Privilege

This Terraform project only needs the following IAM permissions to run. Do not use `AdministratorAccess` for your Terraform IAM user.

Minimum required policy:
```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": [
        "ec2:*"
      ],
      "Resource": "*"
    }
  ]
}
```

In a real organisation, you would further restrict this to specific resource ARNs, specific regions, and time-bounded credentials via AWS STS assume-role.

---

## What bootstrap.sh Does for Security

1. **Disables root SSH login** — `PermitRootLogin no`
2. **Disables password authentication** — `PasswordAuthentication no`
3. **Creates a dedicated non-root user** — `adminuser` with key-based SSH
4. **Runs node_exporter as a dedicated non-root system user** — no privilege escalation from metrics endpoint
5. **Validates SSH config before restart** — `sshd -t` prevents a bad config from locking you out

---

## No Hardcoded Credentials Policy

- **No AWS credentials** in any Terraform file — authentication is via the AWS CLI credential chain (`~/.aws/credentials`, environment variables, or EC2 instance profiles)
- **No SSH private keys** in any file — only the public key is referenced in Terraform (`aws_key_pair` resource)
- **`terraform.tfvars`** is in `.gitignore` — the example file (`terraform.tfvars.example`) never contains real values
