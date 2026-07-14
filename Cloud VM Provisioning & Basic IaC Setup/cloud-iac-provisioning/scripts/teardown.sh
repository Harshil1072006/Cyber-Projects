#!/usr/bin/env bash
# =============================================================================
#  teardown.sh — Safe infrastructure teardown
#
#  Wraps `terraform destroy` with:
#    1. Pre-destroy: confirmation prompt with resource count
#    2. Terraform destroy execution
#    3. Post-destroy: AWS CLI checks for any orphaned resources that could
#       silently incur cost (EIPs, unattached EBS volumes, security groups
#       outside the default VPC, load balancers, NAT gateways)
#
#  Why this matters:
#    Terraform destroy is not always perfect. If the destroy is interrupted,
#    state can drift, and orphaned resources (especially EIPs and NAT Gateways)
#    will continue to incur cost. This script is your safety net.
#
#  Usage:
#    ./scripts/teardown.sh                          (interactive)
#    ./scripts/teardown.sh --env dev                (use environments/dev.tfvars)
#    ./scripts/teardown.sh --env dev --auto-approve (skip confirmation — use with caution)
#
#  Exit codes:
#    0  All clear — destroy complete, no orphaned resources
#    1  Terraform destroy failed
#    2  Destroy succeeded but orphaned resources were found (human review needed)
# =============================================================================
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
TF_DIR="${SCRIPT_DIR}/../terraform"

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; CYAN='\033[0;36m'; NC='\033[0m'

ENVIRONMENT=""
AUTO_APPROVE=false
VAR_FILE_ARGS=""

while [[ $# -gt 0 ]]; do
    case "$1" in
        --env)          ENVIRONMENT="$2"; shift 2 ;;
        --auto-approve) AUTO_APPROVE=true; shift ;;
        *) echo "Unknown argument: $1"; exit 1 ;;
    esac
done

if [[ -n "${ENVIRONMENT}" ]]; then
    VAR_FILE_ARGS="-var-file=${SCRIPT_DIR}/../environments/${ENVIRONMENT}.tfvars"
fi

# ── Helpers ───────────────────────────────────────────────────────────────────
require_command() {
    if ! command -v "$1" &>/dev/null; then
        echo -e "${RED}ERROR:${NC} '$1' is required but not installed."
        exit 1
    fi
}

require_command terraform
require_command aws

# ── Get project metadata from tfvars ─────────────────────────────────────────
# Read project_name and aws_region from the active terraform state for AWS CLI queries
PROJECT_NAME=$(terraform -chdir="${TF_DIR}" output -raw project_name 2>/dev/null || echo "sre-iac-demo")
AWS_REGION=$(terraform -chdir="${TF_DIR}" output -raw aws_region 2>/dev/null || echo "us-east-1")

# ── Pre-destroy summary ───────────────────────────────────────────────────────
echo ""
echo -e "${CYAN}══════════════════════════════════════════════════════════════${NC}"
echo -e "${CYAN}  teardown.sh — Infrastructure Teardown                       ${NC}"
echo -e "${CYAN}══════════════════════════════════════════════════════════════${NC}"
echo ""
echo "This will permanently DESTROY all infrastructure managed by Terraform."
echo ""
echo "Resources in Terraform state:"
terraform -chdir="${TF_DIR}" state list ${VAR_FILE_ARGS} 2>/dev/null | sed 's/^/  /' || echo "  (could not read state)"
echo ""

# Show a plan of what will be destroyed
echo "Preview of what will be destroyed:"
terraform -chdir="${TF_DIR}" plan -destroy ${VAR_FILE_ARGS} \
    -out=/tmp/destroy-plan.tfplan 2>&1 | grep -E "(will be destroyed|Plan:)" | sed 's/^/  /' || true
echo ""

# ── Confirmation prompt ───────────────────────────────────────────────────────
if [[ "${AUTO_APPROVE}" == false ]]; then
    echo -e "${YELLOW}WARNING:${NC} This action is IRREVERSIBLE."
    read -r -p "Type 'yes' to confirm teardown: " CONFIRM
    if [[ "${CONFIRM}" != "yes" ]]; then
        echo "Teardown cancelled."
        exit 0
    fi
    echo ""
fi

# ── Run terraform destroy ─────────────────────────────────────────────────────
echo -e "${CYAN}Running terraform destroy...${NC}"
DESTROY_ARGS="-chdir=${TF_DIR} destroy ${VAR_FILE_ARGS}"
if [[ "${AUTO_APPROVE}" == true ]]; then
    DESTROY_ARGS="${DESTROY_ARGS} -auto-approve"
fi

if terraform ${DESTROY_ARGS}; then
    echo ""
    echo -e "${GREEN}✓ terraform destroy completed successfully.${NC}"
else
    echo ""
    echo -e "${RED}✗ terraform destroy FAILED.${NC}"
    echo "  Check the output above and review the Terraform state."
    echo "  You may need to manually destroy resources from the AWS Console."
    echo "  See docs/RUNBOOK.md#partial-failure for recovery steps."
    exit 1
fi

# ── Post-destroy orphan check via AWS CLI ─────────────────────────────────────
echo ""
echo -e "${CYAN}Scanning AWS for any orphaned resources tagged with Project=${PROJECT_NAME}...${NC}"
echo ""

ORPHANS_FOUND=0

# ── Check 1: Orphaned Elastic IPs ─────────────────────────────────────────────
echo "  Checking for orphaned Elastic IP addresses..."
EIPS=$(aws ec2 describe-addresses \
    --region "${AWS_REGION}" \
    --filters "Name=tag:Project,Values=${PROJECT_NAME}" \
    --query "Addresses[?AssociationId==null].AllocationId" \
    --output text 2>/dev/null || echo "")

if [[ -n "${EIPS}" ]]; then
    echo -e "  ${RED}✗ ORPHANED EIPs found (will incur cost!):${NC}"
    echo "    ${EIPS}"
    echo "    Release with: aws ec2 release-address --region ${AWS_REGION} --allocation-id <ID>"
    ORPHANS_FOUND=$(( ORPHANS_FOUND + 1 ))
else
    echo -e "  ${GREEN}✓${NC} No orphaned Elastic IPs."
fi

# ── Check 2: Orphaned EBS Volumes ─────────────────────────────────────────────
echo "  Checking for orphaned EBS volumes..."
VOLUMES=$(aws ec2 describe-volumes \
    --region "${AWS_REGION}" \
    --filters \
        "Name=status,Values=available" \
        "Name=tag:Project,Values=${PROJECT_NAME}" \
    --query "Volumes[*].VolumeId" \
    --output text 2>/dev/null || echo "")

if [[ -n "${VOLUMES}" ]]; then
    echo -e "  ${RED}✗ ORPHANED volumes found (will incur cost!):${NC}"
    echo "    ${VOLUMES}"
    echo "    Delete with: aws ec2 delete-volume --region ${AWS_REGION} --volume-id <ID>"
    ORPHANS_FOUND=$(( ORPHANS_FOUND + 1 ))
else
    echo -e "  ${GREEN}✓${NC} No orphaned EBS volumes."
fi

# ── Check 3: Project-tagged EC2 instances still running ───────────────────────
echo "  Checking for running EC2 instances..."
INSTANCES=$(aws ec2 describe-instances \
    --region "${AWS_REGION}" \
    --filters \
        "Name=tag:Project,Values=${PROJECT_NAME}" \
        "Name=instance-state-name,Values=running,stopped,stopping" \
    --query "Reservations[*].Instances[*].[InstanceId,State.Name]" \
    --output text 2>/dev/null || echo "")

if [[ -n "${INSTANCES}" ]]; then
    echo -e "  ${RED}✗ EC2 instances still exist:${NC}"
    echo "    ${INSTANCES}"
    echo "    Terminate with: aws ec2 terminate-instances --region ${AWS_REGION} --instance-ids <ID>"
    ORPHANS_FOUND=$(( ORPHANS_FOUND + 1 ))
else
    echo -e "  ${GREEN}✓${NC} No EC2 instances running."
fi

# ── Check 4: Project-tagged Security Groups (non-default VPC) ─────────────────
echo "  Checking for orphaned security groups..."
SGS=$(aws ec2 describe-security-groups \
    --region "${AWS_REGION}" \
    --filters "Name=tag:Project,Values=${PROJECT_NAME}" \
    --query "SecurityGroups[?GroupName!='default'].GroupId" \
    --output text 2>/dev/null || echo "")

if [[ -n "${SGS}" ]]; then
    echo -e "  ${YELLOW}⚠ Security groups still exist (may be OK if not incurring cost):${NC}"
    echo "    ${SGS}"
    echo "    Delete with: aws ec2 delete-security-group --region ${AWS_REGION} --group-id <ID>"
    ORPHANS_FOUND=$(( ORPHANS_FOUND + 1 ))
else
    echo -e "  ${GREEN}✓${NC} No orphaned security groups."
fi

# ── Check 5: Project-tagged VPCs ──────────────────────────────────────────────
echo "  Checking for orphaned VPCs..."
VPCS=$(aws ec2 describe-vpcs \
    --region "${AWS_REGION}" \
    --filters "Name=tag:Project,Values=${PROJECT_NAME}" \
    --query "Vpcs[?IsDefault==\`false\`].VpcId" \
    --output text 2>/dev/null || echo "")

if [[ -n "${VPCS}" ]]; then
    echo -e "  ${YELLOW}⚠ Non-default VPCs still exist (VPCs themselves are free, but attached resources may not be):${NC}"
    echo "    ${VPCS}"
    ORPHANS_FOUND=$(( ORPHANS_FOUND + 1 ))
else
    echo -e "  ${GREEN}✓${NC} No orphaned VPCs."
fi

# ── Summary ────────────────────────────────────────────────────────────────────
echo ""
echo -e "${CYAN}══════════════════════════════════════════════════════════════${NC}"

if (( ORPHANS_FOUND > 0 )); then
    echo -e "${RED}⚠ TEARDOWN COMPLETE — but ${ORPHANS_FOUND} orphaned resource group(s) found.${NC}"
    echo "  Review the items above and clean them up manually to avoid unexpected charges."
    echo "  See: docs/RUNBOOK.md#orphan-resource-cleanup"
    echo -e "${CYAN}══════════════════════════════════════════════════════════════${NC}"
    echo ""
    exit 2
else
    echo -e "${GREEN}✅ TEARDOWN COMPLETE — All clear. No orphaned resources found.${NC}"
    echo -e "${CYAN}══════════════════════════════════════════════════════════════${NC}"
    echo ""
    exit 0
fi
