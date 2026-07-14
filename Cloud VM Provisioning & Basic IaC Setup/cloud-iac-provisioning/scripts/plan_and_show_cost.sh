#!/usr/bin/env bash
# =============================================================================
#  plan_and_show_cost.sh — Cost-aware terraform plan
#
#  Runs `terraform plan`, then:
#    1. Extracts the list of resources that will be created/modified/destroyed
#    2. Flags any resources that are NOT free-tier eligible with a warning
#    3. Reminds the user to tear down promptly to avoid unexpected charges
#    4. Optionally integrates with infracost (if installed) for a full cost estimate
#
#  Usage:
#    ./scripts/plan_and_show_cost.sh                   (uses default variables)
#    ./scripts/plan_and_show_cost.sh --env dev          (uses environments/dev.tfvars)
#    ./scripts/plan_and_show_cost.sh --env staging --save (saves the plan as a file)
#
#  Exit codes:
#    0  Plan complete — review resources and costs
#    1  terraform plan failed
# =============================================================================
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
TF_DIR="${SCRIPT_DIR}/../terraform"

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; CYAN='\033[0;36m'; NC='\033[0m'

ENVIRONMENT=""
SAVE_PLAN=false
PLAN_FILE="/tmp/terraform-plan-$(date +%Y%m%d%H%M%S).tfplan"

while [[ $# -gt 0 ]]; do
    case "$1" in
        --env)   ENVIRONMENT="$2"; shift 2 ;;
        --save)  SAVE_PLAN=true;   shift   ;;
        *) echo "Unknown argument: $1"; exit 1 ;;
    esac
done

VAR_FILE_ARGS=""
if [[ -n "${ENVIRONMENT}" ]]; then
    VAR_FILE_ARGS="-var-file=${SCRIPT_DIR}/../environments/${ENVIRONMENT}.tfvars"
fi

# ── AWS Free Tier resource list ───────────────────────────────────────────────
# Resources that are ALWAYS free (no capacity limits)
FREE_ALWAYS=(
    "aws_vpc"
    "aws_subnet"
    "aws_internet_gateway"
    "aws_route_table"
    "aws_route_table_association"
    "aws_security_group"
    "aws_key_pair"
)

# Resources that are free within limits (e.g., 750 hours/month of t2.micro, 30GB EBS)
FREE_WITH_LIMITS=(
    "aws_instance"        # Free: 750 hours/month of t2.micro or t3.micro
    "aws_ebs_volume"      # Free: 30GB total EBS storage
)

# Resources that are NEVER free or have very limited free usage
NOT_FREE=(
    "aws_nat_gateway"       # NOT FREE: ~$32/month + data transfer
    "aws_lb"                # NOT FREE: ~$16/month minimum
    "aws_db_instance"       # NOT FREE for most configurations
    "aws_elasticache_cluster" # NOT FREE
    "aws_eip"               # Free if attached; $0.005/hour if unattached
    "aws_route53_record"    # NOT FREE: $0.50/hosted zone/month
)

# ── Header ────────────────────────────────────────────────────────────────────
echo ""
echo -e "${CYAN}══════════════════════════════════════════════════════════════${NC}"
echo -e "${CYAN}  plan_and_show_cost.sh — Terraform Plan + Cost Review        ${NC}"
echo -e "${CYAN}══════════════════════════════════════════════════════════════${NC}"
echo ""

# ── Run terraform plan ────────────────────────────────────────────────────────
echo -e "Running: ${CYAN}terraform plan${NC} (this may take 30-60 seconds)..."
echo ""

PLAN_SAVE_ARG=""
if [[ "${SAVE_PLAN}" == true ]]; then
    PLAN_SAVE_ARG="-out=${PLAN_FILE}"
fi

if ! terraform -chdir="${TF_DIR}" plan \
    ${VAR_FILE_ARGS} \
    ${PLAN_SAVE_ARG} \
    -no-color 2>&1 | tee /tmp/tf-plan-output.txt; then
    echo -e "${RED}ERROR:${NC} terraform plan failed. See output above."
    exit 1
fi

echo ""
echo -e "${CYAN}══════════════════════════════════════════════════════════════${NC}"
echo -e "${CYAN}  Resource Summary & Cost Classification                       ${NC}"
echo -e "${CYAN}══════════════════════════════════════════════════════════════${NC}"
echo ""

# ── Parse planned resources ───────────────────────────────────────────────────
CREATED_RESOURCES=$(grep -E '^\s+# .+ will be created' /tmp/tf-plan-output.txt | sed 's/.*# //;s/ will be created//' || true)

if [[ -z "${CREATED_RESOURCES}" ]]; then
    echo "  No resources will be created (plan shows no changes or only modifications)."
else
    echo "  Resources to be CREATED:"
    echo ""

    NOT_FREE_FOUND=0
    while IFS= read -r resource; do
        RESOURCE_TYPE=$(echo "${resource}" | cut -d'.' -f1)

        # Classify the resource
        COST_CLASS="UNKNOWN"
        for r in "${FREE_ALWAYS[@]}"; do
            [[ "${RESOURCE_TYPE}" == "${r}" ]] && COST_CLASS="FREE_ALWAYS" && break
        done
        for r in "${FREE_WITH_LIMITS[@]}"; do
            [[ "${RESOURCE_TYPE}" == "${r}" ]] && COST_CLASS="FREE_LIMIT" && break
        done
        for r in "${NOT_FREE[@]}"; do
            [[ "${RESOURCE_TYPE}" == "${r}" ]] && COST_CLASS="NOT_FREE" && break
        done

        case "${COST_CLASS}" in
            "FREE_ALWAYS")
                echo -e "    ${GREEN}✓ FREE${NC}          ${resource}"
                ;;
            "FREE_LIMIT")
                echo -e "    ${YELLOW}⚠ FREE (LIMIT)${NC}  ${resource}  — Free within 750hrs/mo compute, 30GB EBS"
                ;;
            "NOT_FREE")
                echo -e "    ${RED}✗ NOT FREE${NC}      ${resource}  ← REVIEW THIS!"
                NOT_FREE_FOUND=$(( NOT_FREE_FOUND + 1 ))
                ;;
            *)
                echo -e "    ${YELLOW}? UNKNOWN${NC}       ${resource}  — Verify pricing manually"
                ;;
        esac
    done <<< "${CREATED_RESOURCES}"
    echo ""

    # ── Cost warnings ─────────────────────────────────────────────────────────
    if (( NOT_FREE_FOUND > 0 )); then
        echo -e "${RED}══ ⚠ COST WARNING ══${NC}"
        echo -e "${RED}  ${NOT_FREE_FOUND} resource(s) are NOT free-tier eligible.${NC}"
        echo "  Review the items marked 'NOT FREE' above before running terraform apply."
        echo ""
    fi
fi

# ── Summary box ───────────────────────────────────────────────────────────────
PLAN_SUMMARY=$(grep -E '^Plan:' /tmp/tf-plan-output.txt || echo "Plan: (see output above)")
echo ""
echo "  ${PLAN_SUMMARY}"
echo ""
echo -e "${YELLOW}  FinOps reminders:${NC}"
echo "   • t3.micro instances are free for 750hrs/month (per AWS account)"
echo "   • gp3 EBS volumes are free up to 30GB/month total"
echo "   • Always run teardown.sh after testing to avoid lingering charges"
echo "   • Tag all resources (already done via Terraform tags)"
echo ""

if [[ "${SAVE_PLAN}" == true ]]; then
    echo -e "  Plan saved to: ${CYAN}${PLAN_FILE}${NC}"
    echo "  Apply with: terraform -chdir=terraform apply '${PLAN_FILE}'"
    echo ""
fi

# ── Infracost integration (optional) ─────────────────────────────────────────
if command -v infracost &>/dev/null && [[ "${SAVE_PLAN}" == true ]]; then
    echo -e "${CYAN}infracost detected — running cost estimate...${NC}"
    infracost breakdown --path="${PLAN_FILE}" --format=table 2>/dev/null || echo "  (infracost analysis skipped — needs API key or config)"
    echo ""
fi

echo -e "${CYAN}══════════════════════════════════════════════════════════════${NC}"
echo ""
