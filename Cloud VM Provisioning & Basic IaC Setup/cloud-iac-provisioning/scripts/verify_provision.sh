#!/usr/bin/env bash
# =============================================================================
#  verify_provision.sh — Post-apply smoke test
#
#  Reads the Terraform outputs (public_ip, ssh_command) and performs SSH-based
#  verification of the provisioned instance:
#    1. Checks that the bootstrap marker file exists
#    2. Confirms node_exporter is running and responding on :9100
#    3. Confirms SSH hardening was applied (root login disabled)
#    4. Reports overall health
#
#  Usage:
#    ./scripts/verify_provision.sh                   (reads terraform output)
#    ./scripts/verify_provision.sh --ip 1.2.3.4      (explicit IP override)
#    ./scripts/verify_provision.sh --ssh-key ~/.ssh/my_key.pem
#
#  Exit codes:
#    0  All checks passed
#    1  One or more checks failed
# =============================================================================
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
TF_DIR="${SCRIPT_DIR}/../terraform"

ADMIN_USER="adminuser"
SSH_KEY="${HOME}/.ssh/sre_iac_rsa"
BOOTSTRAP_MARKER="/var/log/bootstrap_done"
NODE_EXPORTER_PORT="9100"
SSH_TIMEOUT=10
MAX_WAIT_SECONDS=180  # 3 minutes max wait for bootstrap to complete

# ── Colour output ─────────────────────────────────────────────────────────────
RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; CYAN='\033[0;36m'; NC='\033[0m'
PASS="${GREEN}✓ PASS${NC}"; FAIL="${RED}✗ FAIL${NC}"; SKIP="${YELLOW}⦿ SKIP${NC}"

CHECKS_PASSED=0; CHECKS_FAILED=0

# ── Argument parsing ──────────────────────────────────────────────────────────
PUBLIC_IP=""
while [[ $# -gt 0 ]]; do
    case "$1" in
        --ip)        PUBLIC_IP="$2";  shift 2 ;;
        --ssh-key)   SSH_KEY="$2";   shift 2 ;;
        --user)      ADMIN_USER="$2"; shift 2 ;;
        *) echo "Unknown argument: $1"; exit 1 ;;
    esac
done

log_check() {
    local status="$1"; local msg="$2"
    if [[ "$status" == "pass" ]]; then
        echo -e "  ${PASS}  ${msg}"; (( CHECKS_PASSED++ ))
    elif [[ "$status" == "fail" ]]; then
        echo -e "  ${FAIL}  ${msg}"; (( CHECKS_FAILED++ ))
    else
        echo -e "  ${SKIP}  ${msg}"
    fi
}

# ── Step 1: Get the public IP from Terraform outputs ─────────────────────────
echo ""
echo -e "${CYAN}══════════════════════════════════════════════════════${NC}"
echo -e "${CYAN}  verify_provision.sh — Post-Provision Smoke Test     ${NC}"
echo -e "${CYAN}══════════════════════════════════════════════════════${NC}"
echo ""

if [[ -z "${PUBLIC_IP}" ]]; then
    echo "Resolving public IP from Terraform outputs..."
    if ! command -v terraform &>/dev/null; then
        echo -e "${RED}ERROR:${NC} terraform not found in PATH. Install Terraform or pass --ip."
        exit 1
    fi
    PUBLIC_IP=$(terraform -chdir="${TF_DIR}" output -raw public_ip 2>/dev/null)
    if [[ -z "${PUBLIC_IP}" ]]; then
        echo -e "${RED}ERROR:${NC} Could not read public_ip from Terraform outputs."
        echo "Make sure you have run 'terraform apply' successfully first."
        exit 1
    fi
fi

echo -e "  Target IP:  ${CYAN}${PUBLIC_IP}${NC}"
echo -e "  SSH Key:    ${CYAN}${SSH_KEY}${NC}"
echo -e "  SSH User:   ${CYAN}${ADMIN_USER}${NC}"
echo ""

# ── Verify SSH key exists ─────────────────────────────────────────────────────
if [[ ! -f "${SSH_KEY}" ]]; then
    echo -e "${RED}ERROR:${NC} SSH key not found at ${SSH_KEY}"
    echo "Generate it with: ssh-keygen -t rsa -b 4096 -f ~/.ssh/sre_iac_rsa"
    exit 1
fi

# ── Helper: run a command on the remote host ──────────────────────────────────
remote() {
    ssh \
        -i "${SSH_KEY}" \
        -o StrictHostKeyChecking=no \
        -o BatchMode=yes \
        -o ConnectTimeout="${SSH_TIMEOUT}" \
        "${ADMIN_USER}@${PUBLIC_IP}" \
        "$@" 2>/dev/null
}

# ── Step 2: Wait for SSH to become available ──────────────────────────────────
echo "Waiting for SSH to become available..."
start_time=$(date +%s)
while true; do
    if remote "echo ok" &>/dev/null; then
        echo -e "  SSH is available on ${PUBLIC_IP}"
        break
    fi
    elapsed=$(( $(date +%s) - start_time ))
    if (( elapsed > MAX_WAIT_SECONDS )); then
        echo -e "${RED}ERROR:${NC} SSH timed out after ${MAX_WAIT_SECONDS}s. Instance may still be booting."
        exit 1
    fi
    echo "  Still waiting... (${elapsed}s elapsed)"
    sleep 10
done
echo ""

# ── Step 3: Wait for bootstrap to complete ────────────────────────────────────
echo "Waiting for cloud-init / bootstrap to complete..."
start_time=$(date +%s)
while true; do
    if remote "test -f ${BOOTSTRAP_MARKER}" &>/dev/null; then
        MARKER_CONTENT=$(remote "cat ${BOOTSTRAP_MARKER}" 2>/dev/null || echo "unknown")
        echo -e "  Bootstrap marker found: ${MARKER_CONTENT}"
        break
    fi
    elapsed=$(( $(date +%s) - start_time ))
    if (( elapsed > MAX_WAIT_SECONDS )); then
        log_check "fail" "Bootstrap marker not found at ${BOOTSTRAP_MARKER} after ${MAX_WAIT_SECONDS}s"
        break
    fi
    echo "  Bootstrap still running... (${elapsed}s elapsed)"
    sleep 15
done
echo ""

# ── Step 4: Run checks ────────────────────────────────────────────────────────
echo "Running health checks:"
echo ""

# Check 1: Bootstrap marker file exists
if remote "test -f ${BOOTSTRAP_MARKER}"; then
    log_check "pass" "Bootstrap marker exists: ${BOOTSTRAP_MARKER}"
else
    log_check "fail" "Bootstrap marker NOT found — bootstrap may have failed. Check: sudo cat /var/log/bootstrap.log"
fi

# Check 2: Admin user exists
if remote "id ${ADMIN_USER}" &>/dev/null; then
    log_check "pass" "Admin user '${ADMIN_USER}' exists"
else
    log_check "fail" "Admin user '${ADMIN_USER}' NOT found"
fi

# Check 3: node_exporter systemd service is running
NODE_EXPORTER_STATUS=$(remote "systemctl is-active node_exporter 2>/dev/null || echo 'inactive'")
if [[ "${NODE_EXPORTER_STATUS}" == "active" ]]; then
    log_check "pass" "node_exporter systemd service is active"
else
    log_check "fail" "node_exporter service status: ${NODE_EXPORTER_STATUS}"
fi

# Check 4: node_exporter HTTP endpoint is responding
if remote "curl -sf http://localhost:${NODE_EXPORTER_PORT}/metrics > /dev/null 2>&1"; then
    # Get a count of metric families for a meaningful health indicator
    METRIC_COUNT=$(remote "curl -sf http://localhost:${NODE_EXPORTER_PORT}/metrics 2>/dev/null | grep -c '^# HELP' || echo 0")
    log_check "pass" "node_exporter HTTP on :${NODE_EXPORTER_PORT} responding (${METRIC_COUNT} metric families)"
else
    log_check "fail" "node_exporter NOT responding on :${NODE_EXPORTER_PORT}"
fi

# Check 5: SSH root login is disabled
ROOT_LOGIN=$(remote "sudo grep -E '^PermitRootLogin' /etc/ssh/sshd_config 2>/dev/null || echo 'not_found'")
if [[ "${ROOT_LOGIN}" == *"no"* ]]; then
    log_check "pass" "SSH root login is disabled (PermitRootLogin no)"
else
    log_check "fail" "SSH root login may NOT be disabled — found: '${ROOT_LOGIN}'"
fi

# Check 6: SSH password auth is disabled
PASS_AUTH=$(remote "sudo grep -E '^PasswordAuthentication' /etc/ssh/sshd_config 2>/dev/null || echo 'not_found'")
if [[ "${PASS_AUTH}" == *"no"* ]]; then
    log_check "pass" "SSH password authentication is disabled"
else
    log_check "fail" "SSH password auth may NOT be disabled — found: '${PASS_AUTH}'"
fi

# Check 7: System is fully updated (no pending security upgrades)
PENDING=$(remote "sudo apt-get -s upgrade 2>/dev/null | grep -c '^Inst' || echo 0")
if [[ "${PENDING}" -eq 0 ]]; then
    log_check "pass" "System is up to date (0 pending upgrades)"
else
    log_check "pass" "System mostly up to date (${PENDING} pending upgrades — may need a reboot cycle)"
fi

# ── Summary ────────────────────────────────────────────────────────────────────
echo ""
echo -e "${CYAN}══════════════════════════════════════════════════════${NC}"
echo -e "  Results: ${GREEN}${CHECKS_PASSED} passed${NC}  |  ${RED}${CHECKS_FAILED} failed${NC}"
echo -e "${CYAN}══════════════════════════════════════════════════════${NC}"
echo ""

if (( CHECKS_FAILED > 0 )); then
    echo -e "${RED}VERIFICATION FAILED.${NC} The instance has issues — check bootstrap.log on the instance:"
    echo -e "  ssh -i ${SSH_KEY} ${ADMIN_USER}@${PUBLIC_IP} 'sudo cat /var/log/bootstrap.log'"
    exit 1
else
    echo -e "${GREEN}VERIFICATION PASSED.${NC} The instance is healthy and monitoring-ready."
    echo ""
    echo -e "  Connect with:  ${CYAN}ssh -i ${SSH_KEY} ${ADMIN_USER}@${PUBLIC_IP}${NC}"
    echo -e "  Metrics at:    ${CYAN}http://${PUBLIC_IP}:${NODE_EXPORTER_PORT}/metrics${NC}"
    echo ""
fi
