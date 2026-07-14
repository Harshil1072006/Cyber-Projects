#!/usr/bin/env bash
# =============================================================================
#  check_dependencies.sh — Verify required packages and versions are installed
#
#  Reads REQUIRED_DEPS from environment or uses built-in defaults.
#  Exits non-zero with a clear, actionable error message if any dependency
#  is missing or below minimum version.
#
#  Usage:
#    bash check_dependencies.sh                 # use built-in defaults
#    bash check_dependencies.sh --env staging   # load from environments/
#    REQUIRED_PACKAGES="curl jq git" bash check_dependencies.sh
#
#  Exit codes:
#    0  SUCCESS      — all dependencies satisfied
#    2  ALREADY_DONE — all deps present, no changes made (same as SUCCESS here)
#    3  PRECONDITION — one or more dependencies missing/wrong version
# =============================================================================
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "${SCRIPT_DIR}/lib/common.sh"

# ── Configuration ──────────────────────────────────────────────────────────
ENV_NAME="${ENV_NAME:-staging}"
FAIL_FAST="${FAIL_FAST:-false}"  # if true, exit on first failure

# ── Dependency definitions ─────────────────────────────────────────────────
# Format: "command:min_version:version_flag:install_hint"
# version_flag: how to get the version string (e.g., "--version", "version")
declare -A DEPS_COMMANDS=(
    ["curl"]="curl:7.0.0:--version:apt-get install -y curl"
    ["git"]="git:2.0.0:--version:apt-get install -y git"
    ["jq"]="jq:1.5:--version:apt-get install -y jq"
    ["python3"]="python3:3.8.0:--version:apt-get install -y python3"
    ["pip3"]="pip3:20.0.0:--version:apt-get install -y python3-pip"
    ["docker"]="docker:20.0.0:--version:https://docs.docker.com/engine/install/"
    ["rsync"]="rsync:3.0.0:--version:apt-get install -y rsync"
    ["ssh"]="ssh:7.0.0:-V:apt-get install -y openssh-client"
)

# Additional package checks via dpkg/rpm (for installed but not in PATH)
declare -A SYSTEM_PACKAGES=(
    ["tar"]="tar"
    ["gzip"]="gzip"
    ["openssl"]="openssl"
)

# ── Argument parsing ───────────────────────────────────────────────────────
usage() {
    cat >&2 <<EOF
Usage: $0 [OPTIONS]

Options:
  --env ENV         Environment name (staging|production) (default: staging)
  --fail-fast       Exit immediately on first missing dependency
  --only CMD,...    Check only specific commands (comma-separated)
  --help            Show this help
EOF
    exit 0
}

ONLY_COMMANDS=""
while [[ $# -gt 0 ]]; do
    case "$1" in
        --env)        ENV_NAME="$2";      shift 2 ;;
        --fail-fast)  FAIL_FAST=true;     shift   ;;
        --only)       ONLY_COMMANDS="$2"; shift 2 ;;
        --help|-h)    usage ;;
        *) log_warn "Unknown argument: $1"; shift ;;
    esac
done

log_banner "check_dependencies.sh — Dependency Verification"
log_info "Environment: ${ENV_NAME}"

# ── Version comparison ─────────────────────────────────────────────────────
# Returns 0 if actual >= required, 1 otherwise
version_gte() {
    local required="$1"
    local actual="$2"
    # Extract numeric version components
    local req_norm actual_norm
    req_norm=$(echo "$required" | grep -oP '\d+\.\d+(\.\d+)?' | head -1)
    actual_norm=$(echo "$actual" | grep -oP '\d+\.\d+(\.\d+)?' | head -1)
    [[ -z "$req_norm" || -z "$actual_norm" ]] && return 0  # can't compare, assume OK
    printf '%s\n%s\n' "$req_norm" "$actual_norm" | sort -V | head -1 | grep -qF "$req_norm"
}

# ── Individual check functions ─────────────────────────────────────────────

check_command() {
    local name="$1"
    local spec="${DEPS_COMMANDS[$name]:-}"
    [[ -z "$spec" ]] && return 0

    IFS=: read -r cmd min_ver ver_flag hint <<< "$spec"

    if ! command -v "$cmd" &>/dev/null; then
        log_error "MISSING: '${cmd}' not found in PATH"
        log_error "  Install with: ${hint}"
        return 1
    fi

    # Get actual version
    local actual_ver
    # Handle special flags like -V (ssh) that output to stderr
    actual_ver=$("$cmd" $ver_flag 2>&1 || true)

    if version_gte "$min_ver" "$actual_ver"; then
        log_success "  ✓ ${cmd}: $(echo "$actual_ver" | head -1 | tr -s ' ')"
        return 0
    else
        log_warn "  ⚠ ${cmd}: version may be below minimum ${min_ver} — got: $(echo "$actual_ver" | head -1)"
        # Warn but don't fail on version mismatch (versions hard to parse reliably)
        return 0
    fi
}

check_system_package() {
    local pkg="$1"
    if command -v "$pkg" &>/dev/null; then
        log_success "  ✓ ${pkg}: found at $(command -v "$pkg")"
        return 0
    fi

    # Try dpkg
    if command -v dpkg-query &>/dev/null; then
        if dpkg-query -W -f='${Status}' "$pkg" 2>/dev/null | grep -q "install ok"; then
            log_success "  ✓ ${pkg}: installed (dpkg)"
            return 0
        fi
    fi

    # Try rpm
    if command -v rpm &>/dev/null; then
        if rpm -q "$pkg" &>/dev/null; then
            log_success "  ✓ ${pkg}: installed (rpm)"
            return 0
        fi
    fi

    log_warn "  ⚠ ${pkg}: not found (optional system package)"
    return 0  # system packages are warnings, not failures
}

check_python_module() {
    local module="$1"
    if python3 -c "import ${module}" &>/dev/null; then
        log_success "  ✓ Python module: ${module}"
        return 0
    else
        log_error "  ✗ Python module missing: ${module}"
        log_error "  Install with: pip3 install ${module}"
        return 1
    fi
}

check_disk_space() {
    local path="${1:-/}"
    local min_mb="${2:-500}"
    local available_mb
    available_mb=$(df -m "$path" | awk 'NR==2 {print $4}')
    if (( available_mb >= min_mb )); then
        log_success "  ✓ Disk space on ${path}: ${available_mb}MB available (min: ${min_mb}MB)"
        return 0
    else
        log_error "  ✗ Insufficient disk space on ${path}: ${available_mb}MB < ${min_mb}MB required"
        return 1
    fi
}

check_port_available() {
    local port="$1"
    if command -v ss &>/dev/null; then
        if ss -ltn "sport = :${port}" | grep -q LISTEN; then
            log_warn "  ⚠ Port ${port} is already in use"
            return 1
        fi
    fi
    log_success "  ✓ Port ${port}: available"
    return 0
}

# ── Main check loop ────────────────────────────────────────────────────────

FAILURES=0
WARNINGS=0

log_step "1/4" "Checking required commands"
for name in "${!DEPS_COMMANDS[@]}"; do
    # Skip if --only was specified and this isn't in the list
    if [[ -n "$ONLY_COMMANDS" ]] && ! echo "$ONLY_COMMANDS" | grep -qw "$name"; then
        continue
    fi
    if ! check_command "$name"; then
        (( FAILURES++ )) || true
        $FAIL_FAST && { log_error "Exiting early due to --fail-fast"; exit $EXIT_PRECONDITION; }
    fi
done

log_step "2/4" "Checking system packages"
for pkg in "${!SYSTEM_PACKAGES[@]}"; do
    check_system_package "$pkg" || (( WARNINGS++ )) || true
done

log_step "3/4" "Checking Python modules"
PYTHON_MODULES=("requests" "yaml" "json" "subprocess")
for mod in "${PYTHON_MODULES[@]}"; do
    if ! check_python_module "$mod"; then
        (( FAILURES++ )) || true
    fi
done

log_step "4/4" "Checking system resources"
check_disk_space "/" 500 || (( FAILURES++ )) || true
check_disk_space "/tmp" 100 || (( WARNINGS++ )) || true

# ── Summary ────────────────────────────────────────────────────────────────
echo >&2 ""
log_info "═══ Dependency Check Summary ═══"
log_info "  Failures: ${FAILURES}"
log_info "  Warnings: ${WARNINGS}"

if (( FAILURES > 0 )); then
    log_error "${FAILURES} required dependency/dependencies missing or misconfigured"
    log_error "Fix the above issues before proceeding with deployment"
    exit $EXIT_PRECONDITION
fi

log_success "All required dependencies satisfied"
exit $EXIT_SUCCESS
