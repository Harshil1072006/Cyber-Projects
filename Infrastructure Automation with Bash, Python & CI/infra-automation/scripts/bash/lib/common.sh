#!/usr/bin/env bash
# =============================================================================
#  lib/common.sh — Shared logging, error handling, and utilities
#
#  Source this at the top of every ops script:
#    source "$(dirname "${BASH_SOURCE[0]}")/lib/common.sh"
#
#  Provides:
#    - Structured, colored logging (log_info / log_warn / log_error / log_success)
#    - require_root            — exits if not running as root
#    - require_command         — exits if a binary is not in PATH
#    - run_with_retry          — retries a command up to N times
#    - is_idempotent_check     — tracks "already in desired state" vs "action taken"
#    - EXIT_CODES              — named constants (0=ok, 2=already_done, 3=failed)
#
#  Exit code conventions (REQUIRE these in all scripts):
#    0  SUCCESS          — action performed successfully
#    2  ALREADY_DONE     — already in desired state, no action needed (idempotent)
#    3  PRECONDITION     — precondition not met (missing dependency, bad config)
#    4  PARTIAL_FAILURE  — partial success, manual review needed
#    1  ERROR            — unexpected failure
# =============================================================================

# Guard against double-sourcing
[[ -n "${_COMMON_SH_LOADED:-}" ]] && return 0
readonly _COMMON_SH_LOADED=1

# ── Exit codes ─────────────────────────────────────────────────────────────
readonly EXIT_SUCCESS=0
readonly EXIT_ALREADY_DONE=2
readonly EXIT_PRECONDITION=3
readonly EXIT_PARTIAL=4
readonly EXIT_ERROR=1

# ── Logging infrastructure ─────────────────────────────────────────────────
# Log destination: stderr + optional log file ($LOG_FILE env var)
LOG_FILE="${LOG_FILE:-}"
SCRIPT_NAME="${BASH_SOURCE[1]##*/}"
SCRIPT_NAME="${SCRIPT_NAME:-common.sh}"

# Colors (disabled when not a terminal or NO_COLOR set)
if [[ -t 2 && -z "${NO_COLOR:-}" ]]; then
    _C_RESET='\033[0m'
    _C_RED='\033[0;31m'
    _C_YELLOW='\033[1;33m'
    _C_GREEN='\033[0;32m'
    _C_BLUE='\033[0;34m'
    _C_CYAN='\033[0;36m'
    _C_BOLD='\033[1m'
else
    _C_RESET='' _C_RED='' _C_YELLOW='' _C_GREEN='' _C_BLUE='' _C_CYAN='' _C_BOLD=''
fi

_log() {
    local level="$1"; shift
    local color="$1"; shift
    local message="$*"
    local timestamp
    timestamp="$(date -u '+%Y-%m-%dT%H:%M:%SZ')"
    local line
    line="[${timestamp}] [${level}] [${SCRIPT_NAME}] ${message}"
    printf "${color}%s${_C_RESET}\n" "$line" >&2
    if [[ -n "$LOG_FILE" ]]; then
        printf '%s\n' "$line" >> "$LOG_FILE"
    fi
}

log_info()    { _log "INFO   " "${_C_BLUE}"   "$@"; }
log_warn()    { _log "WARN   " "${_C_YELLOW}"  "$@"; }
log_error()   { _log "ERROR  " "${_C_RED}"    "$@"; }
log_success() { _log "SUCCESS" "${_C_GREEN}"  "$@"; }
log_debug()   { [[ "${DEBUG:-0}" == "1" ]] && _log "DEBUG  " "${_C_CYAN}" "$@" || true; }

log_banner() {
    local title="$1"
    local width=60
    local line
    line="$(printf '─%.0s' $(seq 1 $width))"
    printf "${_C_BOLD}┌%s┐${_C_RESET}\n" "$line" >&2
    printf "${_C_BOLD}│  %-${width}s │${_C_RESET}\n" "$title" >&2
    printf "${_C_BOLD}└%s┘${_C_RESET}\n" "$line" >&2
}

log_step() {
    local step="$1"
    local desc="$2"
    printf "${_C_BOLD}  ▶ [%s] %s${_C_RESET}\n" "$step" "$desc" >&2
}

# ── Precondition helpers ───────────────────────────────────────────────────

require_root() {
    if [[ "$(id -u)" -ne 0 ]]; then
        log_error "This script must be run as root (got uid=$(id -u))"
        exit $EXIT_PRECONDITION
    fi
}

require_command() {
    local cmd="$1"
    local hint="${2:-install ${cmd}}"
    if ! command -v "$cmd" &>/dev/null; then
        log_error "Required command not found: '${cmd}' — hint: ${hint}"
        exit $EXIT_PRECONDITION
    fi
}

require_var() {
    local var_name="$1"
    local var_val="${!var_name:-}"
    if [[ -z "$var_val" ]]; then
        log_error "Required environment variable not set: ${var_name}"
        exit $EXIT_PRECONDITION
    fi
}

require_file() {
    local path="$1"
    if [[ ! -f "$path" ]]; then
        log_error "Required file not found: ${path}"
        exit $EXIT_PRECONDITION
    fi
}

# ── Retry helper ───────────────────────────────────────────────────────────

run_with_retry() {
    local max_attempts="$1"; shift
    local sleep_sec="${1:-2}"; shift
    local cmd=("$@")
    local attempt=1

    while (( attempt <= max_attempts )); do
        log_debug "Attempt ${attempt}/${max_attempts}: ${cmd[*]}"
        if "${cmd[@]}"; then
            return 0
        fi
        log_warn "Attempt ${attempt}/${max_attempts} failed — retrying in ${sleep_sec}s"
        (( attempt++ ))
        sleep "$sleep_sec"
    done

    log_error "All ${max_attempts} attempts failed: ${cmd[*]}"
    return 1
}

# ── HTTP health check ──────────────────────────────────────────────────────

http_health_check() {
    local url="$1"
    local expected_status="${2:-200}"
    local timeout="${3:-10}"

    require_command curl "apt-get install -y curl"

    local actual_status
    actual_status=$(curl -sf --max-time "$timeout" -o /dev/null -w "%{http_code}" "$url" 2>/dev/null || echo "000")

    if [[ "$actual_status" == "$expected_status" ]]; then
        log_success "Health check passed: ${url} → HTTP ${actual_status}"
        return 0
    else
        log_error "Health check failed: ${url} → HTTP ${actual_status} (expected ${expected_status})"
        return 1
    fi
}

# ── Idempotency state tracker ──────────────────────────────────────────────
# Tracks whether this run CHANGED something or was already in desired state.
_CHANGES_MADE=0
_ALREADY_DONE_COUNT=0

mark_changed() {
    _CHANGES_MADE=$(( _CHANGES_MADE + 1 ))
    log_info "Change applied: $*"
}

mark_already_done() {
    _ALREADY_DONE_COUNT=$(( _ALREADY_DONE_COUNT + 1 ))
    log_info "Already in desired state: $*"
}

# Call at end of script: exits with EXIT_ALREADY_DONE if nothing changed
conclude() {
    if (( _CHANGES_MADE > 0 )); then
        log_success "Script completed: ${_CHANGES_MADE} change(s) applied, ${_ALREADY_DONE_COUNT} already-correct"
        exit $EXIT_SUCCESS
    else
        log_info "Script completed: already in desired state (no changes made)"
        exit $EXIT_ALREADY_DONE
    fi
}

# ── Cleanup trap ───────────────────────────────────────────────────────────

_cleanup_handlers=()

add_cleanup() {
    _cleanup_handlers+=("$@")
}

_run_cleanup() {
    local exit_code=$?
    for handler in "${_cleanup_handlers[@]}"; do
        log_debug "Running cleanup: ${handler}"
        eval "$handler" || true
    done
    return $exit_code
}

trap '_run_cleanup' EXIT

# ── Timestamp / versioning helpers ─────────────────────────────────────────

timestamp_now() {
    date -u '+%Y%m%d_%H%M%S'
}

git_sha() {
    git rev-parse --short HEAD 2>/dev/null || echo "unknown"
}
