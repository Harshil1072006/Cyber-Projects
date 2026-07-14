#!/usr/bin/env bash
# =============================================================================
#  service_watchdog.sh — Systemd service health monitor and auto-restarter
#
#  Usage:
#    ./service_watchdog.sh                     # monitors services in SERVICES array
#    ./service_watchdog.sh nginx postgresql     # override service list via args
#    WATCHDOG_SERVICES="nginx sshd" ./service_watchdog.sh
#
#  Cron example (check every minute):
#    * * * * * /opt/monitoring/scripts/service_watchdog.sh >> /var/log/watchdog.log 2>&1
#
#  Features:
#    - Checks `systemctl is-active` for each service
#    - Attempts `systemctl restart` if service is down
#    - Logs all state changes with timestamps
#    - Sends Slack alerts on failures and restarts
#    - Idempotent: safe to run from cron every minute
#
#  Exit codes:
#    0 — all services healthy (or successfully restarted)
#    1 — one or more services failed to restart
#    2 — script error
# =============================================================================
set -euo pipefail

# ── Configuration ─────────────────────────────────────────────────────────────
readonly SCRIPT_NAME="$(basename "$0")"
readonly LOG_DIR="${LOG_DIR:-/var/log/monitoring}"
readonly LOG_FILE="${LOG_DIR}/service_watchdog.log"
readonly STATE_DIR="${STATE_DIR:-/var/run/monitoring}"
readonly SLACK_WEBHOOK="${WATCHDOG_SLACK_WEBHOOK:-}"
readonly MAX_RESTART_ATTEMPTS="${MAX_RESTART_ATTEMPTS:-3}"
readonly RESTART_COOLDOWN="${RESTART_COOLDOWN:-300}"  # seconds between restarts

# Default list of services to monitor (space-separated or newline)
# Override with WATCHDOG_SERVICES env var or command-line args
DEFAULT_SERVICES="nginx postgresql sshd docker"
SERVICES=()

# ── Helpers ───────────────────────────────────────────────────────────────────
log() {
    local level="$1"; shift
    local msg
    msg="$(date -u '+%Y-%m-%dT%H:%M:%SZ') [${level}] [${SCRIPT_NAME}] $*"
    echo "$msg" | tee -a "${LOG_FILE}"
}

info()    { log "INFO " "$@"; }
warn()    { log "WARN " "$@"; }
error()   { log "ERROR" "$@"; }
success() { log "OK   " "$@"; }

die() {
    error "$@"
    exit 2
}

setup_dirs() {
    mkdir -p "$LOG_DIR"  || die "Cannot create LOG_DIR: $LOG_DIR"
    mkdir -p "$STATE_DIR" || die "Cannot create STATE_DIR: $STATE_DIR"
}

send_slack() {
    local emoji="$1"
    local title="$2"
    local body="$3"

    [[ -z "$SLACK_WEBHOOK" ]] && return 0
    command -v curl &>/dev/null || { warn "curl not available"; return 0; }

    local text="${emoji} *${title}* | \`$(hostname)\` | ${body}"
    curl --silent --fail \
        -X POST \
        -H 'Content-type: application/json' \
        --data "{\"text\": \"${text}\"}" \
        "$SLACK_WEBHOOK" || warn "Slack notification failed"
}

# ── State tracking (to detect flapping) ───────────────────────────────────────

get_restart_count() {
    local service="$1"
    local state_file="${STATE_DIR}/${service}.restarts"
    if [[ -f "$state_file" ]]; then
        cat "$state_file"
    else
        echo "0"
    fi
}

increment_restart_count() {
    local service="$1"
    local state_file="${STATE_DIR}/${service}.restarts"
    local count
    count=$(get_restart_count "$service")
    echo $(( count + 1 )) > "$state_file"
}

get_last_restart_time() {
    local service="$1"
    local state_file="${STATE_DIR}/${service}.last_restart"
    if [[ -f "$state_file" ]]; then
        cat "$state_file"
    else
        echo "0"
    fi
}

set_last_restart_time() {
    local service="$1"
    date +%s > "${STATE_DIR}/${service}.last_restart"
}

reset_service_state() {
    local service="$1"
    rm -f "${STATE_DIR}/${service}.restarts" \
          "${STATE_DIR}/${service}.last_restart"
}

# ── Service management ────────────────────────────────────────────────────────

is_service_active() {
    local service="$1"
    systemctl is-active --quiet "$service" 2>/dev/null
}

restart_service() {
    local service="$1"
    local restart_count
    restart_count=$(get_restart_count "$service")
    local last_restart
    last_restart=$(get_last_restart_time "$service")
    local now
    now=$(date +%s)
    local seconds_since_restart=$(( now - last_restart ))

    # Rate-limit restarts
    if (( seconds_since_restart < RESTART_COOLDOWN )); then
        warn "Service ${service} restart skipped — last restart was ${seconds_since_restart}s ago (cooldown: ${RESTART_COOLDOWN}s)"
        return 1
    fi

    if (( restart_count >= MAX_RESTART_ATTEMPTS )); then
        error "Service ${service} has been restarted ${restart_count} times — NOT attempting again (manual intervention required)"
        send_slack ":rotating_light:" "Service Restart Limit Reached" \
            "${service} has failed ${restart_count} times. Manual intervention required."
        return 1
    fi

    warn "Attempting to restart ${service} (attempt $((restart_count + 1))/${MAX_RESTART_ATTEMPTS})..."

    if systemctl restart "$service" 2>/dev/null; then
        increment_restart_count "$service"
        set_last_restart_time "$service"
        success "Service ${service} restarted successfully"
        send_slack ":arrows_counterclockwise:" "Service Restarted" \
            "${service} was down and has been restarted (attempt $((restart_count + 1))/${MAX_RESTART_ATTEMPTS})"
        return 0
    else
        error "Failed to restart ${service}"
        send_slack ":x:" "Service Restart FAILED" \
            "${service} is DOWN and could not be restarted"
        return 1
    fi
}

check_service() {
    local service="$1"
    local failed=0

    if is_service_active "$service"; then
        success "Service ${service} is active"
        # Reset failure counter on successful check
        reset_service_state "$service"
    else
        warn "Service ${service} is NOT active"
        send_slack ":warning:" "Service DOWN" "${service} is not active — attempting restart"

        if ! restart_service "$service"; then
            failed=1
        fi

        # Verify restart succeeded
        if (( failed == 0 )) && ! is_service_active "$service"; then
            error "Service ${service} is still not active after restart"
            failed=1
        fi
    fi

    return $failed
}

# ── Argument parsing ──────────────────────────────────────────────────────────
parse_args() {
    if [[ $# -gt 0 ]]; then
        SERVICES=("$@")
        info "Using services from command line: ${SERVICES[*]}"
    elif [[ -n "${WATCHDOG_SERVICES:-}" ]]; then
        read -ra SERVICES <<< "$WATCHDOG_SERVICES"
        info "Using services from WATCHDOG_SERVICES env: ${SERVICES[*]}"
    else
        read -ra SERVICES <<< "$DEFAULT_SERVICES"
        info "Using default service list: ${SERVICES[*]}"
    fi
}

# ── Main ──────────────────────────────────────────────────────────────────────
main() {
    parse_args "$@"
    setup_dirs

    # Require systemctl
    if ! command -v systemctl &>/dev/null; then
        warn "systemctl not found — this script requires a systemd-based Linux host"
        exit 0  # Exit cleanly so cron doesn't error-spam on non-systemd hosts
    fi

    info "Watchdog check started for ${#SERVICES[@]} service(s): ${SERVICES[*]}"

    local total_failed=0
    for service in "${SERVICES[@]}"; do
        check_service "$service" || (( total_failed++ )) || true
    done

    if (( total_failed > 0 )); then
        error "Watchdog check FAILED: ${total_failed} service(s) unhealthy"
        exit 1
    fi

    info "Watchdog check PASSED: all ${#SERVICES[@]} service(s) healthy"
    exit 0
}

main "$@"
