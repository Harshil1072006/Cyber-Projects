#!/usr/bin/env bash
# =============================================================================
#  restart_service.sh — Graceful service restart with pre/post health checks
#
#  Verifies the service is healthy before restarting, restarts it gracefully,
#  then verifies it came back up within a timeout. Fails loudly if the service
#  doesn't recover, so the caller (deploy.py) knows to trigger rollback.
#
#  Usage:
#    bash restart_service.sh --service app-server --port 8080
#    bash restart_service.sh --service app-server --health-url http://localhost:8080/health
#    SERVICE_NAME=myapp HEALTH_PORT=8080 bash restart_service.sh
#
#  Exit codes:
#    0  SUCCESS      — service restarted and healthy
#    2  ALREADY_DONE — service was already running; restart skipped (use --force to override)
#    3  PRECONDITION — service not found / not manageable
#    1  ERROR        — restart failed or health check didn't pass post-restart
# =============================================================================
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "${SCRIPT_DIR}/lib/common.sh"

# ── Defaults ───────────────────────────────────────────────────────────────
SERVICE_NAME="${SERVICE_NAME:-app-server}"
HEALTH_PORT="${HEALTH_PORT:-8080}"
HEALTH_URL="${HEALTH_URL:-}"          # if empty, derived from HEALTH_PORT
HEALTH_PATH="${HEALTH_PATH:-/health}"
HEALTH_TIMEOUT="${HEALTH_TIMEOUT:-30}"  # seconds to wait for health check
RESTART_WAIT="${RESTART_WAIT:-3}"       # seconds to wait after restart command
FORCE_RESTART="${FORCE_RESTART:-false}"
GRACEFUL_TIMEOUT="${GRACEFUL_TIMEOUT:-15}"  # seconds for graceful shutdown

# ── Argument parsing ───────────────────────────────────────────────────────
usage() {
    cat >&2 <<EOF
Usage: $0 [OPTIONS]

Options:
  --service NAME        Service name (default: app-server)
  --port PORT           Health check port (default: 8080)
  --health-url URL      Full health check URL (overrides --port)
  --health-path PATH    Health check path (default: /health)
  --timeout SECS        Seconds to wait for post-restart health (default: 30)
  --force               Restart even if service appears healthy
  --help                Show this help
EOF
    exit 0
}

while [[ $# -gt 0 ]]; do
    case "$1" in
        --service)      SERVICE_NAME="$2";    shift 2 ;;
        --port)         HEALTH_PORT="$2";     shift 2 ;;
        --health-url)   HEALTH_URL="$2";      shift 2 ;;
        --health-path)  HEALTH_PATH="$2";     shift 2 ;;
        --timeout)      HEALTH_TIMEOUT="$2";  shift 2 ;;
        --force)        FORCE_RESTART=true;   shift   ;;
        --help|-h)      usage ;;
        *) log_warn "Unknown argument: $1"; shift ;;
    esac
done

# Derive health URL from port if not explicitly set
if [[ -z "$HEALTH_URL" ]]; then
    HEALTH_URL="http://localhost:${HEALTH_PORT}${HEALTH_PATH}"
fi

log_banner "restart_service.sh — Service Management"
log_info "Service: ${SERVICE_NAME} | Health URL: ${HEALTH_URL}"

# ── Service management abstraction ────────────────────────────────────────
# Supports: systemd, supervisor, Docker container, or a PID file approach.
# Determined at runtime based on what's available.

detect_service_manager() {
    if command -v systemctl &>/dev/null && systemctl list-units --type=service 2>/dev/null | grep -q "$SERVICE_NAME"; then
        echo "systemd"
    elif command -v supervisorctl &>/dev/null && supervisorctl status "$SERVICE_NAME" &>/dev/null 2>&1; then
        echo "supervisor"
    elif command -v docker &>/dev/null && docker ps --format '{{.Names}}' 2>/dev/null | grep -qx "$SERVICE_NAME"; then
        echo "docker"
    elif [[ -f "/var/run/${SERVICE_NAME}.pid" ]]; then
        echo "pidfile"
    elif [[ -f "/tmp/${SERVICE_NAME}.pid" ]]; then
        echo "pidfile-tmp"
    else
        echo "unknown"
    fi
}

service_is_running() {
    local manager="$1"
    case "$manager" in
        systemd)     systemctl is-active --quiet "$SERVICE_NAME" 2>/dev/null ;;
        supervisor)  supervisorctl status "$SERVICE_NAME" 2>/dev/null | grep -q "RUNNING" ;;
        docker)      docker ps --format '{{.Names}}' 2>/dev/null | grep -qx "$SERVICE_NAME" ;;
        pidfile)     local pid; pid=$(cat "/var/run/${SERVICE_NAME}.pid" 2>/dev/null || true); [[ -n "$pid" ]] && kill -0 "$pid" 2>/dev/null ;;
        pidfile-tmp) local pid; pid=$(cat "/tmp/${SERVICE_NAME}.pid" 2>/dev/null || true); [[ -n "$pid" ]] && kill -0 "$pid" 2>/dev/null ;;
        *)           return 1 ;;
    esac
}

do_restart() {
    local manager="$1"
    case "$manager" in
        systemd)
            log_info "Restarting via systemctl: ${SERVICE_NAME}"
            systemctl restart "$SERVICE_NAME"
            ;;
        supervisor)
            log_info "Restarting via supervisorctl: ${SERVICE_NAME}"
            supervisorctl restart "$SERVICE_NAME"
            ;;
        docker)
            log_info "Restarting Docker container: ${SERVICE_NAME}"
            docker restart --time "$GRACEFUL_TIMEOUT" "$SERVICE_NAME"
            ;;
        pidfile|pidfile-tmp)
            local pid_file
            [[ "$manager" == "pidfile" ]] && pid_file="/var/run/${SERVICE_NAME}.pid" || pid_file="/tmp/${SERVICE_NAME}.pid"
            local pid
            pid=$(cat "$pid_file" 2>/dev/null || true)
            if [[ -n "$pid" ]] && kill -0 "$pid" 2>/dev/null; then
                log_info "Sending SIGTERM to PID ${pid} (graceful shutdown)"
                kill -TERM "$pid"
                local waited=0
                while kill -0 "$pid" 2>/dev/null && (( waited < GRACEFUL_TIMEOUT )); do
                    sleep 1
                    (( waited++ )) || true
                done
                if kill -0 "$pid" 2>/dev/null; then
                    log_warn "Process didn't exit gracefully — sending SIGKILL"
                    kill -KILL "$pid" || true
                fi
            fi
            # Start the service (assumes a start script exists)
            if [[ -x "/usr/local/bin/start-${SERVICE_NAME}" ]]; then
                "/usr/local/bin/start-${SERVICE_NAME}" &
            elif [[ -x "/etc/init.d/${SERVICE_NAME}" ]]; then
                "/etc/init.d/${SERVICE_NAME}" start
            else
                log_error "Cannot restart '${SERVICE_NAME}': no start mechanism found"
                return 1
            fi
            ;;
        unknown)
            log_error "Cannot determine service manager for '${SERVICE_NAME}'"
            log_error "Tried: systemd, supervisor, docker, pidfile"
            log_error "Make sure the service is managed by one of these"
            exit $EXIT_PRECONDITION
            ;;
    esac
}

# ── Wait for health ────────────────────────────────────────────────────────
wait_for_health() {
    local url="$1"
    local timeout="$2"
    local start
    start=$(date +%s)

    log_info "Waiting up to ${timeout}s for health check: ${url}"
    while true; do
        local elapsed=$(( $(date +%s) - start ))
        if (( elapsed >= timeout )); then
            log_error "Health check timed out after ${timeout}s: ${url}"
            return 1
        fi

        local status_code
        status_code=$(curl -sf --max-time 3 -o /dev/null -w "%{http_code}" "$url" 2>/dev/null || echo "000")

        if [[ "$status_code" == "200" ]]; then
            log_success "Service healthy after ${elapsed}s: HTTP ${status_code}"
            return 0
        fi

        log_debug "Health check: HTTP ${status_code} (${elapsed}s elapsed)"
        sleep 2
    done
}

# ── Main ───────────────────────────────────────────────────────────────────
log_step "1/4" "Detecting service manager"
MANAGER=$(detect_service_manager)
log_info "Service manager: ${MANAGER}"

if [[ "$MANAGER" == "unknown" ]]; then
    log_error "No recognized service manager found for '${SERVICE_NAME}'"
    exit $EXIT_PRECONDITION
fi

log_step "2/4" "Pre-restart state check"
if service_is_running "$MANAGER"; then
    log_info "Service '${SERVICE_NAME}' is currently running"
    if ! $FORCE_RESTART; then
        # Do a quick health check — only skip restart if truly healthy
        pre_healthy=false
        if http_health_check "$HEALTH_URL"; then
            pre_healthy=true
        fi

        if $pre_healthy; then
            log_info "Service is running and healthy. Use --force to restart anyway."
            mark_already_done "service '${SERVICE_NAME}' already running and healthy"
            # Still do the restart (deploy requires it), but note the state
        fi
    else
        log_info "--force specified — will restart regardless"
    fi
else
    log_warn "Service '${SERVICE_NAME}' is NOT running — will start it"
fi

log_step "3/4" "Restarting service"
if ! do_restart "$MANAGER"; then
    log_error "Restart command failed for '${SERVICE_NAME}'"
    exit $EXIT_ERROR
fi

log_info "Waiting ${RESTART_WAIT}s for service to begin startup..."
sleep "$RESTART_WAIT"

log_step "4/4" "Post-restart health check"
if wait_for_health "$HEALTH_URL" "$HEALTH_TIMEOUT"; then
    mark_changed "service '${SERVICE_NAME}' restarted successfully"
else
    log_error "Service '${SERVICE_NAME}' did NOT become healthy after restart!"
    log_error "This will trigger automatic rollback in the deploy pipeline."
    # Log final status for debugging
    case "$MANAGER" in
        systemd)     systemctl status "$SERVICE_NAME" --no-pager 2>&1 | tail -20 >&2 || true ;;
        docker)      docker logs --tail=20 "$SERVICE_NAME" 2>&1 | tail -20 >&2 || true ;;
    esac
    exit $EXIT_ERROR
fi

conclude
