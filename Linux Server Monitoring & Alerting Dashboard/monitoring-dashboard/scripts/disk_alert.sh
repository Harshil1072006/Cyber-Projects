#!/usr/bin/env bash
# =============================================================================
#  disk_alert.sh — Threshold-based disk usage check
#
#  Usage:
#    ./disk_alert.sh                          # uses defaults
#    ./disk_alert.sh --threshold 85 --slack-url https://hooks.slack.com/...
#    DISK_THRESHOLD=90 ./disk_alert.sh
#
#  Cron example (check every 10 minutes):
#    */10 * * * * /opt/monitoring/scripts/disk_alert.sh >> /var/log/disk_alert.log 2>&1
#
#  Exit codes:
#    0 — all filesystems OK
#    1 — at least one filesystem above threshold
#    2 — script error
# =============================================================================
set -euo pipefail

# ── Configuration ─────────────────────────────────────────────────────────────
readonly SCRIPT_NAME="$(basename "$0")"
readonly LOG_DIR="${LOG_DIR:-/var/log/monitoring}"
readonly LOG_FILE="${LOG_DIR}/disk_alert.log"
readonly THRESHOLD="${DISK_THRESHOLD:-85}"        # Percent used — alert if above
readonly SLACK_WEBHOOK="${DISK_SLACK_WEBHOOK:-}"  # Set env var or --slack-url flag

# Filesystems to skip (regex)
readonly EXCLUDE_FS="tmpfs|devtmpfs|overlay|squashfs|fuse\\.lxcfs"

# ── Helpers ───────────────────────────────────────────────────────────────────
log() {
    local level="$1"; shift
    printf '%s [%s] [%s] %s\n' \
        "$(date -u '+%Y-%m-%dT%H:%M:%SZ')" \
        "$level" \
        "$SCRIPT_NAME" \
        "$*" | tee -a "${LOG_FILE}" >&2
}

info()    { log "INFO " "$@"; }
warn()    { log "WARN " "$@"; }
error()   { log "ERROR" "$@"; }
success() { log "OK   " "$@"; }

die() {
    error "$@"
    exit 2
}

setup_logging() {
    if [[ ! -d "$LOG_DIR" ]]; then
        mkdir -p "$LOG_DIR" || die "Cannot create log directory: $LOG_DIR"
    fi
}

send_slack_alert() {
    local message="$1"
    if [[ -z "$SLACK_WEBHOOK" ]]; then
        warn "No Slack webhook configured — skipping Slack notification"
        return 0
    fi

    local payload
    payload=$(printf '{"text": "%s"}' "$message")

    if command -v curl &>/dev/null; then
        curl --silent --fail \
            -X POST \
            -H 'Content-type: application/json' \
            --data "$payload" \
            "$SLACK_WEBHOOK" || warn "Slack notification failed"
    else
        warn "curl not available — cannot send Slack alert"
    fi
}

# ── Argument parsing ──────────────────────────────────────────────────────────
parse_args() {
    while [[ $# -gt 0 ]]; do
        case "$1" in
            --threshold)
                THRESHOLD="$2"; shift 2 ;;
            --slack-url)
                SLACK_WEBHOOK="$2"; shift 2 ;;
            --log-dir)
                LOG_DIR="$2"; shift 2 ;;
            --help|-h)
                grep '^#' "$0" | head -20 | sed 's/^# \{0,2\}//'
                exit 0 ;;
            *)
                die "Unknown argument: $1 (use --help)" ;;
        esac
    done
}

# ── Main ──────────────────────────────────────────────────────────────────────
main() {
    parse_args "$@"
    setup_logging

    info "Starting disk usage check (threshold: ${THRESHOLD}%)"

    local alert_fired=0
    local checked=0

    # Parse df output: skip header, excluded filesystems, and empty lines
    while IFS= read -r line; do
        # df format: Filesystem  1K-blocks  Used  Available  Use%  Mounted on
        local filesystem use_pct mountpoint
        filesystem="$(echo "$line" | awk '{print $1}')"
        use_pct="$(echo "$line" | awk '{print $5}' | tr -d '%')"
        mountpoint="$(echo "$line" | awk '{print $6}')"

        # Skip non-numeric usage (e.g., header)
        if ! [[ "$use_pct" =~ ^[0-9]+$ ]]; then
            continue
        fi

        (( checked++ )) || true

        if (( use_pct >= THRESHOLD )); then
            warn "ALERT: ${filesystem} mounted at ${mountpoint} is ${use_pct}% full (threshold: ${THRESHOLD}%)"
            send_slack_alert ":warning: *Disk Alert* | $(hostname) | ${mountpoint} is ${use_pct}% full (threshold: ${THRESHOLD}%)"
            (( alert_fired++ )) || true
        else
            success "${filesystem} (${mountpoint}) — ${use_pct}% used — OK"
        fi

    done < <(df -hP | grep -Ev "^(${EXCLUDE_FS}|Filesystem)" 2>/dev/null || true)

    info "Check complete: ${checked} filesystem(s) checked, ${alert_fired} alert(s) fired"

    if (( alert_fired > 0 )); then
        exit 1
    fi
    exit 0
}

main "$@"
