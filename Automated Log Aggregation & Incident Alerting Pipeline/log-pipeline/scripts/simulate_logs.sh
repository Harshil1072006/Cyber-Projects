#!/usr/bin/env bash
# =============================================================================
#  simulate_logs.sh — Realistic log traffic generator for pipeline demo
#
#  Generates continuous semi-realistic log output to:
#    /var/log/app/app-server-1.log  (payment-service style logs)
#    /var/log/app/app-server-2.log  (auth-service style logs)
#    /var/log/app/nginx-access.log  (Nginx combined access logs)
#
#  Traffic pattern:
#    - Baseline: ~2 log lines/sec, mostly INFO with occasional WARN
#    - Every 5–10 minutes: a 30-second error burst (simulates an incident)
#    - Error burst: mix of ERROR + incident-tagged messages (auth-failure, 5xx, etc.)
#
#  Filebeat picks up these files and ships them to Logstash → Elasticsearch.
#
#  Usage (inside log-simulator container):
#    bash /scripts/simulate_logs.sh
#    bash /scripts/simulate_logs.sh --rate 5 --no-incidents  # high rate, no bursts
#    bash /scripts/simulate_logs.sh --incident-only          # only generate errors
# =============================================================================
set -euo pipefail

# ── Config ────────────────────────────────────────────────────────────────────
LOG_DIR="${LOG_DIR:-/var/log/app}"
RATE="${RATE:-1}"                    # base sleep between log lines (seconds)
INCIDENT_INTERVAL="${INCIDENT_INTERVAL:-300}"  # seconds between incidents
INCIDENT_DURATION="${INCIDENT_DURATION:-30}"   # seconds of error burst

APP1_LOG="${LOG_DIR}/app-server-1.log"
APP2_LOG="${LOG_DIR}/app-server-2.log"
NGINX_LOG="${LOG_DIR}/nginx-access.log"

NO_INCIDENTS=false
INCIDENT_ONLY=false

# ── Argument parsing ──────────────────────────────────────────────────────────
while [[ $# -gt 0 ]]; do
    case "$1" in
        --rate)           RATE="$2";              shift 2 ;;
        --no-incidents)   NO_INCIDENTS=true;       shift   ;;
        --incident-only)  INCIDENT_ONLY=true;      shift   ;;
        --interval)       INCIDENT_INTERVAL="$2"; shift 2 ;;
        *) shift ;;
    esac
done

# ── Setup ─────────────────────────────────────────────────────────────────────
mkdir -p "$LOG_DIR"

log_to() {
    local file="$1"
    local message="$2"
    # Append with newline, ensure file exists
    printf '%s\n' "$message" >> "$file"
}

# ── Timestamp helpers ─────────────────────────────────────────────────────────
ts()     { date -u '+%Y-%m-%dT%H:%M:%S.000Z'; }
ts_syslog() { date -u '+%b %e %H:%M:%S'; }

# ── Data pools ────────────────────────────────────────────────────────────────

USERS=("user_id=1001" "user_id=2847" "user_id=9123" "user_id=4456" "user_id=7789")
REQUEST_IDS=("req-a1b2c3d4" "req-e5f6g7h8" "req-i9j0k1l2" "req-m3n4o5p6" "req-q7r8s9t0")
ENDPOINTS=("/api/v1/payment" "/api/v1/checkout" "/api/v1/order" "/api/v1/cart" "/api/v1/products")
AUTH_ENDPOINTS=("/api/auth/login" "/api/auth/refresh" "/api/auth/logout" "/api/v1/profile" "/api/v1/me")
NGINX_PATHS=("/" "/api/v1/payment" "/api/v1/orders" "/static/main.js" "/health" "/api/auth/login" "/api/v1/products" "/favicon.ico")
CLIENT_IPS=("10.0.1.25" "10.0.2.44" "192.168.1.10" "172.16.5.88" "10.0.3.112" "203.0.113.45")
HTTP_METHODS=("GET" "POST" "GET" "GET" "PUT" "GET" "DELETE" "GET")
SERVICES=("payment-service" "auth-service" "order-service" "notification-service")

# ── Normal log generators ──────────────────────────────────────────────────────

gen_payment_info() {
    local user="${USERS[$((RANDOM % ${#USERS[@]}))]}"
    local req="${REQUEST_IDS[$((RANDOM % ${#REQUEST_IDS[@]}))]}"
    local ep="${ENDPOINTS[$((RANDOM % ${#ENDPOINTS[@]}))]}"
    local dur=$((RANDOM % 200 + 50))
    local msgs=(
        "$(ts) [INFO] payment-service: Processing payment request ${user} request_id=${req} endpoint=${ep} duration_ms=${dur}"
        "$(ts) [INFO] payment-service: Payment authorized successfully ${user} amount=\$$(( RANDOM % 500 + 10 )).$(( RANDOM % 100 )) request_id=${req}"
        "$(ts) [INFO] payment-service: Webhook sent to stripe ${user} request_id=${req} duration_ms=${dur}"
        "$(ts) [DEBUG] payment-service: Cache hit for product catalog request_id=${req} ttl=300s"
        "$(ts) [INFO] payment-service: Health check passed request_id=${req}"
    )
    echo "${msgs[$((RANDOM % ${#msgs[@]}))]}"
}

gen_auth_info() {
    local user="${USERS[$((RANDOM % ${#USERS[@]}))]}"
    local req="${REQUEST_IDS[$((RANDOM % ${#REQUEST_IDS[@]}))]}"
    local ep="${AUTH_ENDPOINTS[$((RANDOM % ${#AUTH_ENDPOINTS[@]}))]}"
    local msgs=(
        "$(ts) [INFO] auth-service: Login successful ${user} request_id=${req} endpoint=${ep}"
        "$(ts) [INFO] auth-service: JWT token issued ${user} expires_in=3600s"
        "$(ts) [INFO] auth-service: Session refreshed ${user} request_id=${req}"
        "$(ts) [DEBUG] auth-service: Rate limit check passed ${user} count=3/100"
        "$(ts) [INFO] auth-service: User profile fetched ${user} duration_ms=$((RANDOM % 50 + 10))"
    )
    echo "${msgs[$((RANDOM % ${#msgs[@]}))]}"
}

gen_nginx_normal() {
    local ip="${CLIENT_IPS[$((RANDOM % ${#CLIENT_IPS[@]}))]}"
    local path="${NGINX_PATHS[$((RANDOM % ${#NGINX_PATHS[@]}))]}"
    local method="${HTTP_METHODS[$((RANDOM % ${#HTTP_METHODS[@]}))]}"
    local bytes=$((RANDOM % 5000 + 200))
    local status=200
    # Occasionally 304 or 201
    case $((RANDOM % 10)) in
        7) status=304 ;;
        8) status=201 ;;
    esac
    echo "${ip} - - [$(date -u '+%d/%b/%Y:%H:%M:%S +0000')] \"${method} ${path} HTTP/1.1\" ${status} ${bytes} \"-\" \"Mozilla/5.0 (compatible; SRE-Bot/1.0)\""
}

gen_payment_warn() {
    local user="${USERS[$((RANDOM % ${#USERS[@]}))]}"
    local msgs=(
        "$(ts) [WARN] payment-service: Payment processing slow ${user} duration_ms=$((RANDOM % 2000 + 1000)) threshold=1000ms"
        "$(ts) [WARN] payment-service: Retry attempt 2/3 for payment gateway ${user}"
        "$(ts) [WARN] payment-service: High memory usage detected heap_used=78% threshold=75%"
        "$(ts) [WARN] payment-service: Rate limit approaching ${user} count=85/100"
    )
    echo "${msgs[$((RANDOM % ${#msgs[@]}))]}"
}

# ── Incident log generators ───────────────────────────────────────────────────

gen_error_burst() {
    local user="${USERS[$((RANDOM % ${#USERS[@]}))]}"
    local req="${REQUEST_IDS[$((RANDOM % ${#REQUEST_IDS[@]}))]}"
    local ip="${CLIENT_IPS[$((RANDOM % ${#CLIENT_IPS[@]}))]}"

    # Different incident scenarios, selected randomly
    case $((RANDOM % 8)) in
        0)  # Auth failure burst
            echo "$(ts) [ERROR] auth-service: Authentication failed ${user} request_id=${req} — Invalid password attempt 3/5"
            log_to "$APP2_LOG" "$(ts) [ERROR] auth-service: Authentication failed ${user} — Failed password for user admin"
            log_to "$APP2_LOG" "$(ts) [WARN]  auth-service: Account temporarily locked ${user} after 5 failed attempts"
            log_to "$NGINX_LOG" "${ip} - - [$(date -u '+%d/%b/%Y:%H:%M:%S +0000')] \"POST /api/auth/login HTTP/1.1\" 403 512 \"-\" \"curl/7.68\""
            ;;
        1)  # 5xx cascade
            echo "$(ts) [ERROR] payment-service: Internal server error — database connection pool exhausted request_id=${req}"
            log_to "$NGINX_LOG" "${ip} - - [$(date -u '+%d/%b/%Y:%H:%M:%S +0000')] \"POST /api/v1/payment HTTP/1.1\" 500 1024 \"-\" \"Mozilla/5.0\""
            log_to "$NGINX_LOG" "${ip} - - [$(date -u '+%d/%b/%Y:%H:%M:%S +0000')] \"GET /api/v1/order HTTP/1.1\" 502 512 \"-\" \"Mozilla/5.0\""
            ;;
        2)  # OOM kill
            echo "$(ts_syslog) app-server-1 kernel: Out of memory: Killed process $((RANDOM % 9000 + 1000)) (java) score $((RANDOM % 900 + 100)) or sacrifice child"
            log_to "$APP1_LOG" "$(ts) [CRITICAL] payment-service: Process killed by OOM killer — JVM heap exhausted. Last heap: 98.2% used"
            ;;
        3)  # Database error
            echo "$(ts) [ERROR] payment-service: Database connection failed — too many connections (1024/1024) request_id=${req}"
            log_to "$APP1_LOG" "$(ts) [ERROR] payment-service: Query timeout after 30000ms — deadlock detected on table orders"
            log_to "$APP2_LOG" "$(ts) [ERROR] auth-service: Could not connect to database host=pg-primary:5432 — Connection refused"
            ;;
        4)  # Disk full
            echo "$(ts_syslog) app-server-1 kernel: EXT4-fs error (device sda1): ext4_journal_check_start: Detected aborted journal"
            log_to "$APP1_LOG" "$(ts) [ERROR] payment-service: Failed to write audit log — No space left on device (ENOSPC) path=/var/log/payment"
            ;;
        5)  # Service crash
            echo "$(ts) [FATAL] payment-service: Unhandled exception in payment processor — Segmentation fault (core dumped)"
            log_to "$APP1_LOG" "$(ts) [ERROR] payment-service: Process exited with code 139 (SIGSEGV) — restarting in 5s"
            ;;
        6)  # SSL error
            echo "$(ts) [ERROR] payment-service: SSL handshake failed to stripe.com — certificate expired (expired: 2026-07-01)"
            log_to "$NGINX_LOG" "${ip} - - [$(date -u '+%d/%b/%Y:%H:%M:%S +0000')] \"POST /api/v1/payment HTTP/1.1\" 503 256 \"-\" \"Mozilla/5.0\""
            ;;
        7)  # Rate limiting
            echo "$(ts) [WARN] auth-service: Rate limit exceeded for IP ${ip} — 429 Too Many Requests count=150/100"
            log_to "$NGINX_LOG" "${ip} - - [$(date -u '+%d/%b/%Y:%H:%M:%S +0000')] \"POST /api/auth/login HTTP/1.1\" 429 128 \"-\" \"python-requests/2.28\""
            ;;
    esac
}

# ── Main loop ─────────────────────────────────────────────────────────────────

echo "[simulate_logs] Starting log generation → ${LOG_DIR}"
echo "[simulate_logs] Rate=${RATE}s | Incident interval=${INCIDENT_INTERVAL}s | Duration=${INCIDENT_DURATION}s"
echo "[simulate_logs] Ctrl+C to stop"

last_incident=$(date +%s)
incident_mode=false
incident_end=0

while true; do
    now=$(date +%s)

    # Check if we should trigger an incident
    if ! $NO_INCIDENTS && ! $incident_mode; then
        if (( now - last_incident >= INCIDENT_INTERVAL )); then
            incident_mode=true
            incident_end=$(( now + INCIDENT_DURATION ))
            last_incident=$now
            echo "[simulate_logs] ⚡ INCIDENT BURST starting (${INCIDENT_DURATION}s of errors)"
            log_to "$APP1_LOG" "$(ts) [ERROR] payment-service: INCIDENT DETECTED — error rate spike beginning"
        fi
    fi

    # End incident if time is up
    if $incident_mode && (( now >= incident_end )); then
        incident_mode=false
        echo "[simulate_logs] ✓ Incident burst ended — returning to baseline"
        log_to "$APP1_LOG" "$(ts) [INFO] payment-service: Service recovering — error rate returning to normal"
    fi

    if $INCIDENT_ONLY || $incident_mode; then
        # Generate errors
        error_line=$(gen_error_burst)
        log_to "$APP1_LOG" "$error_line"
        sleep 0.5
    else
        # Normal baseline traffic
        case $((RANDOM % 20)) in
            0|1)  # ~10%: WARN
                log_to "$APP1_LOG" "$(gen_payment_warn)"
                ;;
            2)    # ~5%: auth warn
                log_to "$APP2_LOG" "$(ts) [WARN] auth-service: Slow token validation ${USERS[$((RANDOM % ${#USERS[@]}))]} duration_ms=$((RANDOM % 1500 + 800))ms"
                ;;
            *)    # ~85%: INFO (mix all three files)
                case $((RANDOM % 3)) in
                    0) log_to "$APP1_LOG" "$(gen_payment_info)" ;;
                    1) log_to "$APP2_LOG" "$(gen_auth_info)"    ;;
                    2) log_to "$NGINX_LOG" "$(gen_nginx_normal)" ;;
                esac
                ;;
        esac
        sleep "$RATE"
    fi
done
