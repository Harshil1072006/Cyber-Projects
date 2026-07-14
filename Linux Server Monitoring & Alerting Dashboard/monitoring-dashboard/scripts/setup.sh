#!/usr/bin/env bash
# =============================================================================
#  setup.sh — One-shot bootstrap / installer for the monitoring stack
#
#  Usage:
#    chmod +x setup.sh && sudo ./setup.sh
#
#  What this does:
#    1. Checks system prerequisites (Docker, docker compose, curl)
#    2. Creates required directories and sets permissions
#    3. Generates a .env file with sane defaults if not present
#    4. Validates all config files (YAML syntax)
#    5. Pulls Docker images
#    6. Starts the stack with docker compose up -d
#    7. Waits for all services to become healthy
#    8. Prints a summary with URLs and credentials
#
#  Idempotent: safe to run multiple times — won't overwrite existing config
#
#  Requirements:
#    - Docker Engine 24+
#    - docker compose plugin (v2)
#    - curl
#    - python3 (optional, for YAML validation)
# =============================================================================
set -euo pipefail

# ── Constants ─────────────────────────────────────────────────────────────────
readonly SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
readonly PROJECT_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
readonly SCRIPT_NAME="$(basename "$0")"
readonly LOG_FILE="/tmp/monitoring_setup_$(date +%Y%m%d_%H%M%S).log"

readonly MIN_DOCKER_VERSION="24"
readonly COMPOSE_FILE="${PROJECT_ROOT}/docker-compose.yml"
readonly ENV_FILE="${PROJECT_ROOT}/.env"
readonly HEALTH_TIMEOUT=120  # seconds to wait for stack health

# ── Colors ────────────────────────────────────────────────────────────────────
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
BOLD='\033[1m'
NC='\033[0m'  # No Color

# ── Logging ───────────────────────────────────────────────────────────────────
log() {
    local level="$1"; shift
    printf '%s [%s] %s\n' "$(date -u '+%H:%M:%S')" "$level" "$*" | tee -a "$LOG_FILE"
}

info()    { echo -e "${BLUE}[INFO]${NC}  $*" | tee -a "$LOG_FILE"; }
success() { echo -e "${GREEN}[OK]${NC}    $*" | tee -a "$LOG_FILE"; }
warn()    { echo -e "${YELLOW}[WARN]${NC}  $*" | tee -a "$LOG_FILE"; }
error()   { echo -e "${RED}[ERROR]${NC} $*" | tee -a "$LOG_FILE" >&2; }
die()     { error "$@"; exit 1; }

header() {
    echo -e "\n${BOLD}${BLUE}══════════════════════════════════════════${NC}"
    echo -e "${BOLD}${BLUE}  $*${NC}"
    echo -e "${BOLD}${BLUE}══════════════════════════════════════════${NC}\n"
}

# ── Prerequisite checks ───────────────────────────────────────────────────────
check_not_root() {
    # We allow root for setup, but warn
    if [[ $EUID -eq 0 ]]; then
        warn "Running as root. Consider using a user with docker group membership instead."
    fi
}

check_docker() {
    if ! command -v docker &>/dev/null; then
        die "Docker is not installed. Visit https://docs.docker.com/engine/install/"
    fi

    local docker_version
    docker_version=$(docker version --format '{{.Server.Version}}' 2>/dev/null | cut -d. -f1)
    if (( docker_version < MIN_DOCKER_VERSION )); then
        warn "Docker version ${docker_version} detected. Recommend ${MIN_DOCKER_VERSION}+."
    fi

    if ! docker info &>/dev/null; then
        die "Docker daemon is not running. Start it with: sudo systemctl start docker"
    fi

    success "Docker $(docker version --format '{{.Server.Version}}') is available"
}

check_docker_compose() {
    if docker compose version &>/dev/null; then
        success "docker compose $(docker compose version --short) is available"
        COMPOSE_CMD="docker compose"
    elif command -v docker-compose &>/dev/null; then
        warn "Using legacy docker-compose. Recommend upgrading to Docker Compose v2."
        COMPOSE_CMD="docker-compose"
    else
        die "docker compose plugin not found. Install: https://docs.docker.com/compose/install/"
    fi
}

check_curl() {
    command -v curl &>/dev/null && success "curl is available" || warn "curl not found — some checks will be skipped"
}

check_ports() {
    local ports=(9090 9100 9200 9093 3000)
    local port_names=(prometheus node_exporter health_check alertmanager grafana)
    local conflict=0

    for i in "${!ports[@]}"; do
        local port="${ports[$i]}"
        local name="${port_names[$i]}"
        if ss -tlnp 2>/dev/null | grep -q ":${port} " || \
           netstat -tlnp 2>/dev/null | grep -q ":${port} "; then
            warn "Port ${port} (${name}) is already in use — may conflict"
            (( conflict++ )) || true
        fi
    done

    if (( conflict == 0 )); then
        success "All required ports are available"
    fi
}

# ── Directory setup ───────────────────────────────────────────────────────────
setup_directories() {
    local dirs=(
        "${PROJECT_ROOT}/prometheus"
        "${PROJECT_ROOT}/alertmanager"
        "${PROJECT_ROOT}/grafana/provisioning/datasources"
        "${PROJECT_ROOT}/grafana/provisioning/dashboards"
        "${PROJECT_ROOT}/grafana/dashboards"
        "${PROJECT_ROOT}/scripts"
        "${PROJECT_ROOT}/docs"
        "/var/log/monitoring"
        "/var/run/monitoring"
    )

    for dir in "${dirs[@]}"; do
        if [[ ! -d "$dir" ]]; then
            mkdir -p "$dir"
            info "Created directory: $dir"
        fi
    done

    # Make bash scripts executable
    find "${PROJECT_ROOT}/scripts" -name "*.sh" -exec chmod +x {} \;
    success "Directory structure verified and scripts made executable"
}

# ── .env generation ───────────────────────────────────────────────────────────
generate_env() {
    if [[ -f "$ENV_FILE" ]]; then
        info ".env file already exists — skipping generation (delete to regenerate)"
        return 0
    fi

    # Generate a random password
    local gf_password
    gf_password=$(LC_ALL=C tr -dc 'A-Za-z0-9!@#%' < /dev/urandom | head -c 20 2>/dev/null || echo "monitoring123")

    cat > "$ENV_FILE" <<EOF
# Generated by setup.sh on $(date -u)
# ─────────────────────────────────────────────────────────────
# Grafana admin credentials
GF_ADMIN_USER=admin
GF_ADMIN_PASSWORD=${gf_password}

# Slack webhook for alerts (set this!)
SLACK_WEBHOOK_URL=https://hooks.slack.com/services/YOUR/SLACK/WEBHOOK

# Optional: SMTP for email alerts
SMTP_HOST=smtp.gmail.com:587
SMTP_FROM=alertmanager@your-domain.com
SMTP_USER=your-email@gmail.com
SMTP_PASSWORD=your-app-password

# Health check settings
CHECK_INTERVAL=30
METRICS_PORT=9200
EOF

    success ".env file generated at ${ENV_FILE}"
    warn "IMPORTANT: Edit ${ENV_FILE} and set your Slack webhook URL and SMTP credentials"
}

# ── Config validation ─────────────────────────────────────────────────────────
validate_configs() {
    local errors=0

    # Check required files exist
    local required_files=(
        "${PROJECT_ROOT}/docker-compose.yml"
        "${PROJECT_ROOT}/prometheus/prometheus.yml"
        "${PROJECT_ROOT}/prometheus/alert_rules.yml"
        "${PROJECT_ROOT}/alertmanager/alertmanager.yml"
        "${PROJECT_ROOT}/scripts/health_check.py"
        "${PROJECT_ROOT}/scripts/checks_config.yml"
    )

    for f in "${required_files[@]}"; do
        if [[ -f "$f" ]]; then
            success "Found: $(basename "$f")"
        else
            error "Missing required file: $f"
            (( errors++ )) || true
        fi
    done

    # Validate YAML syntax if python3 available
    if command -v python3 &>/dev/null; then
        local yaml_files=(
            "${PROJECT_ROOT}/prometheus/prometheus.yml"
            "${PROJECT_ROOT}/prometheus/alert_rules.yml"
            "${PROJECT_ROOT}/alertmanager/alertmanager.yml"
            "${PROJECT_ROOT}/scripts/checks_config.yml"
        )
        for f in "${yaml_files[@]}"; do
            [[ -f "$f" ]] || continue
            if python3 -c "import yaml; yaml.safe_load(open('$f'))" 2>/dev/null; then
                success "YAML valid: $(basename "$f")"
            else
                error "YAML syntax error in: $f"
                (( errors++ )) || true
            fi
        done
    else
        warn "python3 not found — skipping YAML validation"
    fi

    if (( errors > 0 )); then
        die "${errors} config error(s) found. Fix them before proceeding."
    fi
}

# ── Docker operations ─────────────────────────────────────────────────────────
pull_images() {
    info "Pulling Docker images (this may take a few minutes)..."
    cd "$PROJECT_ROOT"
    $COMPOSE_CMD pull --quiet 2>&1 | tee -a "$LOG_FILE" || warn "Some images failed to pull — will try on start"
}

start_stack() {
    info "Starting monitoring stack..."
    cd "$PROJECT_ROOT"
    $COMPOSE_CMD up -d --build 2>&1 | tee -a "$LOG_FILE"
    success "Stack started"
}

# ── Health polling ────────────────────────────────────────────────────────────
wait_for_service() {
    local name="$1"
    local url="$2"
    local timeout="${HEALTH_TIMEOUT}"
    local elapsed=0
    local interval=5

    printf "  Waiting for %s to become ready" "$name"
    while (( elapsed < timeout )); do
        if curl --silent --fail --max-time 3 "$url" &>/dev/null; then
            echo -e " ${GREEN}✓${NC}"
            return 0
        fi
        printf "."
        sleep "$interval"
        (( elapsed += interval )) || true
    done
    echo -e " ${RED}✗ (timeout after ${timeout}s)${NC}"
    return 1
}

wait_for_stack() {
    header "Waiting for services to become healthy"
    local failed=0

    wait_for_service "Prometheus"         "http://localhost:9090/-/ready"      || (( failed++ )) || true
    wait_for_service "Node Exporter"      "http://localhost:9100/metrics"       || (( failed++ )) || true
    wait_for_service "Health Check Exp."  "http://localhost:9200/metrics"       || (( failed++ )) || true
    wait_for_service "Alertmanager"       "http://localhost:9093/-/ready"       || (( failed++ )) || true
    wait_for_service "Grafana"            "http://localhost:3000/api/health"    || (( failed++ )) || true

    if (( failed > 0 )); then
        warn "${failed} service(s) did not become healthy within ${HEALTH_TIMEOUT}s"
        warn "Check logs with: docker compose logs --tail=50"
        return 1
    fi
    return 0
}

# ── Summary ───────────────────────────────────────────────────────────────────
print_summary() {
    local gf_password
    gf_password=$(grep GF_ADMIN_PASSWORD "${ENV_FILE}" 2>/dev/null | cut -d= -f2 || echo "monitoring123")

    echo -e "\n${BOLD}${GREEN}╔══════════════════════════════════════════════╗${NC}"
    echo -e "${BOLD}${GREEN}║   🚀 Monitoring Stack is UP and Running!     ║${NC}"
    echo -e "${BOLD}${GREEN}╚══════════════════════════════════════════════╝${NC}\n"
    echo -e "  ${BOLD}Service URLs:${NC}"
    echo -e "  ├── Grafana:         ${BLUE}http://localhost:3000${NC}  (admin / ${gf_password})"
    echo -e "  ├── Prometheus:      ${BLUE}http://localhost:9090${NC}"
    echo -e "  ├── Alertmanager:    ${BLUE}http://localhost:9093${NC}"
    echo -e "  ├── Node Exporter:   ${BLUE}http://localhost:9100/metrics${NC}"
    echo -e "  └── Health Check:    ${BLUE}http://localhost:9200/metrics${NC}"
    echo ""
    echo -e "  ${BOLD}Useful commands:${NC}"
    echo -e "  ├── View logs:       docker compose logs -f"
    echo -e "  ├── Stop stack:      docker compose down"
    echo -e "  ├── Reload config:   curl -X POST http://localhost:9090/-/reload"
    echo -e "  └── Run disk check:  ./scripts/disk_alert.sh"
    echo ""
    echo -e "  ${BOLD}Setup log:${NC} ${LOG_FILE}"
    echo ""
    echo -e "  ${YELLOW}⚠  Remember to configure your Slack webhook in .env${NC}"
    echo ""
}

# ── Main ──────────────────────────────────────────────────────────────────────
main() {
    header "Linux Server Monitoring Stack — Setup"
    info "Log file: ${LOG_FILE}"

    check_not_root
    check_docker
    check_docker_compose
    check_curl
    check_ports
    setup_directories
    generate_env
    validate_configs
    pull_images
    start_stack
    wait_for_stack
    print_summary
}

main "$@"
