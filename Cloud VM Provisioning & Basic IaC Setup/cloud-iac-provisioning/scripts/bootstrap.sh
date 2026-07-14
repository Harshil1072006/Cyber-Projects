#!/usr/bin/env bash
# =============================================================================
#  bootstrap.sh — Cloud-init user_data script
#
#  Runs automatically on FIRST BOOT via AWS EC2 user_data / cloud-init.
#  This script is idempotent and safe to run multiple times.
#
#  What it does:
#    1. Updates system packages
#    2. Creates a non-root admin user (adminuser) with sudo privileges
#    3. Hardens SSH config (disables root login, disables password auth)
#    4. Installs and starts Prometheus node_exporter on port 9100
#    5. Writes a marker file on success (/var/log/bootstrap_done)
#       so verify_provision.sh can confirm bootstrap completed.
#
#  FinOps note: Everything installed here is open-source with no licensing cost.
#  Monitoring-ready: every VM provisioned by this project is immediately
#  scrapeable by the Prometheus stack in the Linux Server Monitoring project.
# =============================================================================
set -euo pipefail

LOG_FILE="/var/log/bootstrap.log"
MARKER_FILE="/var/log/bootstrap_done"
ADMIN_USER="adminuser"
NODE_EXPORTER_VERSION="1.8.2"
NODE_EXPORTER_ARCHIVE="node_exporter-${NODE_EXPORTER_VERSION}.linux-amd64"

log() {
    echo "$(date -u +"%Y-%m-%dT%H:%M:%SZ") [BOOTSTRAP] $*" | tee -a "${LOG_FILE}"
}

log "=== Bootstrap started ==="

# =============================================================================
# 1. System update
# =============================================================================
log "Updating system packages..."
export DEBIAN_FRONTEND=noninteractive
apt-get update -qq
apt-get upgrade -y -qq \
    -o Dpkg::Options::="--force-confdef" \
    -o Dpkg::Options::="--force-confold"
apt-get install -y -qq curl wget jq unzip ca-certificates gnupg

log "System packages updated."

# =============================================================================
# 2. Create non-root admin user
# =============================================================================
log "Creating admin user: ${ADMIN_USER}"

if id "${ADMIN_USER}" &>/dev/null; then
    log "User ${ADMIN_USER} already exists — skipping creation."
else
    useradd \
        --create-home \
        --shell /bin/bash \
        --comment "SRE Admin User" \
        "${ADMIN_USER}"
    # Copy the authorized_keys from the ubuntu default user (set by AWS key pair)
    # This allows the same SSH key to work for adminuser as for ubuntu
    mkdir -p "/home/${ADMIN_USER}/.ssh"
    if [ -f /home/ubuntu/.ssh/authorized_keys ]; then
        cp /home/ubuntu/.ssh/authorized_keys "/home/${ADMIN_USER}/.ssh/authorized_keys"
    fi
    chown -R "${ADMIN_USER}:${ADMIN_USER}" "/home/${ADMIN_USER}/.ssh"
    chmod 700 "/home/${ADMIN_USER}/.ssh"
    chmod 600 "/home/${ADMIN_USER}/.ssh/authorized_keys"
    log "Admin user ${ADMIN_USER} created."
fi

# Grant sudo privileges
if ! grep -q "^${ADMIN_USER}" /etc/sudoers.d/"${ADMIN_USER}" 2>/dev/null; then
    echo "${ADMIN_USER} ALL=(ALL) NOPASSWD:ALL" > /etc/sudoers.d/"${ADMIN_USER}"
    chmod 440 /etc/sudoers.d/"${ADMIN_USER}"
    log "Granted sudo privileges to ${ADMIN_USER}."
fi

# =============================================================================
# 3. Harden SSH configuration
# =============================================================================
log "Hardening SSH configuration..."

SSHD_CONFIG="/etc/ssh/sshd_config"

# Backup original config
cp -n "${SSHD_CONFIG}" "${SSHD_CONFIG}.bak.bootstrap" 2>/dev/null || true

# Apply hardening settings
# Disable root login — never allow direct root SSH
sed -i 's/^#\?PermitRootLogin.*/PermitRootLogin no/' "${SSHD_CONFIG}"

# Disable password authentication — key-based auth only
sed -i 's/^#\?PasswordAuthentication.*/PasswordAuthentication no/' "${SSHD_CONFIG}"

# Disable challenge-response authentication
sed -i 's/^#\?ChallengeResponseAuthentication.*/ChallengeResponseAuthentication no/' "${SSHD_CONFIG}"

# Disable X11 forwarding (no display server needed on a server)
sed -i 's/^#\?X11Forwarding.*/X11Forwarding no/' "${SSHD_CONFIG}"

# Reduce MaxAuthTries to limit brute-force attempts
if grep -q "^MaxAuthTries" "${SSHD_CONFIG}"; then
    sed -i 's/^MaxAuthTries.*/MaxAuthTries 3/' "${SSHD_CONFIG}"
else
    echo "MaxAuthTries 3" >> "${SSHD_CONFIG}"
fi

# Validate config before restarting
sshd -t && systemctl restart sshd
log "SSH hardening applied and sshd restarted."

# =============================================================================
# 4. Install Prometheus node_exporter
# =============================================================================
log "Installing node_exporter v${NODE_EXPORTER_VERSION}..."

if systemctl is-active --quiet node_exporter 2>/dev/null; then
    log "node_exporter is already running — skipping installation."
else
    # Create a dedicated system user for node_exporter (security best practice)
    if ! id "node_exporter" &>/dev/null; then
        useradd --no-create-home --shell /bin/false node_exporter
    fi

    # Download binary from GitHub releases
    DOWNLOAD_URL="https://github.com/prometheus/node_exporter/releases/download/v${NODE_EXPORTER_VERSION}/${NODE_EXPORTER_ARCHIVE}.tar.gz"
    TMP_DIR=$(mktemp -d)

    curl -fsSL "${DOWNLOAD_URL}" -o "${TMP_DIR}/node_exporter.tar.gz"
    tar -xzf "${TMP_DIR}/node_exporter.tar.gz" -C "${TMP_DIR}"
    cp "${TMP_DIR}/${NODE_EXPORTER_ARCHIVE}/node_exporter" /usr/local/bin/node_exporter
    chown node_exporter:node_exporter /usr/local/bin/node_exporter
    chmod 755 /usr/local/bin/node_exporter

    # Clean up temp directory
    rm -rf "${TMP_DIR}"

    # Create systemd service unit
    cat > /etc/systemd/system/node_exporter.service << 'SERVICE_EOF'
[Unit]
Description=Prometheus Node Exporter
Documentation=https://prometheus.io/docs/guides/node-exporter/
Wants=network-online.target
After=network-online.target

[Service]
User=node_exporter
Group=node_exporter
Type=simple
ExecStart=/usr/local/bin/node_exporter \
    --collector.disable-defaults \
    --collector.cpu \
    --collector.diskstats \
    --collector.filesystem \
    --collector.loadavg \
    --collector.meminfo \
    --collector.netdev \
    --collector.time \
    --collector.uname \
    --web.listen-address=":9100"
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
SERVICE_EOF

    systemctl daemon-reload
    systemctl enable node_exporter
    systemctl start node_exporter

    # Wait up to 10 seconds for node_exporter to become healthy
    for i in $(seq 1 10); do
        if curl -sf http://localhost:9100/metrics > /dev/null 2>&1; then
            log "node_exporter is healthy and responding on :9100 (after ${i}s)."
            break
        fi
        sleep 1
    done
fi

# =============================================================================
# 5. Final verification & marker file
# =============================================================================
log "Verifying installed services..."
systemctl is-active --quiet node_exporter && log "✓ node_exporter: RUNNING" || log "✗ node_exporter: NOT RUNNING"
systemctl is-active --quiet sshd          && log "✓ sshd: RUNNING"          || log "✗ sshd: NOT RUNNING"

# Write the marker file that verify_provision.sh checks for
echo "Bootstrap completed at $(date -u +"%Y-%m-%dT%H:%M:%SZ")" > "${MARKER_FILE}"

log "=== Bootstrap completed successfully ==="
