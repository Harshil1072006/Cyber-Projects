#!/usr/bin/env bash
# =============================================================================
#  setup_user.sh — Idempotent user/group/SSH/sudoers provisioning
#
#  Creates a service account if it does not already exist, configures SSH
#  authorized keys, and grants sudo access.  Safe to re-run: every step
#  checks current state before making changes.
#
#  Usage:
#    sudo bash setup_user.sh --user deploy --group deploy \
#         --ssh-key "ssh-ed25519 AAAA... deployer@ci" \
#         --sudoers
#
#  Exit codes (from lib/common.sh):
#    0  SUCCESS      — user created/updated successfully
#    2  ALREADY_DONE — user already exists and is fully configured
#    3  PRECONDITION — not running as root
#    1  ERROR        — unexpected failure
# =============================================================================
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=lib/common.sh
source "${SCRIPT_DIR}/lib/common.sh"

# ── Defaults ───────────────────────────────────────────────────────────────
TARGET_USER="${DEPLOY_USER:-deploy}"
TARGET_GROUP="${DEPLOY_GROUP:-deploy}"
SSH_KEY="${SSH_PUBLIC_KEY:-}"
SUDOERS_FILE="/etc/sudoers.d/${TARGET_USER}"
GRANT_SUDO=false
SSH_DIR=""
HOME_DIR=""

# ── Argument parsing ───────────────────────────────────────────────────────
usage() {
    cat >&2 <<EOF
Usage: $0 [OPTIONS]

Options:
  --user NAME       Username to create (default: deploy)
  --group NAME      Primary group     (default: deploy)
  --ssh-key KEY     Public SSH key to add to authorized_keys
  --sudoers         Grant passwordless sudo for deploy-related commands
  --help            Show this help
EOF
    exit 0
}

while [[ $# -gt 0 ]]; do
    case "$1" in
        --user)     TARGET_USER="$2";  shift 2 ;;
        --group)    TARGET_GROUP="$2"; shift 2 ;;
        --ssh-key)  SSH_KEY="$2";      shift 2 ;;
        --sudoers)  GRANT_SUDO=true;   shift   ;;
        --help|-h)  usage ;;
        *) log_warn "Unknown argument: $1"; shift ;;
    esac
done

log_banner "setup_user.sh — User Provisioning"
log_info "Target user: ${TARGET_USER}, group: ${TARGET_GROUP}"

# ── Step 1: Require root ───────────────────────────────────────────────────
require_root

# ── Step 2: Create group (idempotent) ────────────────────────────────────
log_step "1/5" "Group provisioning: ${TARGET_GROUP}"
if getent group "$TARGET_GROUP" &>/dev/null; then
    mark_already_done "group '${TARGET_GROUP}' exists (gid=$(getent group "$TARGET_GROUP" | cut -d: -f3))"
else
    groupadd --system "$TARGET_GROUP"
    mark_changed "group '${TARGET_GROUP}' created"
fi

# ── Step 3: Create user (idempotent) ─────────────────────────────────────
log_step "2/5" "User provisioning: ${TARGET_USER}"
if id -u "$TARGET_USER" &>/dev/null; then
    mark_already_done "user '${TARGET_USER}' exists (uid=$(id -u "$TARGET_USER"))"
    # Ensure the user is in the correct group even if user already exists
    if ! id -Gn "$TARGET_USER" | grep -qw "$TARGET_GROUP"; then
        usermod -aG "$TARGET_GROUP" "$TARGET_USER"
        mark_changed "user '${TARGET_USER}' added to group '${TARGET_GROUP}'"
    fi
else
    useradd \
        --system \
        --gid "$TARGET_GROUP" \
        --create-home \
        --shell /bin/bash \
        --comment "Deployment service account" \
        "$TARGET_USER"
    mark_changed "user '${TARGET_USER}' created"
fi

HOME_DIR="$(getent passwd "$TARGET_USER" | cut -d: -f6)"
SSH_DIR="${HOME_DIR}/.ssh"

# ── Step 4: SSH authorized_keys (idempotent) ──────────────────────────────
log_step "3/5" "SSH key provisioning"
if [[ -z "$SSH_KEY" ]]; then
    log_info "No SSH key provided — skipping"
else
    AUTH_KEYS="${SSH_DIR}/authorized_keys"

    if [[ ! -d "$SSH_DIR" ]]; then
        mkdir -p "$SSH_DIR"
        chmod 700 "$SSH_DIR"
        chown "${TARGET_USER}:${TARGET_GROUP}" "$SSH_DIR"
        mark_changed "created ~/.ssh directory"
    fi

    if [[ ! -f "$AUTH_KEYS" ]]; then
        touch "$AUTH_KEYS"
        chmod 600 "$AUTH_KEYS"
        chown "${TARGET_USER}:${TARGET_GROUP}" "$AUTH_KEYS"
    fi

    # Key fingerprint for idempotency comparison
    KEY_COMMENT="$(echo "$SSH_KEY" | awk '{print $3}')"
    if grep -qF "$KEY_COMMENT" "$AUTH_KEYS" 2>/dev/null || grep -qF "$SSH_KEY" "$AUTH_KEYS" 2>/dev/null; then
        mark_already_done "SSH key for '${KEY_COMMENT:-unknown}' already present"
    else
        echo "$SSH_KEY" >> "$AUTH_KEYS"
        mark_changed "SSH key added for '${KEY_COMMENT:-unknown}'"
    fi

    # Enforce permissions every run (in case something changed them)
    chmod 700 "$SSH_DIR"
    chmod 600 "$AUTH_KEYS"
    chown -R "${TARGET_USER}:${TARGET_GROUP}" "$SSH_DIR"
fi

# ── Step 5: Sudoers (idempotent) ──────────────────────────────────────────
log_step "4/5" "Sudoers configuration"
if $GRANT_SUDO; then
    SUDOERS_CONTENT="# Managed by setup_user.sh — do not edit manually
# Grants ${TARGET_USER} passwordless sudo for service management only
${TARGET_USER} ALL=(ALL) NOPASSWD: /bin/systemctl restart *, /bin/systemctl start *, /bin/systemctl stop *, /bin/systemctl status *, /usr/sbin/useradd, /usr/sbin/usermod, /usr/bin/apt-get install *, /bin/mkdir, /bin/chown, /bin/chmod
"
    EXISTING_CONTENT=""
    [[ -f "$SUDOERS_FILE" ]] && EXISTING_CONTENT="$(cat "$SUDOERS_FILE")"

    if [[ "$EXISTING_CONTENT" == "$SUDOERS_CONTENT" ]]; then
        mark_already_done "sudoers file up-to-date: ${SUDOERS_FILE}"
    else
        # Write to temp file and validate before installing
        TMP_SUDOERS="$(mktemp)"
        add_cleanup "rm -f '${TMP_SUDOERS}'"
        printf '%s' "$SUDOERS_CONTENT" > "$TMP_SUDOERS"
        chmod 440 "$TMP_SUDOERS"

        if visudo -cf "$TMP_SUDOERS" &>/dev/null; then
            install -m 440 -o root -g root "$TMP_SUDOERS" "$SUDOERS_FILE"
            mark_changed "sudoers file written: ${SUDOERS_FILE}"
        else
            log_error "visudo validation failed — sudoers NOT updated"
            exit $EXIT_ERROR
        fi
    fi
else
    log_info "Sudoers not requested — skipping"
fi

# ── Step 6: Verify ────────────────────────────────────────────────────────
log_step "5/5" "Verification"
UID_CHECK="$(id -u "$TARGET_USER" 2>/dev/null || echo "")"
if [[ -z "$UID_CHECK" ]]; then
    log_error "Verification failed: user '${TARGET_USER}' not found after provisioning"
    exit $EXIT_ERROR
fi
log_success "User '${TARGET_USER}' verified (uid=${UID_CHECK}, home=${HOME_DIR})"

conclude
