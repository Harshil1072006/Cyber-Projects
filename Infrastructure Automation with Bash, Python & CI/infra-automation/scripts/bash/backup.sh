#!/usr/bin/env bash
# =============================================================================
#  backup.sh — Idempotent, timestamped backup with rotation and integrity check
#
#  Creates a compressed, timestamped backup of the specified source path.
#  Idempotent: if a backup already exists for the same hour, it does not
#  create a duplicate. Rotates old backups, keeping only KEEP_COUNT most recent.
#  Verifies backup integrity (gzip -t) before marking success.
#
#  Usage:
#    bash backup.sh --source /var/lib/app --dest /backups/app
#    bash backup.sh --source /etc/app --dest /backups/configs --keep 5
#    SOURCE_PATH=/data BACKUP_DEST=/backups bash backup.sh
#
#  Exit codes:
#    0  SUCCESS      — backup created and verified
#    2  ALREADY_DONE — backup for this period already exists
#    3  PRECONDITION — source path doesn't exist / dest not writable
#    1  ERROR        — backup failed or integrity check failed
# =============================================================================
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "${SCRIPT_DIR}/lib/common.sh"

# ── Defaults ───────────────────────────────────────────────────────────────
SOURCE_PATH="${SOURCE_PATH:-/var/lib/app}"
BACKUP_DEST="${BACKUP_DEST:-/var/backups/app}"
KEEP_COUNT="${KEEP_COUNT:-7}"          # keep last N backups
COMPRESS_LEVEL="${COMPRESS_LEVEL:-6}"  # gzip level 1-9
BACKUP_PREFIX="${BACKUP_PREFIX:-backup}"
# Idempotency window: only one backup per DEDUP_WINDOW
DEDUP_WINDOW="${DEDUP_WINDOW:-hourly}"  # hourly or daily

# ── Argument parsing ───────────────────────────────────────────────────────
usage() {
    cat >&2 <<EOF
Usage: $0 [OPTIONS]

Options:
  --source PATH    Path to back up (default: /var/lib/app)
  --dest PATH      Backup destination directory (default: /var/backups/app)
  --keep N         Keep N most recent backups (default: 7)
  --compress N     Gzip level 1-9 (default: 6)
  --prefix NAME    Backup file prefix (default: backup)
  --window W       Dedup window: hourly|daily (default: hourly)
  --help           Show this help
EOF
    exit 0
}

while [[ $# -gt 0 ]]; do
    case "$1" in
        --source)   SOURCE_PATH="$2";  shift 2 ;;
        --dest)     BACKUP_DEST="$2";  shift 2 ;;
        --keep)     KEEP_COUNT="$2";   shift 2 ;;
        --compress) COMPRESS_LEVEL="$2"; shift 2 ;;
        --prefix)   BACKUP_PREFIX="$2"; shift 2 ;;
        --window)   DEDUP_WINDOW="$2"; shift 2 ;;
        --help|-h)  usage ;;
        *) log_warn "Unknown argument: $1"; shift ;;
    esac
done

log_banner "backup.sh — Backup with Rotation"
log_info "Source: ${SOURCE_PATH}"
log_info "Destination: ${BACKUP_DEST}"
log_info "Keep: ${KEEP_COUNT} backups | Dedup window: ${DEDUP_WINDOW}"

# ── Precondition checks ────────────────────────────────────────────────────
log_step "1/5" "Precondition checks"

if [[ ! -e "$SOURCE_PATH" ]]; then
    log_error "Source path does not exist: ${SOURCE_PATH}"
    exit $EXIT_PRECONDITION
fi

# Create destination if needed
if [[ ! -d "$BACKUP_DEST" ]]; then
    if mkdir -p "$BACKUP_DEST" 2>/dev/null; then
        mark_changed "created backup directory: ${BACKUP_DEST}"
    else
        log_error "Cannot create backup destination: ${BACKUP_DEST}"
        exit $EXIT_PRECONDITION
    fi
fi

if [[ ! -w "$BACKUP_DEST" ]]; then
    log_error "Backup destination is not writable: ${BACKUP_DEST}"
    exit $EXIT_PRECONDITION
fi

require_command gzip "apt-get install -y gzip"
require_command tar  "apt-get install -y tar"

# ── Idempotency check ──────────────────────────────────────────────────────
log_step "2/5" "Idempotency check (dedup window: ${DEDUP_WINDOW})"

# Build the "window key" — the period we deduplicate within
case "$DEDUP_WINDOW" in
    hourly) WINDOW_KEY="$(date -u '+%Y%m%d_%H')" ;;
    daily)  WINDOW_KEY="$(date -u '+%Y%m%d')" ;;
    *)      WINDOW_KEY="$(date -u '+%Y%m%d_%H')" ;;
esac

# Look for an existing backup for this window
EXISTING_BACKUP=$(find "$BACKUP_DEST" -name "${BACKUP_PREFIX}_${WINDOW_KEY}*.tar.gz" 2>/dev/null | head -1 || true)
if [[ -n "$EXISTING_BACKUP" ]]; then
    log_info "Backup already exists for window '${WINDOW_KEY}': $(basename "$EXISTING_BACKUP")"
    mark_already_done "backup for window ${WINDOW_KEY} already present"
    conclude  # exits with EXIT_ALREADY_DONE
fi

# ── Create backup ──────────────────────────────────────────────────────────
log_step "3/5" "Creating backup"

TIMESTAMP="$(date -u '+%Y%m%d_%H%M%S')"
BACKUP_NAME="${BACKUP_PREFIX}_${TIMESTAMP}.tar.gz"
BACKUP_PATH="${BACKUP_DEST}/${BACKUP_NAME}"
BACKUP_TMP="${BACKUP_PATH}.tmp"

# Cleanup the temp file on any failure
add_cleanup "rm -f '${BACKUP_TMP}'"

log_info "Creating: ${BACKUP_PATH}"

# Calculate source size for progress info
SOURCE_SIZE="$(du -sh "${SOURCE_PATH}" 2>/dev/null | cut -f1 || echo "unknown")"
log_info "Source size: ${SOURCE_SIZE}"

START_TIME=$(date +%s)

if tar \
    --create \
    --gzip \
    --file="${BACKUP_TMP}" \
    --compress-program="gzip -${COMPRESS_LEVEL}" \
    --preserve-permissions \
    --same-owner \
    --exclude="*.pid" \
    --exclude="*.sock" \
    --exclude="*.tmp" \
    --warning=no-file-changed \
    -C "$(dirname "$SOURCE_PATH")" \
    "$(basename "$SOURCE_PATH")" \
    2>&1 | while read -r line; do log_debug "$line"; done
then
    END_TIME=$(date +%s)
    DURATION=$(( END_TIME - START_TIME ))
    BACKUP_SIZE="$(du -sh "$BACKUP_TMP" | cut -f1)"
    log_info "Compressed size: ${BACKUP_SIZE} (took ${DURATION}s)"
else
    log_error "tar command failed"
    exit $EXIT_ERROR
fi

# ── Integrity check ────────────────────────────────────────────────────────
log_step "4/5" "Verifying backup integrity"

if gzip -t "$BACKUP_TMP" 2>&1; then
    log_success "Integrity check passed: gzip -t OK"
else
    log_error "Integrity check FAILED: ${BACKUP_TMP} may be corrupted"
    exit $EXIT_ERROR
fi

# Verify the archive can be listed (structure is readable)
if tar -tzf "$BACKUP_TMP" &>/dev/null; then
    FILE_COUNT=$(tar -tzf "$BACKUP_TMP" | wc -l)
    log_success "Archive contains ${FILE_COUNT} entries"
else
    log_error "Cannot list archive contents — archive may be corrupt"
    exit $EXIT_ERROR
fi

# Atomically move temp to final location
mv "$BACKUP_TMP" "$BACKUP_PATH"
mark_changed "backup created: ${BACKUP_NAME} (${BACKUP_SIZE})"

# Write metadata sidecar
METADATA_FILE="${BACKUP_DEST}/${BACKUP_PREFIX}_${TIMESTAMP}.meta"
cat > "$METADATA_FILE" <<EOF
{
  "timestamp": "${TIMESTAMP}",
  "source": "${SOURCE_PATH}",
  "archive": "${BACKUP_NAME}",
  "size_compressed": "${BACKUP_SIZE}",
  "file_count": ${FILE_COUNT},
  "git_sha": "$(git_sha)",
  "hostname": "$(hostname -f 2>/dev/null || hostname)",
  "integrity": "gzip-test-passed"
}
EOF
log_info "Metadata written: ${METADATA_FILE}"

# ── Rotation ───────────────────────────────────────────────────────────────
log_step "5/5" "Rotating old backups (keep: ${KEEP_COUNT})"

# List all backups sorted by name (oldest first), get excess ones
mapfile -t ALL_BACKUPS < <(find "$BACKUP_DEST" -name "${BACKUP_PREFIX}_*.tar.gz" -not -name "*.tmp" | sort)
TOTAL_BACKUPS=${#ALL_BACKUPS[@]}

if (( TOTAL_BACKUPS > KEEP_COUNT )); then
    DELETE_COUNT=$(( TOTAL_BACKUPS - KEEP_COUNT ))
    log_info "Found ${TOTAL_BACKUPS} backups — removing ${DELETE_COUNT} oldest"
    for (( i=0; i < DELETE_COUNT; i++ )); do
        OBSOLETE="${ALL_BACKUPS[$i]}"
        OBSOLETE_META="${OBSOLETE%.tar.gz}.meta"
        log_info "  Removing: $(basename "$OBSOLETE")"
        rm -f "$OBSOLETE" "$OBSOLETE_META"
        mark_changed "rotated old backup: $(basename "$OBSOLETE")"
    done
else
    log_info "No rotation needed (${TOTAL_BACKUPS}/${KEEP_COUNT} slots used)"
fi

log_info "Active backups after rotation:"
find "$BACKUP_DEST" -name "${BACKUP_PREFIX}_*.tar.gz" | sort | while read -r f; do
    log_info "  $(basename "$f")  ($(du -sh "$f" | cut -f1))"
done

conclude
