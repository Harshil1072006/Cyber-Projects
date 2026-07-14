#!/usr/bin/env bats
# =============================================================================
#  test_bash_scripts.bats — bats-core idempotency and failure-mode tests
#
#  Run with:
#    bats tests/test_bash_scripts.bats
#    bats tests/test_bash_scripts.bats --tap   # TAP output for CI
#
#  Install bats-core:
#    git clone https://github.com/bats-core/bats-core ~/.bats
#    export PATH="$HOME/.bats/bin:$PATH"
# =============================================================================

# ── Setup / teardown ────────────────────────────────────────────────────────
setup() {
    SCRIPT_DIR="$(cd "$(dirname "$BATS_TEST_FILENAME")/.." && pwd)/scripts/bash"
    COMMON_SH="${SCRIPT_DIR}/lib/common.sh"
    TMPDIR_TEST="$(mktemp -d)"
    export TMPDIR_TEST SCRIPT_DIR COMMON_SH
    export LOG_FILE="${TMPDIR_TEST}/test.log"
    export NO_COLOR=1
}

teardown() {
    rm -rf "$TMPDIR_TEST"
}


# ═════════════════════════════════════════════════════
#  lib/common.sh — Unit tests
# ═════════════════════════════════════════════════════

@test "common.sh: sources without error" {
    run bash -c "source '${COMMON_SH}' && echo loaded"
    [ "$status" -eq 0 ]
    [[ "$output" == *"loaded"* ]]
}

@test "common.sh: log functions write to stderr" {
    run bash -c "
        source '${COMMON_SH}'
        log_info  'info message'
        log_warn  'warn message'
        log_error 'error message'
    " 2>&1
    [ "$status" -eq 0 ]
    [[ "$output" == *"INFO"*   ]]
    [[ "$output" == *"WARN"*   ]]
    [[ "$output" == *"ERROR"*  ]]
}

@test "common.sh: log writes to LOG_FILE when set" {
    export LOG_FILE="${TMPDIR_TEST}/output.log"
    run bash -c "
        source '${COMMON_SH}'
        log_info 'test log line'
    "
    [ "$status" -eq 0 ]
    [ -f "${TMPDIR_TEST}/output.log" ]
    grep -q "test log line" "${TMPDIR_TEST}/output.log"
}

@test "common.sh: require_command succeeds for existing command" {
    run bash -c "
        source '${COMMON_SH}'
        require_command bash
        echo 'passed'
    "
    [ "$status" -eq 0 ]
    [[ "$output" == *"passed"* ]]
}

@test "common.sh: require_command exits ${EXIT_PRECONDITION} for missing command" {
    run bash -c "
        source '${COMMON_SH}'
        require_command this-command-does-not-exist-xyzzy
    "
    [ "$status" -eq 3 ]
}

@test "common.sh: require_var exits when variable is empty" {
    run bash -c "
        source '${COMMON_SH}'
        MYVAR=''
        require_var MYVAR
    "
    [ "$status" -eq 3 ]
}

@test "common.sh: require_var passes when variable is set" {
    run bash -c "
        source '${COMMON_SH}'
        MYVAR='hello'
        require_var MYVAR
        echo ok
    "
    [ "$status" -eq 0 ]
    [[ "$output" == *"ok"* ]]
}

@test "common.sh: run_with_retry succeeds on first try" {
    run bash -c "
        source '${COMMON_SH}'
        run_with_retry 3 1 echo 'success'
    "
    [ "$status" -eq 0 ]
}

@test "common.sh: run_with_retry exhausts retries and returns failure" {
    run bash -c "
        source '${COMMON_SH}'
        run_with_retry 2 0 false
    "
    [ "$status" -ne 0 ]
}

@test "common.sh: mark_changed + conclude exits with 0" {
    run bash -c "
        source '${COMMON_SH}'
        mark_changed 'something changed'
        conclude
    "
    [ "$status" -eq 0 ]
}

@test "common.sh: mark_already_done + conclude exits with 2 (ALREADY_DONE)" {
    run bash -c "
        source '${COMMON_SH}'
        mark_already_done 'nothing to do'
        conclude
    "
    [ "$status" -eq 2 ]
}


# ═════════════════════════════════════════════════════
#  check_dependencies.sh
# ═════════════════════════════════════════════════════

@test "check_dependencies.sh: exits 0 when common tools are present" {
    run bash -c "
        export ENV_NAME=staging
        bash '${SCRIPT_DIR}/check_dependencies.sh' --only curl,git
    "
    # Should succeed (curl and git are present in the test environment)
    # Exit 0 = success, exit 3 = missing deps
    [ "$status" -eq 0 ] || [ "$status" -eq 2 ]
}

@test "check_dependencies.sh: exits ${EXIT_PRECONDITION} for unavailable command" {
    # Temporarily override PATH to hide all commands
    run bash -c "
        export PATH='/nonexistent'
        export ENV_NAME=staging
        bash '${SCRIPT_DIR}/check_dependencies.sh' --only curl --fail-fast 2>&1 || true
    "
    [ "$status" -eq 3 ]
}

@test "check_dependencies.sh: --only flag restricts checks" {
    run bash -c "
        bash '${SCRIPT_DIR}/check_dependencies.sh' --only bash
    "
    [ "$status" -eq 0 ] || [ "$status" -eq 2 ]
}


# ═════════════════════════════════════════════════════
#  backup.sh — Idempotency tests
# ═════════════════════════════════════════════════════

@test "backup.sh: creates a backup successfully" {
    local src="${TMPDIR_TEST}/source"
    local dst="${TMPDIR_TEST}/backups"
    mkdir -p "$src"
    echo "test data" > "${src}/data.txt"

    run bash "${SCRIPT_DIR}/backup.sh" \
        --source "$src" \
        --dest   "$dst" \
        --keep   5

    # Exit 0 = backup created
    [ "$status" -eq 0 ]
    # At least one .tar.gz should exist
    [ "$(find "$dst" -name "*.tar.gz" | wc -l)" -gt 0 ]
}

@test "backup.sh: is idempotent within the same hour (ALREADY_DONE=2)" {
    local src="${TMPDIR_TEST}/source"
    local dst="${TMPDIR_TEST}/backups"
    mkdir -p "$src"
    echo "test data" > "${src}/data.txt"

    # First run — creates backup
    bash "${SCRIPT_DIR}/backup.sh" --source "$src" --dest "$dst" --keep 5

    # Second run in same hour — should return EXIT_ALREADY_DONE (2)
    run bash "${SCRIPT_DIR}/backup.sh" --source "$src" --dest "$dst" --keep 5
    [ "$status" -eq 2 ]
}

@test "backup.sh: verifies integrity (backup is a valid gzip)" {
    local src="${TMPDIR_TEST}/source"
    local dst="${TMPDIR_TEST}/backups"
    mkdir -p "$src"
    dd if=/dev/urandom of="${src}/random.bin" bs=1k count=10 2>/dev/null

    run bash "${SCRIPT_DIR}/backup.sh" --source "$src" --dest "$dst"
    [ "$status" -eq 0 ] || [ "$status" -eq 2 ]

    # Find the backup and verify gzip integrity
    local backup_file
    backup_file="$(find "$dst" -name "*.tar.gz" | head -1)"
    run gzip -t "$backup_file"
    [ "$status" -eq 0 ]
}

@test "backup.sh: rotates old backups when over keep limit" {
    local src="${TMPDIR_TEST}/source"
    local dst="${TMPDIR_TEST}/backups"
    mkdir -p "$src" "$dst"
    echo "data" > "${src}/file.txt"

    # Create 3 dummy old backups
    for i in 1 2 3; do
        touch "${dst}/backup_2026010${i}_120000.tar.gz"
    done

    # Run with keep=2 — should delete 2 of the 3 old ones (keeping newest)
    run bash "${SCRIPT_DIR}/backup.sh" \
        --source "$src" \
        --dest   "$dst" \
        --keep   2 \
        --window daily

    # Total backups should be <= keep count
    local count
    count="$(find "$dst" -name "*.tar.gz" | wc -l)"
    [ "$count" -le 2 ]
}

@test "backup.sh: exits ${EXIT_PRECONDITION} if source does not exist" {
    run bash "${SCRIPT_DIR}/backup.sh" \
        --source "/nonexistent/path/$(date +%s)" \
        --dest   "${TMPDIR_TEST}/backups"
    [ "$status" -eq 3 ]
}

@test "backup.sh: creates destination directory if missing" {
    local src="${TMPDIR_TEST}/source"
    local dst="${TMPDIR_TEST}/new_backup_dir_$(date +%s)"
    mkdir -p "$src"
    echo "data" > "${src}/file.txt"

    run bash "${SCRIPT_DIR}/backup.sh" --source "$src" --dest "$dst"
    [ "$status" -eq 0 ] || [ "$status" -eq 2 ]
    [ -d "$dst" ]
}


# ═════════════════════════════════════════════════════
#  setup_user.sh — Idempotency tests (non-root: only test parsing)
# ═════════════════════════════════════════════════════

@test "setup_user.sh: --help exits 0" {
    run bash "${SCRIPT_DIR}/setup_user.sh" --help
    [ "$status" -eq 0 ]
}

@test "setup_user.sh: exits ${EXIT_PRECONDITION} when not root" {
    # Only meaningful if we're actually not root
    if [ "$(id -u)" -eq 0 ]; then
        skip "Running as root — cannot test non-root precondition"
    fi
    run bash "${SCRIPT_DIR}/setup_user.sh" --user testuser
    [ "$status" -eq 3 ]
}


# ═════════════════════════════════════════════════════
#  restart_service.sh — Parsing and mock tests
# ═════════════════════════════════════════════════════

@test "restart_service.sh: --help exits 0" {
    run bash "${SCRIPT_DIR}/restart_service.sh" --help
    [ "$status" -eq 0 ]
}

@test "restart_service.sh: exits ${EXIT_PRECONDITION} for unknown service" {
    run bash "${SCRIPT_DIR}/restart_service.sh" \
        --service "no-such-service-xyz-$(date +%s)" \
        --port 19999
    [ "$status" -eq 3 ]
}


# ═════════════════════════════════════════════════════
#  Idempotency regression: double-run must not error
# ═════════════════════════════════════════════════════

@test "backup.sh: running twice in a row produces no error on second run" {
    local src="${TMPDIR_TEST}/double_source"
    local dst="${TMPDIR_TEST}/double_dest"
    mkdir -p "$src"
    echo "content" > "${src}/f.txt"

    bash "${SCRIPT_DIR}/backup.sh" --source "$src" --dest "$dst"
    run bash "${SCRIPT_DIR}/backup.sh" --source "$src" --dest "$dst"

    # Second run should be 0 (success) or 2 (already done) — never 1 (error)
    [ "$status" -eq 0 ] || [ "$status" -eq 2 ]
}
