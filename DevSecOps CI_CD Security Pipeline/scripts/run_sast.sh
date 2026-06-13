#!/usr/bin/env bash
# ============================================================
# run_sast.sh — Local SAST Runner
# Runs Semgrep + Bandit against the current directory.
# ============================================================

set -euo pipefail

TARGET="${1:-.}"
REPORT_DIR="./security-reports"
mkdir -p "$REPORT_DIR"

echo "╔══════════════════════════════════════════╗"
echo "║  🔍  SAST — Static Analysis Runner      ║"
echo "╚══════════════════════════════════════════╝"
echo ""

# ── Semgrep ─────────────────────────────────────────────────
echo "▶ Running Semgrep..."
if command -v semgrep &>/dev/null; then
  semgrep scan \
    --config=auto \
    --config=p/owasp-top-ten \
    --config=p/python \
    --json \
    --output="$REPORT_DIR/semgrep.json" \
    "$TARGET" || true
  echo "  ✔ Semgrep done → $REPORT_DIR/semgrep.json"
else
  echo "  ⚠ Semgrep not found. Install: pip install semgrep"
fi

echo ""

# ── Bandit ──────────────────────────────────────────────────
echo "▶ Running Bandit..."
if command -v bandit &>/dev/null; then
  bandit -r "$TARGET" \
    -x "./.venv,./node_modules,./tests" \
    -f json \
    -o "$REPORT_DIR/bandit.json" \
    --severity-level medium || true
  echo "  ✔ Bandit done → $REPORT_DIR/bandit.json"
else
  echo "  ⚠ Bandit not found. Install: pip install bandit"
fi

echo ""
echo "✅ SAST complete. Reports saved to: $REPORT_DIR/"
