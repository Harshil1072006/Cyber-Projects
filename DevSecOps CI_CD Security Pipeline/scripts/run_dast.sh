#!/usr/bin/env bash
# ============================================================
# run_dast.sh — Local DAST Runner
# Runs OWASP ZAP + Nuclei against a target URL.
# Usage: ./run_dast.sh https://target.example.com
# ============================================================

set -euo pipefail

TARGET_URL="${1:-}"
REPORT_DIR="./security-reports"
mkdir -p "$REPORT_DIR"

if [[ -z "$TARGET_URL" ]]; then
  echo "❌ Error: Please provide a target URL."
  echo "   Usage: $0 https://target.example.com"
  exit 1
fi

echo "╔══════════════════════════════════════════╗"
echo "║  🌐  DAST — Dynamic Analysis Runner     ║"
echo "╚══════════════════════════════════════════╝"
echo "  Target: $TARGET_URL"
echo ""

# ── OWASP ZAP ───────────────────────────────────────────────
echo "▶ Running OWASP ZAP Baseline Scan..."
if command -v zap-baseline.py &>/dev/null; then
  zap-baseline.py \
    -t "$TARGET_URL" \
    -r "$REPORT_DIR/zap-report.html" \
    -J "$REPORT_DIR/zap-report.json" \
    -a || true
  echo "  ✔ ZAP done → $REPORT_DIR/zap-report.html"
elif command -v docker &>/dev/null; then
  echo "  ℹ Running ZAP via Docker..."
  docker run --rm \
    -v "$(pwd)/security-reports:/zap/wrk" \
    ghcr.io/zaproxy/zaproxy:stable \
    zap-baseline.py \
    -t "$TARGET_URL" \
    -r "zap-report.html" \
    -J "zap-report.json" || true
  echo "  ✔ ZAP done → $REPORT_DIR/zap-report.html"
else
  echo "  ⚠ ZAP not found. Install via Docker or https://zaproxy.org"
fi

echo ""

# ── Nuclei ──────────────────────────────────────────────────
echo "▶ Running Nuclei Template Scan..."
if command -v nuclei &>/dev/null; then
  nuclei \
    -u "$TARGET_URL" \
    -severity critical,high,medium \
    -json-export "$REPORT_DIR/nuclei-results.json" \
    -o "$REPORT_DIR/nuclei-results.txt" || true
  echo "  ✔ Nuclei done → $REPORT_DIR/nuclei-results.json"
else
  echo "  ⚠ Nuclei not found. Install: https://nuclei.projectdiscovery.io"
fi

echo ""
echo "✅ DAST complete. Reports saved to: $REPORT_DIR/"
