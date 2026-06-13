#!/usr/bin/env bash
# ============================================================
# generate_sbom.sh — Software Bill of Materials Generator
# Uses Trivy to generate a CycloneDX SBOM for the project.
# ============================================================

set -euo pipefail

TARGET="${1:-.}"
REPORT_DIR="./security-reports"
mkdir -p "$REPORT_DIR"

echo "╔══════════════════════════════════════════╗"
echo "║  📦  SBOM Generator (CycloneDX)         ║"
echo "╚══════════════════════════════════════════╝"
echo ""

if command -v trivy &>/dev/null; then
  echo "▶ Generating SBOM with Trivy..."
  trivy fs "$TARGET" \
    --format cyclonedx \
    --output "$REPORT_DIR/sbom.json"
  echo "  ✔ SBOM saved → $REPORT_DIR/sbom.json"

  echo ""
  echo "▶ Running dependency vulnerability scan..."
  trivy fs "$TARGET" \
    --severity CRITICAL,HIGH \
    --format table \
    --output "$REPORT_DIR/trivy-deps.txt" || true
  echo "  ✔ Dependency scan → $REPORT_DIR/trivy-deps.txt"
else
  echo "  ⚠ Trivy not found. Install: https://trivy.dev"
  exit 1
fi

echo ""
echo "✅ SBOM generation complete. Reports saved to: $REPORT_DIR/"
