#!/bin/bash
set -e

echo "=========================================================="
echo "    🚀 DevSecOps Pipeline — One-Command Setup"
echo "=========================================================="

echo "[1/4] Checking prerequisites..."
command -v docker >/dev/null 2>&1 || { echo >&2 "Docker is required but it's not installed. Aborting."; exit 1; }
command -v python3 >/dev/null 2>&1 || { echo >&2 "Python 3 is required but it's not installed. Aborting."; exit 1; }

# Check Docker memory
MEM=$(docker info --format '{{.MemTotal}}' 2>/dev/null || echo "0")
if [ "$MEM" != "0" ]; then
    MEM_GB=$((MEM / 1024 / 1024 / 1024))
    if [ "$MEM_GB" -lt 4 ]; then
        echo "⚠️ Warning: Docker is allocated less than 4GB RAM ($MEM_GB GB). SonarQube may fail to start."
    fi
fi

echo "[2/4] Installing Python dependencies..."
python3 -m pip install -r requirements.txt

echo "[3/4] Spinning up DevSecOps Infrastructure (Jenkins, SonarQube, ZAP, App)..."
docker-compose up -d

echo "[4/4] Waiting for SonarQube to become healthy..."
echo -n "Polling "
until curl -s http://localhost:9000/api/system/status | grep -q '"status":"UP"'; do
    echo -n "."
    sleep 5
done
echo " Done!"

echo "=========================================================="
echo "✅ Setup Complete!"
echo "=========================================================="
echo "Access your local DevSecOps environment:"
echo " - Jenkins:   http://localhost:8080 (Check docker logs devsecops-jenkins for initial password)"
echo " - SonarQube: http://localhost:9000 (admin / admin)"
echo " - ZAP API:   http://localhost:8090"
echo " - Target:    http://localhost:8081"
echo ""
echo "To run the pipeline locally (Mock mode with sample data):"
echo "  python scripts/orchestrator.py --findings-only --report"
echo "=========================================================="
