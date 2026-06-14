# Phase 1 — Environment Setup Guide
# FinSecure API + Security Toolchain

# ═══════════════════════════════════════════════════════════════════
# STEP 1: Build & Run FinSecure API (Local — Maven already installed)
# ═══════════════════════════════════════════════════════════════════

# Navigate to target app
cd "c:\Cyber Project\Java Enterprise App Security Assessment\target-app"

# Build the JAR
mvn clean package -DskipTests

# Run the JAR directly (no Docker needed since Java+Maven are local)
java -jar target/finsecure-api-1.0.0.jar

# Health check (new terminal)
curl http://localhost:8080/api/health

# ───────────────────────────────────────────────────────────────────
# STEP 1b: Run via Docker (if you prefer containerized)
# ───────────────────────────────────────────────────────────────────

# Build the Docker image
docker build -t finsecure-api:1.0 .

# Run container — maps port 8080 (API) and 5005 (JDWP debug)
docker run -d \
  --name finsecure-api \
  -p 8080:8080 \
  -p 5005:5005 \
  finsecure-api:1.0

# Health check
curl http://localhost:8080/api/health

# View logs
docker logs -f finsecure-api

# ═══════════════════════════════════════════════════════════════════
# STEP 2: Install SonarQube via Docker
# ═══════════════════════════════════════════════════════════════════

docker run -d \
  --name sonarqube \
  -p 9000:9000 \
  -e SONAR_ES_BOOTSTRAP_CHECKS_DISABLE=true \
  sonarqube:community

# Health check (wait ~60s for startup)
curl http://localhost:9000/api/system/status

# Login: http://localhost:9000  (admin / admin on first login)

# ═══════════════════════════════════════════════════════════════════
# STEP 3: Install Semgrep CLI
# ═══════════════════════════════════════════════════════════════════

pip install semgrep

# Verify
semgrep --version

# ═══════════════════════════════════════════════════════════════════
# STEP 4: Install OWASP Dependency-Check CLI
# ═══════════════════════════════════════════════════════════════════

# Download latest release zip
$dcVersion = "10.0.2"
Invoke-WebRequest `
  -Uri "https://github.com/jeremylong/DependencyCheck/releases/download/v$dcVersion/dependency-check-$dcVersion-release.zip" `
  -OutFile "$env:USERPROFILE\Tools\dependency-check.zip"

# Extract
Expand-Archive `
  -Path "$env:USERPROFILE\Tools\dependency-check.zip" `
  -DestinationPath "$env:USERPROFILE\Tools\dependency-check" `
  -Force

# Add to PATH (current session)
$env:PATH += ";$env:USERPROFILE\Tools\dependency-check\bin"

# Verify
dependency-check.bat --version

# ═══════════════════════════════════════════════════════════════════
# STEP 5: Install Syft for SBOM Generation
# ═══════════════════════════════════════════════════════════════════

# Install via winget (Windows Package Manager)
winget install anchore.syft

# OR install via Scoop
# scoop install syft

# Verify
syft version

# ═══════════════════════════════════════════════════════════════════
# FINAL HEALTH CHECKS — Run all of these to confirm everything works
# ═══════════════════════════════════════════════════════════════════

# 1. FinSecure API
curl http://localhost:8080/api/health
# Expected: {"status":"UP","service":"FinSecure API","version":"1.0.0",...}

# 2. H2 Database Console
# Open browser: http://localhost:8080/h2-console
# JDBC URL: jdbc:h2:mem:finsecuredb | User: sa | Pass: (empty)

# 3. SonarQube
curl http://localhost:9000/api/system/status
# Expected: {"id":"...","version":"...","status":"UP"}

# 4. Semgrep
semgrep --version
# Expected: semgrep x.y.z

# 5. OWASP Dependency-Check
dependency-check.bat --version
# Expected: Dependency-Check Core version x.y.z

# 6. Syft
syft version
# Expected: syft x.y.z

# ═══════════════════════════════════════════════════════════════════
# QUICK API TEST — Verify vulnerabilities are actually accessible
# ═══════════════════════════════════════════════════════════════════

# Register a user
curl -X POST http://localhost:8080/api/auth/register \
  -H "Content-Type: application/json" \
  -d "{\"username\":\"testuser\",\"password\":\"test123\",\"email\":\"test@test.com\",\"role\":\"USER\"}"

# Login to get a JWT token
curl -X POST http://localhost:8080/api/auth/login \
  -H "Content-Type: application/json" \
  -d "{\"username\":\"alice\",\"password\":\"alice123\"}"

# Test IDOR — access account ID 3 as alice (she only owns account 1)
curl http://localhost:8080/api/accounts/3 \
  -H "Authorization: Bearer <token-from-login>"

# Test Mass Assignment — inject isAdmin: true
curl -X POST http://localhost:8080/api/accounts \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer <token-from-login>" \
  -d "{\"ownerName\":\"Hacker\",\"balance\":0,\"isAdmin\":true}"
