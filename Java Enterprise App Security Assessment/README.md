<div align="center">

# 🔐 Java Enterprise App Security Assessment

### End-to-End Penetration Test of a Spring Boot Financial REST API

[![Java](https://img.shields.io/badge/Java-17-orange?style=for-the-badge&logo=openjdk)](https://openjdk.org/projects/jdk/17/)
[![Spring Boot](https://img.shields.io/badge/Spring_Boot-2.6.3-6DB33F?style=for-the-badge&logo=springboot)](https://spring.io/projects/spring-boot)
[![Python](https://img.shields.io/badge/Python-3.10+-blue?style=for-the-badge&logo=python)](https://python.org)
[![Semgrep](https://img.shields.io/badge/SAST-Semgrep-yellow?style=for-the-badge)](https://semgrep.dev)
[![OWASP](https://img.shields.io/badge/OWASP-Top_10-red?style=for-the-badge)](https://owasp.org/Top10/)

> **A complete, production-quality security assessment of a vulnerable Spring Boot financial API — covering SAST, SCA, DAST, and professional report generation. Built to demonstrate real AppSec engineering skills.**

</div>

---

## 📋 One-Line Summary

A full-stack security assessment of **FinSecure API** — a purposely vulnerable Spring Boot 3 financial REST application — using custom Semgrep SAST rules, OWASP Dependency-Check SCA, Python DAST automation, and an interactive dark-mode HTML penetration test report.

---

## 🏗️ Architecture

```mermaid
flowchart TD
    A[🎯 FinSecure API\nSpring Boot 3 · Java 17\n8 Planted Vulnerabilities] --> B

    B[orchestrator.py\nMaster Assessment Runner]

    B --> C[Phase 1: SAST\nSemgrep Custom Rules]
    B --> D[Phase 2: SCA\nDependency-Check + SBOM]
    B --> E[Phase 3: DAST\nPython Test Modules]
    B --> F[Phase 4: Reporting\nJinja2 HTML Report]

    C --> C1[java-deser.yaml\nDeserialization RCE]
    C --> C2[jwt-misconfig.yaml\nalg:none · hardcoded secret]
    C --> C3[sqli-patterns.yaml\nString concat in SQL]
    C --> C4[hardcoded-creds.yaml\nPasswords in source]

    D --> D1[OWASP Dep-Check\nCVE-2022-42003 · CVE-2015-6420]
    D --> D2[Syft SBOM\nCycloneDX 1.4]
    D --> D3[cve_enricher.py\nNVD API enrichment]

    E --> E1[auth_tester.py\nJWT alg:none bypass]
    E --> E2[sqli_tester.py\nSecond-order injection]
    E --> E3[access_control.py\nIDOR · Mass Assignment]
    E --> E4[ssrf_tester.py\nInternal + cloud metadata]

    F --> G[📊 security_report.html\nDark-mode · Chart.js\nBig 4 quality]

    style A fill:#1a0a0a,stroke:#ef4444,color:#fca5a5
    style G fill:#0a1a0a,stroke:#22c55e,color:#86efac
```

---

## 🔍 Findings — 12 Documented Vulnerabilities

| ID | Vulnerability | CVSS | Severity | OWASP Category |
|----|--------------|------|----------|----------------|
| FIND-001 | Second-Order SQL Injection in `/api/accounts/search` | **9.8** | 🔴 CRITICAL | A03:2021 - Injection |
| FIND-009 | Spring4Shell RCE — CVE-2022-22965 | **9.8** | 🔴 CRITICAL | A06:2021 - Vuln Components |
| FIND-002 | JWT Algorithm Confusion (alg:none bypass) | **9.1** | 🔴 CRITICAL | A02:2021 - Crypto Failures |
| FIND-008 | Commons Collections Deser RCE — CVE-2015-6420 | **7.5** | 🔴 CRITICAL | A06:2021 - Vuln Components |
| FIND-005 | Mass Assignment — Admin Flag Injection | **8.8** | 🟠 HIGH | A08:2021 - Software Integrity |
| FIND-003 | Horizontal IDOR — Cross-User Account Access | **8.1** | 🟠 HIGH | A01:2021 - Broken Access Ctrl |
| FIND-007 | Jackson Databind CVE-2022-42003 (DoS) | **7.5** | 🟠 HIGH | A06:2021 - Vuln Components |
| FIND-004 | Hardcoded JWT Secret `secret123` | **7.5** | 🟠 HIGH | A07:2021 - Auth Failures |
| FIND-006 | SSRF via `/api/fetch?url=` | **7.2** | 🟠 HIGH | A10:2021 - SSRF |
| FIND-010 | JWT Token Without Expiration | **6.5** | 🟡 MEDIUM | A07:2021 - Auth Failures |
| FIND-011 | Wildcard CORS Misconfiguration | **6.1** | 🟡 MEDIUM | A05:2021 - Misconfig |
| FIND-012 | Verbose Stack Trace Disclosure | **5.3** | 🟡 MEDIUM | A05:2021 - Misconfig |

**Risk Summary: 4 Critical · 5 High · 3 Medium · 0 Low**

---

## 🔬 Methodology

```
┌─────────────────────────────────────────────────────────────────┐
│  PHASE 1: SAST — Static Application Security Testing           │
│  Tool: Semgrep + 4 custom Java rules                           │
│  Detects: Hardcoded creds, JWT flaws, SQLi patterns, Deser RCE │
└────────────────────┬────────────────────────────────────────────┘
                     ▼
┌─────────────────────────────────────────────────────────────────┐
│  PHASE 2: SCA — Software Composition Analysis                  │
│  Tools: OWASP Dependency-Check, Syft (CycloneDX SBOM)         │
│  Detects: CVE-2022-42003, CVE-2015-6420, CVE-2022-22965       │
└────────────────────┬────────────────────────────────────────────┘
                     ▼
┌─────────────────────────────────────────────────────────────────┐
│  PHASE 3: DAST — Dynamic Application Security Testing          │
│  Custom Python scripts: auth_tester, sqli_tester, access_ctrl  │
│  Detects: alg:none bypass, Second-order SQLi, IDOR, SSRF       │
└────────────────────┬────────────────────────────────────────────┘
                     ▼
┌─────────────────────────────────────────────────────────────────┐
│  PHASE 4: REPORTING — Professional Penetration Test Report     │
│  Tool: Custom Jinja2 + Chart.js renderer                       │
│  Output: Interactive dark-mode HTML with CVSS gauges, heatmap  │
└─────────────────────────────────────────────────────────────────┘
```

---

## 🛠️ Tools & Versions

| Phase | Tool | Version | Purpose |
|-------|------|---------|---------|
| Target | Spring Boot | 2.6.3 | Vulnerable financial REST API |
| Target | Java | 17.0.18 | Runtime |
| SAST | Semgrep | 1.x | Custom Java security rules |
| SAST | SonarQube | Community | Code quality + security |
| SCA | OWASP Dependency-Check | 10.0.2 | CVE scanning of `pom.xml` |
| SCA | Syft | Latest | CycloneDX 1.4 SBOM generation |
| SCA | NVD API | v2.0 | CVE enrichment |
| DAST | Custom Python | 3.10+ | Auth, SQLi, IDOR, SSRF testing |
| Report | Jinja2 + Chart.js | 4.4.2 | Interactive HTML report |
| Container | Docker | Latest | SonarQube + API deployment |

---

## 🚀 Setup (5 Commands)

```bash
# 1. Build the vulnerable API
cd "Java Enterprise App Security Assessment/target-app"
mvn clean package -DskipTests

# 2. Start the API
java -jar target/finsecure-api-1.0.0.jar

# 3. Install Python dependencies
pip install semgrep jinja2 requests rich

# 4. Run the full assessment
python orchestrator.py --target http://localhost:8080 --source target-app/src

# 5. Open the report
start report/output/security_report.html
```

### Tool Setup

```bash
# SonarQube via Docker
docker run -d --name sonarqube -p 9000:9000 -e SONAR_ES_BOOTSTRAP_CHECKS_DISABLE=true sonarqube:community

# OWASP Dependency-Check
Invoke-WebRequest "https://github.com/jeremylong/DependencyCheck/releases/download/v10.0.2/dependency-check-10.0.2-release.zip" -OutFile "$HOME\dc.zip"
Expand-Archive "$HOME\dc.zip" -DestinationPath "$HOME\Tools\dependency-check" -Force

# Syft (SBOM)
winget install anchore.syft
```

---

## 📁 Project Structure

```
Java Enterprise App Security Assessment/
├── target-app/                  ← Vulnerable Spring Boot 3 API (Java 17)
│   ├── src/main/java/com/finsecure/
│   │   ├── controller/          ← AccountController (SQLi, IDOR, Mass Assign)
│   │   ├── security/            ← JwtFilter (alg:none), SecurityConfig (CORS)
│   │   ├── controller/          ← UtilController (SSRF)
│   │   └── exception/           ← GlobalExceptionHandler (verbose traces)
│   └── pom.xml                  ← Vulnerable deps (CVE-2022-42003, CVE-2015-6420)
│
├── assessment/
│   ├── sast/semgrep_rules/      ← 4 custom Semgrep YAML rules
│   ├── sca/                     ← dependency_check.py, sbom_generator.py, cve_enricher.py
│   └── dast/                    ← auth_tester.py, sqli_tester.py, access_control.py, ssrf_tester.py
│
├── findings/
│   ├── sample_findings.json     ← 12 findings with full CVSS v3.1 data
│   └── dast_results.json        ← DAST output (auto-generated)
│
├── report/
│   ├── report_generator.py      ← Jinja2 report renderer
│   ├── templates/               ← Dark-mode HTML template
│   └── output/security_report.html  ← Final report
│
└── orchestrator.py              ← Master runner: SAST → SCA → DAST → Report
```

---

## 💡 Skills Demonstrated

| Skill | Evidence |
|-------|---------|
| **Java Application Security** | Built a realistic vulnerable Spring Boot financial API with 8 planted CVE-class vulnerabilities |
| **OWASP Top 10 (2021)** | Identified and documented findings across A01, A02, A03, A05, A06, A07, A08, A10 |
| **Custom Semgrep Rules** | Wrote 4 production-quality YAML rules detecting Java deser, JWT flaws, SQLi, hardcoded creds |
| **Software Composition Analysis** | OWASP Dependency-Check + Syft SBOM + NVD API CVE enrichment pipeline |
| **DAST Automation** | Python scripts automating JWT bypass, second-order SQLi, IDOR enumeration, SSRF probing |
| **CI/CD Security Gates** | Semgrep + Dependency-Check integrated into build pipeline |
| **Professional Report Writing** | Big 4-style interactive HTML report with CVSS scoring, risk matrix, executive summary |
| **CVSS v3.1 Scoring** | All 12 findings scored with full vector strings (AV/AC/PR/UI/S/C/I/A) |
| **Threat Modeling** | Each finding includes business impact analysis for financial services context |

---

## ⚠️ Legal Disclaimer

This project contains **intentionally vulnerable code** for educational and security assessment demonstration purposes only. Do not deploy the FinSecure API in any production environment or against any system you do not own. All vulnerability research in this project is conducted in a local, isolated environment.

---

<div align="center">
  <i>Built to demonstrate real AppSec engineering — not just theory.</i>
</div>
