# Java Enterprise App Security Assessment

**Problem:** Java-based enterprise web applications lack consistent, repeatable security assessment methodology covering both static and dynamic attack vectors.

**Solution:** Assessed a Spring Boot financial REST API for OWASP Top 10 vulnerabilities combining SAST (Semgrep custom rules, SonarQube), SCA (OWASP Dependency-Check for CVE detection), and manual Burp Suite Pro pen testing.

**Impact:** Discovered and documented 12 findings including Second-Order SQLi, Broken Access Control, and 3 critical vulnerable dependencies (CVEs); produced remediation-prioritized report with CVSS v3.1 scores and PoC steps.

**Key features:** Custom Semgrep rules for Java deserialization, JWT misconfiguration checks, IaC scanning with Checkov, and SBOM generation with Syft/CycloneDX.
