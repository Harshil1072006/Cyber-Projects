# Java Enterprise App Security Assessment

A comprehensive security testing tool for Spring Boot REST APIs with SAST, SCA, and DAST capabilities.

## Features
- **SAST**: Integration with SonarQube and custom Semgrep rules for Java.
- **SCA**: Dependency checking using OSV.
- **DAST**: Active scanning for SQLi, XXE, Deserialization, SSRF, LDAP injection, etc.
- **Auth Testing**: JWT auditing, OAuth2 checks, and missing access control.
- **Reporting**: Generates beautiful HTML and PDF executive summaries and technical reports.

## Installation

```bash
pip install -r requirements.txt
pip install -e .
```

## Quick Start
1. Copy `config/config.yaml.example` to `config/config.yaml` and configure your target.
2. Run `make scan`.
3. View the generated report in the `reports/` directory.
