<div align="center">

# 🎯 BurpKit

**Advanced SQL Injection Testing Suite for Bug Bounty Hunters**

[![Python](https://img.shields.io/badge/Python-3.10+-blue?style=for-the-badge&logo=python)]()
[![License](https://img.shields.io/badge/Use-Authorized_Only-red?style=for-the-badge&logo=hackthebox)]()
[![Status](https://img.shields.io/badge/Status-Active-brightgreen?style=for-the-badge)]()

</div>

---

## 📌 What Is BurpKit?

**BurpKit** is a custom Python-based SQL Injection scanner and testing suite built for authorized **bug bounty hunting** on platforms like HackerOne and Bugcrowd. It goes beyond simple URL testing — combining a smart web crawler, a powerful multi-technique fuzzer, an HTML/JSON report generator, and SQLMap integration into one cohesive toolkit.

> ⚠️ **Authorized Use Only.** Only use this toolkit against targets you have **explicit written permission** to test. Unauthorized use is illegal.

---

## ✨ Features

| Feature | Description |
|---|---|
| 🕷️ **Smart Web Crawler** | Auto-discovers endpoints, forms, and injectable parameters across a target site |
| 💉 **Multi-Technique Fuzzer** | Tests Error-Based, Boolean-Blind, Time-Based, UNION-Based, and Stacked-Query SQLi |
| 🍪 **Cookie & Header Injection** | Optionally inject payloads into session cookies and HTTP headers |
| ⚡ **Parallel Scanning** | Multi-threaded fuzzing for high-speed coverage |
| 📊 **Rich HTML Reports** | Auto-generates detailed HTML and JSON vulnerability reports with curl PoC commands |
| 🔁 **Manual Repro Helper** | Step-by-step exploit reproduction guides for each finding |
| 🗃️ **SQLMap Integration** | Wrapper to run SQLMap against discovered endpoints automatically |

---

## 📁 Project Structure

```
BurpKit/
│
├── main.py              # Entry point — CLI interface for the full scanner
├── crawler.py           # Web crawler — discovers URLs, forms, and parameters
├── sqli_fuzzer.py       # Core fuzzing engine — all SQLi techniques and payload logic
├── reporter.py          # Report generator — HTML & JSON outputs with PoC details
├── manual_repro.py      # Manual exploitation reproduction helper
├── sqlmap_runner.py     # SQLMap integration wrapper
└── requirements.txt     # Python dependencies
```

---

## 🚀 Usage

```bash
# Install dependencies
pip install -r requirements.txt

# Basic crawl and scan
python main.py -u https://target.example.com

# With session cookies
python main.py -u https://target.example.com -c "session=abc123; csrf=xyz"

# No-crawl mode (test a single URL's params only)
python main.py -u "https://target.example.com/search?q=test&cat=1" --no-crawl

# Enable cookie + header injection with 10 threads
python main.py -u https://target.example.com --test-cookies --test-headers --threads 10

# Custom report output
python main.py -u https://target.example.com -o my_report.html
```

---

## 🧪 SQLi Techniques Covered

| Code | Technique | Description |
|------|-----------|-------------|
| `E` | **Error-Based** | Extracts data through DB error messages |
| `B` | **Boolean-Blind** | Infers data via true/false response differences |
| `T` | **Time-Based** | Uses DB sleep/delay functions to confirm injection |
| `U` | **UNION-Based** | Appends UNION queries to dump data directly |
| `S` | **Stacked-Query** | Executes multiple statements in a single injection |

---

## 📋 CLI Options

| Flag | Default | Description |
|------|---------|-------------|
| `-u / --url` | *(required)* | Target URL |
| `-c / --cookie` | None | Session cookies string |
| `--no-crawl` | False | Skip crawling, test only the given URL's params |
| `-o / --output` | `sqli_report.html` | Output HTML report filename |
| `--threads` | `5` | Number of parallel fuzzing threads |
| `--max-pages` | `100` | Max pages to crawl |
| `--test-cookies` | False | Inject payloads into cookie values |
| `--test-headers` | False | Inject payloads into HTTP headers |
| `--timeout` | `15` | Per-request timeout in seconds |

---

<div align="center">
  <i>Built for ethical hackers, bug bounty hunters, and security researchers.</i>
</div>
