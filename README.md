<div align="center">

# 🛡️ AI-Powered VAPT Platform

**Vulnerability Assessment & Penetration Testing — Automated, AI-Enhanced, All-in-One**

[![Python](https://img.shields.io/badge/Python-3.10+-blue?style=for-the-badge&logo=python)](https://python.org)
[![FastAPI](https://img.shields.io/badge/FastAPI-0.115+-green?style=for-the-badge&logo=fastapi)](https://fastapi.tiangolo.com)
[![License](https://img.shields.io/badge/License-MIT-yellow?style=for-the-badge)](LICENSE)
[![Status](https://img.shields.io/badge/Status-Active-brightgreen?style=for-the-badge)]()

</div>

---

## 📌 What Is This?

This is a **full-stack AI-powered VAPT (Vulnerability Assessment & Penetration Testing) platform** built from scratch. It combines industry-standard open-source security tools with a custom AI engine to automatically scan targets — files or live URLs — and generate professional vulnerability reports.

**No manual tool juggling. No CLI expertise required. Just upload and scan.**

---

## 🚀 Key Features

| Feature | Description |
|---|---|
| 🔍 **SAST Scanning** | Static analysis of source code for insecure patterns using Semgrep |
| 🌐 **DAST Scanning** | Active web vulnerability testing (XSS, SQLi, CSRF) via OWASP ZAP |
| 🔬 **Binary Analysis** | Reverse-engineered binary scanning with Radare2 & Ghidra |
| 🛡️ **CVE Detection** | Dependency and container vulnerability checks via Trivy |
| ⚡ **Nuclei Templates** | 9000+ vulnerability templates tested against live targets |
| 🤖 **AI Executive Reports** | LLaMA 3 (offline) or Groq API (online) generates analyst-grade summaries |
| 💉 **SQLi Fuzzer** | Custom SQL injection fuzzer with crawler for web targets |
| 🧠 **ML Vulnerability Predictor** | Random Forest classifier trained to detect code-level vulnerabilities |
| 📊 **Export Reports** | Download scan results as JSON or structured text reports |
| 🔄 **Live Scan Logs** | Real-time streamed log feed per scan via REST API |

---

## 🗂️ Project Structure

```
Cyber-Project/
│
├── vapt_v1/                        # Core VAPT Engine (FastAPI backend)
│   ├── app.py                      # Main API server (v1.1.1)
│   ├── ai_engine.py                # LLaMA 3 / Groq AI analysis engine
│   ├── database.py                 # SQLite async database (SQLAlchemy)
│   ├── file_processor.py           # Upload extraction & file preparation
│   ├── scanners/
│   │   ├── orchestrator.py         # Coordinates all scanners
│   │   ├── sast_scanner.py         # Static analysis (Semgrep)
│   │   ├── binary_scanner.py       # Binary analysis (Radare2/Ghidra)
│   │   ├── trivy_scanner.py        # CVE/dependency scanning (Trivy)
│   │   ├── nuclei_scanner.py       # Template-based scanning (Nuclei)
│   │   └── zap_scanner.py          # Web DAST scanning (OWASP ZAP)
│   ├── frontend/                   # Web dashboard UI
│   └── start_vapt.bat              # One-click Windows launcher
│
├── burp_tools/                     # SQL Injection Testing Suite
│   ├── main.py                     # Entry point — crawl & fuzz a URL
│   ├── sqli_fuzzer.py              # Core SQLi payload engine
│   ├── crawler.py                  # URL crawler / endpoint discovery
│   ├── reporter.py                 # HTML & JSON report generation
│   ├── manual_repro.py             # Manual exploit reproduction helper
│   └── sqlmap_runner.py            # SQLMap integration wrapper
│
└── VAPT_ML_Engine/                 # ML-Based Vulnerability Predictor
    ├── train.py                    # Train Random Forest on code snippets
    ├── train_fast.py               # Faster training variant
    ├── predictor.py                # Prediction CLI / module
    ├── predictor_fast.py           # Fast predictor variant
    └── app.py                      # Flask web interface for ML engine
```

---

## 🧰 Tools Integrated

| Tool | Version | Purpose |
|------|---------|---------|
| [Semgrep](https://semgrep.dev) | Latest | SAST — static code analysis |
| [OWASP ZAP](https://zaproxy.org) | 2.17.0 | DAST — active web scanning |
| [Trivy](https://trivy.dev) | Latest | CVE detection in dependencies & containers |
| [Nuclei](https://nuclei.projectdiscovery.io) | Latest | Template-based vulnerability scanning |
| [Radare2](https://rada.re) | Latest | Binary reverse engineering |
| [Ghidra](https://ghidra-sre.org) | 12.0.4 | NSA binary analysis framework |
| [Meta LLaMA 3 8B](https://ai.meta.com/llama/) | Q4_K_M | Offline AI analysis engine |
| [Groq API](https://groq.com) | — | Online AI analysis (fast inference) |

> **Note:** Tools and model files are large binaries excluded from this repo (via `.gitignore`).
> See the **Setup** section below to download them.

---

## ⚙️ Setup & Installation

### Prerequisites
- Python 3.10+
- Windows (primary), Linux support partial
- 8GB+ RAM recommended (for offline LLM)

### 1. Clone the Repository
```bash
git clone https://github.com/Harshil1072006/Cyber-Project.git
cd Cyber-Project
```

### 2. Set Up the VAPT Engine
```bash
cd vapt_v1
python -m venv venv
venv\Scripts\activate
pip install -r requirements.txt
```

### 3. Download Tools (Windows)
```powershell
# Downloads Nuclei, Trivy, ZAP, Radare2, Ghidra automatically
powershell -ExecutionPolicy Bypass -File download_tools.ps1
```

### 4. Download the AI Model (Optional — for offline AI)
```bash
python download_model.py
# Downloads Meta-LLaMA-3-8B-Instruct-Q4_K_M.gguf (~4GB)
# OR set a Groq API key for online mode (free & faster)
```

### 5. Launch the Engine
```bash
# Option A: One-click launcher
start_vapt.bat

# Option B: Manual
uvicorn app:app --host 127.0.0.1 --port 8484 --reload
```

The dashboard will be available at: **http://127.0.0.1:8484**

---

## 🌐 API Reference

| Method | Endpoint | Description |
|--------|----------|-------------|
| `GET` | `/` | Engine health & version |
| `GET` | `/api/health` | Tool availability status |
| `POST` | `/api/scan/upload` | Upload file/archive for scanning |
| `POST` | `/api/scan/url` | Scan a live URL (DAST) |
| `GET` | `/api/scans` | List all scans |
| `GET` | `/api/scan/{id}` | Get scan results + AI report |
| `GET` | `/api/scan/{id}/logs` | Live streaming scan logs |
| `GET` | `/api/scan/{id}/export` | Export as JSON or text |
| `DELETE` | `/api/scan/{id}` | Delete a scan |
| `POST` | `/api/settings/ai` | Configure Groq API key |

---

## 💉 SQLi Fuzzer (burp_tools)

A standalone SQL injection testing suite with a crawler, payload fuzzer, and HTML report generator.

```bash
cd burp_tools
pip install -r requirements.txt

# Crawl and fuzz a target URL
python main.py -u "https://target.example.com/" -o report.html
```

Generates a detailed **HTML report** with all discovered endpoints, payloads tested, and confirmed vulnerabilities.

---

## 🧠 ML Vulnerability Predictor (VAPT_ML_Engine)

A machine learning model trained to classify code snippets as **safe** or **vulnerable**.

```bash
cd VAPT_ML_Engine

# Train the model
python train.py --samples 10000

# Run prediction
python predictor.py

# Or launch the web UI
python app.py
```

Uses **TF-IDF vectorization** + **Random Forest classifier** trained on synthetic safe/vulnerable C code patterns (buffer overflows, format strings, etc.).

---

## 🔄 Scan Modes

| Mode | Description |
|------|-------------|
| **Offline** | SAST + Binary + Trivy only. No network calls. Works on air-gapped systems. |
| **Online** | Full suite: adds Nuclei + ZAP active scanning against live targets. |
| **AI: Offline** | LLaMA 3 runs locally for analysis. Requires the `.gguf` model file. |
| **AI: Online** | Uses Groq API for faster, cloud-based AI analysis. Just add your API key. |

---

## 📋 Requirements

### vapt_v1
```
fastapi>=0.115.0
uvicorn[standard]>=0.34.0
python-multipart>=0.0.20
sqlalchemy>=2.0.38
aiosqlite>=0.21.0
python-magic-bin>=0.4.14
httpx>=0.28.0
pydantic>=2.11.0
```

### burp_tools
```
requests
beautifulsoup4
```

---

## ⚠️ Legal Disclaimer

> This tool is intended **strictly for authorized penetration testing and security research**.
> Only use it on systems and applications you own or have explicit written permission to test.
> Unauthorized use against systems is **illegal** and unethical.
> The authors take no responsibility for misuse.

---

## 👨‍💻 Author

**Harshil** — Cybersecurity Enthusiast & Developer  
🔗 [GitHub](https://github.com/Harshil1072006)

---

<div align="center">

**⭐ Star this repo if you find it useful!**

</div>
