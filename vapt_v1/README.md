<div align="center">

# 🛡️ VAPT Platform v1

**AI-Powered Vulnerability Assessment & Penetration Testing Platform**

[![Python](https://img.shields.io/badge/Python-3.10+-blue?style=for-the-badge&logo=python)](https://python.org)
[![FastAPI](https://img.shields.io/badge/FastAPI-0.115+-green?style=for-the-badge&logo=fastapi)](https://fastapi.tiangolo.com)
[![React](https://img.shields.io/badge/Frontend-React%20%2B%20Vite-61DAFB?style=for-the-badge&logo=react)]()
[![AI](https://img.shields.io/badge/AI-LLaMA%203%20%7C%20Groq-purple?style=for-the-badge&logo=meta)]()
[![Status](https://img.shields.io/badge/Status-Active-brightgreen?style=for-the-badge)]()

</div>

---

## 📌 What Is VAPT Platform?

**VAPT Platform v1** is a full-stack, AI-enhanced vulnerability assessment and penetration testing solution built from scratch. It orchestrates multiple industry-standard security tools, runs them automatically against a target (uploaded files or live URLs), and uses a **local LLaMA 3 AI model** (or the **Groq API** for online inference) to generate executive-grade, human-readable vulnerability reports.

**No manual tool juggling. No CLI expertise required. Upload and scan.**

---

## ✨ Key Features

| Feature | Description |
|---|---|
| 🔍 **SAST Scanning** | Static code analysis for insecure patterns using Semgrep |
| 🌐 **DAST Scanning** | Active web vulnerability testing (XSS, SQLi, CSRF) via OWASP ZAP |
| 🔬 **Binary Analysis** | Reverse-engineering binary scanning with Radare2 & Ghidra |
| 🛡️ **CVE Detection** | Dependency and container vulnerability checks via Trivy |
| ⚡ **Nuclei Templates** | 9000+ vulnerability templates tested against live targets |
| 🤖 **AI Executive Reports** | LLaMA 3 (offline) or Groq API (online) generates analyst-grade summaries |
| 💉 **SQLi Fuzzer** | Custom SQL injection fuzzer with crawler for web targets |
| 📊 **JSON/Text Export** | Download full scan results as structured reports |
| 🔄 **Live Scan Logs** | Real-time streamed log feed per scan via REST API |
| 🖥️ **Web Dashboard** | Beautiful React + Vite frontend for managing all scans |

---

## 📁 Project Structure

```
vapt_v1/
│
├── app.py                          # Main FastAPI server (v1.1.1)
├── ai_engine.py                    # LLaMA 3 / Groq AI analysis engine
├── database.py                     # SQLite async database (SQLAlchemy)
├── file_processor.py               # Upload extraction & file preparation
│
├── scanners/
│   ├── orchestrator.py             # Coordinates all scanners in sequence
│   ├── sast_scanner.py             # Static analysis (Semgrep)
│   ├── binary_scanner.py           # Binary analysis (Radare2 / Ghidra)
│   ├── trivy_scanner.py            # CVE/dependency scanning (Trivy)
│   ├── nuclei_scanner.py           # Template-based scanning (Nuclei)
│   └── zap_scanner.py              # Web DAST scanning (OWASP ZAP)
│
├── frontend/                       # React + Vite web dashboard
│   ├── src/
│   │   ├── App.jsx                 # Main React application
│   │   └── index.css               # Global styles
│   └── index.html                  # HTML entry point
│
├── tools/                          # Downloaded security tool binaries
├── models/                         # LLaMA 3 model file (.gguf)
├── uploads/                        # Scan upload workspace
│
├── start_vapt.bat                  # One-click Windows launcher
├── download_tools.ps1              # Script to download all tool binaries
└── requirements.txt                # Python dependencies
```

---

## 🚀 Quick Start (Windows)

### 1. Install Python Dependencies
```bash
pip install -r requirements.txt
```

### 2. Download Security Tools
```powershell
# Run in PowerShell (downloads Semgrep, Trivy, Nuclei, ZAP, Radare2, Ghidra)
.\download_tools.ps1
```

### 3. (Optional) Configure AI
- **Offline**: Download the LLaMA 3 8B Q4_K_M model into the `models/` directory
- **Online**: Get a free Groq API key from [console.groq.com](https://console.groq.com) and enter it in the dashboard settings

### 4. Launch the Platform
```bat
start_vapt.bat
```
Then open `http://localhost:8484` in your browser.

---

## 🧰 Integrated Security Tools

| Tool | Purpose |
|------|---------|
| [Semgrep](https://semgrep.dev) | SAST — static code analysis |
| [OWASP ZAP](https://zaproxy.org) | DAST — active web scanning |
| [Trivy](https://trivy.dev) | CVE detection in dependencies & containers |
| [Nuclei](https://nuclei.projectdiscovery.io) | Template-based vulnerability scanning |
| [Radare2](https://rada.re) | Binary reverse engineering |
| [Ghidra](https://ghidra-sre.org) | NSA binary analysis framework |
| [Meta LLaMA 3 8B](https://ai.meta.com/llama/) | Offline AI analysis engine |
| [Groq API](https://groq.com) | Online AI analysis (fast inference) |

> **Note:** Tool binaries and model files are large and excluded from this repo via `.gitignore`. Run `download_tools.ps1` to fetch them automatically.

---

## 🔗 API Endpoints

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/api/health` | GET | Check tool availability status |
| `/api/scan/upload` | POST | Upload a file/archive for scanning |
| `/api/scan/url` | POST | Scan a live URL target |
| `/api/scans` | GET | List all previous scans |
| `/api/scan/{id}` | GET | Get detailed scan results |
| `/api/scan/{id}/logs` | GET | Stream live scan logs |
| `/api/scan/{id}/export` | GET | Export results (JSON/text) |
| `/api/settings/ai` | GET/POST | Configure AI mode and Groq key |

---

<div align="center">
  <i>The future of security testing — automated, intelligent, and accessible.</i>
</div>
