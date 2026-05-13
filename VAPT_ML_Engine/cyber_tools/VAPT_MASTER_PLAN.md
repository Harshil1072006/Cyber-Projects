# 🛡️ VAPT Command Center: MASTER PLAN

## 1. Project Goal
To build a premium, local-first intelligence platform that automates the VAPT workflow. The goal is to allow a user to enter a single Target (IP/URL) and receive a correlated, actionable security report without manual CLI interaction.

## 2. The "One-Click" Pipeline Architecture
The core of the system is the **Automated Workflow**. Instead of running tools one-by-one, the system uses "Pipelines":

### Standard "Full Audit" Workflow:
1. **Recon Phase**: `Subfinder` + `Amass` find the attack surface.
2. **Filtering Phase**: `httpx` identifies live web services.
3. **Port Scan Phase**: `Nmap` / `RustScan` identifies open ports and services.
4. **Enrichment Phase**: `WhatWeb` identifies tech stacks (CMS, OS, Apps).
5. **Vulnerability Phase**: `Nuclei` + `Nikto` scan for specific flaws based on the tech stack found.
6. **Correlation Phase**: The engine links an Nmap port to a Nuclei finding and a Searchsploit exploit.

## 3. The "Flag Cockpit" (GUI Tool Configuration)
Each tool will have a dedicated GUI panel that replaces complex terminal flags with intuitive controls:
- **Toggles & Switches**: For binary flags (e.g., Nmap `-sV`, `-O`, `-sC`).
- **Sliders**: For numeric values (e.g., Nmap timing `-T4`).
- **Dropdowns & File Pickers**: For wordlists, protocols, and templates.
- **Live Preview**: A real-time terminal command box that updates as you toggle GUI elements.

## 4. The Tool Library (Integrated CLI Tools)
| Category | Tool | Description |
|---|---|---|
| **Recon** | [Subfinder](https://github.com/projectdiscovery/subfinder) | Rapid subdomain discovery. |
| **Recon** | [Amass](https://github.com/OWASP/Amass) | In-depth asset mapping. |
| **Scanning** | [Nmap](https://nmap.org) | Industry-standard port scanner. |
| **Scanning** | [RustScan](https://github.com/RustScan/RustScan) | Extremely fast port discovery. |
| **Web** | [httpx](https://github.com/projectdiscovery/httpx) | Multi-purpose HTTP toolkit. |
| **Web** | [FFUF](https://github.com/ffuf/ffuf) | High-speed web fuzzing. |
| **Web** | [WhatWeb](https://github.com/urbanadventurer/WhatWeb) | Tech stack identification. |
| **Vuln** | [Nuclei](https://github.com/projectdiscovery/nuclei) | Template-based vulnerability scanner. |
| **Vuln** | [Nikto](https://github.com/sullo/nikto) | Web server security scanner. |
| **Auth** | [Hydra](https://github.com/vanhauser-thc/thc-hydra) | Multi-protocol network logon cracker. |
| **Utils** | [Searchsploit](https://github.com/exploitdb/exploitdb) | ExploitDB search utility. |
| **Utils** | [Hashcat](https://github.com/hashcat/hashcat) | Advanced password recovery. |

## 5. Technical Architecture
### Backend (The Brain)
- **Framework**: FastAPI (Python 3.10+).
- **Orchestration**: `ToolPlugin` base class architecture.
- **Security**: Strict `subprocess.run(array_args)` execution (Zero Shell Injection).
- **Persistence**: SQLite (SQLAlchemy) with a normalized finding schema.

### Frontend (The Dashboard)
- **Framework**: Next.js / React.
- **UI Design**: "Cyber-Premium" (Glassmorphism, Dark Mode, High-Contrast findings).
- **Communication**: WebSockets for real-time tool output streaming.

## 6. Implementation Roadmap
- **Phase 1**: Base Architecture (Plugin system, DB models, Secure runner).
- **Phase 2**: Core Tool Integration (Nmap, Subfinder, httpx).
- **Phase 3**: Correlation Engine (Linking ports to vulnerabilities).
- **Phase 4**: Frontend Development (Dashboard, Live Terminal, Reports).
- **Phase 5**: AI Integration (Result analysis & exploit suggestions).
- **Phase 6**: Burp Suite Bridge (Integration with Burp via Webhooks).
