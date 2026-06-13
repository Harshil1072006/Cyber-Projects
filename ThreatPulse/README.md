<div align="center">

# 🔴 ThreatPulse

**Automated Threat Intelligence Pipeline — Collect, Enrich, Score & Alert**

[![Python](https://img.shields.io/badge/Python-3.10+-blue?style=for-the-badge&logo=python)]()
[![Docker](https://img.shields.io/badge/Docker-Compose-2496ED?style=for-the-badge&logo=docker)]()
[![PostgreSQL](https://img.shields.io/badge/Database-PostgreSQL-336791?style=for-the-badge&logo=postgresql)]()
[![Elasticsearch](https://img.shields.io/badge/SIEM-Elasticsearch-005571?style=for-the-badge&logo=elasticsearch)]()
[![Grafana](https://img.shields.io/badge/Viz-Grafana-F46800?style=for-the-badge&logo=grafana)]()
[![Status](https://img.shields.io/badge/Status-Active-brightgreen?style=for-the-badge)]()

</div>

---

## 📌 What Is ThreatPulse?

**ThreatPulse** is a fully automated threat intelligence aggregation and processing platform. Security teams lose hours every day manually checking threat feeds — ThreatPulse eliminates that.

It continuously collects **Indicators of Compromise (IoCs)** from 9 open-source threat intelligence feeds, normalizes and deduplicates them, enriches each IoC with contextual data, dynamically scores them by risk and confidence, and pushes the most dangerous ones to your SIEM for real-time alerting — all automatically.

---

## 🏗️ Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                    THREAT FEEDS (9 Sources)                  │
│  Feodo Tracker │ MalwareBazaar │ URLhaus │ AbuseIPDB        │
│  AlienVault OTX │ PhishTank │ Emerging Threats              │
│  CINS Army │ Blocklist.de                                    │
└─────────────────┬───────────────────────────────────────────┘
                  │  Scheduled Collection (Celery)
                  ▼
┌─────────────────────────────────────────────────────────────┐
│              PROCESSING (Normalize + Deduplicate)            │
│  • IPv6 compression  • Domain lowercasing  • Deduplication  │
└─────────────────┬───────────────────────────────────────────┘
                  │
                  ▼
┌─────────────────────────────────────────────────────────────┐
│                   STORAGE (PostgreSQL)                       │
│           IOCs, enrichment data, scores, metadata           │
└──────┬──────────────────────────┬───────────────────────────┘
       │  Enrichment Workers      │  Scoring Engine
       ▼                          ▼
┌─────────────────┐    ┌──────────────────────────────────────┐
│  AbuseIPDB      │    │  Confidence Score (0-100)            │
│  VirusTotal     │    │  Risk Score (0-100)                  │
│  Shodan         │    │  Based on: feed trust, age,          │
│  ipinfo         │    │  enrichment context, frequency       │
│  DNS / WHOIS    │    └──────────────────────────────────────┘
└─────────────────┘
       │
       ▼
┌─────────────────────────────────────────────────────────────┐
│               OUTPUT & ALERTING                             │
│  Elasticsearch (SIEM) ──── Real-time threat alerts          │
│  Grafana Dashboard ─────── Visual IoC analytics             │
│  Syslog Push ───────────── SIEM integration                 │
└─────────────────────────────────────────────────────────────┘
```

---

## 🌐 Threat Intelligence Sources

| Feed | Type | IoC Types |
|------|------|-----------|
| [Feodo Tracker](https://feodotracker.abuse.ch) | Botnet C2 | IPs |
| [MalwareBazaar](https://bazaar.abuse.ch) | Malware Samples | Hashes, URLs |
| [URLhaus](https://urlhaus.abuse.ch) | Malware URLs | URLs |
| [AbuseIPDB](https://www.abuseipdb.com) | Reported IPs | IPs |
| [AlienVault OTX](https://otx.alienvault.com) | Community Intel | IPs, Domains, Hashes |
| [PhishTank](https://phishtank.org) | Phishing Sites | URLs |
| [Emerging Threats](https://rules.emergingthreats.net) | Network Rules | IPs |
| [CINS Army](https://cinsscore.com) | Bad Actors | IPs |
| [Blocklist.de](https://www.blocklist.de) | Attack IPs | IPs |

---

## 📁 Project Structure

```
ThreatPulse/
│
├── src/
│   ├── collectors/             # One collector per threat feed
│   │   ├── base_collector.py   # Abstract base class
│   │   ├── feodo_tracker.py
│   │   ├── malware_bazaar.py
│   │   ├── urlhaus.py
│   │   ├── abuseipdb.py
│   │   ├── alienvault_otx.py
│   │   ├── phishtank.py
│   │   ├── emerging_threats.py
│   │   ├── cins_army.py
│   │   └── blocklist_de.py
│   │
│   ├── processor/              # Data normalization & deduplication
│   │   ├── cleaner.py
│   │   ├── deduplicator.py
│   │   ├── validator.py
│   │   └── scorer.py
│   │
│   ├── enrichment/             # OSINT enrichment workers
│   │   ├── abuseipdb_enrich.py
│   │   ├── virustotal_enrich.py
│   │   ├── shodan_enrich.py
│   │   ├── ipinfo_enrich.py
│   │   ├── dns_enrich.py
│   │   ├── whois_enrich.py
│   │   └── enrichment_worker.py
│   │
│   ├── scoring/                # Risk & confidence scoring
│   │   ├── risk.py
│   │   └── confidence.py
│   │
│   ├── siem/                   # SIEM push integrations
│   │   ├── elastic_push.py
│   │   └── syslog_push.py
│   │
│   ├── reporting/              # Report generation
│   │   └── report_generator.py
│   │
│   ├── tasks/                  # Celery task orchestration
│   │   ├── celery_app.py
│   │   ├── collect_tasks.py
│   │   ├── enrich_tasks.py
│   │   ├── process_tasks.py
│   │   ├── report_tasks.py
│   │   └── manual_run.py
│   │
│   ├── db/                     # Database models & session
│   │   ├── models.py
│   │   └── session.py
│   │
│   └── config.py               # Centralized configuration
│
├── tests/                      # Unit tests
├── docker-compose.yml          # Full infrastructure stack
├── Dockerfile                  # Application container
├── requirements.txt            # Python dependencies
└── .env.example                # Environment variable template
```

---

## 🚀 Quick Start

### 1. Configure Environment
```bash
cp .env.example .env
# Edit .env — add optional API keys for AbuseIPDB, AlienVault OTX, VirusTotal, Shodan
```

### 2. Launch Infrastructure (Docker)
```bash
docker-compose up -d
# Starts: PostgreSQL, Redis, Elasticsearch, Grafana, Celery
```

### 3. Install Local Dependencies
```bash
python -m venv venv
venv\Scripts\activate     # Windows
# source venv/bin/activate  # Linux/Mac
pip install -r requirements.txt
```

### 4. Run Data Ingest
```bash
python -m src.tasks.manual_run
```

### 5. Access Dashboards
| Service | URL | Credentials |
|---------|-----|-------------|
| Grafana | `http://localhost:3000` | admin / admin |
| Elasticsearch | `http://localhost:9200/threat-intel/_search` | — |

---

## 🧪 Running Tests
```bash
pytest tests/ -v
```

---

<div align="center">
  <i>Continuous threat intelligence. Zero manual effort.</i>
</div>
