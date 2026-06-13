# Threat Intelligence Pipeline

**Security teams lose hours every day manually checking threat feeds. This pipeline automates that.**

An automated pipeline that continuously collects, processes, enriches, and delivers information about cyber threats to help a security team detect attacks faster and respond smarter.

## Architecture

1. **Feeds**: 9 Open Source Intelligence (OSINT) Threat Feeds (Feodo Tracker, MalwareBazaar, URLhaus, AbuseIPDB, AlienVault OTX, PhishTank, Emerging Threats, CINS Army, Blocklist.de).
2. **Collection & Processing**: Python collectors run on schedules. Raw data is normalized (IPv6 compression, lowercasing, duplicate merging) and stored in PostgreSQL.
3. **Enrichment**: OSINT worker pulls unenriched IOCs and queries AbuseIPDB for context (Country, ASN, Abuse score).
4. **Scoring**: Confidence (0-100) and Risk (0-100) algorithms dynamically score each IOC based on feed trust, age, and enrichment context.
5. **Output**: 
   - High-confidence IOCs are pushed to **Elasticsearch (SIEM)** for real-time alerting.
   - All data is visualized in **Grafana** directly querying the PostgreSQL database.

## Setup Instructions

1. Clone the repository.
2. Run `cp .env.example .env` and optionally add API keys for AbuseIPDB and AlienVault OTX.
3. Launch the infrastructure:
   ```bash
   docker-compose up -d
   ```
4. Install dependencies locally to run the collectors:
   ```bash
   python -m venv venv
   source venv/bin/activate  # Or venv\Scripts\activate on Windows
   pip install -r requirements.txt
   ```
5. Run the MVP data ingest script:
   ```bash
   python -m src.tasks.manual_run
   ```
6. Access Grafana at `http://localhost:3000` (admin/admin).
7. Access Elasticsearch at `http://localhost:9200/threat-intel/_search`.

## MVP Execution

For demonstration purposes, I have created all components for MVP Steps 1-10. 
You can orchestrate them using a unified entry point script.
