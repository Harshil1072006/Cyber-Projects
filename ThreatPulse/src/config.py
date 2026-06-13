"""
config.py — Central configuration for the Threat Intelligence Pipeline.

Loads settings from environment variables (.env file) and provides
constants, feed URLs, trust tiers, and retention policies.
"""

import os
from pathlib import Path
from dotenv import load_dotenv

# ─── Load .env ───────────────────────────────────────────────────────────────

BASE_DIR = Path(__file__).resolve().parent.parent
load_dotenv(BASE_DIR / ".env")


# ─── Database ────────────────────────────────────────────────────────────────

DATABASE_URL = os.getenv(
    "DATABASE_URL",
    "postgresql://tip_user:tip_password@localhost:5432/threat_intel",
)

# ─── Redis ───────────────────────────────────────────────────────────────────

REDIS_URL = os.getenv("REDIS_URL", "redis://localhost:6379/0")

# ─── API Keys ────────────────────────────────────────────────────────────────

ABUSEIPDB_API_KEY = os.getenv("ABUSEIPDB_API_KEY", "")
VIRUSTOTAL_API_KEY = os.getenv("VIRUSTOTAL_API_KEY", "")
ALIENVAULT_OTX_API_KEY = os.getenv("ALIENVAULT_OTX_API_KEY", "")
IPINFO_API_KEY = os.getenv("IPINFO_API_KEY", "")
SHODAN_API_KEY = os.getenv("SHODAN_API_KEY", "")

# ─── SIEM ────────────────────────────────────────────────────────────────────

ELASTICSEARCH_URL = os.getenv("ELASTICSEARCH_URL", "http://localhost:9200")
ELASTICSEARCH_INDEX = os.getenv("ELASTICSEARCH_INDEX", "threat-intel")
SIEM_TYPE = os.getenv("SIEM_TYPE", "elastic")  # 'elastic' | 'wazuh' | 'splunk'

# ─── Logging ─────────────────────────────────────────────────────────────────

LOG_LEVEL = os.getenv("LOG_LEVEL", "INFO")
LOG_DIR = BASE_DIR / "logs"
LOG_DIR.mkdir(exist_ok=True)

# ─── Data Directories ────────────────────────────────────────────────────────

DATA_DIR = BASE_DIR / "data"
RAW_DATA_DIR = DATA_DIR / "raw"
STAGING_DIR = DATA_DIR / "staging"
RAW_DATA_DIR.mkdir(parents=True, exist_ok=True)
STAGING_DIR.mkdir(parents=True, exist_ok=True)

# ─── IOC Retention Windows (days) ────────────────────────────────────────────

RETENTION_DAYS = {
    "ip": int(os.getenv("IOC_RETENTION_DAYS_IP", "30")),
    "domain": int(os.getenv("IOC_RETENTION_DAYS_DOMAIN", "60")),
    "url": int(os.getenv("IOC_RETENTION_DAYS_URL", "7")),
    "hash_md5": int(os.getenv("IOC_RETENTION_DAYS_HASH", "365")),
    "hash_sha1": int(os.getenv("IOC_RETENTION_DAYS_HASH", "365")),
    "hash_sha256": int(os.getenv("IOC_RETENTION_DAYS_HASH", "365")),
}

# ─── Enrichment ──────────────────────────────────────────────────────────────

ENRICHMENT_CACHE_TTL_HOURS = int(os.getenv("ENRICHMENT_CACHE_TTL_HOURS", "24"))

# ─── Feed URLs ───────────────────────────────────────────────────────────────

FEED_URLS = {
    "feodo_tracker": "https://feodotracker.abuse.ch/downloads/ipblocklist.csv",
    "malware_bazaar": "https://mb-api.abuse.ch/api/v1/",
    "urlhaus": "https://urlhaus.abuse.ch/downloads/csv_recent/",
    "abuseipdb": "https://api.abuseipdb.com/api/v2/blacklist",
    "alienvault_otx": "https://otx.alienvault.com/api/v1/indicators/export",
    "phishtank": "http://data.phishtank.com/data/online-valid.csv",
    "emerging_threats": "https://rules.emergingthreats.net/blockrules/compromised-ips.txt",
    "cins_army": "https://cinsscore.com/list/ci-badguys.txt",
    "blocklist_de": "https://lists.blocklist.de/lists/all.txt",
}

# ─── Feed Trust Tiers (Section 4.2 of Blueprint) ────────────────────────────
# Tier 1 = High trust (curated, low FP), Tier 2 = Medium, Tier 3 = Lower

FEED_TRUST_TIERS = {
    "feodo_tracker": 1,       # Expert-curated botnet C2
    "malware_bazaar": 1,      # Verified malware samples
    "abuseipdb": 2,           # Community-validated
    "alienvault_otx": 2,      # Community-driven, validated
    "urlhaus": 2,             # Community-driven
    "phishtank": 2,           # Community-verified phishing
    "emerging_threats": 2,    # IDS/IPS rule sets
    "cins_army": 3,           # Broad scanner list
    "blocklist_de": 3,        # Generic attack IPs
}

# Points awarded per trust tier (used in confidence scoring)
TRUST_TIER_POINTS = {
    1: 30,  # Tier 1 → +30 points
    2: 20,  # Tier 2 → +20 points
    3: 10,  # Tier 3 → +10 points
}

# Feeds known for low false positive rates (bonus in scoring)
LOW_FP_FEEDS = {"feodo_tracker", "malware_bazaar"}

# ─── Feed Collection Schedules ───────────────────────────────────────────────

COLLECTION_SCHEDULE = {
    "hourly": ["urlhaus", "phishtank"],
    "every_6h": ["abuseipdb", "alienvault_otx"],
    "daily": [
        "feodo_tracker",
        "malware_bazaar",
        "blocklist_de",
        "cins_army",
        "emerging_threats",
    ],
}

# ─── Source Name Normalization Lookup (Section 6 — Step 7) ────────────────────

SOURCE_NAME_MAP = {
    "feodo": "feodo_tracker",
    "feodo_tracker": "feodo_tracker",
    "feodotracker": "feodo_tracker",
    "Feodo": "feodo_tracker",
    "malwarebazaar": "malware_bazaar",
    "malware_bazaar": "malware_bazaar",
    "MalwareBazaar": "malware_bazaar",
    "urlhaus": "urlhaus",
    "URLhaus": "urlhaus",
    "abuseipdb": "abuseipdb",
    "AbuseIPDB": "abuseipdb",
    "alienvault": "alienvault_otx",
    "alienvault_otx": "alienvault_otx",
    "AlienVault": "alienvault_otx",
    "otx": "alienvault_otx",
    "phishtank": "phishtank",
    "PhishTank": "phishtank",
    "emerging_threats": "emerging_threats",
    "emergingthreats": "emerging_threats",
    "cins": "cins_army",
    "cins_army": "cins_army",
    "CINS": "cins_army",
    "blocklist_de": "blocklist_de",
    "blocklist": "blocklist_de",
    "Blocklist.de": "blocklist_de",
}

# ─── HTTP Settings ───────────────────────────────────────────────────────────

HTTP_TIMEOUT = 30  # seconds
MAX_RETRIES = 3
RETRY_BACKOFF = [60, 300, 900]  # 1 min, 5 min, 15 min

# ─── Scoring Thresholds (Section 9.4) ────────────────────────────────────────

SCORE_ACTIONS = {
    "critical": {"risk_min": 80, "confidence_min": 70, "action": "Block + Alert + Escalate"},
    "high":     {"risk_min": 60, "confidence_min": 50, "action": "Alert within 1h + Investigate"},
    "medium":   {"risk_min": 40, "confidence_min": 30, "action": "Watchlist + Manual review"},
    "low":      {"risk_min": 0,  "confidence_min": 0,  "action": "Store for correlation only"},
}

# ─── IOC Category Risk Points (Section 9.3) ──────────────────────────────────

IOC_CATEGORY_RISK = {
    "ransomware": 40,
    "wiper": 40,
    "botnet_c2": 35,
    "c2": 35,
    "data_exfiltration": 30,
    "exfiltration": 30,
    "phishing": 20,
    "scanner": 10,
    "brute_force": 10,
    "exploit_kit": 25,
    "malware": 30,
    "trojan": 30,
    "dropper": 25,
    "unknown": 5,
}
