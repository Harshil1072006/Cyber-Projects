"""
abuseipdb_enrich.py — Enrichment logic using the AbuseIPDB Check API.

Calls the /api/v2/check endpoint to get detailed information about an IP,
such as usage type, country code, and total abuse reports.
"""

import logging
import requests

from src.config import ABUSEIPDB_API_KEY, HTTP_TIMEOUT

logger = logging.getLogger(__name__)

ABUSEIPDB_CHECK_URL = "https://api.abuseipdb.com/api/v2/check"

def enrich_ip_abuseipdb(ip_address: str) -> dict | None:
    """
    Enrich an IP address using AbuseIPDB.
    
    Returns a dict with extracted fields or None if failed.
    """
    if not ABUSEIPDB_API_KEY or ABUSEIPDB_API_KEY.startswith("your_"):
        logger.debug("AbuseIPDB API key not configured. Skipping enrichment.")
        return None
        
    headers = {
        "Key": ABUSEIPDB_API_KEY,
        "Accept": "application/json",
    }
    
    params = {
        "ipAddress": ip_address,
        "maxAgeInDays": 90
    }
    
    try:
        response = requests.get(
            ABUSEIPDB_CHECK_URL, 
            headers=headers, 
            params=params, 
            timeout=HTTP_TIMEOUT
        )
        
        if response.status_code == 429:
            logger.warning("AbuseIPDB rate limit hit during enrichment.")
            return None
            
        response.raise_for_status()
        data = response.json().get("data", {})
        
        return {
            "country_code": data.get("countryCode"),
            "abuse_reports": data.get("totalReports"),
            "usage_type": data.get("usageType"),
            "abuse_confidence_score": data.get("abuseConfidenceScore"),
        }
        
    except Exception as e:
        logger.error(f"Error enriching IP {ip_address} via AbuseIPDB: {e}")
        return None
