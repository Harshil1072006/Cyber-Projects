"""
virustotal_enrich.py — Enrichment via the VirusTotal API v3.

Supports IP addresses, domains, URLs, and file hashes.
Returns detection counts and reputation data from the world's
largest multi-engine scanning service.
"""

import hashlib
import logging
import requests

from src.config import VIRUSTOTAL_API_KEY, HTTP_TIMEOUT

logger = logging.getLogger(__name__)

VT_BASE_URL = "https://www.virustotal.com/api/v3"


def _vt_headers() -> dict:
    return {"x-apikey": VIRUSTOTAL_API_KEY, "Accept": "application/json"}


def _is_configured() -> bool:
    return bool(VIRUSTOTAL_API_KEY and not VIRUSTOTAL_API_KEY.startswith("your_"))


def enrich_ip_virustotal(ip_address: str) -> dict | None:
    """Enrich an IP address via VirusTotal."""
    if not _is_configured():
        logger.debug("VirusTotal API key not configured. Skipping IP enrichment.")
        return None

    url = f"{VT_BASE_URL}/ip_addresses/{ip_address}"
    return _fetch_vt_result(url, "ip", ip_address)


def enrich_domain_virustotal(domain: str) -> dict | None:
    """Enrich a domain via VirusTotal."""
    if not _is_configured():
        logger.debug("VirusTotal API key not configured. Skipping domain enrichment.")
        return None

    url = f"{VT_BASE_URL}/domains/{domain}"
    return _fetch_vt_result(url, "domain", domain)


def enrich_hash_virustotal(file_hash: str) -> dict | None:
    """Enrich a file hash (MD5/SHA1/SHA256) via VirusTotal."""
    if not _is_configured():
        logger.debug("VirusTotal API key not configured. Skipping hash enrichment.")
        return None

    url = f"{VT_BASE_URL}/files/{file_hash}"
    return _fetch_vt_result(url, "hash", file_hash)


def enrich_url_virustotal(target_url: str) -> dict | None:
    """Enrich a URL via VirusTotal (uses URL ID = base64url of the URL)."""
    if not _is_configured():
        logger.debug("VirusTotal API key not configured. Skipping URL enrichment.")
        return None

    import base64
    url_id = base64.urlsafe_b64encode(target_url.encode()).decode().rstrip("=")
    url = f"{VT_BASE_URL}/urls/{url_id}"
    return _fetch_vt_result(url, "url", target_url)


def _fetch_vt_result(endpoint: str, ioc_type: str, ioc_value: str) -> dict | None:
    """Shared fetch logic for all VirusTotal endpoints."""
    try:
        response = requests.get(endpoint, headers=_vt_headers(), timeout=HTTP_TIMEOUT)

        if response.status_code == 404:
            logger.debug(f"VirusTotal has no record for {ioc_type}: {ioc_value[:60]}")
            return None

        if response.status_code == 429:
            logger.warning("VirusTotal rate limit hit. Back off and retry later.")
            return None

        response.raise_for_status()
        data = response.json().get("data", {}).get("attributes", {})

        last_analysis = data.get("last_analysis_stats", {})
        malicious = last_analysis.get("malicious", 0)
        total_engines = sum(last_analysis.values()) if last_analysis else 0

        return {
            "vt_detections": malicious,
            "vt_total_engines": total_engines,
            # Normalise to 0-100 reputation scale
            "reputation_score": round((malicious / total_engines) * 100, 1)
            if total_engines > 0
            else 0.0,
            "country_code": data.get("country"),          # IPs only
            "asn": str(data.get("asn", "")) or None,      # IPs only
        }

    except Exception as exc:
        logger.error(f"VirusTotal enrichment failed for {ioc_type} '{ioc_value[:60]}': {exc}")
        return None
