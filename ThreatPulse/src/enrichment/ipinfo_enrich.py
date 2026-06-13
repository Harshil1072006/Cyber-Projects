"""
ipinfo_enrich.py — Geolocation and ASN enrichment via IPinfo API.

IPinfo provides country, region, city, ASN, and org data for IPs.
Free tier: 50,000 requests/month (no key required for basic use).
"""

import logging
import requests

from src.config import IPINFO_API_KEY, HTTP_TIMEOUT

logger = logging.getLogger(__name__)

IPINFO_BASE_URL = "https://ipinfo.io"


def enrich_ip_ipinfo(ip_address: str) -> dict | None:
    """
    Enrich an IP address with geolocation and ASN data via IPinfo.

    Args:
        ip_address: IPv4 or IPv6 address string.

    Returns:
        Dict with country_code, asn, city, org, or None on failure.
    """
    url = f"{IPINFO_BASE_URL}/{ip_address}/json"

    params = {}
    if IPINFO_API_KEY and not IPINFO_API_KEY.startswith("your_"):
        params["token"] = IPINFO_API_KEY

    try:
        response = requests.get(url, params=params, timeout=HTTP_TIMEOUT)

        if response.status_code == 429:
            logger.warning("IPinfo rate limit reached. Skipping this IP.")
            return None

        if response.status_code == 403:
            logger.warning("IPinfo API key invalid or quota exceeded.")
            return None

        response.raise_for_status()
        data = response.json()

        # IPinfo returns "bogon": true for private/reserved IPs
        if data.get("bogon"):
            logger.debug(f"IPinfo: {ip_address} is a bogon (private/reserved). Skipping.")
            return None

        # Parse ASN — IPinfo returns "org" as "AS12345 Some ISP"
        org_field = data.get("org", "")
        asn = org_field.split(" ")[0] if org_field else None       # e.g. "AS15169"
        org_name = " ".join(org_field.split(" ")[1:]) if org_field else None

        return {
            "country_code": data.get("country"),          # "US", "CN", "RU"
            "asn": org_field or None,                      # Full "AS##### OrgName"
            "city": data.get("city"),
            "region": data.get("region"),
            "hostname": data.get("hostname"),
            "org_name": org_name,
        }

    except Exception as exc:
        logger.error(f"IPinfo enrichment failed for {ip_address}: {exc}")
        return None
