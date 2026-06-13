"""
shodan_enrich.py — Open port and banner enrichment via Shodan InternetDB.

Uses the free Shodan InternetDB endpoint (no API key required) to retrieve
known open ports, CVEs, and tags for an IP address.

Free InternetDB endpoint: https://internetdb.shodan.io/{ip}
"""

import logging
import requests

from src.config import HTTP_TIMEOUT

logger = logging.getLogger(__name__)

SHODAN_INTERNETDB_URL = "https://internetdb.shodan.io"


def enrich_ip_shodan(ip_address: str) -> dict | None:
    """
    Retrieve open ports, known CVEs, and hostnames for an IP via Shodan InternetDB.

    This endpoint is completely free and requires no API key.

    Args:
        ip_address: IPv4 address string.

    Returns:
        Dict with open_ports (list[int]), cves, hostnames, tags — or None on failure.
    """
    url = f"{SHODAN_INTERNETDB_URL}/{ip_address}"

    try:
        response = requests.get(url, timeout=HTTP_TIMEOUT)

        # 404 = IP not in Shodan database (not necessarily malicious)
        if response.status_code == 404:
            logger.debug(f"Shodan InternetDB: No data for {ip_address}")
            return None

        if response.status_code == 429:
            logger.warning("Shodan InternetDB rate limit hit.")
            return None

        response.raise_for_status()
        data = response.json()

        ports = data.get("ports", [])
        cpes = data.get("cpes", [])
        cves = data.get("vulns", [])
        hostnames = data.get("hostnames", [])
        tags = data.get("tags", [])

        return {
            "open_ports": ports,
            "cves": cves,           # List of CVE IDs e.g. ["CVE-2021-44228"]
            "cpes": cpes,           # Software fingerprints
            "hostnames": hostnames,
            "shodan_tags": tags,    # e.g. ["vpn", "self-signed", "eol-product"]
        }

    except Exception as exc:
        logger.error(f"Shodan enrichment failed for {ip_address}: {exc}")
        return None
