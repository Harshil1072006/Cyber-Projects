"""
dns_enrich.py — DNS resolution enrichment for domains and IPs.

Performs forward lookups (A, MX, NS, TXT) for domains and reverse
lookups (PTR) for IPs using the dnspython library.
"""

import logging
from typing import Optional

logger = logging.getLogger(__name__)


def enrich_domain_dns(domain: str) -> dict | None:
    """
    Perform DNS lookups for a domain — A, MX, NS, TXT records.

    Args:
        domain: Domain name to resolve.

    Returns:
        Dict with a_records, mx_records, ns_records, txt_records or None on failure.
    """
    try:
        import dns.resolver
    except ImportError:
        logger.warning("dnspython not installed. Run: pip install dnspython")
        return None

    resolver = dns.resolver.Resolver()
    resolver.lifetime = 5.0  # 5-second timeout per query

    results: dict = {}

    # A records — primary IP resolution
    try:
        a_records = [str(r) for r in resolver.resolve(domain, "A")]
        results["a_records"] = a_records
    except Exception:
        results["a_records"] = []

    # MX records — mail exchange (useful for phishing domain detection)
    try:
        mx_records = [str(r.exchange).rstrip(".") for r in resolver.resolve(domain, "MX")]
        results["mx_records"] = mx_records
    except Exception:
        results["mx_records"] = []

    # NS records — nameservers (detect fast-flux or bulletproof hosting)
    try:
        ns_records = [str(r).rstrip(".") for r in resolver.resolve(domain, "NS")]
        results["ns_records"] = ns_records
    except Exception:
        results["ns_records"] = []

    # TXT records — SPF, DKIM, verification tokens
    try:
        txt_records = [str(r) for r in resolver.resolve(domain, "TXT")]
        results["txt_records"] = txt_records
    except Exception:
        results["txt_records"] = []

    # If nothing resolved at all, return None to avoid storing empty enrichment
    if not any(results.values()):
        logger.debug(f"DNS: No records found for {domain}")
        return None

    return results


def enrich_ip_reverse_dns(ip_address: str) -> dict | None:
    """
    Perform a reverse DNS (PTR) lookup for an IP address.

    Args:
        ip_address: IPv4 or IPv6 address string.

    Returns:
        Dict with ptr_hostname or None on failure.
    """
    try:
        import dns.resolver
        import dns.reversename
    except ImportError:
        logger.warning("dnspython not installed. Run: pip install dnspython")
        return None

    try:
        rev_name = dns.reversename.from_address(ip_address)
        ptr_records = [
            str(r).rstrip(".")
            for r in dns.resolver.resolve(rev_name, "PTR")
        ]
        return {"ptr_hostname": ptr_records[0] if ptr_records else None}
    except Exception as exc:
        logger.debug(f"Reverse DNS failed for {ip_address}: {exc}")
        return None
