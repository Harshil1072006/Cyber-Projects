"""
whois_enrich.py — WHOIS lookup enrichment for domains.

Uses the python-whois library to retrieve registrar, creation date,
expiry date, and nameservers for a domain IOC.
"""

import logging
from datetime import datetime, timezone
from typing import Optional

logger = logging.getLogger(__name__)


def enrich_domain_whois(domain: str) -> dict | None:
    """
    Perform WHOIS lookup on a domain.

    Args:
        domain: The domain name to look up (e.g., "evil.example.com").

    Returns:
        Dict with registrar, whois_created, whois_expires, nameservers or None on failure.
    """
    try:
        import whois  # python-whois package
    except ImportError:
        logger.warning("python-whois not installed. Run: pip install python-whois")
        return None

    try:
        # Strip subdomains for WHOIS lookup — WHOIS operates on registered domains
        parts = domain.split(".")
        if len(parts) > 2:
            registered_domain = ".".join(parts[-2:])
        else:
            registered_domain = domain

        w = whois.whois(registered_domain)

        if not w or not w.domain_name:
            logger.debug(f"WHOIS returned no data for {domain}")
            return None

        # creation_date can be a single datetime or a list of datetimes
        creation_date = w.creation_date
        if isinstance(creation_date, list):
            creation_date = creation_date[0]

        expiry_date = w.expiration_date
        if isinstance(expiry_date, list):
            expiry_date = expiry_date[0]

        # Normalise to aware datetime if naive
        if isinstance(creation_date, datetime) and creation_date.tzinfo is None:
            creation_date = creation_date.replace(tzinfo=timezone.utc)
        if isinstance(expiry_date, datetime) and expiry_date.tzinfo is None:
            expiry_date = expiry_date.replace(tzinfo=timezone.utc)

        # Registrar may also be a list
        registrar = w.registrar
        if isinstance(registrar, list):
            registrar = registrar[0]

        # Nameservers
        name_servers = w.name_servers
        if isinstance(name_servers, str):
            name_servers = [name_servers]
        if isinstance(name_servers, list):
            name_servers = [ns.lower() for ns in name_servers if ns]

        return {
            "whois_registrar": str(registrar)[:500] if registrar else None,
            "whois_created": creation_date,
            "whois_expires": expiry_date,
            "nameservers": name_servers,
        }

    except Exception as exc:
        logger.warning(f"WHOIS lookup failed for {domain}: {exc}")
        return None
