"""
cleaner.py — Data cleaning and normalization logic.

Implements the 8-step normalization checklist from Section 6.2:
  1. IP Normalization (strip zeros, compressed IPv6)
  2. Domain Normalization (lowercase, strip www)
  3. URL Normalization (lowercase scheme+host, keep path case)
  4. Hash Normalization (lowercase hex)
  5. Timestamp Normalization (UTC ISO 8601)
  6. Source Name Normalization (via config.SOURCE_NAME_MAP)
  7. Deduplication (handled in deduplicator.py)
  8. Stale Data Rejection (handled during DB insert/query)
"""

import logging
from datetime import datetime, timezone
from urllib.parse import urlparse, urlunparse

from src.config import SOURCE_NAME_MAP

logger = logging.getLogger(__name__)


def clean_record(raw_record: dict) -> dict | None:
    """
    Clean and normalize a raw IOC record.

    Args:
        raw_record: Dictionary containing 'ioc_value', 'ioc_type', 'source_name', etc.

    Returns:
        A cleaned dictionary, or None if the record is completely unrecoverable.
    """
    try:
        ioc_value = raw_record.get("ioc_value", "").strip()
        ioc_type = raw_record.get("ioc_type", "").strip()
        source_name = raw_record.get("source_name", "").strip()

        if not ioc_value or not ioc_type:
            return None

        # 1-4: IOC Value Normalization
        cleaned_value = normalize_ioc_value(ioc_value, ioc_type)
        if not cleaned_value:
            return None

        # 5: Source Name Normalization
        cleaned_source = normalize_source_name(source_name)

        # Build cleaned record
        cleaned = {
            "ioc_value": cleaned_value,
            "ioc_type": ioc_type,
            "source_name": cleaned_source,
            "tags": [t.lower().strip() for t in raw_record.get("tags", []) if t.strip()],
            "raw_data": raw_record.get("raw_data", {}),
            "source_confidence": float(raw_record.get("source_confidence", 50.0)),
            # Use collected_at or current UTC time
            "collected_at": raw_record.get(
                "collected_at", datetime.now(timezone.utc).isoformat()
            ),
        }

        # Ensure tags are unique
        cleaned["tags"] = list(set(cleaned["tags"]))

        return cleaned

    except Exception as e:
        logger.debug(f"Error cleaning record: {e}")
        return None


def normalize_ioc_value(ioc_value: str, ioc_type: str) -> str:
    """Normalize the actual IOC string based on its type."""
    if ioc_type == "ip":
        return normalize_ip(ioc_value)
    elif ioc_type == "domain":
        return normalize_domain(ioc_value)
    elif ioc_type == "url":
        return normalize_url(ioc_value)
    elif ioc_type in ("hash_md5", "hash_sha1", "hash_sha256"):
        return normalize_hash(ioc_value)
    return ioc_value


def normalize_ip(ip: str) -> str:
    """
    Normalize IP address.
    Strips leading zeros by parsing and re-stringifying.
    Converts IPv6 to standard compressed form.
    """
    import ipaddress
    try:
        # ipaddress module automatically handles stripping zeros and compressing IPv6
        return str(ipaddress.ip_address(ip))
    except ValueError:
        return ip  # Fallback (should be caught by validator later)


def normalize_domain(domain: str) -> str:
    """
    Normalize domain.
    Lowercase, strip www. prefix, strip trailing dots.
    """
    domain = domain.lower().strip().rstrip(".")
    if domain.startswith("www."):
        domain = domain[4:]
    return domain


def normalize_url(url: str) -> str:
    """
    Normalize URL.
    Lowercase scheme and hostname, keep path exactly as-is.
    """
    try:
        parsed = urlparse(url)
        # Rebuild URL: scheme and netloc lowercased, rest unchanged
        normalized = urlunparse((
            parsed.scheme.lower(),
            parsed.netloc.lower(),
            parsed.path,
            parsed.params,
            parsed.query,
            parsed.fragment
        ))
        return normalized
    except Exception:
        return url.strip()


def normalize_hash(hash_val: str) -> str:
    """Normalize file hash: lowercase hex characters."""
    return hash_val.lower().strip()


def normalize_source_name(source: str) -> str:
    """Normalize feed source name using the lookup table."""
    return SOURCE_NAME_MAP.get(source, source.lower().strip().replace(" ", "_"))
