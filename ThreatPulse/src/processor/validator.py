"""
validator.py — IOC format validation per Section 3.2 of the blueprint.

Validates:
  - IP: valid octets (0-255), rejects RFC1918 private, loopback, multicast
  - Domain: valid DNS format, minimum one dot, no invalid chars
  - URL: valid scheme + hostname
  - Hash: correct hex length (MD5=32, SHA1=40, SHA256=64), rejects all-zeros
"""

import ipaddress
import logging
import re
from urllib.parse import urlparse

logger = logging.getLogger(__name__)

# ─── Regex Patterns ──────────────────────────────────────────────────────────

# Valid domain characters: letters, digits, hyphens, dots
DOMAIN_REGEX = re.compile(
    r"^(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$"
)

# Valid hex hash patterns
HASH_LENGTHS = {
    "hash_md5": 32,
    "hash_sha1": 40,
    "hash_sha256": 64,
}

HEX_REGEX = re.compile(r"^[a-f0-9]+$")

# ─── Private / Reserved IP Ranges (RFC 1918, loopback, multicast) ────────────

PRIVATE_NETWORKS = [
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("127.0.0.0/8"),       # Loopback
    ipaddress.ip_network("169.254.0.0/16"),     # Link-local
    ipaddress.ip_network("224.0.0.0/4"),        # Multicast
    ipaddress.ip_network("240.0.0.0/4"),        # Reserved
    ipaddress.ip_network("0.0.0.0/8"),          # "This" network
    ipaddress.ip_network("255.255.255.255/32"), # Broadcast
]


def validate_ioc(ioc_value: str, ioc_type: str) -> tuple[bool, str]:
    """
    Validate an IOC value based on its type.

    Args:
        ioc_value: The raw IOC string
        ioc_type: One of 'ip', 'domain', 'url', 'hash_md5', 'hash_sha1', 'hash_sha256'

    Returns:
        (is_valid, reason) — True with empty reason if valid,
                              False with rejection reason if invalid.
    """
    if not ioc_value or not ioc_value.strip():
        return False, "Empty IOC value"

    ioc_value = ioc_value.strip()

    if ioc_type == "ip":
        return validate_ip(ioc_value)
    elif ioc_type == "domain":
        return validate_domain(ioc_value)
    elif ioc_type == "url":
        return validate_url(ioc_value)
    elif ioc_type in HASH_LENGTHS:
        return validate_hash(ioc_value, ioc_type)
    else:
        return False, f"Unknown IOC type: {ioc_type}"


def validate_ip(ip: str) -> tuple[bool, str]:
    """
    Validate an IP address.

    Checks:
      - Valid IPv4 or IPv6 format
      - Not in private/reserved ranges (RFC 1918)
      - Not loopback or multicast
    """
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return False, f"Invalid IP format: {ip}"

    # Reject private and reserved ranges
    if addr.is_private:
        return False, f"Private IP rejected: {ip}"
    if addr.is_loopback:
        return False, f"Loopback IP rejected: {ip}"
    if addr.is_multicast:
        return False, f"Multicast IP rejected: {ip}"
    if addr.is_reserved:
        return False, f"Reserved IP rejected: {ip}"
    if addr.is_link_local:
        return False, f"Link-local IP rejected: {ip}"

    # Additional check against explicit private networks
    for network in PRIVATE_NETWORKS:
        if addr in network:
            return False, f"IP in reserved range {network}: {ip}"

    return True, ""


def validate_domain(domain: str) -> tuple[bool, str]:
    """
    Validate a domain name.

    Checks:
      - Valid DNS format
      - At least one dot (minimum TLD + SLD)
      - No invalid characters
      - Not an IP address
    """
    domain = domain.lower().strip()

    # Must have at least one dot
    if "." not in domain:
        return False, f"Domain missing TLD: {domain}"

    # Check for IP address masquerading as domain
    try:
        ipaddress.ip_address(domain)
        return False, f"IP address, not a domain: {domain}"
    except ValueError:
        pass

    # Validate against DNS regex
    if not DOMAIN_REGEX.match(domain):
        return False, f"Invalid domain format: {domain}"

    # Reject very short domains (likely invalid)
    if len(domain) < 4:
        return False, f"Domain too short: {domain}"

    return True, ""


def validate_url(url: str) -> tuple[bool, str]:
    """
    Validate a URL.

    Checks:
      - Has valid scheme (http/https)
      - Has a hostname
    """
    try:
        parsed = urlparse(url)
    except Exception:
        return False, f"Unparseable URL: {url}"

    if parsed.scheme not in ("http", "https", "ftp"):
        return False, f"Invalid URL scheme: {parsed.scheme}"

    if not parsed.hostname:
        return False, f"URL missing hostname: {url}"

    return True, ""


def validate_hash(hash_value: str, hash_type: str) -> tuple[bool, str]:
    """
    Validate a file hash.

    Checks:
      - Correct length for type (MD5=32, SHA1=40, SHA256=64)
      - Valid hex characters only
      - Not all zeros (placeholder hash)
    """
    hash_value = hash_value.lower().strip()
    expected_length = HASH_LENGTHS.get(hash_type)

    if not expected_length:
        return False, f"Unknown hash type: {hash_type}"

    if len(hash_value) != expected_length:
        return False, (
            f"Hash length {len(hash_value)} != expected {expected_length} "
            f"for {hash_type}"
        )

    if not HEX_REGEX.match(hash_value):
        return False, f"Non-hex characters in hash: {hash_value[:20]}..."

    # Reject all-zero hashes (placeholder values)
    if hash_value == "0" * expected_length:
        return False, "All-zero placeholder hash rejected"

    return True, ""
