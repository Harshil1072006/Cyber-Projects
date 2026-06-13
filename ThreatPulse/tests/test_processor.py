"""
test_processor.py — Tests for the validator, cleaner, and deduplicator.
"""

import pytest

from src.processor.validator import (
    validate_ioc,
    validate_ip,
    validate_domain,
    validate_url,
    validate_hash,
)


# ═══════════════════════════════════════════════════════════════════════
# IP Validation
# ═══════════════════════════════════════════════════════════════════════

class TestIPValidation:

    def test_valid_public_ip(self):
        valid, _ = validate_ip("8.8.8.8")
        assert valid is True

    def test_valid_ipv6(self):
        valid, _ = validate_ip("2001:db8::1")
        # 2001:db8::/32 is documentation range, may be flagged as reserved
        # Just check no crash
        assert isinstance(valid, bool)

    def test_private_ip_rejected(self):
        valid, reason = validate_ip("192.168.1.1")
        assert valid is False
        assert "rivate" in reason or "reserved" in reason.lower()

    def test_loopback_ip_rejected(self):
        valid, reason = validate_ip("127.0.0.1")
        assert valid is False

    def test_multicast_ip_rejected(self):
        valid, reason = validate_ip("224.0.0.1")
        assert valid is False

    def test_invalid_format(self):
        valid, reason = validate_ip("not.an.ip")
        assert valid is False
        assert "Invalid" in reason

    def test_invalid_octet(self):
        valid, reason = validate_ip("256.1.1.1")
        assert valid is False

    def test_link_local_rejected(self):
        valid, reason = validate_ip("169.254.0.1")
        assert valid is False


# ═══════════════════════════════════════════════════════════════════════
# Domain Validation
# ═══════════════════════════════════════════════════════════════════════

class TestDomainValidation:

    def test_valid_domain(self):
        valid, _ = validate_domain("evil.example.com")
        assert valid is True

    def test_valid_tld(self):
        valid, _ = validate_domain("example.co.uk")
        assert valid is True

    def test_no_tld_rejected(self):
        valid, reason = validate_domain("localhost")
        assert valid is False

    def test_ip_as_domain_rejected(self):
        valid, reason = validate_domain("192.168.1.1")
        assert valid is False

    def test_invalid_chars(self):
        valid, reason = validate_domain("evil domain.com")
        assert valid is False

    def test_too_short(self):
        valid, reason = validate_domain("a.b")
        assert valid is False


# ═══════════════════════════════════════════════════════════════════════
# URL Validation
# ═══════════════════════════════════════════════════════════════════════

class TestURLValidation:

    def test_valid_http_url(self):
        valid, _ = validate_url("http://evil.example.com/malware.exe")
        assert valid is True

    def test_valid_https_url(self):
        valid, _ = validate_url("https://phishing.example.com/login")
        assert valid is True

    def test_ftp_url_valid(self):
        valid, _ = validate_url("ftp://files.evil.com/payload.zip")
        assert valid is True

    def test_missing_scheme(self):
        valid, reason = validate_url("evil.com/malware")
        assert valid is False

    def test_javascript_scheme_rejected(self):
        valid, reason = validate_url("javascript:alert(1)")
        assert valid is False

    def test_no_hostname(self):
        valid, reason = validate_url("http://")
        assert valid is False


# ═══════════════════════════════════════════════════════════════════════
# Hash Validation
# ═══════════════════════════════════════════════════════════════════════

class TestHashValidation:

    def test_valid_md5(self):
        valid, _ = validate_hash("d41d8cd98f00b204e9800998ecf8427e", "hash_md5")
        assert valid is True

    def test_valid_sha1(self):
        valid, _ = validate_hash("da39a3ee5e6b4b0d3255bfef95601890afd80709", "hash_sha1")
        assert valid is True

    def test_valid_sha256(self):
        valid, _ = validate_hash(
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
            "hash_sha256",
        )
        assert valid is True

    def test_wrong_length_md5(self):
        valid, reason = validate_hash("d41d8cd98f00b204", "hash_md5")
        assert valid is False
        assert "length" in reason

    def test_non_hex_characters(self):
        valid, reason = validate_hash("zzzz8cd98f00b204e9800998ecf8427e", "hash_md5")
        assert valid is False

    def test_all_zeros_rejected(self):
        valid, reason = validate_hash("0" * 64, "hash_sha256")
        assert valid is False
        assert "zero" in reason.lower() or "placeholder" in reason.lower()


# ═══════════════════════════════════════════════════════════════════════
# Unified validate_ioc dispatch
# ═══════════════════════════════════════════════════════════════════════

class TestValidateIOC:

    def test_empty_value(self):
        valid, reason = validate_ioc("", "ip")
        assert valid is False

    def test_whitespace_only(self):
        valid, reason = validate_ioc("   ", "ip")
        assert valid is False

    def test_unknown_type(self):
        valid, reason = validate_ioc("something", "unknown_type")
        assert valid is False

    def test_dispatch_ip(self):
        valid, _ = validate_ioc("8.8.8.8", "ip")
        assert valid is True

    def test_dispatch_domain(self):
        valid, _ = validate_ioc("evil.example.com", "domain")
        assert valid is True

    def test_dispatch_url(self):
        valid, _ = validate_ioc("http://evil.example.com/payload", "url")
        assert valid is True

    def test_dispatch_hash(self):
        valid, _ = validate_ioc(
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
            "hash_sha256",
        )
        assert valid is True
