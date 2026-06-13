"""
test_enrichment.py — Tests for enrichment modules using mocked HTTP APIs.
"""

import pytest
import responses

from src.enrichment.virustotal_enrich import (
    enrich_ip_virustotal,
    enrich_domain_virustotal,
    enrich_hash_virustotal,
)
from src.enrichment.ipinfo_enrich import enrich_ip_ipinfo
from src.enrichment.shodan_enrich import enrich_ip_shodan
from src.enrichment.dns_enrich import enrich_domain_dns, enrich_ip_reverse_dns


# ═══════════════════════════════════════════════════════════════════════
# VirusTotal Enrichment
# ═══════════════════════════════════════════════════════════════════════

class TestVirusTotalEnrichment:

    @responses.activate
    def test_vt_ip_enrichment(self, monkeypatch):
        """VirusTotal IP enrichment parses detection stats correctly."""
        monkeypatch.setattr("src.enrichment.virustotal_enrich.VIRUSTOTAL_API_KEY", "test_key")

        responses.add(
            responses.GET,
            "https://www.virustotal.com/api/v3/ip_addresses/198.51.100.1",
            json={
                "data": {
                    "attributes": {
                        "last_analysis_stats": {
                            "malicious": 15,
                            "suspicious": 2,
                            "undetected": 60,
                            "harmless": 3,
                        },
                        "country": "RU",
                        "asn": 12345,
                    }
                }
            },
            status=200,
        )

        result = enrich_ip_virustotal("198.51.100.1")

        assert result is not None
        assert result["vt_detections"] == 15
        assert result["country_code"] == "RU"
        assert result["reputation_score"] > 0

    @responses.activate
    def test_vt_not_found(self, monkeypatch):
        """VirusTotal returns None for unknown IOCs (404)."""
        monkeypatch.setattr("src.enrichment.virustotal_enrich.VIRUSTOTAL_API_KEY", "test_key")

        responses.add(
            responses.GET,
            "https://www.virustotal.com/api/v3/ip_addresses/198.51.100.99",
            status=404,
        )

        result = enrich_ip_virustotal("198.51.100.99")
        assert result is None

    @responses.activate
    def test_vt_rate_limited(self, monkeypatch):
        """VirusTotal rate limit (429) returns None gracefully."""
        monkeypatch.setattr("src.enrichment.virustotal_enrich.VIRUSTOTAL_API_KEY", "test_key")

        responses.add(
            responses.GET,
            "https://www.virustotal.com/api/v3/ip_addresses/198.51.100.1",
            status=429,
        )

        result = enrich_ip_virustotal("198.51.100.1")
        assert result is None

    def test_vt_no_api_key(self, monkeypatch):
        """Skips enrichment when no API key is configured."""
        monkeypatch.setattr("src.enrichment.virustotal_enrich.VIRUSTOTAL_API_KEY", "")
        result = enrich_ip_virustotal("198.51.100.1")
        assert result is None

    @responses.activate
    def test_vt_hash_enrichment(self, monkeypatch):
        """VirusTotal hash enrichment returns detections."""
        monkeypatch.setattr("src.enrichment.virustotal_enrich.VIRUSTOTAL_API_KEY", "test_key")

        test_hash = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        responses.add(
            responses.GET,
            f"https://www.virustotal.com/api/v3/files/{test_hash}",
            json={
                "data": {
                    "attributes": {
                        "last_analysis_stats": {
                            "malicious": 42,
                            "suspicious": 3,
                            "undetected": 25,
                            "harmless": 0,
                        },
                    }
                }
            },
            status=200,
        )

        result = enrich_hash_virustotal(test_hash)
        assert result is not None
        assert result["vt_detections"] == 42


# ═══════════════════════════════════════════════════════════════════════
# IPinfo Enrichment
# ═══════════════════════════════════════════════════════════════════════

class TestIPinfoEnrichment:

    @responses.activate
    def test_ipinfo_enrichment(self):
        """IPinfo returns country and ASN data."""
        responses.add(
            responses.GET,
            "https://ipinfo.io/198.51.100.1/json",
            json={
                "ip": "198.51.100.1",
                "country": "DE",
                "city": "Frankfurt",
                "region": "Hessen",
                "org": "AS12345 Evil Corp Hosting",
                "hostname": "evil.example.com",
            },
            status=200,
        )

        result = enrich_ip_ipinfo("198.51.100.1")

        assert result is not None
        assert result["country_code"] == "DE"
        assert "AS12345" in result["asn"]
        assert result["city"] == "Frankfurt"

    @responses.activate
    def test_ipinfo_bogon(self):
        """IPinfo returns None for bogon (private) IPs."""
        responses.add(
            responses.GET,
            "https://ipinfo.io/192.168.1.1/json",
            json={"ip": "192.168.1.1", "bogon": True},
            status=200,
        )

        result = enrich_ip_ipinfo("192.168.1.1")
        assert result is None

    @responses.activate
    def test_ipinfo_rate_limited(self):
        """IPinfo rate limit returns None."""
        responses.add(
            responses.GET,
            "https://ipinfo.io/198.51.100.1/json",
            status=429,
        )

        result = enrich_ip_ipinfo("198.51.100.1")
        assert result is None


# ═══════════════════════════════════════════════════════════════════════
# Shodan InternetDB
# ═══════════════════════════════════════════════════════════════════════

class TestShodanEnrichment:

    @responses.activate
    def test_shodan_enrichment(self):
        """Shodan InternetDB returns open ports and CVEs."""
        responses.add(
            responses.GET,
            "https://internetdb.shodan.io/198.51.100.1",
            json={
                "ip": "198.51.100.1",
                "ports": [22, 80, 443, 8080],
                "vulns": ["CVE-2021-44228", "CVE-2023-12345"],
                "cpes": ["cpe:/a:apache:http_server:2.4.51"],
                "hostnames": ["evil.example.com"],
                "tags": ["self-signed"],
            },
            status=200,
        )

        result = enrich_ip_shodan("198.51.100.1")

        assert result is not None
        assert 22 in result["open_ports"]
        assert 8080 in result["open_ports"]
        assert "CVE-2021-44228" in result["cves"]
        assert len(result["hostnames"]) == 1

    @responses.activate
    def test_shodan_not_found(self):
        """Shodan returns None for IPs not in their database."""
        responses.add(
            responses.GET,
            "https://internetdb.shodan.io/198.51.100.99",
            status=404,
        )

        result = enrich_ip_shodan("198.51.100.99")
        assert result is None
