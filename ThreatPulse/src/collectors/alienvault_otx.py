"""
alienvault_otx.py — Collector for AlienVault OTX threat intelligence pulses.

Source: https://otx.alienvault.com/api/v1/indicators/export
Format: REST API (JSON)
IOC Type: IPs, Domains, URLs, Hashes (multi-type)
Update Frequency: Daily pulses
API Key: Required (free)
Trust Tier: 2 (Medium — community-driven, validated)
"""

import logging
from typing import Any

import requests

from src.collectors.base_collector import BaseCollector
from src.config import FEED_URLS, ALIENVAULT_OTX_API_KEY

logger = logging.getLogger(__name__)

# OTX pulse subscription endpoint for subscribed pulses
OTX_PULSES_URL = "https://otx.alienvault.com/api/v1/pulses/subscribed"


class AlienVaultOTXCollector(BaseCollector):
    """Collect multi-type IOCs from AlienVault OTX subscribed pulses."""

    @property
    def feed_name(self) -> str:
        return "alienvault_otx"

    @property
    def feed_url(self) -> str:
        return OTX_PULSES_URL

    @property
    def requires_api_key(self) -> bool:
        return True

    @property
    def api_headers(self) -> dict:
        return {
            "X-OTX-API-KEY": ALIENVAULT_OTX_API_KEY,
            "Accept": "application/json",
        }

    def collect(self) -> list[dict[str, Any]]:
        """Override to check for API key before collection."""
        if not ALIENVAULT_OTX_API_KEY or ALIENVAULT_OTX_API_KEY.startswith("your_"):
            logger.warning(
                f"[{self.feed_name}] No API key configured — skipping. "
                "Set ALIENVAULT_OTX_API_KEY in .env"
            )
            return []
        return super().collect()

    def parse_response(self, response: requests.Response) -> list[dict[str, Any]]:
        """
        Parse OTX subscribed pulses response.

        Each pulse contains indicators of various types:
        IPv4, domain, hostname, URL, FileHash-SHA256, etc.
        """
        records = []

        try:
            data = response.json()
        except ValueError:
            logger.error(f"[{self.feed_name}] Invalid JSON response")
            return []

        pulses = data.get("results", [])
        for pulse in pulses:
            pulse_name = pulse.get("name", "unknown_pulse")
            indicators = pulse.get("indicators", [])

            for ind in indicators:
                try:
                    ioc_value = ind.get("indicator", "").strip()
                    ioc_type_raw = ind.get("type", "").strip()

                    if not ioc_value:
                        continue

                    # Map OTX types to our schema types
                    ioc_type = self._map_ioc_type(ioc_type_raw)
                    if not ioc_type:
                        continue

                    tags = list(pulse.get("tags", []))
                    tags = [t.lower() for t in tags if t]

                    record = self._make_record(
                        ioc_value=ioc_value,
                        ioc_type=ioc_type,
                        tags=tags,
                        raw_data={
                            "indicator": ioc_value,
                            "type": ioc_type_raw,
                            "pulse_name": pulse_name,
                            "pulse_id": pulse.get("id", ""),
                            "title": ind.get("title", ""),
                            "description": ind.get("description", ""),
                            "created": ind.get("created", ""),
                        },
                    )
                    records.append(record)

                except Exception as e:
                    logger.debug(f"[{self.feed_name}] Skipping indicator: {e}")
                    continue

        return records

    @staticmethod
    def _map_ioc_type(otx_type: str) -> str | None:
        """Map OTX indicator types to our schema IOC types."""
        mapping = {
            "IPv4": "ip",
            "IPv6": "ip",
            "domain": "domain",
            "hostname": "domain",
            "URL": "url",
            "FileHash-SHA256": "hash_sha256",
            "FileHash-SHA1": "hash_sha1",
            "FileHash-MD5": "hash_md5",
        }
        return mapping.get(otx_type)
