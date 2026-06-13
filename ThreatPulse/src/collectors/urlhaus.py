"""
urlhaus.py — Collector for URLhaus malware distribution URLs.

Source: https://urlhaus.abuse.ch/downloads/csv_recent/
Format: CSV download
IOC Type: URLs (and extracted domains)
Update Frequency: Real-time
API Key: Not required
Trust Tier: 2 (Medium — community-driven, validated)
"""

import csv
import io
import logging
from typing import Any
from urllib.parse import urlparse

import requests

from src.collectors.base_collector import BaseCollector
from src.config import FEED_URLS

logger = logging.getLogger(__name__)


class URLhausCollector(BaseCollector):
    """Collect malware distribution URLs from URLhaus (abuse.ch)."""

    @property
    def feed_name(self) -> str:
        return "urlhaus"

    @property
    def feed_url(self) -> str:
        return FEED_URLS["urlhaus"]

    def parse_response(self, response: requests.Response) -> list[dict[str, Any]]:
        """
        Parse URLhaus CSV response.

        CSV columns: id, dateadded, url, url_status, last_online,
                     threat, tags, urlhaus_link, reporter
        Lines starting with '#' are comments.
        """
        records = []
        content = response.text

        reader = csv.reader(io.StringIO(content))
        for row in reader:
            if not row or row[0].strip().startswith("#"):
                continue

            try:
                if len(row) < 7:
                    continue

                url = row[2].strip().strip('"')
                if not url or not url.startswith(("http://", "https://")):
                    continue

                url_status = row[3].strip().strip('"')
                threat = row[5].strip().strip('"') if len(row) > 5 else "malware"
                tags_raw = row[6].strip().strip('"') if len(row) > 6 else ""
                date_added = row[1].strip().strip('"')

                # Build tags
                tags = ["malware_url"]
                if threat and threat.lower() != "none":
                    tags.append(threat.lower())
                if tags_raw:
                    tags.extend([t.strip().lower() for t in tags_raw.split(",") if t.strip()])

                # Create URL IOC
                record = self._make_record(
                    ioc_value=url,
                    ioc_type="url",
                    tags=list(set(tags)),
                    raw_data={
                        "id": row[0].strip().strip('"'),
                        "dateadded": date_added,
                        "url": url,
                        "url_status": url_status,
                        "threat": threat,
                        "tags": tags_raw,
                        "reporter": row[8].strip().strip('"') if len(row) > 8 else "",
                    },
                )
                records.append(record)

                # Also extract the domain as a separate IOC
                try:
                    parsed = urlparse(url)
                    domain = parsed.hostname
                    if domain and not self._is_ip_address(domain):
                        domain_record = self._make_record(
                            ioc_value=domain.lower(),
                            ioc_type="domain",
                            tags=["malware_hosting"] + tags[1:],
                            raw_data={"extracted_from_url": url},
                        )
                        records.append(domain_record)
                except Exception:
                    pass

            except (IndexError, ValueError) as e:
                logger.debug(f"[{self.feed_name}] Skipping row: {e}")
                continue

        return records

    @staticmethod
    def _is_ip_address(value: str) -> bool:
        """Check if a string looks like an IP address."""
        parts = value.split(".")
        if len(parts) == 4:
            try:
                return all(0 <= int(p) <= 255 for p in parts)
            except ValueError:
                return False
        return False
