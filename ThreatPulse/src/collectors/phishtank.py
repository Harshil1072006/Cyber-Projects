"""
phishtank.py — Collector for PhishTank verified phishing URLs.

Source: http://data.phishtank.com/data/online-valid.csv
Format: CSV download
IOC Type: URLs (phishing)
Update Frequency: Hourly
API Key: Optional
Trust Tier: 2 (Medium — community-verified)
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


class PhishTankCollector(BaseCollector):
    """Collect verified phishing URLs from PhishTank."""

    @property
    def feed_name(self) -> str:
        return "phishtank"

    @property
    def feed_url(self) -> str:
        return FEED_URLS["phishtank"]

    def parse_response(self, response: requests.Response) -> list[dict[str, Any]]:
        """
        Parse PhishTank CSV response.

        CSV columns: phish_id, url, phish_detail_url, submission_time,
                     verified, verification_time, online, target
        """
        records = []
        content = response.text

        reader = csv.DictReader(io.StringIO(content))
        for row in reader:
            try:
                url = row.get("url", "").strip()
                if not url or not url.startswith(("http://", "https://")):
                    continue

                target = row.get("target", "unknown")
                verified = row.get("verified", "")
                online = row.get("online", "")

                tags = ["phishing"]
                if target and target.lower() != "other":
                    tags.append(target.lower())

                record = self._make_record(
                    ioc_value=url,
                    ioc_type="url",
                    tags=tags,
                    raw_data={
                        "phish_id": row.get("phish_id", ""),
                        "url": url,
                        "submission_time": row.get("submission_time", ""),
                        "verified": verified,
                        "verification_time": row.get("verification_time", ""),
                        "online": online,
                        "target": target,
                    },
                )
                records.append(record)

                # Extract domain
                try:
                    parsed = urlparse(url)
                    domain = parsed.hostname
                    if domain:
                        domain_record = self._make_record(
                            ioc_value=domain.lower(),
                            ioc_type="domain",
                            tags=["phishing", "phishing_domain"],
                            raw_data={"extracted_from_url": url},
                        )
                        records.append(domain_record)
                except Exception:
                    pass

            except Exception as e:
                logger.debug(f"[{self.feed_name}] Skipping row: {e}")
                continue

        return records
