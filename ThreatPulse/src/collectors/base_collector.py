"""
base_collector.py — Abstract base class for all feed collectors.

Provides:
  - HTTP fetching with configurable timeout
  - Exponential backoff retry (1m → 5m → 15m) per Section 5.3
  - Structured logging for every fetch attempt
  - Consistent interface: collect() → list of raw IOC dicts
"""

import abc
import json
import logging
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import requests

from src.config import (
    HTTP_TIMEOUT,
    MAX_RETRIES,
    RETRY_BACKOFF,
    RAW_DATA_DIR,
    FEED_TRUST_TIERS,
    TRUST_TIER_POINTS,
)

logger = logging.getLogger(__name__)


class BaseCollector(abc.ABC):
    """
    Abstract base class for all threat feed collectors.

    Subclasses must implement:
        - feed_name: str property
        - feed_url: str property
        - parse_response(response) → list[dict]
    """

    # ─── Properties to override ──────────────────────────────────────────

    @property
    @abc.abstractmethod
    def feed_name(self) -> str:
        """Normalized feed name (e.g., 'feodo_tracker')."""
        ...

    @property
    @abc.abstractmethod
    def feed_url(self) -> str:
        """URL to fetch data from."""
        ...

    @property
    def requires_api_key(self) -> bool:
        """Override and return True if the feed needs an API key."""
        return False

    @property
    def api_headers(self) -> dict:
        """Override to provide custom headers (e.g., API key auth)."""
        return {}

    @property
    def request_method(self) -> str:
        """HTTP method to use. Override for POST-based APIs."""
        return "GET"

    @property
    def request_payload(self) -> dict | None:
        """Override to provide a POST body."""
        return None

    # ─── Core Collection Logic ───────────────────────────────────────────

    def collect(self) -> list[dict[str, Any]]:
        """
        Fetch, parse, and return raw IOC records from this feed.

        Returns a list of dicts, each containing at minimum:
            - ioc_value: str
            - ioc_type: str ('ip', 'domain', 'url', 'hash_sha256', etc.)
            - source_name: str
            - raw_data: dict (original record)
        """
        logger.info(f"[{self.feed_name}] Starting collection from {self.feed_url}")
        response = self._fetch_with_retry()

        if response is None:
            logger.error(f"[{self.feed_name}] Collection failed after all retries")
            return []

        try:
            records = self.parse_response(response)
            logger.info(
                f"[{self.feed_name}] Collected {len(records)} IOCs successfully"
            )
            self._save_raw(records)
            return records
        except Exception as e:
            logger.exception(f"[{self.feed_name}] Parse error: {e}")
            return []

    # ─── Abstract Parse Method ───────────────────────────────────────────

    @abc.abstractmethod
    def parse_response(self, response: requests.Response) -> list[dict[str, Any]]:
        """
        Parse the HTTP response into a list of raw IOC dicts.

        Each dict must contain:
            - ioc_value: the indicator string
            - ioc_type: one of 'ip', 'domain', 'url', 'hash_sha256', etc.
            - source_name: normalized feed name
            - tags: list of string labels
            - raw_data: the original record (for provenance)
        """
        ...

    # ─── HTTP Fetch with Retry ───────────────────────────────────────────

    def _fetch_with_retry(self) -> requests.Response | None:
        """
        Fetch the feed URL with exponential backoff retry.

        Retry schedule (Section 5.3): 1 min → 5 min → 15 min.
        Handles: timeouts, HTTP 429/503, connection errors.
        """
        for attempt in range(MAX_RETRIES):
            try:
                logger.debug(
                    f"[{self.feed_name}] Attempt {attempt + 1}/{MAX_RETRIES}"
                )

                if self.request_method.upper() == "POST":
                    response = requests.post(
                        self.feed_url,
                        headers=self.api_headers,
                        json=self.request_payload,
                        timeout=HTTP_TIMEOUT,
                    )
                else:
                    response = requests.get(
                        self.feed_url,
                        headers=self.api_headers,
                        timeout=HTTP_TIMEOUT,
                    )

                # Rate limit — back off and retry
                if response.status_code == 429:
                    wait = RETRY_BACKOFF[min(attempt, len(RETRY_BACKOFF) - 1)]
                    logger.warning(
                        f"[{self.feed_name}] Rate limited (429). "
                        f"Waiting {wait}s before retry."
                    )
                    time.sleep(wait)
                    continue

                # Server error — retry
                if response.status_code >= 500:
                    wait = RETRY_BACKOFF[min(attempt, len(RETRY_BACKOFF) - 1)]
                    logger.warning(
                        f"[{self.feed_name}] Server error ({response.status_code}). "
                        f"Waiting {wait}s before retry."
                    )
                    time.sleep(wait)
                    continue

                response.raise_for_status()
                return response

            except requests.exceptions.Timeout:
                wait = RETRY_BACKOFF[min(attempt, len(RETRY_BACKOFF) - 1)]
                logger.warning(
                    f"[{self.feed_name}] Timeout after {HTTP_TIMEOUT}s. "
                    f"Waiting {wait}s before retry."
                )
                time.sleep(wait)

            except requests.exceptions.ConnectionError:
                wait = RETRY_BACKOFF[min(attempt, len(RETRY_BACKOFF) - 1)]
                logger.warning(
                    f"[{self.feed_name}] Connection error. "
                    f"Waiting {wait}s before retry."
                )
                time.sleep(wait)

            except requests.exceptions.RequestException as e:
                logger.error(f"[{self.feed_name}] Request failed: {e}")
                return None

        return None

    # ─── Helpers ─────────────────────────────────────────────────────────

    def _save_raw(self, records: list[dict]) -> None:
        """Save raw records to a JSON file for audit/debugging."""
        timestamp = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H%M%S")
        filepath = RAW_DATA_DIR / f"{self.feed_name}_{timestamp}.json"
        try:
            with open(filepath, "w", encoding="utf-8") as f:
                json.dump(records, f, indent=2, default=str)
            logger.debug(f"[{self.feed_name}] Raw data saved to {filepath}")
        except Exception as e:
            logger.warning(f"[{self.feed_name}] Failed to save raw data: {e}")

    def get_trust_tier(self) -> int:
        """Return the trust tier (1/2/3) for this feed."""
        return FEED_TRUST_TIERS.get(self.feed_name, 3)

    def get_source_confidence(self) -> float:
        """Return the confidence points for this feed's trust tier."""
        tier = self.get_trust_tier()
        return float(TRUST_TIER_POINTS.get(tier, 10))

    def _make_record(
        self,
        ioc_value: str,
        ioc_type: str,
        tags: list[str] | None = None,
        raw_data: dict | None = None,
    ) -> dict[str, Any]:
        """Create a standardized IOC record dict."""
        return {
            "ioc_value": ioc_value,
            "ioc_type": ioc_type,
            "source_name": self.feed_name,
            "tags": tags or [],
            "raw_data": raw_data or {},
            "source_confidence": self.get_source_confidence(),
            "collected_at": datetime.now(timezone.utc).isoformat(),
        }
