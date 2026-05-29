"""
crawler.py — Domain-scoped web crawler for SQLi scanner.

Discovers endpoints (query-string parameters and HTML forms) within a
single target domain. Intended for authorized bug bounty use only.
"""

import requests
from bs4 import BeautifulSoup
from urllib.parse import urljoin, urlparse, parse_qs, urlencode
from typing import Optional


class Crawler:
    """Crawls a target domain and collects injectable endpoints."""

    def __init__(
        self,
        base_url: str,
        cookies: Optional[dict] = None,
        headers: Optional[dict] = None,
    ):
        self.base_url = base_url.rstrip("/")
        self.base_domain = urlparse(base_url).netloc

        self.session = requests.Session()
        if cookies:
            self.session.cookies.update(cookies)
        if headers:
            self.session.headers.update(headers)

        # Sensible browser-like default so targets don't outright reject us
        self.session.headers.setdefault(
            "User-Agent",
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
            "AppleWebKit/537.36 (KHTML, like Gecko) "
            "Chrome/124.0.0.0 Safari/537.36",
        )

        self._visited: set[str] = set()
        self.endpoints: list[dict] = []

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def crawl(self) -> list[dict]:
        """Start crawling from base_url and return all discovered endpoints."""
        self._crawl_url(self.base_url)
        return self.endpoints

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _crawl_url(self, url: str) -> None:
        """Recursively crawl *url* if it belongs to the target domain."""
        # Normalise: strip fragment, collapse trailing slash
        normalised = self._normalise(url)
        if not normalised or normalised in self._visited:
            return
        if not self._same_domain(normalised):
            return

        self._visited.add(normalised)

        try:
            response = self.session.get(normalised, timeout=10, allow_redirects=True)
            response.raise_for_status()
        except requests.RequestException:
            return

        # --- Query-string parameters on the current URL ---
        parsed = urlparse(normalised)
        qs_params = parse_qs(parsed.query, keep_blank_values=True)
        if qs_params:
            flat_params = {k: v[0] for k, v in qs_params.items()}
            self._add_endpoint(normalised, "GET", flat_params, "query_string")

        # --- Parse HTML ---
        try:
            soup = BeautifulSoup(response.text, "lxml")
        except Exception:
            return

        # Extract forms
        for form in soup.find_all("form"):
            self._extract_form(normalised, form)

        # Follow anchor tags
        for anchor in soup.find_all("a", href=True):
            href = anchor["href"].strip()
            if href.startswith(("javascript:", "mailto:", "tel:", "#")):
                continue
            absolute = urljoin(normalised, href)
            self._crawl_url(absolute)

    def _extract_form(self, page_url: str, form) -> None:
        """Parse a <form> tag and register it as an endpoint."""
        action = form.get("action", "")
        method = (form.get("method", "get") or "get").upper()
        if method not in ("GET", "POST"):
            method = "GET"

        # Resolve the action URL relative to the current page
        action_url = urljoin(page_url, action) if action else page_url
        action_url = self._normalise(action_url)

        if not self._same_domain(action_url):
            return

        params: dict[str, str] = {}

        for field in form.find_all(["input", "textarea", "select"]):
            name = field.get("name")
            if not name:
                continue
            field_type = (field.get("type") or "text").lower()
            # Skip submit, button, image, file, reset, hidden (not injectable)
            if field_type in ("submit", "button", "image", "file", "reset"):
                continue
            if field.name == "select":
                # Use first <option> value if present
                first_option = field.find("option")
                value = first_option.get("value", "") if first_option else ""
            else:
                value = field.get("value", "")
            params[name] = value or ""

        if params:
            self._add_endpoint(action_url, method, params, "form")

    def _add_endpoint(
        self, url: str, method: str, params: dict, ep_type: str
    ) -> None:
        """Append a unique endpoint to self.endpoints."""
        # De-duplicate on (url, method, frozenset of param names)
        key = (url, method, frozenset(params.keys()))
        if hasattr(self, "_endpoint_keys"):
            if key in self._endpoint_keys:
                return
        else:
            self._endpoint_keys: set = set()

        self._endpoint_keys.add(key)
        self.endpoints.append(
            {
                "url": url,
                "method": method,
                "params": params,
                "type": ep_type,
            }
        )

    # ------------------------------------------------------------------
    # Utility
    # ------------------------------------------------------------------

    def _same_domain(self, url: str) -> bool:
        parsed = urlparse(url)
        return parsed.netloc == self.base_domain

    @staticmethod
    def _normalise(url: str) -> str:
        """Strip fragment and return lowercase scheme+netloc, original path/query."""
        try:
            p = urlparse(url)
            # Rebuild without fragment
            clean = p._replace(fragment="").geturl()
            return clean
        except Exception:
            return ""
