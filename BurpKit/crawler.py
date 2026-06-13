"""
crawler.py — Domain-scoped web crawler for SQLi scanner.

Discovers endpoints (query-string parameters, HTML forms, cookie params,
and injectable headers) within a single target domain.

New in this version:
  • Records `found_on` — which page each endpoint was discovered from.
  • Configurable `max_pages` to prevent infinite crawls.
  • Optional `expose_cookies` — add each session cookie as a "cookie"
    type endpoint so the fuzzer can test cookie injection.
  • Optional `expose_headers` — add common injectable HTTP headers as
    "header" type endpoints.

Intended for authorized bug bounty use only.
"""

import requests
from bs4 import BeautifulSoup
from urllib.parse import urljoin, urlparse, parse_qs, urlencode
from typing import Optional


# Common injectable HTTP headers to surface as endpoints when
# `expose_headers=True` is passed to the constructor.
INJECTABLE_HEADERS: list[str] = [
    "X-Forwarded-For",
    "X-Forwarded-Host",
    "X-Real-IP",
    "Referer",
    "User-Agent",
    "X-Custom-IP-Authorization",
    "X-Original-URL",
    "X-Rewrite-URL",
    "CF-Connecting-IP",
    "True-Client-IP",
    "Via",
]


class Crawler:
    """Crawls a target domain and collects injectable endpoints."""

    def __init__(
        self,
        base_url: str,
        cookies: Optional[dict] = None,
        headers: Optional[dict] = None,
        max_pages: int = 100,
        expose_cookies: bool = False,
        expose_headers: bool = False,
    ):
        """
        Parameters
        ----------
        base_url        : Target root URL.
        cookies         : Dict of session cookies.
        headers         : Extra request headers.
        max_pages       : Maximum pages to crawl (prevents runaway crawls).
        expose_cookies  : If True, add each cookie as a testable endpoint.
        expose_headers  : If True, add common injectable headers as endpoints.
        """
        self.base_url       = base_url.rstrip("/")
        self.base_domain    = urlparse(base_url).netloc
        self.max_pages      = max_pages
        self.expose_cookies = expose_cookies
        self.expose_headers = expose_headers

        self.session = requests.Session()
        if cookies:
            self.session.cookies.update(cookies)
        if headers:
            self.session.headers.update(headers)

        self.session.headers.setdefault(
            "User-Agent",
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
            "AppleWebKit/537.36 (KHTML, like Gecko) "
            "Chrome/124.0.0.0 Safari/537.36",
        )

        self._visited: set[str]     = set()
        self._endpoint_keys: set    = set()
        self.endpoints: list[dict]  = []

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def crawl(self) -> list[dict]:
        """
        Start crawling from base_url and return all discovered endpoints.
        Also adds cookie/header virtual endpoints if configured.
        """
        self._crawl_url(self.base_url, found_on=self.base_url)

        # --- Cookie injection endpoints ---
        if self.expose_cookies:
            session_cookies = dict(self.session.cookies)
            if session_cookies:
                self._add_endpoint(
                    url=self.base_url,
                    method="GET",
                    params={k: v for k, v in session_cookies.items()},
                    ep_type="cookie",
                    found_on=self.base_url,
                )

        # --- Header injection endpoints ---
        if self.expose_headers:
            self._add_endpoint(
                url=self.base_url,
                method="GET",
                params={h: "" for h in INJECTABLE_HEADERS},
                ep_type="header",
                found_on=self.base_url,
            )

        return self.endpoints

    # ------------------------------------------------------------------
    # Internal crawl engine
    # ------------------------------------------------------------------

    def _crawl_url(self, url: str, found_on: str) -> None:
        """Recursively crawl *url* if it belongs to the target domain."""
        if len(self._visited) >= self.max_pages:
            return

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
        parsed    = urlparse(normalised)
        qs_params = parse_qs(parsed.query, keep_blank_values=True)
        if qs_params:
            flat_params = {k: v[0] for k, v in qs_params.items()}
            self._add_endpoint(normalised, "GET", flat_params, "query_string", found_on=found_on)

        # --- Parse HTML ---
        try:
            soup = BeautifulSoup(response.text, "lxml")
        except Exception:
            return

        # Extract forms
        for form in soup.find_all("form"):
            self._extract_form(normalised, form, page_found_on=found_on)

        # Follow anchor tags
        for anchor in soup.find_all("a", href=True):
            href = anchor["href"].strip()
            if href.startswith(("javascript:", "mailto:", "tel:", "#")):
                continue
            absolute = urljoin(normalised, href)
            self._crawl_url(absolute, found_on=normalised)

    def _extract_form(self, page_url: str, form, page_found_on: str) -> None:
        """Parse a <form> tag and register it as an endpoint."""
        action = form.get("action", "")
        method = (form.get("method", "get") or "get").upper()
        if method not in ("GET", "POST"):
            method = "GET"

        action_url = urljoin(page_url, action) if action else page_url
        action_url = self._normalise(action_url)

        if not self._same_domain(action_url):
            return

        # Try to detect JSON-body forms
        enctype   = (form.get("enctype", "") or "").lower()
        is_json   = "json" in enctype or "application/json" in enctype
        ep_type   = "json_body" if is_json else "form"

        params: dict[str, str] = {}
        for field in form.find_all(["input", "textarea", "select"]):
            name = field.get("name")
            if not name:
                continue
            field_type = (field.get("type") or "text").lower()
            if field_type in ("submit", "button", "image", "file", "reset"):
                continue
            if field.name == "select":
                first_option = field.find("option")
                value = first_option.get("value", "") if first_option else ""
            else:
                value = field.get("value", "")
            params[name] = value or ""

        # Include hidden fields — they are often injectable (e.g. IDOR + SQLi)
        for field in form.find_all("input", type="hidden"):
            name = field.get("name")
            if name:
                params[name] = field.get("value", "") or ""

        if params:
            self._add_endpoint(action_url, method, params, ep_type, found_on=page_found_on)

    def _add_endpoint(
        self, url: str, method: str, params: dict, ep_type: str, found_on: str = ""
    ) -> None:
        """Append a unique endpoint to self.endpoints."""
        key = (url, method, frozenset(params.keys()), ep_type)
        if key in self._endpoint_keys:
            return
        self._endpoint_keys.add(key)
        self.endpoints.append(
            {
                "url":      url,
                "method":   method,
                "params":   params,
                "type":     ep_type,
                "found_on": found_on or url,
            }
        )

    # ------------------------------------------------------------------
    # Utility
    # ------------------------------------------------------------------

    def _same_domain(self, url: str) -> bool:
        parsed = urlparse(url)
        # Also allow subdomains of the target domain
        return (
            parsed.netloc == self.base_domain
            or parsed.netloc.endswith("." + self.base_domain)
        )

    @staticmethod
    def _normalise(url: str) -> str:
        """Strip fragment; rebuild clean URL."""
        try:
            p = urlparse(url)
            return p._replace(fragment="").geturl()
        except Exception:
            return ""
