"""
HTTP Client wrapper.
Provides a pre-configured requests Session.
"""

import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry
from typing import Dict, Any


class HttpClient:
    """Wrapper around requests.Session to provide consistent configuration."""

    @staticmethod
    def get_session(
        timeout: int = 30, auth_headers: Dict[str, str] = None
    ) -> requests.Session:
        """Returns a configured requests session."""
        session = requests.Session()

        # Configure retries
        retry_strategy = Retry(
            total=3,
            backoff_factor=1,
            status_forcelist=[429, 500, 502, 503, 504],
            allowed_methods=["HEAD", "GET", "OPTIONS"],
        )
        adapter = HTTPAdapter(max_retries=retry_strategy)
        session.mount("https://", adapter)
        session.mount("http://", adapter)

        # Disable SSL verification for typical pentest scenarios (optional, but common)
        session.verify = False

        # Suppress insecure request warnings if verify=False
        import urllib3

        urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

        if auth_headers:
            session.headers.update(auth_headers)

        return session
