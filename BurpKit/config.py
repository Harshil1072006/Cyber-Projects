"""
config.py — BurpKit Centralized Configuration
Override default scanner settings here without touching the CLI.
"""

# ─── Default Scan Settings ────────────────────────────────────
DEFAULT_THREADS   = 5
DEFAULT_TIMEOUT   = 15      # seconds per request
DEFAULT_MAX_PAGES = 100

# ─── Output ───────────────────────────────────────────────────
DEFAULT_REPORT_FILE = "sqli_report.html"

# ─── Extra Injection Surfaces ────────────────────────────────
TEST_COOKIES_DEFAULT = False
TEST_HEADERS_DEFAULT = False

# ─── Additional Custom Payloads ──────────────────────────────
# Add custom payloads here to extend the built-in list.
CUSTOM_PAYLOADS: list[str] = [
    # e.g. "' AND EXTRACTVALUE(1,CONCAT(0x7e,VERSION()))--"
]

# ─── Target Ignore Patterns ──────────────────────────────────
# URLs matching these patterns will be skipped during crawling.
IGNORE_URL_PATTERNS: list[str] = [
    "logout",
    "signout",
    "delete",
    "remove",
    ".pdf",
    ".png",
    ".jpg",
    ".css",
    ".js",
]

# ─── Request Headers ─────────────────────────────────────────
DEFAULT_USER_AGENT = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
    "AppleWebKit/537.36 (KHTML, like Gecko) "
    "Chrome/124.0.0.0 Safari/537.36"
)

EXTRA_HEADERS: dict[str, str] = {
    # "X-Forwarded-For": "127.0.0.1",
}
