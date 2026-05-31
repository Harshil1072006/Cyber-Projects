"""
reporter.py — Generates rich HTML and JSON reports from SQLi findings.

Each finding card includes:
  • Severity badge + DB engine badge + confidence badge + CVSS score
  • Injection point detail (where exactly it was found)
  • Raw HTTP request (collapsible)
  • Response snippet (collapsible)
  • curl PoC with copy button
  • Step-by-step manual repro guide
  • sqlmap command
  • Remediation advice
  • CWE-89 link

Report-level features:
  • JS filter buttons (All / CRITICAL / HIGH / by Technique)
  • Summary statistics bar (total, by severity, by engine, by technique)
  • Dark terminal theme
"""

import json
import html as _html
from datetime import datetime
from typing import Optional


def generate_report(
    findings: list[dict],
    output_filename: str = "sqli_report.html",
    target_url: str = "",
) -> None:
    """
    Write an HTML report and a companion JSON report.

    Parameters
    ----------
    findings        : List of finding dicts produced by SQLiFuzzer.
    output_filename : Path for the HTML file (default: sqli_report.html).
    target_url      : The original scan target URL (for the report header).
    """
    _write_html(findings, output_filename, target_url)
    _write_json(findings, output_filename)
    print(f"[reporter] HTML report saved → {output_filename}")


# ---------------------------------------------------------------------------
# CSS
# ---------------------------------------------------------------------------

_CSS = """
    @import url('https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@400;700&family=Inter:wght@400;600;700&display=swap');

    :root {
        --bg:       #0b0d12;
        --bg2:      #10131a;
        --bg3:      #161b27;
        --border:   #1e2535;
        --green:    #00e676;
        --red:      #ff3d3d;
        --orange:   #ff9800;
        --blue:     #40c4ff;
        --purple:   #bb86fc;
        --text:     #cdd6f4;
        --muted:    #585b70;
        --mono:     'JetBrains Mono', 'Courier New', monospace;
        --sans:     'Inter', system-ui, sans-serif;
    }

    * { box-sizing: border-box; margin: 0; padding: 0; }

    body {
        background: var(--bg);
        color: var(--text);
        font-family: var(--sans);
        font-size: 14px;
        line-height: 1.6;
        min-height: 100vh;
    }

    /* ---- Layout ---- */
    .page-wrapper { max-width: 1100px; margin: 0 auto; padding: 36px 24px 80px; }

    /* ---- Header ---- */
    .report-header {
        border-bottom: 1px solid var(--border);
        padding-bottom: 20px;
        margin-bottom: 28px;
    }
    .report-header h1 {
        font-size: 26px;
        font-weight: 700;
        letter-spacing: 1px;
        color: var(--green);
        text-shadow: 0 0 20px rgba(0,230,118,0.3);
        display: flex;
        align-items: center;
        gap: 12px;
    }
    .report-header .meta {
        color: var(--muted);
        font-size: 12px;
        margin-top: 6px;
        font-family: var(--mono);
    }
    .report-header .target-url {
        color: var(--blue);
        font-family: var(--mono);
        font-size: 13px;
        margin-top: 4px;
    }

    /* ---- Summary bar ---- */
    .summary-bar {
        display: grid;
        grid-template-columns: repeat(auto-fit, minmax(140px, 1fr));
        gap: 12px;
        margin-bottom: 28px;
    }
    .stat-card {
        background: var(--bg2);
        border: 1px solid var(--border);
        border-radius: 8px;
        padding: 14px 18px;
        text-align: center;
    }
    .stat-card .num {
        font-size: 28px;
        font-weight: 700;
        font-family: var(--mono);
        line-height: 1;
    }
    .stat-card .label { font-size: 11px; color: var(--muted); margin-top: 4px; text-transform: uppercase; letter-spacing: 0.5px; }
    .stat-card.critical .num { color: var(--red); }
    .stat-card.high     .num { color: var(--orange); }
    .stat-card.total    .num { color: var(--green); }
    .stat-card.blue     .num { color: var(--blue); }

    /* ---- Filter bar ---- */
    .filter-bar {
        display: flex;
        gap: 8px;
        flex-wrap: wrap;
        margin-bottom: 24px;
        align-items: center;
    }
    .filter-bar span { color: var(--muted); font-size: 12px; margin-right: 4px; }
    .filter-btn {
        background: var(--bg3);
        border: 1px solid var(--border);
        color: var(--text);
        padding: 5px 14px;
        border-radius: 20px;
        font-size: 12px;
        cursor: pointer;
        font-family: var(--sans);
        transition: all 0.15s ease;
    }
    .filter-btn:hover, .filter-btn.active {
        background: var(--green);
        color: #000;
        border-color: var(--green);
    }
    .filter-btn.crit-btn.active  { background: var(--red); border-color: var(--red); color: #fff; }
    .filter-btn.high-btn.active  { background: var(--orange); border-color: var(--orange); color: #000; }

    /* ---- Finding card ---- */
    .finding {
        background: var(--bg2);
        border: 1px solid var(--border);
        border-left: 4px solid var(--muted);
        border-radius: 10px;
        margin-bottom: 24px;
        overflow: hidden;
        transition: box-shadow 0.2s;
    }
    .finding:hover { box-shadow: 0 0 24px rgba(0,230,118,0.08); }
    .finding.CRITICAL { border-left-color: var(--red); }
    .finding.HIGH     { border-left-color: var(--orange); }

    .finding-header {
        padding: 16px 20px;
        display: flex;
        align-items: flex-start;
        gap: 12px;
        flex-wrap: wrap;
        border-bottom: 1px solid var(--border);
    }
    .finding-number {
        font-family: var(--mono);
        font-size: 12px;
        color: var(--muted);
        min-width: 30px;
        margin-top: 2px;
    }
    .finding-title {
        font-size: 15px;
        font-weight: 600;
        flex: 1;
        color: var(--text);
    }
    .badges { display: flex; gap: 6px; flex-wrap: wrap; align-items: center; }
    .badge {
        display: inline-block;
        padding: 2px 9px;
        border-radius: 12px;
        font-size: 11px;
        font-weight: 700;
        font-family: var(--mono);
        letter-spacing: 0.3px;
        white-space: nowrap;
    }
    .badge.CRITICAL { background: rgba(255,61,61,0.15); color: var(--red); border: 1px solid rgba(255,61,61,0.4); }
    .badge.HIGH     { background: rgba(255,152,0,0.15); color: var(--orange); border: 1px solid rgba(255,152,0,0.4); }
    .badge.db-engine { background: rgba(64,196,255,0.1); color: var(--blue); border: 1px solid rgba(64,196,255,0.3); }
    .badge.confidence { background: rgba(187,134,252,0.1); color: var(--purple); border: 1px solid rgba(187,134,252,0.3); }
    .badge.cvss { background: rgba(255,61,61,0.1); color: #ff8a80; border: 1px solid rgba(255,61,61,0.2); }
    .badge.cwe  { background: rgba(0,230,118,0.08); color: var(--green); border: 1px solid rgba(0,230,118,0.2); text-decoration: none; }
    .badge.technique { background: rgba(255,152,0,0.1); color: #ffb74d; border: 1px solid rgba(255,152,0,0.2); }

    /* ---- Finding body ---- */
    .finding-body { padding: 16px 20px; }

    /* ---- Info grid ---- */
    .info-grid {
        display: grid;
        grid-template-columns: 120px 1fr;
        gap: 6px 12px;
        margin-bottom: 16px;
        font-size: 13px;
    }
    .info-grid .label { color: var(--muted); font-weight: 600; align-self: start; padding-top: 1px; }
    .info-grid .value { color: var(--text); word-break: break-all; font-family: var(--mono); font-size: 12px; }
    .info-grid .value.url-val { color: var(--blue); }
    .info-grid .value.param-val { color: #f38ba8; }
    .info-grid .value.payload-val { color: var(--orange); }
    .info-grid .value.evidence-val { color: #a6e3a1; }
    .info-grid .value.found-on-val { color: var(--muted); font-size: 11px; font-family: var(--mono); }
    .info-grid .value.req-val { color: var(--purple); font-size: 11px; }

    /* ---- Section headings ---- */
    .section-head {
        font-size: 11px;
        font-weight: 700;
        text-transform: uppercase;
        letter-spacing: 0.8px;
        color: var(--muted);
        margin: 16px 0 8px;
        display: flex;
        align-items: center;
        gap: 8px;
    }
    .section-head::after {
        content: '';
        flex: 1;
        height: 1px;
        background: var(--border);
    }

    /* ---- Collapsible raw request / response ---- */
    .collapsible summary {
        cursor: pointer;
        font-size: 12px;
        color: var(--muted);
        padding: 8px 12px;
        background: var(--bg3);
        border: 1px solid var(--border);
        border-radius: 6px;
        list-style: none;
        display: flex;
        align-items: center;
        gap: 8px;
        user-select: none;
        transition: color 0.15s;
    }
    .collapsible summary:hover { color: var(--green); }
    .collapsible summary::before { content: '▶'; font-size: 9px; transition: transform 0.2s; }
    .collapsible[open] summary::before { transform: rotate(90deg); }
    .collapsible pre {
        background: #060809;
        border: 1px solid var(--border);
        border-top: none;
        border-radius: 0 0 6px 6px;
        padding: 14px 16px;
        font-family: var(--mono);
        font-size: 12px;
        color: #8ec07c;
        overflow-x: auto;
        white-space: pre-wrap;
        word-break: break-all;
        line-height: 1.5;
        max-height: 400px;
        overflow-y: auto;
    }

    /* ---- curl PoC ---- */
    .curl-box {
        background: #060809;
        border: 1px solid var(--border);
        border-radius: 6px;
        padding: 12px 14px;
        display: flex;
        align-items: flex-start;
        gap: 10px;
        margin-bottom: 12px;
    }
    .curl-box code {
        font-family: var(--mono);
        font-size: 12px;
        color: var(--orange);
        flex: 1;
        word-break: break-all;
        white-space: pre-wrap;
    }
    .copy-btn {
        background: var(--bg3);
        border: 1px solid var(--border);
        color: var(--muted);
        padding: 4px 10px;
        border-radius: 4px;
        font-size: 11px;
        cursor: pointer;
        white-space: nowrap;
        transition: all 0.15s;
        font-family: var(--sans);
        flex-shrink: 0;
    }
    .copy-btn:hover { color: var(--green); border-color: var(--green); }
    .copy-btn.copied { color: var(--green); border-color: var(--green); }

    /* ---- Manual repro steps ---- */
    .repro-steps { list-style: none; counter-reset: step-counter; }
    .repro-steps li {
        counter-increment: step-counter;
        display: flex;
        gap: 14px;
        margin-bottom: 12px;
        font-size: 13px;
    }
    .repro-steps li::before {
        content: counter(step-counter);
        background: var(--bg3);
        border: 1px solid var(--border);
        color: var(--green);
        font-family: var(--mono);
        font-size: 11px;
        font-weight: 700;
        min-width: 26px;
        height: 26px;
        border-radius: 50%;
        display: flex;
        align-items: center;
        justify-content: center;
        flex-shrink: 0;
        margin-top: 1px;
    }
    .repro-steps li .step-body {
        background: var(--bg3);
        border: 1px solid var(--border);
        border-radius: 6px;
        padding: 10px 14px;
        flex: 1;
        font-family: var(--mono);
        font-size: 12px;
        color: var(--text);
        white-space: pre-wrap;
        word-break: break-word;
        line-height: 1.6;
    }

    /* ---- sqlmap box ---- */
    .sqlmap-box {
        background: #060809;
        border: 1px solid var(--border);
        border-radius: 6px;
        padding: 12px 14px;
        display: flex;
        align-items: flex-start;
        gap: 10px;
    }
    .sqlmap-box code {
        font-family: var(--mono);
        font-size: 12px;
        color: var(--purple);
        flex: 1;
        word-break: break-all;
    }

    /* ---- Remediation ---- */
    .remediation-box {
        background: rgba(0,230,118,0.04);
        border: 1px solid rgba(0,230,118,0.15);
        border-radius: 6px;
        padding: 12px 16px;
        font-size: 13px;
        color: #a6e3a1;
        margin-bottom: 4px;
    }
    .remediation-box strong { color: var(--green); }

    /* ---- Empty state ---- */
    .no-findings {
        text-align: center;
        padding: 60px 0;
        color: var(--muted);
        font-size: 16px;
    }
    .no-findings .icon { font-size: 48px; margin-bottom: 12px; }

    /* ---- Footer ---- */
    footer {
        margin-top: 60px;
        color: var(--muted);
        font-size: 11px;
        text-align: center;
        font-family: var(--mono);
        border-top: 1px solid var(--border);
        padding-top: 20px;
    }
"""

# ---------------------------------------------------------------------------
# JavaScript (filter buttons + copy-to-clipboard)
# ---------------------------------------------------------------------------

_JS = """
    function filterFindings(btn, severity) {
        document.querySelectorAll('.filter-btn').forEach(b => b.classList.remove('active'));
        btn.classList.add('active');
        document.querySelectorAll('.finding').forEach(f => {
            if (severity === 'ALL' || f.dataset.severity === severity || f.dataset.technique === severity) {
                f.style.display = '';
            } else {
                f.style.display = 'none';
            }
        });
    }

    function copyText(id, btn) {
        const text = document.getElementById(id).textContent;
        navigator.clipboard.writeText(text).then(() => {
            btn.textContent = '✓ Copied!';
            btn.classList.add('copied');
            setTimeout(() => { btn.textContent = 'Copy'; btn.classList.remove('copied'); }, 2000);
        });
    }
"""


# ---------------------------------------------------------------------------
# HTML helpers
# ---------------------------------------------------------------------------

def _e(s: str) -> str:
    """HTML-escape a string."""
    return _html.escape(str(s))


def _severity_class(sev: str) -> str:
    return "CRITICAL" if sev == "CRITICAL" else "HIGH"


def _technique_label(code: str) -> str:
    return {
        "E": "Error-Based",
        "B": "Boolean-Blind",
        "T": "Time-Based",
        "U": "UNION-Based",
        "S": "Stacked-Query",
    }.get(code, code)


def _endpoint_label(ep_type: str) -> str:
    return {
        "query_string": "URL Query String",
        "form":         "HTML Form Field",
        "cookie":       "HTTP Cookie",
        "header":       "HTTP Header",
        "json_body":    "JSON Body Field",
    }.get(ep_type, ep_type or "Parameter")


# ---------------------------------------------------------------------------
# HTML report writer
# ---------------------------------------------------------------------------

def _write_html(
    findings: list[dict], output_filename: str, target_url: str = ""
) -> None:
    timestamp     = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    total         = len(findings)
    critical_count = sum(1 for f in findings if f.get("severity") == "CRITICAL")
    high_count    = sum(1 for f in findings if f.get("severity") == "HIGH")
    unique_dbs    = len({f.get("db_engine", "Unknown") for f in findings} - {"Unknown", "Unknown (blind)"})

    # Technique breakdown
    technique_counts: dict[str, int] = {}
    for f in findings:
        tc = f.get("technique_code", "E")[0].upper()
        technique_counts[tc] = technique_counts.get(tc, 0) + 1

    # Build filter buttons
    filter_btns = [
        '<span>Filter:</span>',
        '<button class="filter-btn active" onclick="filterFindings(this,\'ALL\')">All findings</button>',
    ]
    if critical_count:
        filter_btns.append(
            '<button class="filter-btn crit-btn" onclick="filterFindings(this,\'CRITICAL\')">🔴 CRITICAL</button>'
        )
    if high_count:
        filter_btns.append(
            '<button class="filter-btn high-btn" onclick="filterFindings(this,\'HIGH\')">🟠 HIGH</button>'
        )
    for tc, cnt in technique_counts.items():
        label = _technique_label(tc)
        filter_btns.append(
            f'<button class="filter-btn" onclick="filterFindings(this,\'{_e(tc)}\')">{_e(label)} ({cnt})</button>'
        )

    # Build finding cards
    finding_blocks: list[str] = []
    for idx, f in enumerate(findings, start=1):
        finding_blocks.append(_build_finding_card(idx, f))

    no_findings_html = ""
    if total == 0:
        no_findings_html = (
            '<div class="no-findings">'
            '<div class="icon">✅</div>'
            '<p>No SQL injection vulnerabilities detected.</p>'
            '<p style="font-size:13px;margin-top:8px;color:#585b70;">'
            'This does not guarantee the application is safe — consider expanding scope.</p>'
            '</div>'
        )

    target_line = ""
    if target_url:
        target_line = f'<div class="target-url">Target: {_e(target_url)}</div>'

    stat_cards = f"""
    <div class="summary-bar">
        <div class="stat-card total">
            <div class="num">{total}</div>
            <div class="label">Total Findings</div>
        </div>
        <div class="stat-card critical">
            <div class="num">{critical_count}</div>
            <div class="label">Critical</div>
        </div>
        <div class="stat-card high">
            <div class="num">{high_count}</div>
            <div class="label">High</div>
        </div>
        <div class="stat-card blue">
            <div class="num">{unique_dbs}</div>
            <div class="label">DB Engines</div>
        </div>
        <div class="stat-card blue">
            <div class="num">{len(technique_counts)}</div>
            <div class="label">Techniques</div>
        </div>
    </div>
    """

    html_content = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>SQLi Scan Report — {_e(timestamp)}</title>
    <style>{_CSS}</style>
</head>
<body>
<div class="page-wrapper">

    <div class="report-header">
        <h1>🔍 SQL Injection Scan Report</h1>
        <div class="meta">Generated: {_e(timestamp)} &nbsp;|&nbsp; For authorized bug bounty use only</div>
        {target_line}
    </div>

    {stat_cards}

    <div class="filter-bar">{''.join(filter_btns)}</div>

    {''.join(finding_blocks)}
    {no_findings_html}

    <footer>Generated by SQLi Scanner &bull; Authorized use only &bull; CWE-89</footer>
</div>
<script>{_JS}</script>
</body>
</html>"""

    with open(output_filename, "w", encoding="utf-8") as fh:
        fh.write(html_content)


def _build_finding_card(idx: int, f: dict) -> str:
    severity     = f.get("severity", "HIGH")
    sev_class    = _severity_class(severity)
    tc           = f.get("technique_code", "E")[0].upper()
    db_engine    = f.get("db_engine", "Unknown")
    confidence   = f.get("confidence", "HIGH")
    cvss_score   = f.get("cvss_score", 8.8)
    cwe          = f.get("cwe", "CWE-89")
    cwe_url      = f.get("cwe_url", "https://cwe.mitre.org/data/definitions/89.html")
    req_num      = f.get("request_number", "?")
    ep_type      = f.get("endpoint_type", "query_string")
    found_on     = f.get("found_on", f.get("url", ""))
    raw_request  = f.get("raw_request", "")
    resp_snippet = f.get("response_snippet", "")
    curl_poc     = f.get("curl_poc", "")
    sqlmap_cmd   = f.get("sqlmap_command", "")
    manual_steps = f.get("manual_steps", [])
    remediation  = f.get("remediation", "Use parameterised queries.")

    curl_id   = f"curl-{idx}"
    sqlmap_id = f"sqlmap-{idx}"
    req_id    = f"rawreq-{idx}"
    resp_id   = f"rawresp-{idx}"

    # --- Badges ---
    badges = f"""
        <div class="badges">
            <span class="badge {sev_class}">{_e(severity)}</span>
            <span class="badge technique">{_e(_technique_label(tc))}</span>
            <span class="badge db-engine">🗄 {_e(db_engine)}</span>
            <span class="badge confidence">conf: {_e(confidence)}</span>
            <span class="badge cvss">CVSS {cvss_score}</span>
            <a class="badge cwe" href="{_e(cwe_url)}" target="_blank">{_e(cwe)}</a>
        </div>
    """

    # --- Info grid ---
    info_grid = f"""
        <div class="info-grid">
            <span class="label">URL</span>
            <span class="value url-val">{_e(f.get('url',''))}</span>

            <span class="label">Discovered on</span>
            <span class="value found-on-val">{_e(found_on)}</span>

            <span class="label">Inject point</span>
            <span class="value">{_e(_endpoint_label(ep_type))}</span>

            <span class="label">Parameter</span>
            <span class="value param-val">{_e(f.get('param',''))}</span>

            <span class="label">Payload</span>
            <span class="value payload-val">{_e(f.get('payload',''))}</span>

            <span class="label">Evidence</span>
            <span class="value evidence-val">{_e(f.get('evidence',''))}</span>

            <span class="label">Request #</span>
            <span class="value req-val">Request #{req_num} in scan session</span>
        </div>
    """

    # --- Raw HTTP request collapsible ---
    raw_req_section = ""
    if raw_request:
        raw_req_section = f"""
        <p class="section-head">Raw HTTP Request</p>
        <details class="collapsible">
            <summary>Click to expand raw request sent to server</summary>
            <pre id="{_e(req_id)}">{_e(raw_request)}</pre>
        </details>
        """

    # --- Response snippet collapsible ---
    resp_section = ""
    if resp_snippet:
        resp_section = f"""
        <p class="section-head">Response Snippet</p>
        <details class="collapsible">
            <summary>Click to expand — excerpt around the matched signature</summary>
            <pre id="{_e(resp_id)}">{_e(resp_snippet)}</pre>
        </details>
        """

    # --- curl PoC ---
    curl_section = ""
    if curl_poc:
        curl_section = f"""
        <p class="section-head">curl Proof-of-Concept</p>
        <div class="curl-box">
            <code id="{_e(curl_id)}">{_e(curl_poc)}</code>
            <button class="copy-btn" onclick="copyText('{_e(curl_id)}', this)">Copy</button>
        </div>
        """

    # --- Manual repro steps ---
    repro_section = ""
    if manual_steps:
        step_items = "".join(
            f'<li><div class="step-body">{_e(step)}</div></li>'
            for step in manual_steps
        )
        repro_section = f"""
        <p class="section-head">Step-by-Step Manual Reproduction</p>
        <ol class="repro-steps">{step_items}</ol>
        """

    # --- sqlmap command ---
    sqlmap_section = ""
    if sqlmap_cmd:
        sqlmap_section = f"""
        <p class="section-head">sqlmap — Deep Exploitation Command</p>
        <div class="sqlmap-box">
            <code id="{_e(sqlmap_id)}">{_e(sqlmap_cmd)}</code>
            <button class="copy-btn" onclick="copyText('{_e(sqlmap_id)}', this)">Copy</button>
        </div>
        """

    # --- Remediation ---
    remediation_section = f"""
        <p class="section-head">Remediation</p>
        <div class="remediation-box">
            <strong>🛡 Fix:</strong> {_e(remediation)}
        </div>
    """

    return f"""
    <div class="finding {sev_class}" data-severity="{_e(severity)}" data-technique="{_e(tc)}">
        <div class="finding-header">
            <span class="finding-number">#{idx}</span>
            <span class="finding-title">{_e(f.get('type','Unknown'))}</span>
            {badges}
        </div>
        <div class="finding-body">
            {info_grid}
            {raw_req_section}
            {resp_section}
            {curl_section}
            {repro_section}
            {sqlmap_section}
            {remediation_section}
        </div>
    </div>
    """


# ---------------------------------------------------------------------------
# JSON generation
# ---------------------------------------------------------------------------

def _write_json(findings: list[dict], html_filename: str) -> None:
    """Save findings as JSON next to the HTML report."""
    stem         = html_filename.rsplit(".", 1)[0] if "." in html_filename else html_filename
    json_filename = stem + ".json"

    payload = {
        "generated_at":   datetime.now().isoformat(),
        "total_findings": len(findings),
        "findings":       findings,
    }

    with open(json_filename, "w", encoding="utf-8") as fh:
        json.dump(payload, fh, indent=2)

    print(f"[reporter] JSON report saved → {json_filename}")
