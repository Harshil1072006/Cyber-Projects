"""
reporter.py — Generates HTML and JSON reports from SQLi findings.

HTML report uses a dark, terminal-inspired theme with per-severity
border colours (red = CRITICAL, orange = HIGH).
"""

import json
import html
from datetime import datetime
from typing import Optional


def generate_report(
    findings: list[dict],
    output_filename: str = "sqli_report.html",
) -> None:
    """
    Write an HTML report and a companion JSON report.

    Parameters
    ----------
    findings        : List of finding dicts produced by SQLiFuzzer.
    output_filename : Path/name for the HTML file (default: sqli_report.html).
                      The JSON file will use the same stem with .json extension.
    """
    _write_html(findings, output_filename)
    _write_json(findings, output_filename)
    print(f"[reporter] HTML report saved → {output_filename}")


# ---------------------------------------------------------------------------
# HTML generation
# ---------------------------------------------------------------------------

_CSS = """
    * { box-sizing: border-box; margin: 0; padding: 0; }
    body {
        background: #0d0d0d;
        color: #00ff41;
        font-family: 'Courier New', Courier, monospace;
        font-size: 14px;
        padding: 30px;
        line-height: 1.6;
    }
    h1 {
        font-size: 28px;
        letter-spacing: 2px;
        border-bottom: 1px solid #00ff41;
        padding-bottom: 10px;
        margin-bottom: 6px;
        text-shadow: 0 0 8px #00ff41;
    }
    .meta {
        color: #888;
        font-size: 12px;
        margin-bottom: 30px;
    }
    .summary {
        background: #111;
        border: 1px solid #333;
        padding: 12px 18px;
        border-radius: 4px;
        margin-bottom: 30px;
        font-size: 16px;
    }
    .summary span { color: #ff5555; font-weight: bold; }
    .finding {
        background: #0a0a0a;
        border-radius: 6px;
        padding: 18px 22px;
        margin-bottom: 22px;
        border-left: 5px solid #888;
        transition: box-shadow 0.2s;
    }
    .finding:hover { box-shadow: 0 0 12px rgba(0,255,65,0.15); }
    .finding.CRITICAL { border-left-color: #ff3333; }
    .finding.HIGH     { border-left-color: #ff9900; }
    .finding h2 {
        font-size: 16px;
        margin-bottom: 12px;
        letter-spacing: 1px;
    }
    .finding h2 .badge {
        display: inline-block;
        padding: 2px 10px;
        border-radius: 3px;
        font-size: 11px;
        font-weight: bold;
        margin-left: 10px;
        vertical-align: middle;
    }
    .badge.CRITICAL { background: #ff3333; color: #fff; }
    .badge.HIGH     { background: #ff9900; color: #000; }
    table {
        width: 100%;
        border-collapse: collapse;
        margin-top: 6px;
    }
    td {
        padding: 5px 10px;
        vertical-align: top;
        border-bottom: 1px solid #1a1a1a;
    }
    td:first-child {
        color: #888;
        width: 100px;
        white-space: nowrap;
    }
    td:last-child {
        color: #e0ffe0;
        word-break: break-all;
    }
    .payload-cell {
        color: #ff9900 !important;
        font-style: italic;
    }
    .evidence-cell { color: #aaffaa !important; }
    footer {
        margin-top: 40px;
        color: #333;
        font-size: 11px;
        text-align: center;
    }
"""


def _write_html(findings: list[dict], output_filename: str) -> None:
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    total = len(findings)
    critical_count = sum(1 for f in findings if f.get("severity") == "CRITICAL")
    high_count = sum(1 for f in findings if f.get("severity") == "HIGH")

    finding_blocks = []
    for idx, f in enumerate(findings, start=1):
        severity = f.get("severity", "HIGH")
        finding_html = f"""
        <div class="finding {severity}">
            <h2>
                #{idx} &mdash; {html.escape(f.get('type', 'Unknown'))}
                <span class="badge {severity}">{severity}</span>
            </h2>
            <table>
                <tr>
                    <td>URL</td>
                    <td>{html.escape(f.get('url', ''))}</td>
                </tr>
                <tr>
                    <td>Parameter</td>
                    <td>{html.escape(f.get('param', ''))}</td>
                </tr>
                <tr>
                    <td>Payload</td>
                    <td class="payload-cell">{html.escape(f.get('payload', ''))}</td>
                </tr>
                <tr>
                    <td>Evidence</td>
                    <td class="evidence-cell">{html.escape(f.get('evidence', ''))}</td>
                </tr>
            </table>
        </div>"""
        finding_blocks.append(finding_html)

    no_findings_msg = ""
    if total == 0:
        no_findings_msg = (
            '<p style="color:#555;text-align:center;padding:40px 0;">'
            "No SQL injection vulnerabilities detected."
            "</p>"
        )

    html_content = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>SQLi Scan Report — {timestamp}</title>
    <style>{_CSS}</style>
</head>
<body>
    <h1>&#x1F50D; SQL Injection Scan Report</h1>
    <p class="meta">Generated: {timestamp} &nbsp;|&nbsp; For authorized bug bounty use only</p>

    <div class="summary">
        Total findings: <span>{total}</span>
        &nbsp;&nbsp;|&nbsp;&nbsp;
        CRITICAL: <span style="color:#ff3333">{critical_count}</span>
        &nbsp;&nbsp;|&nbsp;&nbsp;
        HIGH: <span style="color:#ff9900">{high_count}</span>
    </div>

    {''.join(finding_blocks)}
    {no_findings_msg}

    <footer>
        Generated by SQLi Scanner &bull; Authorized use only
    </footer>
</body>
</html>"""

    with open(output_filename, "w", encoding="utf-8") as fh:
        fh.write(html_content)


# ---------------------------------------------------------------------------
# JSON generation
# ---------------------------------------------------------------------------

def _write_json(findings: list[dict], html_filename: str) -> None:
    """Save findings as JSON next to the HTML report."""
    stem = html_filename.rsplit(".", 1)[0] if "." in html_filename else html_filename
    json_filename = stem + ".json"

    payload = {
        "generated_at": datetime.now().isoformat(),
        "total_findings": len(findings),
        "findings": findings,
    }

    with open(json_filename, "w", encoding="utf-8") as fh:
        json.dump(payload, fh, indent=2)

    print(f"[reporter] JSON report saved → {json_filename}")
