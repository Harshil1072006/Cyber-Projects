"""
The Correlation Engine.
Reads findings for a scan and automatically triggers follow-up tools
based on what was found. Example rules:
  - Port 80/443 found -> trigger httpx and nuclei
  - Subdomain found  -> trigger nmap on that subdomain
"""
from typing import Any


CORRELATION_RULES: list[dict] = [
    {
        "id": "open_web_port",
        "description": "Open web port found -> probe with httpx + nuclei",
        "condition": lambda f: f["type"] == "port" and f.get("port") in (80, 443, 8080, 8443),
        "suggest_tools": [
            {"tool": "httpx",   "auto_options": {"title": True, "tech_detect": True, "status_code": True}},
            {"tool": "nuclei",  "auto_options": {"severities": ["medium", "high", "critical"]}},
        ],
    },
    {
        "id": "open_ssh_port",
        "description": "Open SSH port found -> flag for Hydra brute-force",
        "condition": lambda f: f["type"] == "port" and f.get("service") in ("ssh", "openssh"),
        "suggest_tools": [
            {"tool": "hydra", "auto_options": {"protocol": "ssh"}},
        ],
    },
    {
        "id": "open_ftp_port",
        "description": "Open FTP port found -> flag for Hydra brute-force",
        "condition": lambda f: f["type"] == "port" and f.get("service") == "ftp",
        "suggest_tools": [
            {"tool": "hydra", "auto_options": {"protocol": "ftp"}},
        ],
    },
    {
        "id": "subdomain_found",
        "description": "Subdomain found -> scan with nmap",
        "condition": lambda f: f["type"] == "subdomain",
        "suggest_tools": [
            {"tool": "nmap", "auto_options": {"service_detection": True, "default_scripts": True, "timing": 4}},
        ],
    },
    {
        "id": "live_web_service",
        "description": "Live web service found -> directory fuzz with gobuster",
        "condition": lambda f: f["type"] == "web_service",
        "suggest_tools": [
            {"tool": "gobuster", "auto_options": {"mode": "dir", "threads": 20}},
        ],
    },
]


def correlate(findings: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """
    Iterate over findings and apply correlation rules.
    Returns a list of "suggested actions" that the user can launch with one click.
    """
    suggestions = []
    seen = set()
    for finding in findings:
        for rule in CORRELATION_RULES:
            try:
                if rule["condition"](finding):
                    for suggestion in rule["suggest_tools"]:
                        key = (finding.get("host"), suggestion["tool"], finding.get("port"))
                        if key not in seen:
                            seen.add(key)
                            suggestions.append({
                                "rule_id": rule["id"],
                                "description": rule["description"],
                                "target": finding.get("host"),
                                "tool": suggestion["tool"],
                                "auto_options": suggestion["auto_options"],
                                "triggered_by": finding,
                            })
            except Exception:
                continue
    return suggestions
