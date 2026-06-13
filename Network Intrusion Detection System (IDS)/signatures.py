"""
signatures.py — IDS Attack Signature Database
Defines known attack patterns used by the signature detection engine.
"""

from dataclasses import dataclass, field
from typing import Optional


@dataclass
class Signature:
    """Represents a single attack signature rule."""
    id:          str
    name:        str
    description: str
    severity:    str                    # CRITICAL, HIGH, MEDIUM, LOW
    protocol:    Optional[str]          # TCP, UDP, ICMP, ARP, DNS, or None (any)
    dst_ports:   list[int] = field(default_factory=list)
    src_ports:   list[int] = field(default_factory=list)
    payload_keywords: list[str] = field(default_factory=list)
    category:    str = "generic"


# ─── Signature Database ──────────────────────────────────────

SIGNATURES: list[Signature] = [

    # ── Reconnaissance ────────────────────────────────────────
    Signature(
        id="REC-001",
        name="Nmap SYN Stealth Scan",
        description="Detects Nmap-style SYN scan (half-open TCP connections)",
        severity="MEDIUM",
        protocol="TCP",
        category="recon",
    ),
    Signature(
        id="REC-002",
        name="NULL Scan",
        description="TCP packet with no flags set — used for OS/port fingerprinting",
        severity="MEDIUM",
        protocol="TCP",
        category="recon",
    ),
    Signature(
        id="REC-003",
        name="Xmas Scan",
        description="TCP packet with FIN+PSH+URG flags — used for stealth scanning",
        severity="MEDIUM",
        protocol="TCP",
        category="recon",
    ),

    # ── Brute Force ───────────────────────────────────────────
    Signature(
        id="BF-001",
        name="SSH Brute Force",
        description="Repeated connection attempts on SSH port",
        severity="HIGH",
        protocol="TCP",
        dst_ports=[22],
        category="brute_force",
    ),
    Signature(
        id="BF-002",
        name="FTP Brute Force",
        description="Repeated connection attempts on FTP port",
        severity="HIGH",
        protocol="TCP",
        dst_ports=[21],
        category="brute_force",
    ),
    Signature(
        id="BF-003",
        name="RDP Brute Force",
        description="Repeated connection attempts on RDP port",
        severity="CRITICAL",
        protocol="TCP",
        dst_ports=[3389],
        category="brute_force",
    ),
    Signature(
        id="BF-004",
        name="HTTP Login Brute Force",
        description="Repeated POST requests to login endpoints",
        severity="HIGH",
        protocol="TCP",
        dst_ports=[80, 443, 8080, 8443],
        payload_keywords=["POST /login", "POST /admin", "POST /wp-login"],
        category="brute_force",
    ),

    # ── DoS / DDoS ────────────────────────────────────────────
    Signature(
        id="DOS-001",
        name="SYN Flood",
        description="High volume of TCP SYN packets (potential DDoS)",
        severity="CRITICAL",
        protocol="TCP",
        category="dos",
    ),
    Signature(
        id="DOS-002",
        name="ICMP Flood / Ping Flood",
        description="High volume of ICMP echo requests",
        severity="HIGH",
        protocol="ICMP",
        category="dos",
    ),
    Signature(
        id="DOS-003",
        name="UDP Flood",
        description="High volume of UDP packets to random ports",
        severity="HIGH",
        protocol="UDP",
        category="dos",
    ),

    # ── Exploitation Attempts ─────────────────────────────────
    Signature(
        id="EXP-001",
        name="SQL Injection Attempt (HTTP)",
        description="SQL injection keywords detected in HTTP payload",
        severity="CRITICAL",
        protocol="TCP",
        dst_ports=[80, 443, 8080, 8443],
        payload_keywords=["' OR '1'='1", "UNION SELECT", "1=1--", "DROP TABLE",
                          "xp_cmdshell", "' OR 1=1", "information_schema"],
        category="exploit",
    ),
    Signature(
        id="EXP-002",
        name="XSS Attempt (HTTP)",
        description="Cross-site scripting payload detected in HTTP payload",
        severity="HIGH",
        protocol="TCP",
        dst_ports=[80, 443, 8080, 8443],
        payload_keywords=["<script>", "javascript:", "onerror=", "onload=",
                          "alert(", "document.cookie"],
        category="exploit",
    ),
    Signature(
        id="EXP-003",
        name="Directory Traversal Attempt",
        description="Path traversal sequences detected in HTTP request",
        severity="HIGH",
        protocol="TCP",
        dst_ports=[80, 443, 8080, 8443],
        payload_keywords=["../../../", "..\\..\\", "%2e%2e%2f", "%252e%252e"],
        category="exploit",
    ),
    Signature(
        id="EXP-004",
        name="Shellcode Pattern Detected",
        description="Common shellcode NOP sled or patterns in payload",
        severity="CRITICAL",
        protocol="TCP",
        payload_keywords=["\x90\x90\x90\x90", "/bin/sh", "/bin/bash",
                          "cmd.exe", "powershell -enc"],
        category="exploit",
    ),

    # ── ARP Attacks ───────────────────────────────────────────
    Signature(
        id="ARP-001",
        name="ARP Spoofing / Poisoning",
        description="ARP reply where sender MAC does not match known mapping (potential MitM)",
        severity="CRITICAL",
        protocol="ARP",
        category="mitm",
    ),
    Signature(
        id="ARP-002",
        name="ARP Broadcast Storm",
        description="Excessive ARP broadcast traffic detected",
        severity="HIGH",
        protocol="ARP",
        category="dos",
    ),

    # ── C2 / Exfiltration ─────────────────────────────────────
    Signature(
        id="C2-001",
        name="DNS Tunneling Indicator",
        description="Unusually long DNS query (possible data exfiltration via DNS)",
        severity="HIGH",
        protocol="DNS",
        category="c2",
    ),
    Signature(
        id="C2-002",
        name="Suspicious Outbound Port",
        description="Outbound connection on uncommon/suspicious port",
        severity="MEDIUM",
        protocol="TCP",
        dst_ports=[4444, 5555, 6666, 7777, 8888, 9999, 31337],
        category="c2",
    ),
]


def get_signatures_by_category(category: str) -> list[Signature]:
    return [s for s in SIGNATURES if s.category == category]


def get_signature_by_id(sig_id: str) -> Optional[Signature]:
    for s in SIGNATURES:
        if s.id == sig_id:
            return s
    return None
