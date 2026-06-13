"""
config.py — IDS Configuration
All tuneable settings for the Network Intrusion Detection System.
"""

# ─── Network Interface ────────────────────────────────────────
# Set to None to auto-detect, or specify e.g. "eth0", "Ethernet"
INTERFACE = None

# ─── Thresholds ──────────────────────────────────────────────
# Port scan: alert if >N unique ports seen from one IP in TIME_WINDOW seconds
PORT_SCAN_THRESHOLD     = 15      # unique ports
PORT_SCAN_TIME_WINDOW   = 10      # seconds

# Brute force: alert if >N failed login packets from one IP in TIME_WINDOW seconds
BRUTE_FORCE_THRESHOLD   = 20      # packets
BRUTE_FORCE_TIME_WINDOW = 30      # seconds

# DoS / SYN flood: alert if >N SYN packets from one IP in TIME_WINDOW seconds
DOS_SYN_THRESHOLD       = 100     # SYN packets
DOS_TIME_WINDOW         = 5       # seconds

# ICMP flood: alert if >N ICMP requests from one IP in TIME_WINDOW seconds
ICMP_FLOOD_THRESHOLD    = 50      # packets
ICMP_TIME_WINDOW        = 5       # seconds

# ─── Alert Settings ──────────────────────────────────────────
ALERT_TO_CONSOLE = True
ALERT_TO_LOG     = True
LOG_FILE         = "ids_alerts.log"

# Severity levels for console colour
SEVERITY_COLOURS = {
    "CRITICAL": "bold red",
    "HIGH":     "bold yellow",
    "MEDIUM":   "yellow",
    "LOW":      "dim cyan",
    "INFO":     "dim white",
}

# ─── Ports of Interest ───────────────────────────────────────
SENSITIVE_PORTS = {
    21:   "FTP",
    22:   "SSH",
    23:   "Telnet",
    25:   "SMTP",
    53:   "DNS",
    80:   "HTTP",
    110:  "POP3",
    143:  "IMAP",
    443:  "HTTPS",
    445:  "SMB",
    1433: "MSSQL",
    3306: "MySQL",
    3389: "RDP",
    5432: "PostgreSQL",
    5900: "VNC",
    6379: "Redis",
    8080: "HTTP-Alt",
    8443: "HTTPS-Alt",
    27017: "MongoDB",
}

# ─── Whitelist ───────────────────────────────────────────────
# IPs in this list will never trigger alerts
WHITELISTED_IPS = [
    "127.0.0.1",
    "::1",
]

# ─── Capture Filter ──────────────────────────────────────────
# BPF filter applied to packet capture (empty = capture all)
CAPTURE_FILTER = ""
