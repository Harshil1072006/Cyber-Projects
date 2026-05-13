import re
from typing import Any
from backend.plugins.base_plugin import ToolPlugin


class NmapPlugin(ToolPlugin):
    name = "nmap"
    description = "Port scanner and service/OS detection"

    # Maps GUI option keys to CLI flags
    FLAG_MAP = {
        "service_detection": "-sV",
        "os_detection": "-O",
        "default_scripts": "-sC",
        "skip_host_discovery": "-Pn",
        "aggressive": "-A",
        "udp_scan": "-sU",
        "all_ports": "-p-",
        "vuln_scripts": "--script=vuln",
        "http_enum": "--script=http-enum",
        "smb_scripts": "--script=smb-enum-shares,smb-enum-users",
    }

    TIMING_MAP = {1: "-T1", 2: "-T2", 3: "-T3", 4: "-T4", 5: "-T5"}

    def build_command(self, target: str, options: dict) -> list[str]:
        cmd = ["nmap"]
        # Timing
        timing = options.get("timing", 4)
        cmd.append(self.TIMING_MAP.get(timing, "-T4"))
        # Boolean flags
        for key, flag in self.FLAG_MAP.items():
            if options.get(key):
                cmd.append(flag)
        # Custom ports
        if options.get("ports") and not options.get("all_ports"):
            cmd.extend(["-p", options["ports"]])
        # Output format: always use greppable output for easy parsing
        cmd.extend(["-oG", "-"])
        cmd.append(target)
        return cmd

    def parse_output(self, raw_output: str, target: str) -> list[dict[str, Any]]:
        findings = []
        for line in raw_output.splitlines():
            if line.startswith("#") or not line.strip():
                continue
            # Parse ports: "80/open/tcp//http//Apache httpd 2.4.41/"
            ports_match = re.search(r"Ports:\s(.+)", line)
            host_match = re.search(r"Host:\s(\S+)", line)
            host = host_match.group(1) if host_match else target

            if ports_match:
                port_entries = ports_match.group(1).split(",")
                for entry in port_entries:
                    parts = [p.strip() for p in entry.split("/")]
                    if len(parts) >= 3 and parts[1] == "open":
                        port_num = int(parts[0]) if parts[0].isdigit() else None
                        protocol = parts[2] if len(parts) > 2 else "tcp"
                        service = parts[4] if len(parts) > 4 else ""
                        version = parts[6] if len(parts) > 6 else ""
                        title = f"Open Port {port_num}/{protocol}"
                        if service:
                            title += f" ({service})"
                        if version:
                            title += f" - {version}"
                        findings.append({
                            "type": "port",
                            "severity": "info",
                            "title": title,
                            "host": host,
                            "port": port_num,
                            "protocol": protocol,
                            "service": service,
                            "extra": {"version": version},
                        })
        return findings


class GobusterPlugin(ToolPlugin):
    name = "gobuster"
    description = "Directory and DNS brute-forcing"

    FLAG_MAP = {
        "follow_redirects": "-r",
        "show_status_length": "-l",
        "no_tls_validation": "-k",
        "expanded_mode": "-e",
        "quiet": "-q",
    }

    STATUS_MAP = {
        "common": "200,204,301,302,307,401,403",
        "all": "200,204,301,302,307,401,403,404,500",
        "success_only": "200,204",
    }

    def build_command(self, target: str, options: dict) -> list[str]:
        mode = options.get("mode", "dir")
        cmd = ["gobuster", mode]
        cmd.extend(["-u", target])
        wordlist = options.get("wordlist", "/usr/share/wordlists/dirb/common.txt")
        cmd.extend(["-w", wordlist])
        status_preset = options.get("status_preset", "common")
        cmd.extend(["-s", self.STATUS_MAP.get(status_preset, status_preset)])
        threads = options.get("threads", 10)
        cmd.extend(["-t", str(threads)])
        for key, flag in self.FLAG_MAP.items():
            if options.get(key):
                cmd.append(flag)
        if options.get("extensions"):
            cmd.extend(["-x", options["extensions"]])
        return cmd

    def parse_output(self, raw_output: str, target: str) -> list[dict[str, Any]]:
        findings = []
        for line in raw_output.splitlines():
            line = line.strip()
            if not line or line.startswith("=") or line.startswith("/") is False and "http" not in line:
                continue
            # Lines like: /admin (Status: 200) [Size: 1234]
            m = re.match(r"(\S+)\s+\(Status:\s+(\d+)\)(?:\s+\[Size:\s+(\d+)\])?", line)
            if m:
                path, status_code, size = m.group(1), m.group(2), m.group(3)
                severity = "info" if status_code == "200" else "info"
                if status_code in ("401", "403"):
                    severity = "medium"
                findings.append({
                    "type": "directory",
                    "severity": severity,
                    "title": f"Found: {path} [{status_code}]",
                    "host": target,
                    "extra": {"status_code": status_code, "size": size},
                })
        return findings


class HydraPlugin(ToolPlugin):
    name = "hydra"
    description = "Multi-protocol credential brute-forcing"

    PROTOCOL_OPTIONS = ["ssh", "ftp", "http-get", "http-post-form", "rdp", "smb", "telnet", "mysql", "mssql"]

    def build_command(self, target: str, options: dict) -> list[str]:
        cmd = ["hydra"]
        # Login/password source
        if options.get("username"):
            cmd.extend(["-l", options["username"]])
        elif options.get("username_list"):
            cmd.extend(["-L", options["username_list"]])
        if options.get("password"):
            cmd.extend(["-p", options["password"]])
        elif options.get("password_list"):
            cmd.extend(["-P", options["password_list"]])
        # Threads
        tasks = options.get("tasks", 16)
        cmd.extend(["-t", str(tasks)])
        if options.get("verbose"):
            cmd.append("-v")
        if options.get("stop_on_first"):
            cmd.append("-f")
        cmd.append(target)
        cmd.append(options.get("protocol", "ssh"))
        # Extra service args (e.g. port)
        if options.get("port"):
            cmd.extend(["-s", str(options["port"])])
        return cmd

    def parse_output(self, raw_output: str, target: str) -> list[dict[str, Any]]:
        findings = []
        for line in raw_output.splitlines():
            # "[22][ssh] host: 192.168.1.1   login: admin   password: 1234"
            m = re.search(r"\[(\d+)\]\[(\w+)\].*login:\s*(\S+)\s+password:\s*(\S+)", line)
            if m:
                port, protocol, login, password = m.groups()
                findings.append({
                    "type": "credential",
                    "severity": "critical",
                    "title": f"Valid Credential Found: {login}:{password}",
                    "host": target,
                    "port": int(port),
                    "protocol": protocol,
                    "extra": {"login": login, "password": password},
                })
        return findings


class NucleiPlugin(ToolPlugin):
    name = "nuclei"
    description = "Template-based vulnerability scanner"

    SEVERITY_OPTIONS = ["info", "low", "medium", "high", "critical"]

    FLAG_MAP = {
        "headless": "-headless",
        "no_interactsh": "-no-interactsh",
        "silent": "-silent",
    }

    def build_command(self, target: str, options: dict) -> list[str]:
        cmd = ["nuclei", "-u", target]
        severities = options.get("severities", ["medium", "high", "critical"])
        if severities:
            cmd.extend(["-severity", ",".join(severities)])
        if options.get("templates"):
            cmd.extend(["-t", options["templates"]])
        if options.get("tags"):
            cmd.extend(["-tags", options["tags"]])
        cmd.extend(["-json"])  # Always output JSON for clean parsing
        for key, flag in self.FLAG_MAP.items():
            if options.get(key):
                cmd.append(flag)
        return cmd

    def parse_output(self, raw_output: str, target: str) -> list[dict[str, Any]]:
        import json
        findings = []
        for line in raw_output.splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                data = json.loads(line)
                findings.append({
                    "type": "vuln",
                    "severity": data.get("info", {}).get("severity", "info"),
                    "title": data.get("info", {}).get("name", "Unknown Vulnerability"),
                    "host": data.get("host", target),
                    "description": data.get("info", {}).get("description", ""),
                    "extra": {
                        "template_id": data.get("template-id"),
                        "matcher_name": data.get("matcher-name"),
                        "matched_at": data.get("matched-at"),
                        "tags": data.get("info", {}).get("tags", []),
                        "reference": data.get("info", {}).get("reference", []),
                    },
                })
            except json.JSONDecodeError:
                continue
        return findings


class SubfinderPlugin(ToolPlugin):
    name = "subfinder"
    description = "Passive subdomain discovery"

    def build_command(self, target: str, options: dict) -> list[str]:
        cmd = ["subfinder", "-d", target]
        if options.get("silent"):
            cmd.append("-silent")
        if options.get("recursive"):
            cmd.append("-recursive")
        return cmd

    def parse_output(self, raw_output: str, target: str) -> list[dict[str, Any]]:
        findings = []
        for line in raw_output.splitlines():
            sub = line.strip()
            if sub:
                findings.append({
                    "type": "subdomain",
                    "severity": "info",
                    "title": f"Subdomain: {sub}",
                    "host": sub,
                    "extra": {"root_domain": target},
                })
        return findings


class HttpxPlugin(ToolPlugin):
    name = "httpx"
    description = "Fast HTTP probing tool"

    FLAG_MAP = {
        "title": "-title",
        "tech_detect": "-tech-detect",
        "status_code": "-status-code",
        "follow_redirects": "-follow-redirects",
        "content_length": "-content-length",
    }

    def build_command(self, target: str, options: dict) -> list[str]:
        cmd = ["httpx", "-u", target]
        for key, flag in self.FLAG_MAP.items():
            if options.get(key, True):
                cmd.append(flag)
        cmd.extend(["-json"])
        return cmd

    def parse_output(self, raw_output: str, target: str) -> list[dict[str, Any]]:
        import json
        findings = []
        for line in raw_output.splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                data = json.loads(line)
                tech = data.get("tech", [])
                findings.append({
                    "type": "web_service",
                    "severity": "info",
                    "title": f"Live: {data.get('url', target)} [{data.get('status-code', '?')}]",
                    "host": data.get("url", target),
                    "extra": {
                        "status_code": data.get("status-code"),
                        "title": data.get("title"),
                        "technologies": tech,
                        "content_length": data.get("content-length"),
                    },
                })
            except json.JSONDecodeError:
                continue
        return findings


# Registry: all available plugins
TOOL_REGISTRY: dict[str, ToolPlugin] = {
    "nmap": NmapPlugin(),
    "gobuster": GobusterPlugin(),
    "hydra": HydraPlugin(),
    "nuclei": NucleiPlugin(),
    "subfinder": SubfinderPlugin(),
    "httpx": HttpxPlugin(),
}
