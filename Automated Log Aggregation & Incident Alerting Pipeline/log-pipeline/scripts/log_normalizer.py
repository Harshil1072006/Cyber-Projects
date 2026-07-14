#!/usr/bin/env python3
"""
log_normalizer.py — Raw log parser and normalizer.

Reads unstructured log lines from stdin or a file and outputs
normalized JSON records with consistent fields:
  - @timestamp   (ISO 8601, UTC)
  - host.name
  - service.name
  - log.level    (debug / info / warn / error / critical)
  - log.format   (syslog / app / nginx / json / unknown)
  - log.original (raw message text)
  - message      (cleaned, human-readable summary)
  - tags         []  (populated by log_tagger.py)

Usage:
  cat /var/log/syslog | python log_normalizer.py --service myapp
  python log_normalizer.py --file app.log --host web-01 --service api
  python log_normalizer.py --file app.log --output-es --es-host http://localhost:9200

Can be used as a pre-processing step before sending to Elasticsearch,
or run inline for testing/validation of the Logstash pipeline output.
"""

import re
import sys
import json
import argparse
import logging
from datetime import datetime, timezone
from typing import Optional

# ── Logging ───────────────────────────────────────────────────────────────────
logging.basicConfig(
    level=logging.WARNING,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    stream=sys.stderr,
)
log = logging.getLogger("log_normalizer")

# ── Regex patterns ─────────────────────────────────────────────────────────────

# Syslog: "Jul 13 14:32:01 hostname program[pid]: message"
SYSLOG_RE = re.compile(
    r"^(?P<month>Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)\s+"
    r"(?P<day>\d{1,2})\s+(?P<time>\d{2}:\d{2}:\d{2})\s+"
    r"(?P<hostname>\S+)\s+(?P<program>[^\[\s:]+)(?:\[(?P<pid>\d+)\])?:\s*"
    r"(?P<message>.+)$",
    re.DOTALL,
)

# ISO timestamp app log: "2026-07-13T14:32:01.123Z [ERROR] service: message"
APP_LOG_RE = re.compile(
    r"^(?P<timestamp>\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}(?:[.,]\d+)?(?:Z|[+-]\d{4})?)\s+"
    r"\[?(?P<level>DEBUG|INFO|WARN(?:ING)?|ERROR|CRITICAL|FATAL|EXCEPTION)\]?\s+"
    r"(?:(?P<service>[a-zA-Z0-9_.-]+):\s+)?(?P<message>.+)$",
    re.IGNORECASE | re.DOTALL,
)

# Nginx combined log format
NGINX_RE = re.compile(
    r'^(?P<client_ip>\S+)\s+-\s+(?P<user>\S+)\s+\[(?P<time>[^\]]+)\]\s+'
    r'"(?P<method>\w+)\s+(?P<path>\S+)\s+HTTP/(?P<http_ver>[^"]+)"\s+'
    r'(?P<status>\d+)\s+(?P<bytes>\d+)'
    r'(?:\s+"(?P<referrer>[^"]*)"\s+"(?P<user_agent>[^"]*)")?',
)

# Log level keywords for inference
LEVEL_PATTERNS = [
    (re.compile(r"\b(fatal|critical|emerg|alert)\b", re.I), "critical"),
    (re.compile(r"\b(error|err|fail|exception)\b", re.I),   "error"),
    (re.compile(r"\b(warn(?:ing)?)\b", re.I),                "warn"),
    (re.compile(r"\b(debug|trace|verbose)\b", re.I),         "debug"),
]

MONTH_MAP = {
    "Jan": 1, "Feb": 2, "Mar": 3, "Apr": 4, "May": 5, "Jun": 6,
    "Jul": 7, "Aug": 8, "Sep": 9, "Oct": 10, "Nov": 11, "Dec": 12,
}

# ── Parsers ────────────────────────────────────────────────────────────────────

def infer_level(text: str) -> str:
    """Infer log level from message content when not explicitly stated."""
    for pattern, level in LEVEL_PATTERNS:
        if pattern.search(text):
            return level
    return "info"


def normalize_level(raw: str) -> str:
    """Canonicalize log level variants to: debug/info/warn/error/critical."""
    mapping = {
        "warning": "warn", "err": "error", "fatal": "critical",
        "exception": "error", "trace": "debug", "verbose": "debug",
        "notice": "info", "severe": "error",
    }
    clean = raw.strip().lower()
    return mapping.get(clean, clean)


def parse_syslog(line: str, hostname: str, service: str) -> Optional[dict]:
    m = SYSLOG_RE.match(line.strip())
    if not m:
        return None

    d = m.groupdict()
    now = datetime.now(tz=timezone.utc)
    try:
        ts = datetime(
            year=now.year,
            month=MONTH_MAP[d["month"]],
            day=int(d["day"]),
            hour=int(d["time"][:2]),
            minute=int(d["time"][3:5]),
            second=int(d["time"][6:]),
            tzinfo=timezone.utc,
        )
    except (ValueError, KeyError):
        ts = now

    msg = d["message"].strip()
    return {
        "@timestamp":    ts.isoformat(),
        "host":          {"name": d["hostname"] or hostname},
        "process":       {"name": d["program"], "pid": d.get("pid")},
        "service":       {"name": service or d["program"]},
        "log": {
            "level":    infer_level(msg),
            "format":   "syslog",
            "original": msg,
        },
        "message": msg,
        "tags":    [],
    }


def parse_app_log(line: str, hostname: str, service: str) -> Optional[dict]:
    m = APP_LOG_RE.match(line.strip())
    if not m:
        return None

    d = m.groupdict()
    try:
        ts_str = d["timestamp"].replace(",", ".").replace(" ", "T")
        if not ts_str.endswith("Z") and "+" not in ts_str[-6:]:
            ts_str += "Z"
        ts = datetime.fromisoformat(ts_str.replace("Z", "+00:00"))
    except ValueError:
        ts = datetime.now(tz=timezone.utc)

    msg = d["message"].strip()
    return {
        "@timestamp": ts.isoformat(),
        "host":       {"name": hostname},
        "service":    {"name": d.get("service") or service},
        "log": {
            "level":    normalize_level(d["level"]),
            "format":   "app",
            "original": msg,
        },
        "message": msg,
        "tags":    [],
    }


def parse_nginx(line: str, hostname: str, service: str) -> Optional[dict]:
    m = NGINX_RE.match(line.strip())
    if not m:
        return None

    d = m.groupdict()
    try:
        ts = datetime.strptime(d["time"], "%d/%b/%Y:%H:%M:%S %z")
    except ValueError:
        ts = datetime.now(tz=timezone.utc)

    status = int(d["status"])
    if status >= 500:
        level = "error"
    elif status >= 400:
        level = "warn"
    else:
        level = "info"

    msg = f'{d["method"]} {d["path"]} → {status}'
    return {
        "@timestamp": ts.isoformat(),
        "host":       {"name": hostname},
        "service":    {"name": service or "nginx"},
        "log": {
            "level":    level,
            "format":   "nginx_access",
            "original": line.strip(),
        },
        "http": {
            "request":  {"method": d["method"]},
            "response": {"status_code": status, "body": {"bytes": int(d["bytes"])}},
        },
        "url":     {"original": d["path"]},
        "source":  {"ip": d["client_ip"]},
        "message": msg,
        "tags":    [],
    }


def parse_json_log(line: str, hostname: str, service: str) -> Optional[dict]:
    """Handle pre-structured JSON logs (structlog, zerolog, etc.)."""
    stripped = line.strip()
    if not stripped.startswith("{"):
        return None
    try:
        payload = json.loads(stripped)
    except json.JSONDecodeError:
        return None

    ts_raw = (
        payload.get("timestamp") or payload.get("time") or
        payload.get("ts") or payload.get("@timestamp")
    )
    try:
        ts = datetime.fromisoformat(str(ts_raw).replace("Z", "+00:00"))
    except (ValueError, TypeError):
        ts = datetime.now(tz=timezone.utc)

    raw_level = (
        payload.get("level") or payload.get("severity") or
        payload.get("lvl") or "info"
    )
    msg = (
        payload.get("message") or payload.get("msg") or
        payload.get("text") or stripped
    )
    svc = payload.get("service") or payload.get("app") or service

    record: dict = {
        "@timestamp": ts.isoformat(),
        "host":       {"name": payload.get("host") or hostname},
        "service":    {"name": svc},
        "log": {
            "level":    normalize_level(str(raw_level)),
            "format":   "json",
            "original": msg,
        },
        "message": msg,
        "tags":    [],
    }

    # Promote useful extra fields
    for key in ("request_id", "trace_id", "user_id", "duration_ms", "status_code"):
        if key in payload:
            record[key] = payload[key]

    return record


def parse_line(line: str, hostname: str = "unknown", service: str = "unknown") -> dict:
    """Try all parsers in order; fall back to raw record."""
    stripped = line.strip()
    if not stripped:
        return {}

    for parser in (parse_json_log, parse_app_log, parse_syslog, parse_nginx):
        result = parser(stripped, hostname, service)
        if result:
            return result

    # Unknown format fallback
    return {
        "@timestamp": datetime.now(tz=timezone.utc).isoformat(),
        "host":       {"name": hostname},
        "service":    {"name": service},
        "log": {
            "level":    infer_level(stripped),
            "format":   "unknown",
            "original": stripped,
        },
        "message": stripped,
        "tags":    ["_unparsed"],
    }


# ── CLI ────────────────────────────────────────────────────────────────────────

def main() -> None:
    parser = argparse.ArgumentParser(
        description="Normalize raw log lines to structured JSON",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    parser.add_argument("--file",     "-f", help="Input log file (default: stdin)")
    parser.add_argument("--host",           default="unknown",   help="Source hostname")
    parser.add_argument("--service",  "-s", default="unknown",   help="Service name")
    parser.add_argument("--output",   "-o", default="-",         help="Output file (default: stdout)")
    parser.add_argument("--pretty",         action="store_true", help="Pretty-print JSON")
    parser.add_argument("--skip-empty",     action="store_true", help="Skip empty/unparsed lines")
    args = parser.parse_args()

    infile  = open(args.file, "r", encoding="utf-8", errors="replace") if args.file else sys.stdin
    outfile = open(args.output, "w", encoding="utf-8")            if args.output != "-" else sys.stdout

    indent = 2 if args.pretty else None
    count = parsed = 0

    try:
        for line in infile:
            count += 1
            record = parse_line(line, hostname=args.host, service=args.service)
            if not record:
                continue
            if args.skip_empty and "_unparsed" in record.get("tags", []):
                continue
            parsed += 1
            print(json.dumps(record, indent=indent, default=str), file=outfile)
    finally:
        if args.file:
            infile.close()
        if args.output != "-":
            outfile.close()

    log.info("Processed %d lines, parsed %d successfully", count, parsed)


if __name__ == "__main__":
    main()
