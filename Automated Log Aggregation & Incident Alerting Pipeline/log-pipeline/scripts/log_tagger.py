#!/usr/bin/env python3
"""
log_tagger.py — Semantic incident tagger for normalized log records.

Reads normalized JSON log records (from log_normalizer.py or stdin)
and appends semantic tags to each record's `tags` array:

  auth-failure      → failed logins, permission denied, sudo failures
  5xx-error         → HTTP 500–599 from app or access logs
  oom-kill          → out-of-memory kernel events
  disk-full         → ENOSPC / no space left errors
  service-crash     → segfaults, panics, unexpected exits
  database-error    → connection failures, deadlocks, query timeouts
  ssl-error         → certificate / TLS handshake failures
  rate-limited      → 429 / throttling events
  slow-query        → database queries over threshold (default: 1000ms)
  deploy-event      → deployment markers / restart events
  dependency-down   → upstream service unavailability

Also enriches records with:
  alert.severity    → critical / high / medium / low
  alert.fired       → bool, true if any incident tag was applied

Usage:
  cat normalized.jsonl | python log_tagger.py
  python log_tagger.py --input normalized.jsonl --output tagged.jsonl
  python log_tagger.py --file raw.log --normalize  # normalize then tag in one pass
"""

import re
import sys
import json
import logging
import argparse
from typing import Optional

logging.basicConfig(
    level=logging.WARNING,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    stream=sys.stderr,
)
log = logging.getLogger("log_tagger")

# ── Tag rule definitions ───────────────────────────────────────────────────────
# Each rule: (tag_name, severity, compiled_regex)
# Severity: critical > high > medium > low
# Rules are checked in order; multiple tags CAN fire for one event.

TAG_RULES: list[tuple[str, str, re.Pattern]] = [

    # ── Authentication & Authorization ─────────────────────────────────────
    (
        "auth-failure", "high",
        re.compile(
            r"(?i)("
            r"authentication fail(ed|ure)?|"
            r"invalid (password|credentials?|user)|"
            r"(failed|incorrect) (password|login|auth)|"
            r"unauthorized|"
            r"403\s+forbidden|"
            r"access denied|"
            r"permission denied|"
            r"sudo:.+FAILED|"
            r"Failed password for|"
            r"login attempt|"
            r"bad password|"
            r"account locked"
            r")"
        ),
    ),

    # ── OOM Kill ───────────────────────────────────────────────────────────
    (
        "oom-kill", "critical",
        re.compile(
            r"(?i)("
            r"out of memory|"
            r"oom.?kill(er)?|"
            r"killed process|"
            r"memory exhausted|"
            r"cannot allocate memory|"
            r"oom_score|"
            r"Memory cgroup out of memory"
            r")"
        ),
    ),

    # ── Disk Full ──────────────────────────────────────────────────────────
    (
        "disk-full", "critical",
        re.compile(
            r"(?i)("
            r"no space left on device|"
            r"disk (full|space)|"
            r"filesystem.*(full|exhausted)|"
            r"inode.*(exhausted|full)|"
            r"ENOSPC|"
            r"quota exceeded"
            r")"
        ),
    ),

    # ── Service Crash ──────────────────────────────────────────────────────
    (
        "service-crash", "critical",
        re.compile(
            r"(?i)("
            r"segfault|"
            r"segmentation fault|"
            r"core dump(ed)?|"
            r"panic:|"
            r"fatal error|"
            r"SIGSEGV|"
            r"SIGKILL|"
            r"SIGABRT|"
            r"process exited (with code [^0]|abnormally)|"
            r"killed by signal|"
            r"unhandled exception|"
            r"stack overflow"
            r")"
        ),
    ),

    # ── Database Errors ────────────────────────────────────────────────────
    (
        "database-error", "high",
        re.compile(
            r"(?i)("
            r"connection refused|"
            r"connection reset by peer|"
            r"too many connections|"
            r"deadlock (detected|found)|"
            r"lock (timeout|wait timeout)|"
            r"query (timeout|killed)|"
            r"relation .* does not exist|"
            r"could not connect to (server|database)|"
            r"database .* unavailable|"
            r"mysql.*error|"
            r"psql.*error|"
            r"redis.*connection"
            r")"
        ),
    ),

    # ── HTTP 5xx Errors ────────────────────────────────────────────────────
    (
        "5xx-error", "high",
        re.compile(
            r"(?i)("
            r"500\s+(internal server error)?|"
            r"502\s+(bad gateway)?|"
            r"503\s+(service unavailable)?|"
            r"504\s+(gateway timeout)?|"
            r"HTTP/\d\.?\d?\s+5\d\d|"
            r'" 5\d\d '                          # nginx/apache log format
            r")"
        ),
    ),

    # ── SSL / TLS Errors ──────────────────────────────────────────────────
    (
        "ssl-error", "high",
        re.compile(
            r"(?i)("
            r"certificate (expired|invalid|revoked|not yet valid)|"
            r"ssl (error|handshake failed)|"
            r"tls (error|handshake)|"
            r"unable to verify (the|ssl) certificate|"
            r"certificate verification failed|"
            r"self.signed certificate|"
            r"hostname mismatch"
            r")"
        ),
    ),

    # ── Rate Limiting ──────────────────────────────────────────────────────
    (
        "rate-limited", "medium",
        re.compile(
            r"(?i)("
            r"rate.?limit(ed)?|"
            r"too many requests|"
            r"429|"
            r"throttl(ed|ing)|"
            r"request quota exceeded"
            r")"
        ),
    ),

    # ── Slow Queries ───────────────────────────────────────────────────────
    (
        "slow-query", "medium",
        re.compile(
            r"(?i)("
            r"slow query|"
            r"query took \d{4,}|"              # 1000ms+
            r"duration: \d{4,}ms|"
            r"execution time: \d{4,}|"
            r"long running (query|transaction)"
            r")"
        ),
    ),

    # ── Deploy / Restart Events ────────────────────────────────────────────
    (
        "deploy-event", "low",
        re.compile(
            r"(?i)("
            r"deploying version|"
            r"deployment started|"
            r"service restart(ing|ed)?|"
            r"container started|"
            r"rolling update|"
            r"new release|"
            r"version bump"
            r")"
        ),
    ),

    # ── Dependency / Upstream Down ─────────────────────────────────────────
    (
        "dependency-down", "high",
        re.compile(
            r"(?i)("
            r"upstream (server |service |host )?(unavailable|down|unreachable)|"
            r"backend (unavailable|connection failed)|"
            r"service (unavailable|unreachable|timeout)|"
            r"health.?check (failed|timeout)"
            r")"
        ),
    ),
]

# Severity ranking for escalation
SEVERITY_RANK = {"critical": 4, "high": 3, "medium": 2, "low": 1}

# Tags that always mean critical severity regardless of log.level
CRITICAL_TAGS = {"oom-kill", "disk-full", "service-crash"}


def tag_record(record: dict) -> dict:
    """
    Apply all tag rules to a normalized log record.
    Mutates the record in-place and returns it.
    """
    text = record.get("log", {}).get("original") or record.get("message", "")
    existing_tags: list = record.get("tags", [])
    fired_tags: list[str] = []
    max_severity = "low"

    for tag_name, severity, pattern in TAG_RULES:
        if tag_name not in existing_tags and pattern.search(text):
            fired_tags.append(tag_name)
            if SEVERITY_RANK.get(severity, 0) > SEVERITY_RANK.get(max_severity, 0):
                max_severity = severity

    # Also consider log.level in severity calculation
    log_level = record.get("log", {}).get("level", "info")
    if log_level in ("critical", "fatal"):
        max_severity = "critical"
    elif log_level == "error" and SEVERITY_RANK.get(max_severity, 0) < 3:
        max_severity = "high"
    elif log_level in ("warn", "warning") and SEVERITY_RANK.get(max_severity, 0) < 2:
        max_severity = "medium"

    # Escalate severity for critical tags
    if any(t in CRITICAL_TAGS for t in fired_tags):
        max_severity = "critical"

    record["tags"] = existing_tags + fired_tags
    record["alert"] = {
        "severity": max_severity,
        "fired":    len(fired_tags) > 0,
        "tags":     fired_tags,
    }

    return record


def process_stream(infile, outfile, pretty: bool = False) -> tuple[int, int]:
    """Process JSONL stream. Returns (total_lines, tagged_count)."""
    total = 0
    tagged = 0
    indent = 2 if pretty else None

    for line in infile:
        line = line.strip()
        if not line:
            continue
        total += 1

        try:
            record = json.loads(line)
        except json.JSONDecodeError as e:
            log.warning("Skipping malformed JSON line %d: %s", total, e)
            continue

        record = tag_record(record)
        if record["alert"]["fired"]:
            tagged += 1

        print(json.dumps(record, indent=indent, default=str), file=outfile)

    return total, tagged


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Tag normalized log records with semantic incident labels",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    parser.add_argument("--input",  "-i", default="-",   help="Input JSONL file (default: stdin)")
    parser.add_argument("--output", "-o", default="-",   help="Output JSONL file (default: stdout)")
    parser.add_argument("--pretty",       action="store_true", help="Pretty-print output JSON")
    parser.add_argument("--normalize",    action="store_true",
                        help="Run log_normalizer first (accepts raw logs, not pre-normalized JSON)")
    parser.add_argument("--host",         default="unknown", help="Hostname (used with --normalize)")
    parser.add_argument("--service", "-s",default="unknown", help="Service (used with --normalize)")
    args = parser.parse_args()

    infile  = open(args.input,  "r", encoding="utf-8") if args.input  != "-" else sys.stdin
    outfile = open(args.output, "w", encoding="utf-8") if args.output != "-" else sys.stdout

    if args.normalize:
        # Import here to allow standalone use without normalizer
        from log_normalizer import parse_line
        import io

        def normalize_and_tag(raw_in, raw_out, pretty):
            total = tagged = 0
            indent = 2 if pretty else None
            for line in raw_in:
                total += 1
                record = parse_line(line, hostname=args.host, service=args.service)
                if not record:
                    continue
                record = tag_record(record)
                if record["alert"]["fired"]:
                    tagged += 1
                print(json.dumps(record, indent=indent, default=str), file=raw_out)
            return total, tagged

        total, tagged = normalize_and_tag(infile, outfile, args.pretty)
    else:
        total, tagged = process_stream(infile, outfile, args.pretty)

    if args.input != "-":
        infile.close()
    if args.output != "-":
        outfile.close()

    log.info("Tagged %d/%d records with incident labels", tagged, total)
    sys.stderr.write(f"[log_tagger] {total} records processed, {tagged} incident tags applied\n")


if __name__ == "__main__":
    main()
