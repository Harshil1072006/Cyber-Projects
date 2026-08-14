"""
log_enricher.py — Enriches normalized log JSON records with:
  - Severity score (0-100) based on log level + message patterns
  - Source classification (auth / db / web / sys / unknown)
  - Alert flag when severity >= threshold
"""

import re
import json
import sys
import logging
from typing import Optional

logging.basicConfig(level=logging.WARNING, stream=sys.stderr)
log = logging.getLogger("log_enricher")

# Severity base scores per log level
LEVEL_SCORES = {
    "critical": 90,
    "error": 70,
    "warn": 40,
    "warning": 40,
    "info": 10,
    "debug": 5,
}

# Boost patterns: (regex, score_addition, classification)
BOOST_RULES = [
    (re.compile(r"(out of memory|oom.?kill)", re.I), 85, "sys"),
    (re.compile(r"(failed password|auth.*fail|access denied|unauthorized)", re.I), 20, "auth"),
    (re.compile(r"(connection refused|connection reset|connection timeout)", re.I), 15, "db"),
    (re.compile(r"(no space left|ENOSPC|disk full)", re.I), 85, "sys"),
    (re.compile(r"(segfault|segmentation fault|core dump)", re.I), 50, "sys"),
    (re.compile(r"(deadlock|lock wait timeout|query timeout)", re.I), 15, "db"),
    (re.compile(r"(sql|mysql|postgres|mongodb|redis)", re.I), 5, "db"),
    (re.compile(r"(nginx|apache|haproxy|http|request)", re.I), 5, "web"),
    (re.compile(r"(sshd|sudo|login|passwd|shadow)", re.I), 5, "auth"),
]

DEFAULT_ALERT_THRESHOLD = 60


def classify_source(text: str, base_class: str = "unknown") -> str:
    """Return the highest-confidence source classification for a message."""
    for _, _, cls in BOOST_RULES:
        for pattern, _, rule_cls in BOOST_RULES:
            if pattern.search(text):
                return rule_cls
    return base_class


def score_record(record: dict, alert_threshold: int = DEFAULT_ALERT_THRESHOLD) -> dict:
    """
    Enrich a normalized log record with severity_score, source_class, and alert flag.
    Mutates and returns the record.
    """
    text = record.get("log", {}).get("original") or record.get("message", "")
    level = record.get("log", {}).get("level", "info").lower()

    base_score = LEVEL_SCORES.get(level, 10)
    boost = 0
    source_class = "unknown"

    for pattern, addition, cls in BOOST_RULES:
        if pattern.search(text):
            boost += addition
            source_class = cls  # last matching class wins

    severity_score = min(100, base_score + boost)

    record.setdefault("enrichment", {}).update({
        "severity_score": severity_score,
        "source_class": source_class,
        "alert": severity_score >= alert_threshold,
    })
    return record


def enrich_stream(infile, outfile, alert_threshold: int = DEFAULT_ALERT_THRESHOLD) -> tuple:
    """Process JSONL stream. Returns (total, alerted)."""
    total = alerted = 0
    for line in infile:
        line = line.strip()
        if not line:
            continue
        total += 1
        try:
            record = json.loads(line)
        except json.JSONDecodeError:
            log.warning("Skipping malformed JSON")
            continue
        record = score_record(record, alert_threshold)
        if record["enrichment"]["alert"]:
            alerted += 1
        print(json.dumps(record, default=str), file=outfile)
    return total, alerted


if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser()
    parser.add_argument("--threshold", type=int, default=DEFAULT_ALERT_THRESHOLD)
    args = parser.parse_args()

    total, alerted = enrich_stream(sys.stdin, sys.stdout, args.threshold)
    sys.stderr.write(f"[enricher] {total} records, {alerted} alerts fired\n")
