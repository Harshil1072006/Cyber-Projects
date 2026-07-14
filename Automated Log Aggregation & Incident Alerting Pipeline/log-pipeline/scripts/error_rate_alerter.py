#!/usr/bin/env python3
"""
error_rate_alerter.py — Elasticsearch-backed error rate monitor.

Queries Elasticsearch on a configurable interval and fires alerts when:
  1. FLAT THRESHOLD:  error count in last N minutes > absolute threshold
  2. RATE SPIKE:      current error rate is > X times the baseline rate
                      (baseline = average over the past hour excluding
                       the most recent window)

Why both metrics?
  - Flat threshold catches sustained high volume (e.g., 50 errors/5min always bad)
  - Rate spike catches sudden bursts on services that normally have low error volume
    (e.g., 0 → 10 errors is a 10x spike even if 10 is below the flat threshold)

Configuration (env vars or --flags):
  ES_HOST              Elasticsearch URL   (default: http://localhost:9200)
  ALERT_THRESHOLD      Flat count limit    (default: 20 per CHECK_WINDOW_MIN)
  SPIKE_MULTIPLIER     Spike factor        (default: 3.0x baseline)
  CHECK_WINDOW_MIN     Rolling window      (default: 5 minutes)
  BASELINE_WINDOW_MIN  Baseline lookback   (default: 60 minutes)
  CHECK_INTERVAL       Loop sleep seconds  (default: 60)
  SLACK_WEBHOOK_URL    Slack webhook       (optional)
  ES_INDEX_PATTERN     Index pattern       (default: logs-*)

Usage:
  python error_rate_alerter.py                           # runs as a loop
  python error_rate_alerter.py --once                    # single check + exit
  python error_rate_alerter.py --dry-run                 # print alert without sending
  python error_rate_alerter.py --service payment-service # filter to one service
  ES_HOST=http://es:9200 python error_rate_alerter.py
"""

import os
import sys
import json
import time
import logging
import argparse
import textwrap
from datetime import datetime, timezone, timedelta
from typing import Optional

import requests
from elasticsearch import Elasticsearch, exceptions as es_exceptions

# ── Configuration ──────────────────────────────────────────────────────────────
ES_HOST             = os.getenv("ES_HOST",             "http://localhost:9200")
ALERT_THRESHOLD     = int(os.getenv("ALERT_THRESHOLD",   "20"))
SPIKE_MULTIPLIER    = float(os.getenv("SPIKE_MULTIPLIER", "3.0"))
CHECK_WINDOW_MIN    = int(os.getenv("CHECK_WINDOW_MIN",   "5"))
BASELINE_WINDOW_MIN = int(os.getenv("BASELINE_WINDOW_MIN","60"))
CHECK_INTERVAL      = int(os.getenv("CHECK_INTERVAL",     "60"))
SLACK_WEBHOOK_URL   = os.getenv("SLACK_WEBHOOK_URL",     "")
ES_INDEX_PATTERN    = os.getenv("ES_INDEX_PATTERN",      "logs-*")

# ── Logging ───────────────────────────────────────────────────────────────────
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    datefmt="%Y-%m-%dT%H:%M:%S",
    stream=sys.stdout,
)
log = logging.getLogger("error_rate_alerter")

# ── Elasticsearch client ───────────────────────────────────────────────────────

def get_es_client(es_host: str) -> Elasticsearch:
    return Elasticsearch(
        es_host,
        retry_on_timeout=True,
        max_retries=3,
        request_timeout=30,
    )


def wait_for_es(es: Elasticsearch, timeout: int = 120) -> bool:
    """Wait up to `timeout` seconds for Elasticsearch to become available."""
    log.info("Waiting for Elasticsearch at %s...", ES_HOST)
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            health = es.cluster.health(wait_for_status="yellow", timeout="5s")
            log.info("Elasticsearch ready (status: %s)", health["status"])
            return True
        except Exception:
            time.sleep(5)
    log.error("Elasticsearch did not become available within %ds", timeout)
    return False


# ── Elasticsearch queries ──────────────────────────────────────────────────────

def count_errors(
    es: Elasticsearch,
    since_minutes: int,
    until_minutes: int = 0,
    service: Optional[str] = None,
    index: str = ES_INDEX_PATTERN,
) -> int:
    """
    Count error-level log events in the time window [now-since_min, now-until_min].
    Returns -1 on query failure.
    """
    must_filters: list = [
        {"range": {
            "@timestamp": {
                "gte": f"now-{since_minutes}m",
                "lte": f"now-{until_minutes}m" if until_minutes > 0 else "now",
            }
        }},
        {"terms": {"log.level": ["error", "critical", "fatal"]}},
    ]

    if service:
        must_filters.append({"term": {"service.name": service}})

    query = {"query": {"bool": {"filter": must_filters}}}

    try:
        resp = es.count(index=index, body=query)
        return int(resp["count"])
    except es_exceptions.NotFoundError:
        log.debug("Index pattern %s not found yet (no logs ingested)", index)
        return 0
    except Exception as exc:
        log.error("ES count query failed: %s", exc)
        return -1


def get_error_breakdown(
    es: Elasticsearch,
    since_minutes: int,
    service: Optional[str] = None,
    index: str = ES_INDEX_PATTERN,
    top_n: int = 5,
) -> dict:
    """
    Get per-service and top-message breakdown for the alert notification.
    Returns dict with 'by_service' and 'top_messages'.
    """
    must_filters: list = [
        {"range": {"@timestamp": {"gte": f"now-{since_minutes}m"}}},
        {"terms": {"log.level": ["error", "critical", "fatal"]}},
    ]
    if service:
        must_filters.append({"term": {"service.name": service}})

    query = {
        "query": {"bool": {"filter": must_filters}},
        "aggs": {
            "by_service": {
                "terms": {"field": "service.name", "size": top_n}
            },
            "top_messages": {
                "terms": {"field": "log.original.keyword", "size": top_n}
            },
            "tags_breakdown": {
                "terms": {"field": "tags", "size": 10}
            },
        },
        "size": 0,
    }

    try:
        resp = es.search(index=index, body=query)
        aggs = resp.get("aggregations", {})
        return {
            "by_service":    [(b["key"], b["doc_count"]) for b in aggs.get("by_service",    {}).get("buckets", [])],
            "top_messages":  [(b["key"], b["doc_count"]) for b in aggs.get("top_messages",  {}).get("buckets", [])],
            "tags_breakdown": [(b["key"], b["doc_count"]) for b in aggs.get("tags_breakdown", {}).get("buckets", [])],
        }
    except Exception as exc:
        log.warning("Could not get error breakdown: %s", exc)
        return {"by_service": [], "top_messages": [], "tags_breakdown": []}


# ── Alert routing ──────────────────────────────────────────────────────────────

def format_alert_text(
    alert_type: str,
    current_count: int,
    baseline_count: int,
    spike_ratio: float,
    breakdown: dict,
    window_min: int,
    service: Optional[str],
) -> str:
    """Format a human-readable alert message."""
    now = datetime.now(tz=timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")

    lines = [
        f"🚨 *Error Rate Alert: {alert_type}*",
        f"*Time:* {now}",
        f"*Service filter:* {service or 'all services'}",
        f"*Window:* last {window_min} minutes",
        f"*Current error count:* {current_count}",
        f"*Baseline avg ({BASELINE_WINDOW_MIN}m):* {baseline_count:.1f}",
        f"*Spike ratio:* {spike_ratio:.1f}x",
        "",
    ]

    if breakdown["by_service"]:
        lines.append("*Top services by error count:*")
        for svc, count in breakdown["by_service"][:5]:
            lines.append(f"  • `{svc}`: {count} errors")
        lines.append("")

    if breakdown["top_messages"]:
        lines.append("*Top error messages:*")
        for msg, count in breakdown["top_messages"][:3]:
            short_msg = msg[:100] + "…" if len(msg) > 100 else msg
            lines.append(f"  • ({count}x) `{short_msg}`")
        lines.append("")

    if breakdown["tags_breakdown"]:
        tag_summary = ", ".join(f"`{t}`" for t, _ in breakdown["tags_breakdown"][:5])
        lines.append(f"*Incident tags:* {tag_summary}")
        lines.append("")

    lines += [
        f"*Kibana:* http://localhost:5601 → search `log.level: error`",
        "*See:* RUNBOOK.md#error-rate-spike for remediation steps",
    ]

    return "\n".join(lines)


def send_slack_alert(message: str, webhook_url: str) -> bool:
    """Send a Slack webhook notification. Returns True on success."""
    if not webhook_url:
        return False
    try:
        resp = requests.post(
            webhook_url,
            json={"text": message},
            timeout=10,
        )
        resp.raise_for_status()
        log.info("Slack alert sent successfully")
        return True
    except requests.RequestException as exc:
        log.error("Failed to send Slack alert: %s", exc)
        return False


def fire_alert(
    alert_type: str,
    current_count: int,
    baseline_count: float,
    spike_ratio: float,
    breakdown: dict,
    window_min: int,
    service: Optional[str],
    dry_run: bool = False,
    slack_url: str = "",
) -> None:
    """Print alert to console and optionally send to Slack."""
    message = format_alert_text(
        alert_type, current_count, baseline_count,
        spike_ratio, breakdown, window_min, service,
    )

    # Always print to stdout (visible in Docker logs / cron output)
    print("\n" + "═" * 60)
    print(message.replace("*", "").replace("`", ""))
    print("═" * 60 + "\n")

    if dry_run:
        log.info("[DRY RUN] Alert would be sent to Slack")
        return

    if slack_url:
        send_slack_alert(message, slack_url)
    else:
        log.info("No Slack webhook configured — alert logged to stdout only")


# ── Main check logic ───────────────────────────────────────────────────────────

def run_check(
    es: Elasticsearch,
    service: Optional[str],
    dry_run: bool,
    slack_url: str,
) -> bool:
    """
    Run one error rate check. Returns True if an alert fired.
    """
    # Current window count
    current = count_errors(es, since_minutes=CHECK_WINDOW_MIN, service=service)
    if current < 0:
        log.warning("Skipping check — Elasticsearch query failed")
        return False

    # Baseline: error count in the full baseline window, normalized to same duration
    baseline_total = count_errors(
        es,
        since_minutes=BASELINE_WINDOW_MIN,
        until_minutes=CHECK_WINDOW_MIN,  # exclude the current window
        service=service,
    )
    baseline_windows = (BASELINE_WINDOW_MIN - CHECK_WINDOW_MIN) / CHECK_WINDOW_MIN
    baseline_per_window = baseline_total / max(baseline_windows, 1)
    spike_ratio = current / max(baseline_per_window, 1)

    log.info(
        "Error check: current=%d (last %dm)  baseline=%.1f/window  spike=%.1fx  threshold=%d",
        current, CHECK_WINDOW_MIN, baseline_per_window, spike_ratio, ALERT_THRESHOLD,
    )

    alert_fired = False
    alert_type  = None

    if current > ALERT_THRESHOLD and spike_ratio >= SPIKE_MULTIPLIER:
        alert_type = f"Threshold Breach + Spike ({current} errors, {spike_ratio:.1f}x baseline)"
        alert_fired = True
    elif current > ALERT_THRESHOLD:
        alert_type = f"Threshold Breach ({current} errors > {ALERT_THRESHOLD} threshold)"
        alert_fired = True
    elif spike_ratio >= SPIKE_MULTIPLIER:
        alert_type = f"Rate Spike ({spike_ratio:.1f}x baseline — current={current}, baseline={baseline_per_window:.1f})"
        alert_fired = True

    if alert_fired:
        breakdown = get_error_breakdown(es, since_minutes=CHECK_WINDOW_MIN, service=service)
        fire_alert(
            alert_type=alert_type,
            current_count=current,
            baseline_count=baseline_per_window,
            spike_ratio=spike_ratio,
            breakdown=breakdown,
            window_min=CHECK_WINDOW_MIN,
            service=service,
            dry_run=dry_run,
            slack_url=slack_url,
        )

    return alert_fired


# ── CLI ────────────────────────────────────────────────────────────────────────

def main() -> None:
    global ALERT_THRESHOLD, SPIKE_MULTIPLIER, CHECK_INTERVAL
    parser = argparse.ArgumentParser(
        description="Monitor Elasticsearch for error rate spikes and fire alerts",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=textwrap.dedent(__doc__),
    )
    parser.add_argument("--once",       action="store_true", help="Run once and exit")
    parser.add_argument("--dry-run",    action="store_true", help="Print alerts but don't send Slack")
    parser.add_argument("--service",    default=None,        help="Filter to specific service.name")
    parser.add_argument("--es-host",    default=ES_HOST,     help="Elasticsearch URL")
    parser.add_argument("--threshold",  type=int, default=ALERT_THRESHOLD,  help="Flat error count threshold")
    parser.add_argument("--multiplier", type=float, default=SPIKE_MULTIPLIER, help="Spike ratio multiplier")
    parser.add_argument("--interval",   type=int, default=CHECK_INTERVAL,   help="Check interval (seconds)")
    parser.add_argument("--slack-url",  default=SLACK_WEBHOOK_URL,          help="Slack webhook URL")
    args = parser.parse_args()

    # Apply CLI overrides
    ALERT_THRESHOLD  = args.threshold
    SPIKE_MULTIPLIER = args.multiplier
    CHECK_INTERVAL   = args.interval

    es = get_es_client(args.es_host)

    if not wait_for_es(es):
        sys.exit(1)

    log.info(
        "Starting alerter | threshold=%d | spike=%.1fx | window=%dm | interval=%ds | service=%s",
        ALERT_THRESHOLD, SPIKE_MULTIPLIER, CHECK_WINDOW_MIN, CHECK_INTERVAL, args.service or "all",
    )

    if args.once:
        fired = run_check(es, args.service, args.dry_run, args.slack_url)
        sys.exit(0 if not fired else 1)

    while True:
        try:
            run_check(es, args.service, args.dry_run, args.slack_url)
        except KeyboardInterrupt:
            log.info("Shutting down alerter")
            sys.exit(0)
        except Exception as exc:  # pylint: disable=broad-except
            log.error("Unexpected error in check loop: %s", exc)

        log.debug("Sleeping %ds...", CHECK_INTERVAL)
        time.sleep(CHECK_INTERVAL)


if __name__ == "__main__":
    main()
