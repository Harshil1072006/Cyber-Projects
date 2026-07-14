#!/usr/bin/env python3
"""
health_check.py — Custom synthetic health-check exporter for Prometheus.

Reads a checks_config.yml file describing HTTP endpoints, TCP ports, and
systemd service names to probe. Exposes results on a /metrics HTTP endpoint
using the prometheus_client library.

Metrics exposed:
  health_check_status{service_name, target_url, check_type}  — 1=up, 0=down
  health_check_response_time_seconds{...}                     — latency
  health_check_total{...}                                     — total runs
  health_check_errors_total{...}                              — total failures

Usage:
  python health_check.py                    # uses ./checks_config.yml
  CHECK_INTERVAL=30 METRICS_PORT=9200 python health_check.py

Author: SRE Portfolio Project
"""

import os
import sys
import time
import socket
import logging
import threading
import subprocess
from pathlib import Path
from typing import Any

import yaml
import requests
from prometheus_client import (
    start_http_server,
    Gauge,
    Counter,
    Histogram,
    CollectorRegistry,
    REGISTRY,
)

# ── Logging setup ──────────────────────────────────────────────────────────────
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    datefmt="%Y-%m-%dT%H:%M:%S",
    stream=sys.stdout,
)
log = logging.getLogger("health_check")

# ── Configuration ──────────────────────────────────────────────────────────────
CONFIG_PATH = Path(os.getenv("CONFIG_PATH", "./checks_config.yml"))
METRICS_PORT = int(os.getenv("METRICS_PORT", "9200"))
CHECK_INTERVAL = int(os.getenv("CHECK_INTERVAL", "30"))  # seconds

# ── Prometheus metrics ─────────────────────────────────────────────────────────
LABEL_NAMES = ["service_name", "target_url", "check_type"]

CHECK_STATUS = Gauge(
    "health_check_status",
    "Health check result: 1=UP, 0=DOWN",
    LABEL_NAMES,
)

RESPONSE_TIME = Histogram(
    "health_check_response_time_seconds",
    "Health check response time in seconds",
    LABEL_NAMES,
    buckets=[0.05, 0.1, 0.25, 0.5, 1.0, 2.0, 3.0, 5.0, 10.0],
)

CHECK_TOTAL = Counter(
    "health_check_total",
    "Total number of health checks performed",
    LABEL_NAMES,
)

CHECK_ERRORS = Counter(
    "health_check_errors_total",
    "Total number of health check failures",
    LABEL_NAMES,
)

EXPORTER_INFO = Gauge(
    "health_check_exporter_info",
    "Health check exporter metadata",
    ["version", "config_path"],
)
EXPORTER_INFO.labels(version="1.0.0", config_path=str(CONFIG_PATH)).set(1)


# ── Config loader ──────────────────────────────────────────────────────────────

def load_config(path: Path) -> dict[str, Any]:
    """Load and validate YAML configuration file."""
    if not path.exists():
        log.error("Config file not found: %s", path)
        sys.exit(1)

    with path.open() as f:
        config = yaml.safe_load(f)

    if not config or "checks" not in config:
        log.error("Config must have a top-level 'checks' key")
        sys.exit(1)

    log.info("Loaded %d check(s) from %s", len(config["checks"]), path)
    return config


# ── Check implementations ──────────────────────────────────────────────────────

def check_http(check: dict[str, Any]) -> tuple[bool, float]:
    """
    Perform an HTTP/HTTPS GET request and verify status code + optional body keyword.
    Returns (is_up, response_time_seconds).
    """
    url = check["url"]
    timeout = check.get("timeout", 5)
    expected_status = check.get("expected_status", 200)
    expected_body = check.get("expected_body", None)

    try:
        start = time.monotonic()
        resp = requests.get(url, timeout=timeout, verify=check.get("verify_tls", True))
        elapsed = time.monotonic() - start

        if resp.status_code != expected_status:
            log.warning(
                "[HTTP] %s returned %d, expected %d",
                url,
                resp.status_code,
                expected_status,
            )
            return False, elapsed

        if expected_body and expected_body not in resp.text:
            log.warning(
                "[HTTP] %s body does not contain expected string: %r",
                url,
                expected_body,
            )
            return False, elapsed

        return True, elapsed

    except requests.exceptions.Timeout:
        log.warning("[HTTP] Timeout reaching %s (timeout=%ds)", url, timeout)
        return False, float(timeout)
    except requests.exceptions.ConnectionError as exc:
        log.warning("[HTTP] Connection error for %s: %s", url, exc)
        return False, 0.0
    except Exception as exc:  # pylint: disable=broad-except
        log.error("[HTTP] Unexpected error for %s: %s", url, exc)
        return False, 0.0


def check_tcp(check: dict[str, Any]) -> tuple[bool, float]:
    """
    Attempt a TCP connection to host:port.
    Returns (is_up, connect_time_seconds).
    """
    host = check["host"]
    port = int(check["port"])
    timeout = check.get("timeout", 5)

    try:
        start = time.monotonic()
        with socket.create_connection((host, port), timeout=timeout):
            elapsed = time.monotonic() - start
        return True, elapsed
    except (socket.timeout, ConnectionRefusedError, OSError) as exc:
        log.warning("[TCP] Cannot connect to %s:%d — %s", host, port, exc)
        return False, 0.0


def check_systemd(check: dict[str, Any]) -> tuple[bool, float]:
    """
    Check whether a systemd service is active using `systemctl is-active`.
    Returns (is_active, 0.0) — latency not meaningful here.
    """
    service = check["service"]
    try:
        start = time.monotonic()
        result = subprocess.run(
            ["systemctl", "is-active", "--quiet", service],
            timeout=5,
            capture_output=True,
        )
        elapsed = time.monotonic() - start
        is_active = result.returncode == 0
        if not is_active:
            log.warning("[systemd] Service %s is NOT active", service)
        return is_active, elapsed
    except FileNotFoundError:
        # systemctl not available (e.g., running in Docker without systemd)
        log.debug("[systemd] systemctl not found, marking %s as unknown (UP)", service)
        return True, 0.0
    except subprocess.TimeoutExpired:
        log.warning("[systemd] Timeout checking service %s", service)
        return False, 5.0
    except Exception as exc:  # pylint: disable=broad-except
        log.error("[systemd] Error checking %s: %s", service, exc)
        return False, 0.0


# ── Check dispatcher ───────────────────────────────────────────────────────────

CHECKERS = {
    "http": check_http,
    "tcp": check_tcp,
    "systemd": check_systemd,
}


def run_check(check: dict[str, Any]) -> None:
    """Execute a single check and update Prometheus metrics."""
    check_type = check.get("type", "http")
    service_name = check.get("name", check.get("url", check.get("service", "unknown")))
    target_url = check.get("url", f"{check.get('host', '')}:{check.get('port', '')}") or check.get("service", "")

    labels = {
        "service_name": service_name,
        "target_url": target_url,
        "check_type": check_type,
    }

    checker = CHECKERS.get(check_type)
    if not checker:
        log.error("Unknown check type: %s (supported: %s)", check_type, list(CHECKERS))
        return

    CHECK_TOTAL.labels(**labels).inc()

    try:
        is_up, response_time = checker(check)
    except Exception as exc:  # pylint: disable=broad-except
        log.error("Unhandled error in checker %s: %s", check_type, exc)
        is_up, response_time = False, 0.0

    CHECK_STATUS.labels(**labels).set(1 if is_up else 0)
    RESPONSE_TIME.labels(**labels).observe(response_time)

    if not is_up:
        CHECK_ERRORS.labels(**labels).inc()

    log.info(
        "[%s] %s → %s (%.3fs)",
        check_type.upper(),
        service_name,
        "UP" if is_up else "DOWN",
        response_time,
    )


# ── Main loop ──────────────────────────────────────────────────────────────────

def check_loop(config: dict[str, Any]) -> None:
    """Run all checks in a loop, sleeping CHECK_INTERVAL between full passes."""
    checks = config["checks"]
    log.info("Starting check loop: %d checks, interval=%ds", len(checks), CHECK_INTERVAL)

    while True:
        for check in checks:
            try:
                run_check(check)
            except Exception as exc:  # pylint: disable=broad-except
                log.error("Error running check %s: %s", check.get("name", "?"), exc)

        log.debug("Sleeping %ds before next check pass...", CHECK_INTERVAL)
        time.sleep(CHECK_INTERVAL)


def main() -> None:
    config = load_config(CONFIG_PATH)

    log.info("Starting health-check exporter on port %d", METRICS_PORT)
    start_http_server(METRICS_PORT)
    log.info("Metrics available at http://0.0.0.0:%d/metrics", METRICS_PORT)

    # Run checks in a background daemon thread so we can shutdown cleanly
    worker = threading.Thread(target=check_loop, args=(config,), daemon=True)
    worker.start()

    # Main thread just keeps the process alive
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        log.info("Shutting down health-check exporter")
        sys.exit(0)


if __name__ == "__main__":
    main()
