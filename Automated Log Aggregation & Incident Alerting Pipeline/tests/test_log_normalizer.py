"""
Tests for log_normalizer.py — covers all parsers, level inference,
and normalization helpers without requiring Elasticsearch.
"""
import sys
import os

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "log-pipeline", "scripts"))

from log_normalizer import (
    infer_level,
    normalize_level,
    parse_syslog,
    parse_app_log,
    parse_nginx,
)


# ── infer_level ──────────────────────────────────────────────────────────────────

def test_infer_level_error():
    assert infer_level("Connection refused error occurred") == "error"

def test_infer_level_warn():
    assert infer_level("warning: disk space low") == "warn"

def test_infer_level_critical():
    assert infer_level("FATAL: out of memory") == "critical"

def test_infer_level_debug():
    assert infer_level("verbose trace of request") == "debug"

def test_infer_level_info_default():
    assert infer_level("Server started successfully") == "info"


# ── normalize_level ───────────────────────────────────────────────────────────────

def test_normalize_level_warning():
    assert normalize_level("WARNING") == "warn"

def test_normalize_level_err():
    assert normalize_level("ERR") == "error"

def test_normalize_level_fatal():
    assert normalize_level("FATAL") == "critical"

def test_normalize_level_exception():
    assert normalize_level("EXCEPTION") == "error"

def test_normalize_level_info_passthrough():
    assert normalize_level("INFO") == "info"

def test_normalize_level_debug_passthrough():
    assert normalize_level("debug") == "debug"


# ── parse_syslog ─────────────────────────────────────────────────────────────────

SAMPLE_SYSLOG = "Jul 13 14:32:01 web-01 sshd[1234]: Accepted publickey for user"

def test_parse_syslog_returns_dict():
    result = parse_syslog(SAMPLE_SYSLOG, "default-host", "ssh")
    assert result is not None
    assert isinstance(result, dict)

def test_parse_syslog_fields():
    result = parse_syslog(SAMPLE_SYSLOG, "default-host", "ssh")
    assert result["host"]["name"] == "web-01"
    assert result["log"]["format"] == "syslog"
    assert "Accepted publickey" in result["message"]
    assert result["process"]["name"] == "sshd"

def test_parse_syslog_bad_line():
    assert parse_syslog("not a syslog line at all", "h", "s") is None


# ── parse_app_log ─────────────────────────────────────────────────────────────────

APP_LOG = "2026-07-13T14:32:01.123Z [ERROR] api: Database connection failed"

def test_parse_app_log_returns_dict():
    result = parse_app_log(APP_LOG, "app-host", "api")
    assert result is not None

def test_parse_app_log_fields():
    result = parse_app_log(APP_LOG, "app-host", "api")
    assert result["log"]["level"] == "error"
    assert result["log"]["format"] == "app"
    assert "Database connection failed" in result["message"]
    assert result["host"]["name"] == "app-host"

def test_parse_app_log_warn_level():
    line = "2026-07-13T14:32:01Z [WARN] service: Memory usage high"
    result = parse_app_log(line, "h", "svc")
    assert result is not None
    assert result["log"]["level"] == "warn"

def test_parse_app_log_bad_line():
    assert parse_app_log("Jul 13 random syslog line", "h", "s") is None


# ── parse_nginx ───────────────────────────────────────────────────────────────────

NGINX_LINE = '192.168.1.1 - frank [10/Oct/2000:13:55:36 -0700] "GET /apache_pb.gif HTTP/1.0" 200 2326 "http://referer.example.com/" "Mozilla/4.08"'

def test_parse_nginx_returns_dict():
    result = parse_nginx(NGINX_LINE, "nginx-host", "nginx")
    assert result is not None

def test_parse_nginx_fields():
    result = parse_nginx(NGINX_LINE, "nginx-host", "nginx")
    assert result["log"]["format"] == "nginx_access"
    assert result["log"]["level"] == "info"  # 200
    assert result["http"]["response"]["status_code"] == 200
    assert result["url"]["original"] == "/apache_pb.gif"

def test_parse_nginx_500_is_error():
    line = '10.0.0.1 - - [10/Oct/2000:13:55:36 -0700] "POST /api HTTP/1.1" 500 512'
    result = parse_nginx(line, "h", "nginx")
    assert result is not None
    assert result["log"]["level"] == "error"

def test_parse_nginx_404_is_warn():
    line = '10.0.0.1 - - [10/Oct/2000:13:55:36 -0700] "GET /missing HTTP/1.1" 404 0'
    result = parse_nginx(line, "h", "nginx")
    assert result is not None
    assert result["log"]["level"] == "warn"

def test_parse_nginx_bad_line():
    assert parse_nginx("not an nginx log line", "h", "s") is None
