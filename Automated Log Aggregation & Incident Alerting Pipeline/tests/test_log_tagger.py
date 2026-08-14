"""Tests for log_tagger.py — tag_record and process_stream functions."""
import sys, os, io, json
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "log-pipeline", "scripts"))

from log_tagger import tag_record, process_stream


def make_record(message, log_level="info"):
    return {
        "message": message,
        "log": {"level": log_level, "original": message, "format": "app"},
        "tags": [],
    }


# ── tag_record ────────────────────────────────────────────────────────────────────

def test_tag_auth_failure():
    r = tag_record(make_record("Failed password for root from 10.0.0.1"))
    assert "auth-failure" in r["tags"]
    assert r["alert"]["fired"] is True

def test_tag_oom_kill():
    r = tag_record(make_record("Out of memory: Kill process 1234 (java)"))
    assert "oom-kill" in r["tags"]
    assert r["alert"]["severity"] == "critical"

def test_tag_disk_full():
    r = tag_record(make_record("ENOSPC: no space left on device"))
    assert "disk-full" in r["tags"]
    assert r["alert"]["severity"] == "critical"

def test_tag_service_crash():
    r = tag_record(make_record("Segmentation fault (core dumped)"))
    assert "service-crash" in r["tags"]
    assert r["alert"]["severity"] == "critical"

def test_tag_database_error():
    r = tag_record(make_record("ERROR: connection refused to database host"))
    assert "database-error" in r["tags"]

def test_no_tags_on_clean_log():
    r = tag_record(make_record("Server started successfully on port 8080"))
    assert r["alert"]["fired"] is False
    assert len(r["alert"]["tags"]) == 0

def test_alert_severity_elevated_by_log_level_error():
    r = tag_record(make_record("Something happened", log_level="error"))
    assert r["alert"]["severity"] == "high"

def test_alert_severity_elevated_by_log_level_critical():
    r = tag_record(make_record("Something happened", log_level="critical"))
    assert r["alert"]["severity"] == "critical"

def test_multiple_tags_can_fire():
    r = tag_record(make_record(
        "authentication failed and no space left on device"
    ))
    assert "auth-failure" in r["tags"]
    assert "disk-full" in r["tags"]


# ── process_stream ────────────────────────────────────────────────────────────────

def test_process_stream_counts():
    records = [
        {"message": "Failed password for root", "log": {"level": "warn", "original": "Failed password for root"}, "tags": []},
        {"message": "All good, started fine", "log": {"level": "info", "original": "All good, started fine"}, "tags": []},
    ]
    infile = io.StringIO("\n".join(json.dumps(r) for r in records))
    outfile = io.StringIO()

    total, tagged = process_stream(infile, outfile)
    assert total == 2
    assert tagged == 1

def test_process_stream_skips_malformed():
    infile = io.StringIO("this is not json\n{\"message\": \"ok\", \"log\": {\"level\": \"info\", \"original\": \"ok\"}, \"tags\": []}\n")
    outfile = io.StringIO()
    total, tagged = process_stream(infile, outfile)
    # Only the valid JSON line counts
    assert total == 2

def test_process_stream_empty():
    infile = io.StringIO("")
    outfile = io.StringIO()
    total, tagged = process_stream(infile, outfile)
    assert total == 0
    assert tagged == 0
