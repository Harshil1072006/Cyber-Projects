"""Tests for ELK log_enricher.py"""
import sys, os, io, json
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "scripts"))

from log_enricher import score_record, enrich_stream, LEVEL_SCORES


def make_record(message, level="info"):
    return {"message": message, "log": {"level": level, "original": message}}


# ── score_record ──────────────────────────────────────────────────────────────────

def test_score_record_info_no_boost():
    r = score_record(make_record("Server started"))
    assert r["enrichment"]["severity_score"] == LEVEL_SCORES["info"]
    assert r["enrichment"]["alert"] is False

def test_score_record_error_level_boosts_score():
    r = score_record(make_record("Something failed", level="error"))
    assert r["enrichment"]["severity_score"] >= LEVEL_SCORES["error"]

def test_score_record_oom_kill_is_critical():
    r = score_record(make_record("Out of memory: kill process 1234"))
    assert r["enrichment"]["severity_score"] >= 90
    assert r["enrichment"]["alert"] is True

def test_score_record_auth_failure():
    r = score_record(make_record("Failed password for user root", level="warn"))
    assert r["enrichment"]["source_class"] == "auth"
    assert r["enrichment"]["severity_score"] >= 60

def test_score_record_disk_full_critical():
    r = score_record(make_record("ENOSPC: no space left on device"))
    assert r["enrichment"]["alert"] is True

def test_score_record_score_capped_at_100():
    r = score_record(make_record("out of memory critical failure", level="critical"))
    assert r["enrichment"]["severity_score"] <= 100

def test_score_record_custom_threshold_high():
    r = score_record(make_record("failed password", level="warn"), alert_threshold=95)
    assert r["enrichment"]["alert"] is False  # score won't reach 95

def test_score_record_custom_threshold_low():
    r = score_record(make_record("info log entry", level="info"), alert_threshold=5)
    assert r["enrichment"]["alert"] is True  # info = 10 >= 5


# ── enrich_stream ─────────────────────────────────────────────────────────────────

def test_enrich_stream_counts():
    records = [
        make_record("Out of memory kill", level="error"),
        make_record("Normal startup", level="info"),
    ]
    infile = io.StringIO("\n".join(json.dumps(r) for r in records))
    outfile = io.StringIO()
    total, alerted = enrich_stream(infile, outfile)
    assert total == 2
    assert alerted >= 1

def test_enrich_stream_empty():
    total, alerted = enrich_stream(io.StringIO(""), io.StringIO())
    assert total == 0
    assert alerted == 0

def test_enrich_stream_outputs_valid_json():
    records = [make_record("test message")]
    infile = io.StringIO(json.dumps(records[0]))
    outfile = io.StringIO()
    enrich_stream(infile, outfile)
    outfile.seek(0)
    result = json.loads(outfile.read())
    assert "enrichment" in result
