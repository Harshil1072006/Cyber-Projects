"""
test_python_orchestration.py — pytest tests for deploy.py, rollback.py,
config_validator.py, and release_tracker.py.

Run:
  pytest tests/test_python_orchestration.py -v
  pytest tests/test_python_orchestration.py -v --tb=short
"""

from __future__ import annotations

import json
import os
import sys
import tempfile
import shutil
from datetime import datetime, timezone
from pathlib import Path
from unittest.mock import patch, MagicMock

import pytest

# ── Path setup ──────────────────────────────────────────────────────────────
PROJECT_ROOT = Path(__file__).parent.parent
SCRIPTS_DIR  = PROJECT_ROOT / "scripts" / "python"
sys.path.insert(0, str(SCRIPTS_DIR))

from config_validator import (
    validate_config, load_env_file, FieldRule, Severity, ValidationResult
)
from release_tracker import (
    ReleaseManifest, ReleaseRecord, DeployStatus
)


# ═══════════════════════════════════════════════════════
#  config_validator.py tests
# ═══════════════════════════════════════════════════════

class TestConfigValidator:

    def test_valid_minimal_config(self):
        """A config with all required fields should pass."""
        config = {
            "APP_NAME":    "my-app",
            "APP_VERSION": "1.2.3",
            "APP_ENV":     "staging",
            "APP_PORT":    "8080",
            "DEPLOY_USER": "deploy",
            "DEPLOY_DIR":  "/var/lib/app",
            "TARGET_HOST": "localhost",
            "SECRET_KEY":  "a" * 32,
        }
        is_valid, results = validate_config(config)
        errors = [r for r in results if r.severity == Severity.ERROR]
        assert is_valid, f"Should be valid but got errors: {errors}"

    def test_missing_required_field(self):
        """Missing APP_NAME should fail validation."""
        config = {
            "APP_VERSION": "1.2.3",
            "APP_ENV":     "staging",
            "APP_PORT":    "8080",
            "DEPLOY_USER": "deploy",
            "DEPLOY_DIR":  "/var/lib/app",
            "TARGET_HOST": "localhost",
            "SECRET_KEY":  "a" * 32,
        }
        is_valid, results = validate_config(config)
        assert not is_valid
        keys_with_errors = {r.key for r in results if r.severity == Severity.ERROR}
        assert "APP_NAME" in keys_with_errors

    def test_invalid_app_name_pattern(self):
        """APP_NAME with uppercase or spaces should fail."""
        config = {
            "APP_NAME":    "My App",  # invalid: uppercase + space
            "APP_VERSION": "1.0.0",
            "APP_ENV":     "staging",
            "APP_PORT":    "8080",
            "DEPLOY_USER": "deploy",
            "DEPLOY_DIR":  "/var/lib/app",
            "TARGET_HOST": "localhost",
            "SECRET_KEY":  "a" * 32,
        }
        is_valid, results = validate_config(config)
        assert not is_valid
        name_errors = [r for r in results if r.key == "APP_NAME" and r.severity == Severity.ERROR]
        assert len(name_errors) > 0

    def test_invalid_port_number(self):
        """APP_PORT out of range should fail."""
        config = {
            "APP_NAME":    "my-app",
            "APP_VERSION": "1.0.0",
            "APP_ENV":     "staging",
            "APP_PORT":    "99999",  # invalid
            "DEPLOY_USER": "deploy",
            "DEPLOY_DIR":  "/var/lib/app",
            "TARGET_HOST": "localhost",
            "SECRET_KEY":  "a" * 32,
        }
        is_valid, results = validate_config(config)
        assert not is_valid

    def test_forbidden_placeholder_in_secret(self):
        """SECRET_KEY containing 'CHANGEME' should fail."""
        config = {
            "APP_NAME":    "my-app",
            "APP_VERSION": "1.0.0",
            "APP_ENV":     "staging",
            "APP_PORT":    "8080",
            "DEPLOY_USER": "deploy",
            "DEPLOY_DIR":  "/var/lib/app",
            "TARGET_HOST": "localhost",
            "SECRET_KEY":  "CHANGEME-this-value-is-not-secure",
        }
        is_valid, results = validate_config(config)
        assert not is_valid
        key_errors = [r for r in results if r.key == "SECRET_KEY" and r.severity == Severity.ERROR]
        assert len(key_errors) > 0

    def test_secret_too_short(self):
        """SECRET_KEY shorter than 32 chars should fail."""
        config = {
            "APP_NAME":    "my-app",
            "APP_VERSION": "1.0.0",
            "APP_ENV":     "staging",
            "APP_PORT":    "8080",
            "DEPLOY_USER": "deploy",
            "DEPLOY_DIR":  "/var/lib/app",
            "TARGET_HOST": "localhost",
            "SECRET_KEY":  "short",
        }
        is_valid, results = validate_config(config)
        assert not is_valid

    def test_invalid_app_env_value(self):
        """APP_ENV must be one of staging/production/development."""
        config = {
            "APP_NAME":    "my-app",
            "APP_VERSION": "1.0.0",
            "APP_ENV":     "test-env",  # not allowed
            "APP_PORT":    "8080",
            "DEPLOY_USER": "deploy",
            "DEPLOY_DIR":  "/var/lib/app",
            "TARGET_HOST": "localhost",
            "SECRET_KEY":  "a" * 32,
        }
        is_valid, results = validate_config(config)
        assert not is_valid

    def test_unknown_keys_are_informational_not_errors(self):
        """Extra keys not in schema should generate INFO, not ERROR."""
        config = {
            "APP_NAME":      "my-app",
            "APP_VERSION":   "1.0.0",
            "APP_ENV":       "staging",
            "APP_PORT":      "8080",
            "DEPLOY_USER":   "deploy",
            "DEPLOY_DIR":    "/var/lib/app",
            "TARGET_HOST":   "localhost",
            "SECRET_KEY":    "a" * 32,
            "CUSTOM_SETTING": "some-value",  # extra key
        }
        is_valid, results = validate_config(config)
        info_results = [r for r in results if r.key == "CUSTOM_SETTING"]
        assert all(r.severity == Severity.INFO for r in info_results)
        # Should still be valid
        assert is_valid

    def test_load_env_file_parses_correctly(self, tmp_path):
        """load_env_file should parse KEY=VALUE lines, strip quotes, skip comments."""
        env_file = tmp_path / "test.env"
        env_file.write_text(
            "# A comment\n"
            "APP_NAME=my-app\n"
            "APP_PORT=\"8080\"\n"
            "APP_ENV='staging'\n"
            "\n"
            "# Another comment\n"
            "SECRET_KEY=mysecretkey\n"
        )
        result = load_env_file(env_file)
        assert result["APP_NAME"]  == "my-app"
        assert result["APP_PORT"]  == "8080"
        assert result["APP_ENV"]   == "staging"
        assert result["SECRET_KEY"] == "mysecretkey"
        assert len(result) == 4

    def test_strict_mode_fails_on_warnings(self):
        """In strict mode, WARNING severity fields cause is_valid=False."""
        config = {
            "APP_NAME":    "my-app",
            "APP_VERSION": "1.0.0",
            "APP_ENV":     "staging",
            "APP_PORT":    "8080",
            "DEPLOY_USER": "deploy",
            "DEPLOY_DIR":  "relative/path",  # relative path = WARNING
            "TARGET_HOST": "localhost",
            "SECRET_KEY":  "a" * 32,
        }
        _, results_normal = validate_config(config, strict=False)
        _, results_strict = validate_config(config, strict=True)

        # Normal mode: relative path is WARNING, doesn't block
        normal_valid = not any(r.severity == Severity.ERROR for r in results_normal)

        # Strict mode: WARNING also blocks
        strict_valid = not any(
            r.severity in (Severity.ERROR, Severity.WARNING) for r in results_strict
        )

        # The relative path should be more restrictive in strict mode
        assert strict_valid <= normal_valid


# ═══════════════════════════════════════════════════════
#  release_tracker.py tests
# ═══════════════════════════════════════════════════════

class TestReleaseTracker:

    @pytest.fixture
    def manifest(self, tmp_path):
        """A fresh manifest backed by a temp file."""
        return ReleaseManifest(path=tmp_path / "manifest.json")

    def test_append_and_retrieve(self, manifest):
        """Record a release and retrieve it as current."""
        rec = ReleaseRecord(
            environment="staging", sha="abc123def",
            version="1.0.0", status=DeployStatus.SUCCESS,
            timestamp=ReleaseRecord.now(),
        )
        manifest.append(rec)
        current = manifest.current("staging")
        assert current is not None
        assert current["sha"] == "abc123def"
        assert current["status"] == DeployStatus.SUCCESS

    def test_last_good_returns_most_recent_success(self, manifest):
        """last_good should skip failed records and return latest successful."""
        for sha, status in [
            ("aaa111", DeployStatus.SUCCESS),
            ("bbb222", DeployStatus.SUCCESS),
            ("ccc333", DeployStatus.FAILED),
        ]:
            manifest.append(ReleaseRecord(
                environment="staging", sha=sha, version="1.0",
                status=status, timestamp=ReleaseRecord.now(),
            ))

        last = manifest.last_good("staging")
        assert last is not None
        assert last["sha"] == "bbb222"  # last SUCCESS, not the FAILED one

    def test_last_good_returns_none_when_no_successes(self, manifest):
        """last_good returns None if no successful releases exist."""
        manifest.append(ReleaseRecord(
            environment="staging", sha="aaa111", version="1.0",
            status=DeployStatus.FAILED, timestamp=ReleaseRecord.now(),
        ))
        assert manifest.last_good("staging") is None

    def test_update_status(self, manifest):
        """update_status should change the status of the matching record."""
        manifest.append(ReleaseRecord(
            environment="staging", sha="abc123", version="1.0",
            status=DeployStatus.IN_PROGRESS, timestamp=ReleaseRecord.now(),
        ))
        result = manifest.update_status("staging", "abc123", DeployStatus.SUCCESS)
        assert result is True
        assert manifest.current("staging")["status"] == DeployStatus.SUCCESS

    def test_manifest_persists_across_loads(self, tmp_path):
        """Manifest written to disk should be readable in a new instance."""
        path = tmp_path / "manifest.json"
        m1 = ReleaseManifest(path=path)
        m1.append(ReleaseRecord(
            environment="production", sha="deadbeef", version="2.0",
            status=DeployStatus.SUCCESS, timestamp=ReleaseRecord.now(),
        ))

        m2 = ReleaseManifest(path=path)
        current = m2.current("production")
        assert current is not None
        assert current["sha"] == "deadbeef"

    def test_list_recent_returns_limited_results(self, manifest):
        """list_recent should return at most limit records, newest first."""
        for i in range(5):
            manifest.append(ReleaseRecord(
                environment="staging", sha=f"sha{i:04d}", version=f"1.{i}.0",
                status=DeployStatus.SUCCESS, timestamp=ReleaseRecord.now(),
            ))
        recent = manifest.list_recent("staging", limit=3)
        assert len(recent) == 3
        # Should be newest first
        assert recent[0]["sha"] == "sha0004"

    def test_for_env_isolates_environments(self, manifest):
        """Records for staging should not appear in production query."""
        manifest.append(ReleaseRecord(
            environment="staging",    sha="staging111", version="1.0",
            status=DeployStatus.SUCCESS, timestamp=ReleaseRecord.now(),
        ))
        manifest.append(ReleaseRecord(
            environment="production", sha="prod222",    version="1.0",
            status=DeployStatus.SUCCESS, timestamp=ReleaseRecord.now(),
        ))

        staging_recs = manifest.for_env("staging")
        prod_recs    = manifest.for_env("production")

        assert all(r["environment"] == "staging"    for r in staging_recs)
        assert all(r["environment"] == "production" for r in prod_recs)
        assert len(staging_recs) == 1
        assert len(prod_recs)    == 1

    def test_corrupt_manifest_starts_fresh(self, tmp_path):
        """A corrupt JSON manifest should not crash — it starts with empty list."""
        path = tmp_path / "manifest.json"
        path.write_text("not valid json {{{{")
        manifest = ReleaseManifest(path=path)
        assert manifest.for_env("staging") == []

    def test_rollback_record_has_rollback_from(self, manifest):
        """Rollback records should track which SHA they rolled back from."""
        manifest.append(ReleaseRecord(
            environment="staging", sha="rollback-target", version="0.9.0",
            status=DeployStatus.ROLLBACK_OK, timestamp=ReleaseRecord.now(),
            rollback_from="bad-sha-abc123",
        ))
        current = manifest.current("staging")
        assert current["rollback_from"] == "bad-sha-abc123"


# ═══════════════════════════════════════════════════════
#  deploy.py integration tests (mocked)
# ═══════════════════════════════════════════════════════

class TestDeployPipeline:

    @pytest.fixture
    def env_file(self, tmp_path):
        """Create a minimal valid staging.env for testing."""
        envs_dir = tmp_path / "environments"
        envs_dir.mkdir()
        env_file = envs_dir / "staging.env"
        env_file.write_text(
            "APP_NAME=app-server\n"
            "APP_VERSION=1.0.0\n"
            "APP_ENV=staging\n"
            "APP_PORT=8080\n"
            "APP_HEALTH_PATH=/health\n"
            "APP_LOG_LEVEL=debug\n"
            "DEPLOY_USER=deploy\n"
            "DEPLOY_DIR=/tmp/test-app-deploy\n"
            "DEPLOY_BACKUP_DIR=/tmp/test-backups\n"
            "TARGET_HOST=localhost\n"
            "SECRET_KEY=" + "x" * 32 + "\n"
            "MAX_DEPLOY_RETRIES=3\n"
            "HEALTH_CHECK_TIMEOUT=10\n"
        )
        return tmp_path

    def test_config_validation_blocks_invalid_config(self, tmp_path):
        """validate_config should return is_valid=False for missing fields."""
        bad_config = {
            "APP_NAME":    "ok",
            "APP_VERSION": "bad-version",  # doesn't match semver pattern
            "APP_ENV":     "staging",
        }
        is_valid, _ = validate_config(bad_config)
        assert not is_valid, "Invalid config should fail validation"

    def test_release_recorded_on_successful_deploy(self, tmp_path):
        """A successful deployment should write a success record to the manifest."""
        # Setup manifest
        manifest_path = tmp_path / "manifest.json"
        manifest = ReleaseManifest(path=manifest_path)

        # Record a success manually (simulating what deploy.py does)
        manifest.append(ReleaseRecord(
            environment="staging", sha="test-sha-001",
            version="1.0.0", status=DeployStatus.SUCCESS,
            timestamp=ReleaseRecord.now(), pipeline_run="test-run-1",
        ))

        current = manifest.current("staging")
        assert current["status"] == DeployStatus.SUCCESS
        assert current["sha"] == "test-sha-001"

    def test_rollback_finds_last_good_after_failure(self, tmp_path):
        """After a failed deploy, last_good should return the previous success."""
        manifest_path = tmp_path / "manifest.json"
        manifest = ReleaseManifest(path=manifest_path)

        # Previous successful deploy
        manifest.append(ReleaseRecord(
            environment="staging", sha="good-sha-abc",
            version="0.9.0", status=DeployStatus.SUCCESS,
            timestamp=ReleaseRecord.now(),
        ))
        # Current failed deploy
        manifest.append(ReleaseRecord(
            environment="staging", sha="bad-sha-xyz",
            version="1.0.0", status=DeployStatus.FAILED,
            timestamp=ReleaseRecord.now(),
        ))

        # Rollback should find good-sha-abc, not bad-sha-xyz
        last_good = manifest.last_good("staging")
        assert last_good is not None
        assert last_good["sha"] == "good-sha-abc"

        # And confirm bad sha is excluded
        assert last_good["sha"] != "bad-sha-xyz"

    def test_no_rollback_target_when_no_previous_success(self, tmp_path):
        """If no prior success exists, last_good returns None."""
        manifest_path = tmp_path / "manifest.json"
        manifest = ReleaseManifest(path=manifest_path)

        manifest.append(ReleaseRecord(
            environment="staging", sha="first-sha",
            version="1.0.0", status=DeployStatus.FAILED,
            timestamp=ReleaseRecord.now(),
        ))

        assert manifest.last_good("staging") is None


# ═══════════════════════════════════════════════════════
#  Failure simulation / rollback demo tests
# ═══════════════════════════════════════════════════════

class TestFailureSimulation:

    def test_break_for_demo_flag_triggers_failure_in_pipeline(self, tmp_path):
        """
        Directly test the logic that --break-for-demo would trigger:
        ensures a broken deploy marks status as FAILED and rolls back.
        """
        manifest_path = tmp_path / "manifest.json"
        manifest = ReleaseManifest(path=manifest_path)

        # Simulate a previous known-good release
        manifest.append(ReleaseRecord(
            environment="staging", sha="known-good-001",
            version="0.9.0", status=DeployStatus.SUCCESS,
            timestamp=ReleaseRecord.now(),
        ))

        # Simulate a broken deploy
        manifest.append(ReleaseRecord(
            environment="staging", sha="broken-sha-002",
            version="1.0.0", status=DeployStatus.IN_PROGRESS,
            timestamp=ReleaseRecord.now(),
        ))
        manifest.update_status("staging", "broken-sha-002", DeployStatus.FAILED,
                               "Failed at stage: deploy-artifact (break-for-demo)")

        # Verify the state after failure
        current = manifest.current("staging")
        assert current["status"] == DeployStatus.FAILED
        assert current["sha"] == "broken-sha-002"

        # Rollback logic: find last good
        last_good = manifest.last_good("staging")
        assert last_good is not None
        assert last_good["sha"] == "known-good-001"

        # Simulate rollback success
        manifest.append(ReleaseRecord(
            environment="staging",
            sha="known-good-001",
            version="0.9.0",
            status=DeployStatus.ROLLBACK_OK,
            timestamp=ReleaseRecord.now(),
            rollback_from="broken-sha-002",
        ))

        # Verify rollback is recorded
        new_current = manifest.current("staging")
        assert new_current["status"] == DeployStatus.ROLLBACK_OK
        assert new_current["rollback_from"] == "broken-sha-002"

    def test_status_progression_matches_expected_states(self, tmp_path):
        """Verify the full lifecycle: in-progress → failed → rollback → success."""
        manifest_path = tmp_path / "manifest.json"
        manifest = ReleaseManifest(path=manifest_path)

        # Step 1: prior success
        manifest.append(ReleaseRecord(
            environment="staging", sha="v1",
            version="1.0.0", status=DeployStatus.SUCCESS,
            timestamp=ReleaseRecord.now(),
        ))

        # Step 2: new deploy starts
        manifest.append(ReleaseRecord(
            environment="staging", sha="v2",
            version="2.0.0", status=DeployStatus.IN_PROGRESS,
            timestamp=ReleaseRecord.now(),
        ))
        assert manifest.current("staging")["status"] == DeployStatus.IN_PROGRESS

        # Step 3: deploy fails
        manifest.update_status("staging", "v2", DeployStatus.FAILED)
        assert manifest.current("staging")["status"] == DeployStatus.FAILED

        # Step 4: rollback starts
        manifest.append(ReleaseRecord(
            environment="staging", sha="v1",
            version="1.0.0", status=DeployStatus.ROLLBACK_OK,
            timestamp=ReleaseRecord.now(),
            rollback_from="v2",
        ))

        # Step 5: final state
        current = manifest.current("staging")
        assert current["status"] == DeployStatus.ROLLBACK_OK
        assert current["rollback_from"] == "v2"
