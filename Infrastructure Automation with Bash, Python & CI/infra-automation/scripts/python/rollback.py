#!/usr/bin/env python3
"""
rollback.py — Revert to the last known-good release.

Reads the release manifest to find the last successful deployment,
then re-runs the relevant ops scripts pointed at that previous version.
Logs the rollback event and confirms health before marking success.

Usage:
  python rollback.py --env staging
  python rollback.py --env production --failed-sha abc123
  python rollback.py --env staging --target-sha def456  # roll back to specific version
  python rollback.py --env staging --dry-run

Exit codes:
  0  Rollback successful
  1  Rollback failed
  2  No known-good release to roll back to
"""

from __future__ import annotations

import os
import sys
import json
import time
import logging
import argparse
import subprocess
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

SCRIPTS_DIR = Path(__file__).parent
sys.path.insert(0, str(SCRIPTS_DIR))

from config_validator import load_env_file
from release_tracker import (
    ReleaseManifest, ReleaseRecord, DeployStatus,
    get_git_sha, get_pipeline_run_id, get_triggered_by,
)

PROJECT_ROOT = Path(__file__).parent.parent.parent
BASH_SCRIPTS = PROJECT_ROOT / "scripts" / "bash"
ENVS_DIR     = PROJECT_ROOT / "environments"
LOG_DIR      = PROJECT_ROOT / "deploy-logs"

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    datefmt="%Y-%m-%dT%H:%M:%S",
)
log = logging.getLogger("rollback")


# ── Script runner (mirrors deploy.py's) ───────────────────────────────────

def run_script(script_name: str, args: list[str], env_config: dict[str, str],
               log_dir: Optional[Path] = None, dry_run: bool = False) -> tuple[bool, int]:
    """Run a bash ops script. Returns (success, exit_code)."""
    script = BASH_SCRIPTS / script_name
    if not script.exists():
        log.error("Script not found: %s", script)
        return False, 1

    if dry_run:
        log.info("[DRY RUN] Would run: bash %s %s", script_name, " ".join(args))
        return True, 0

    env = os.environ.copy()
    env.update(env_config)
    env["NO_COLOR"] = "1"

    cmd = ["bash", str(script)] + args
    log.info("Running: %s", " ".join(cmd))

    try:
        result = subprocess.run(
            cmd, capture_output=True, text=True,
            env=env, timeout=300,
        )
    except subprocess.TimeoutExpired:
        log.error("Script timed out: %s", script_name)
        return False, 124
    except Exception as exc:
        log.error("Script execution failed: %s — %s", script_name, exc)
        return False, 1

    success = result.returncode in (0, 2)  # 2 = already-done is OK

    for line in result.stdout.splitlines():
        log.info("  [%s] %s", script_name, line)
    for line in result.stderr.splitlines():
        (log.info if success else log.warning)("  [%s] %s", script_name, line)

    if log_dir:
        log_dir.mkdir(parents=True, exist_ok=True)
        log_file = log_dir / f"rollback_{script_name}.log"
        log_file.write_text(
            f"CMD: bash {script_name} {' '.join(args)}\nEXIT: {result.returncode}\n"
            f"STDOUT:\n{result.stdout}\nSTDERR:\n{result.stderr}\n",
            encoding="utf-8",
        )

    if not success:
        log.error("Script failed: %s (exit %d)", script_name, result.returncode)

    return success, result.returncode


# ── Health check ───────────────────────────────────────────────────────────

def check_health(env_config: dict[str, str], timeout: int = 30) -> bool:
    import urllib.request, urllib.error
    host  = env_config.get("TARGET_HOST", "localhost")
    port  = env_config.get("APP_PORT",    "8080")
    path  = env_config.get("APP_HEALTH_PATH", "/health")
    url   = f"http://{host}:{port}{path}"

    log.info("Post-rollback health check: %s (timeout=%ds)", url, timeout)
    start = time.time()
    while time.time() - start < timeout:
        try:
            with urllib.request.urlopen(url, timeout=5) as resp:
                if resp.status == 200:
                    body = resp.read(200).decode(errors="replace")
                    log.info("Health check PASSED: HTTP 200 — %s", body[:80])
                    return True
        except (urllib.error.URLError, OSError) as exc:
            log.debug("Health pending: %s", exc)
        time.sleep(3)

    log.error("Health check FAILED after %ds", timeout)
    return False


# ── Rollback pipeline ──────────────────────────────────────────────────────

class RollbackPipeline:
    def __init__(
        self,
        environment: str,
        failed_sha: Optional[str] = None,
        target_sha: Optional[str] = None,
        dry_run: bool = False,
    ):
        self.environment = environment
        self.failed_sha  = failed_sha
        self.dry_run     = dry_run
        self.start_time  = time.time()
        self.manifest    = ReleaseManifest()

        # Load env config
        env_file = ENVS_DIR / f"{environment}.env"
        if not env_file.exists():
            raise FileNotFoundError(f"Env file not found: {env_file}")
        self.env_config = load_env_file(env_file)

        # Find the release to roll back to
        if target_sha:
            # Explicit target: find this SHA in the manifest
            self.target_release = self._find_release(target_sha)
            if not self.target_release:
                raise ValueError(f"SHA {target_sha} not found in manifest for {environment}")
        else:
            # Auto: find last known-good (excluding the current failed one)
            self.target_release = self._find_last_good(exclude_sha=failed_sha)

        if not self.target_release:
            raise ValueError(
                f"No known-good release found for {environment}. "
                "Cannot roll back — manual intervention required."
            )

        self.rollback_sha     = self.target_release["sha"]
        self.rollback_version = self.target_release.get("version", "unknown")

        # Log dir
        ts = datetime.now(tz=timezone.utc).strftime("%Y%m%d_%H%M%S")
        self.log_dir = LOG_DIR / f"rollback_{environment}_{ts}"

        # Patch env config with rollback version
        self.env_config["APP_VERSION"] = self.rollback_version
        self.env_config["DEPLOY_SHA"]  = self.rollback_sha

    def _find_release(self, sha: str) -> Optional[dict]:
        for rec in reversed(self.manifest.for_env(self.environment)):
            if rec.get("sha", "").startswith(sha) or sha.startswith(rec.get("sha", "")[:8]):
                return rec
        return None

    def _find_last_good(self, exclude_sha: Optional[str] = None) -> Optional[dict]:
        for rec in reversed(self.manifest.for_env(self.environment)):
            if rec.get("status") not in (DeployStatus.SUCCESS, DeployStatus.ROLLBACK_OK):
                continue
            if exclude_sha and rec.get("sha", "").startswith(exclude_sha[:8]):
                continue
            return rec
        return None

    def run(self) -> int:
        log.info("╔══════════════════════════════════════════════════╗")
        log.info("║  ⚠  ROLLBACK INITIATED                          ║")
        log.info("╠══════════════════════════════════════════════════╣")
        log.info("║  Environment:     %-31s ║", self.environment)
        log.info("║  Failed SHA:      %-31s ║", (self.failed_sha or "N/A")[:12])
        log.info("║  Rolling back to: %-31s ║", self.rollback_sha[:12])
        log.info("║  Version:         %-31s ║", self.rollback_version)
        log.info("╚══════════════════════════════════════════════════╝")

        # Record rollback start
        self.manifest.append(ReleaseRecord(
            environment   = self.environment,
            sha           = self.rollback_sha,
            version       = self.rollback_version,
            status        = DeployStatus.IN_PROGRESS,
            timestamp     = ReleaseRecord.now(),
            pipeline_run  = get_pipeline_run_id(),
            triggered_by  = "rollback.py (auto)",
            notes         = f"Rollback from {self.failed_sha or 'unknown'}",
            rollback_from = self.failed_sha,
        ))

        rollback_steps = [
            ("restore-artifact",  self._restore_artifact),
            ("restart-service",   self._restart_service),
            ("post-health-check", self._health_check),
        ]

        failed_step: Optional[str] = None
        for step_name, step_fn in rollback_steps:
            log.info("\n── Rollback Step: %s ──", step_name)
            try:
                if not step_fn():
                    failed_step = step_name
                    break
            except Exception as exc:
                log.error("Uncaught error in rollback step '%s': %s", step_name, exc)
                failed_step = step_name
                break

        duration = time.time() - self.start_time

        if failed_step is None:
            log.info("\n✅ ROLLBACK SUCCESSFUL in %.1fs", duration)
            self.manifest.update_status(
                self.environment, self.rollback_sha,
                DeployStatus.ROLLBACK_OK,
                f"Rolled back from {self.failed_sha or 'unknown'} in {duration:.1f}s",
            )
            self._write_log("rollback_success")
            return 0
        else:
            log.error("\n❌ ROLLBACK FAILED at step: %s", failed_step)
            log.error("MANUAL INTERVENTION REQUIRED — see RUNBOOK.md#rollback-failed")
            self.manifest.update_status(
                self.environment, self.rollback_sha,
                DeployStatus.ROLLBACK_FAIL,
                f"Rollback failed at step: {failed_step}",
            )
            self._write_log("rollback_failed")
            return 1

    def _restore_artifact(self) -> bool:
        """Restore the previous version's artifact/config files."""
        deploy_dir      = self.env_config.get("DEPLOY_DIR", "/var/lib/app")
        backup_dir      = self.env_config.get("DEPLOY_BACKUP_DIR", "/var/backups/app")

        if self.dry_run:
            log.info("[DRY RUN] Would restore %s → %s", backup_dir, deploy_dir)
            return True

        # Look for a pre-deploy backup tagged with the rollback SHA
        backup_pattern = f"pre-deploy-{self.rollback_sha[:8]}"
        import glob
        backups = sorted(glob.glob(f"{backup_dir}/{backup_pattern}*.tar.gz"))

        if backups:
            backup_file = backups[-1]
            log.info("Restoring from backup: %s", backup_file)
            try:
                subprocess.run(
                    ["tar", "-xzf", backup_file, "-C", deploy_dir],
                    check=True, capture_output=True,
                )
                log.info("Artifact restored from backup")
                return True
            except subprocess.CalledProcessError as exc:
                log.error("Failed to extract backup: %s", exc)
                return False
        else:
            # No backup — write a rollback version marker (demo mode)
            log.warning("No backup found for %s — writing rollback version marker", self.rollback_sha[:8])
            deploy_path = Path(deploy_dir)
            deploy_path.mkdir(parents=True, exist_ok=True)
            version_file = deploy_path / "DEPLOYED_VERSION"
            version_file.write_text(
                json.dumps({
                    "version":      self.rollback_version,
                    "sha":          self.rollback_sha,
                    "env":          self.environment,
                    "deployed":     datetime.now(tz=timezone.utc).isoformat(),
                    "rollback":     True,
                    "rollback_from": self.failed_sha,
                }, indent=2),
                encoding="utf-8",
            )
            log.info("Rollback version marker written: %s", version_file)
            return True

    def _restart_service(self) -> bool:
        app_name   = self.env_config.get("APP_NAME", "app-server")
        app_port   = self.env_config.get("APP_PORT",  "8080")
        host       = self.env_config.get("TARGET_HOST", "localhost")
        timeout    = self.env_config.get("HEALTH_CHECK_TIMEOUT", "30")
        health_url = f"http://{host}:{app_port}{self.env_config.get('APP_HEALTH_PATH', '/health')}"

        ok, _ = run_script("restart_service.sh", [
            "--service",    app_name,
            "--port",       app_port,
            "--health-url", health_url,
            "--timeout",    timeout,
            "--force",
        ], self.env_config, log_dir=self.log_dir, dry_run=self.dry_run)
        return ok

    def _health_check(self) -> bool:
        if self.dry_run:
            log.info("[DRY RUN] Skipping health check")
            return True
        timeout = int(self.env_config.get("HEALTH_CHECK_TIMEOUT", "30"))
        return check_health(self.env_config, timeout=timeout)

    def _write_log(self, status: str) -> None:
        self.log_dir.mkdir(parents=True, exist_ok=True)
        summary = {
            "type":          "rollback",
            "environment":   self.environment,
            "failed_sha":    self.failed_sha,
            "rollback_to":   self.rollback_sha,
            "version":       self.rollback_version,
            "status":        status,
            "duration_sec":  time.time() - self.start_time,
            "timestamp":     datetime.now(tz=timezone.utc).isoformat(),
        }
        (self.log_dir / "rollback_summary.json").write_text(
            json.dumps(summary, indent=2), encoding="utf-8",
        )
        log.info("Rollback log: %s", self.log_dir / "rollback_summary.json")


# ── CLI ────────────────────────────────────────────────────────────────────

def main() -> int:
    parser = argparse.ArgumentParser(
        description="Roll back to the last known-good release",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    parser.add_argument("--env",          required=True, choices=["staging", "production"])
    parser.add_argument("--failed-sha",   default=None, help="SHA of the failed deployment")
    parser.add_argument("--target-sha",   default=None, help="Specific SHA to roll back to")
    parser.add_argument("--dry-run",      action="store_true")
    args = parser.parse_args()

    try:
        pipeline = RollbackPipeline(
            environment = args.env,
            failed_sha  = args.failed_sha,
            target_sha  = args.target_sha,
            dry_run     = args.dry_run,
        )
    except (FileNotFoundError, ValueError) as exc:
        log.error("%s", exc)
        return 2

    return pipeline.run()


if __name__ == "__main__":
    sys.exit(main())
