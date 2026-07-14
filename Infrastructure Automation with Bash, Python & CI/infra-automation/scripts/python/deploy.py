#!/usr/bin/env python3
"""
deploy.py — Deployment orchestrator for infra-automation.

Orchestrates a full deployment:
  1. Validate config (config_validator.py)
  2. Record in-progress release (release_tracker.py)
  3. Run pre-deploy checks (check_dependencies.sh)
  4. Back up current state (backup.sh)
  5. Set up/update the deploy user (setup_user.sh)
  6. Deploy the artifact
  7. Restart the service (restart_service.sh)
  8. Post-deploy health check
  9. Record final status (success/failed)
  10. On failure: automatically invoke rollback.py

Usage:
  python deploy.py --env staging
  python deploy.py --env production --sha abc123 --version 1.2.3
  python deploy.py --env staging --dry-run         # print plan, don't execute
  python deploy.py --env staging --break-for-demo  # trigger deliberate failure

Exit codes:
  0  Deployment successful
  1  Deployment failed (rollback was attempted)
  2  Rollback also failed (environment may be degraded)
  3  Pre-deployment validation failed (deployment never started)
"""

from __future__ import annotations

import os
import sys
import json
import time
import shutil
import logging
import argparse
import subprocess
import traceback
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

# Ensure scripts/python is importable
SCRIPTS_DIR = Path(__file__).parent
sys.path.insert(0, str(SCRIPTS_DIR))

from config_validator import load_env_file, validate_config
from release_tracker import ReleaseManifest, ReleaseRecord, DeployStatus, get_git_sha, get_pipeline_run_id, get_triggered_by

# ── Configuration ──────────────────────────────────────────────────────────
PROJECT_ROOT = Path(__file__).parent.parent.parent
BASH_SCRIPTS = PROJECT_ROOT / "scripts" / "bash"
ENVS_DIR     = PROJECT_ROOT / "environments"
LOG_DIR      = PROJECT_ROOT / "deploy-logs"

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    datefmt="%Y-%m-%dT%H:%M:%S",
)
log = logging.getLogger("deploy")

# ── Exit codes ─────────────────────────────────────────────────────────────
EXIT_SUCCESS         = 0
EXIT_DEPLOY_FAILED   = 1
EXIT_ROLLBACK_FAILED = 2
EXIT_PRECONDITION    = 3


# ── Step result ────────────────────────────────────────────────────────────
@dataclass
class StepResult:
    name:        str
    success:     bool
    duration_sec: float
    stdout:      str = ""
    stderr:      str = ""
    exit_code:   int = 0
    skipped:     bool = False


# ── Script runner ──────────────────────────────────────────────────────────

class ScriptRunner:
    """Runs bash scripts, captures output, and respects dry-run mode."""

    def __init__(self, env_config: dict[str, str], dry_run: bool = False,
                 log_dir: Optional[Path] = None, target_host: Optional[str] = None):
        self.env_config  = env_config
        self.dry_run     = dry_run
        self.log_dir     = log_dir
        self.target_host = target_host  # None = run locally; set for SSH

    def _build_env(self) -> dict[str, str]:
        """Merge OS environment with deploy config."""
        env = os.environ.copy()
        env.update(self.env_config)
        env["NO_COLOR"] = "1"   # structured logs, no ANSI in captured output
        env["DEBUG"]    = os.getenv("DEBUG", "0")
        return env

    def _run_local(self, script: Path, args: list[str], step_name: str) -> StepResult:
        """Run a bash script locally."""
        cmd = ["bash", str(script)] + args
        start = time.time()

        if self.dry_run:
            log.info("[DRY RUN] Would run: %s %s", script.name, " ".join(args))
            return StepResult(name=step_name, success=True, duration_sec=0.0, skipped=True)

        log.info("Running: bash %s %s", script.name, " ".join(args))
        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                env=self._build_env(),
                timeout=300,  # 5-minute timeout per script
            )
        except subprocess.TimeoutExpired:
            return StepResult(
                name=step_name, success=False, exit_code=124,
                duration_sec=time.time() - start,
                stderr="Script timed out after 300 seconds",
            )
        except Exception as exc:
            return StepResult(
                name=step_name, success=False, exit_code=1,
                duration_sec=time.time() - start,
                stderr=str(exc),
            )

        duration = time.time() - start
        # Exit code 2 = ALREADY_DONE (idempotent — still a success)
        success = result.returncode in (0, 2)

        if self.log_dir:
            self.log_dir.mkdir(parents=True, exist_ok=True)
            log_file = self.log_dir / f"{step_name}.log"
            log_file.write_text(
                f"COMMAND: bash {script} {' '.join(args)}\n"
                f"EXIT:    {result.returncode}\n"
                f"STDOUT:\n{result.stdout}\n"
                f"STDERR:\n{result.stderr}\n",
                encoding="utf-8",
            )

        # Stream output to our logger
        for line in result.stdout.splitlines():
            log.info("  [%s] %s", script.name, line)
        for line in result.stderr.splitlines():
            (log.warning if success else log.error)("  [%s] %s", script.name, line)

        return StepResult(
            name=step_name, success=success,
            duration_sec=duration, exit_code=result.returncode,
            stdout=result.stdout, stderr=result.stderr,
        )

    def _run_remote(self, script: Path, args: list[str], step_name: str) -> StepResult:
        """Copy script to remote host via SSH and execute it there."""
        host      = self.target_host
        ssh_key   = self.env_config.get("SSH_KEY_PATH", "")
        deploy_user = self.env_config.get("DEPLOY_USER", "deploy")

        if self.dry_run:
            log.info("[DRY RUN] Would SSH to %s and run: %s", host, script.name)
            return StepResult(name=step_name, success=True, duration_sec=0.0, skipped=True)

        # Build SSH base command
        ssh_base = ["ssh", "-o", "StrictHostKeyChecking=no", "-o", "BatchMode=yes"]
        if ssh_key:
            ssh_base += ["-i", ssh_key]
        ssh_target = f"{deploy_user}@{host}"

        # Build env var string for remote execution
        env_vars = " ".join(f"{k}={v!r}" for k, v in self.env_config.items()
                            if not k.startswith("PATH"))

        # SCP the lib/ directory and the target script
        lib_dir = script.parent / "lib"
        remote_tmp = f"/tmp/deploy-{step_name}-{int(time.time())}"

        scp_cmd = ["scp", "-o", "StrictHostKeyChecking=no"]
        if ssh_key:
            scp_cmd += ["-i", ssh_key]
        scp_cmd += ["-r", str(lib_dir), str(script), f"{ssh_target}:{remote_tmp}/"]

        start = time.time()
        subprocess.run(scp_cmd, check=True, capture_output=True)

        remote_script = f"{remote_tmp}/{script.name}"
        remote_cmd = f"chmod +x {remote_script} && {env_vars} bash {remote_script} {' '.join(args)}"
        result = subprocess.run(
            ssh_base + [ssh_target, remote_cmd],
            capture_output=True, text=True, timeout=300,
        )

        # Cleanup remote temp
        subprocess.run(ssh_base + [ssh_target, f"rm -rf {remote_tmp}"],
                       capture_output=True)

        duration = time.time() - start
        success  = result.returncode in (0, 2)

        return StepResult(
            name=step_name, success=success,
            duration_sec=duration, exit_code=result.returncode,
            stdout=result.stdout, stderr=result.stderr,
        )

    def run(self, script_name: str, args: list[str] = None) -> StepResult:
        args = args or []
        script = BASH_SCRIPTS / script_name
        if not script.exists():
            return StepResult(
                name=script_name, success=False, exit_code=1,
                duration_sec=0, stderr=f"Script not found: {script}",
            )

        if self.target_host and self.target_host not in ("localhost", "127.0.0.1"):
            return self._run_remote(script, args, script_name)
        return self._run_local(script, args, script_name)


# ── Health check ───────────────────────────────────────────────────────────

def check_health(env_config: dict[str, str], timeout: int = 30) -> bool:
    """Poll the health endpoint until it responds 200 or timeout."""
    import urllib.request
    import urllib.error

    host   = env_config.get("TARGET_HOST", "localhost")
    port   = env_config.get("APP_PORT",    "8080")
    path   = env_config.get("APP_HEALTH_PATH", "/health")
    url    = f"http://{host}:{port}{path}"

    log.info("Health check: %s (timeout=%ds)", url, timeout)
    start = time.time()
    while time.time() - start < timeout:
        try:
            with urllib.request.urlopen(url, timeout=5) as resp:
                if resp.status == 200:
                    body = resp.read(200).decode(errors="replace")
                    log.info("Health check PASSED: HTTP 200 — %s", body[:80])
                    return True
        except (urllib.error.URLError, OSError) as exc:
            log.debug("Health check pending: %s", exc)
        time.sleep(3)

    log.error("Health check FAILED after %ds: %s", timeout, url)
    return False


# ── Deployment pipeline ────────────────────────────────────────────────────

class DeployPipeline:
    def __init__(
        self,
        environment: str,
        sha: str,
        version: str,
        dry_run: bool = False,
        break_for_demo: bool = False,
        skip_backup: bool = False,
    ):
        self.environment    = environment
        self.sha            = sha
        self.version        = version
        self.dry_run        = dry_run
        self.break_for_demo = break_for_demo
        self.skip_backup    = skip_backup
        self.start_time     = time.time()
        self.step_results: list[StepResult] = []

        # Load env config
        env_file = ENVS_DIR / f"{environment}.env"
        if not env_file.exists():
            raise FileNotFoundError(f"Environment file not found: {env_file}")
        self.env_config = load_env_file(env_file)
        self.env_config["APP_VERSION"]  = version
        self.env_config["DEPLOY_SHA"]   = sha
        self.env_config["ENV_NAME"]     = environment

        # Log directory for this run
        ts = datetime.now(tz=timezone.utc).strftime("%Y%m%d_%H%M%S")
        self.log_dir = LOG_DIR / f"{environment}_{sha[:8]}_{ts}"
        self.log_dir.mkdir(parents=True, exist_ok=True)

        # Script runner
        target_host = self.env_config.get("TARGET_HOST", "localhost")
        self.runner = ScriptRunner(
            self.env_config, dry_run=dry_run,
            log_dir=self.log_dir, target_host=target_host,
        )

        # Release manifest
        self.manifest = ReleaseManifest()

    def _record_step(self, result: StepResult) -> None:
        self.step_results.append(result)
        status = "✓ PASS" if result.success else "✗ FAIL"
        if result.skipped:
            status = "⦿ SKIP"
        log.info("%s  %-30s  %.1fs", status, result.name, result.duration_sec)

    def _write_deploy_log(self, final_status: str) -> None:
        """Write a JSON summary of all steps to deploy-logs/."""
        summary = {
            "environment": self.environment,
            "sha":         self.sha,
            "version":     self.version,
            "status":      final_status,
            "duration_sec": time.time() - self.start_time,
            "timestamp":   datetime.now(tz=timezone.utc).isoformat(),
            "steps":       [
                {
                    "name":        r.name,
                    "success":     r.success,
                    "exit_code":   r.exit_code,
                    "duration_sec": r.duration_sec,
                    "skipped":     r.skipped,
                }
                for r in self.step_results
            ],
        }
        summary_file = self.log_dir / "deploy_summary.json"
        summary_file.write_text(json.dumps(summary, indent=2), encoding="utf-8")
        log.info("Deploy log written: %s", summary_file)

    # ── Pipeline stages ────────────────────────────────────────────────────

    def stage_validate_config(self) -> bool:
        log.info("── Stage 1: Config Validation ──")
        env_file = ENVS_DIR / f"{self.environment}.env"
        is_valid, results = validate_config(self.env_config, strict=False)
        errors = [r for r in results if r.severity.value == "ERROR"]

        if errors:
            log.error("Config validation failed — %d error(s):", len(errors))
            for e in errors:
                log.error("  ✗ %s: %s", e.key, e.message)
            return False

        log.info("Config validation passed (%d keys, 0 errors)", len(self.env_config))
        return True

    def stage_pre_checks(self) -> bool:
        log.info("── Stage 2: Pre-Deploy Checks ──")
        result = self.runner.run("check_dependencies.sh", ["--env", self.environment])
        self._record_step(result)
        return result.success

    def stage_backup(self) -> bool:
        log.info("── Stage 3: Backup ──")
        if self.skip_backup:
            log.info("Backup skipped (--skip-backup)")
            return True

        deploy_dir = self.env_config.get("DEPLOY_DIR", "/var/lib/app")
        backup_dir = self.env_config.get("DEPLOY_BACKUP_DIR", "/var/backups/app")

        result = self.runner.run("backup.sh", [
            "--source", deploy_dir,
            "--dest",   backup_dir,
            "--prefix", f"pre-deploy-{self.sha[:8]}",
        ])
        self._record_step(result)
        return result.success

    def stage_setup_user(self) -> bool:
        log.info("── Stage 4: User Setup ──")
        deploy_user = self.env_config.get("DEPLOY_USER", "deploy")
        result = self.runner.run("setup_user.sh", ["--user", deploy_user, "--sudoers"])
        self._record_step(result)
        return result.success

    def stage_deploy_artifact(self) -> bool:
        log.info("── Stage 5: Deploy Artifact ──")

        # Deliberate failure injection for demo/testing
        if self.break_for_demo:
            log.error("🔥 DELIBERATE FAILURE INJECTED (--break-for-demo)")
            log.error("This simulates a broken artifact deploy to trigger rollback")
            result = StepResult(
                name="deploy_artifact", success=False,
                exit_code=1, duration_sec=0.5,
                stderr="SIMULATED FAILURE: artifact is deliberately broken",
            )
            self._record_step(result)
            return False

        deploy_dir  = self.env_config.get("DEPLOY_DIR", "/var/lib/app")
        artifact_url = self.env_config.get("ARTIFACT_URL", "")

        if artifact_url:
            # Download and extract artifact
            artifact_file = f"/tmp/artifact-{self.sha[:8]}.tar.gz"
            log.info("Downloading artifact from: %s", artifact_url)
            result = subprocess.run(
                ["curl", "-fsSL", "-o", artifact_file, artifact_url],
                capture_output=True, text=True, timeout=120,
            )
            if result.returncode != 0:
                log.error("Artifact download failed: %s", result.stderr)
                return False

            # Extract
            subprocess.run(["tar", "-xzf", artifact_file, "-C", deploy_dir], check=True)
        else:
            # Local demo mode: write a version marker file to simulate deploy
            if not self.dry_run:
                deploy_path = Path(deploy_dir)
                deploy_path.mkdir(parents=True, exist_ok=True)
                version_file = deploy_path / "DEPLOYED_VERSION"
                version_file.write_text(
                    json.dumps({
                        "version":   self.version,
                        "sha":       self.sha,
                        "env":       self.environment,
                        "deployed":  datetime.now(tz=timezone.utc).isoformat(),
                    }, indent=2),
                    encoding="utf-8",
                )
                log.info("Version marker written: %s", version_file)
            else:
                log.info("[DRY RUN] Would write version marker to %s", deploy_dir)

        self._record_step(StepResult(
            name="deploy_artifact", success=True, exit_code=0, duration_sec=0.3,
        ))
        return True

    def stage_restart_service(self) -> bool:
        log.info("── Stage 6: Service Restart ──")
        app_name  = self.env_config.get("APP_NAME", "app-server")
        app_port  = self.env_config.get("APP_PORT", "8080")
        host      = self.env_config.get("TARGET_HOST", "localhost")
        timeout   = self.env_config.get("HEALTH_CHECK_TIMEOUT", "30")
        health_url = f"http://{host}:{app_port}{self.env_config.get('APP_HEALTH_PATH', '/health')}"

        result = self.runner.run("restart_service.sh", [
            "--service", app_name,
            "--port",    app_port,
            "--health-url", health_url,
            "--timeout", timeout,
            "--force",
        ])
        self._record_step(result)
        return result.success

    def stage_health_check(self) -> bool:
        log.info("── Stage 7: Post-Deploy Health Check ──")
        if self.dry_run:
            log.info("[DRY RUN] Skipping health check")
            return True
        timeout = int(self.env_config.get("HEALTH_CHECK_TIMEOUT", "30"))
        return check_health(self.env_config, timeout=timeout)

    # ── Orchestrator ───────────────────────────────────────────────────────

    def run(self) -> int:
        log.info("╔══════════════════════════════════════════════════╗")
        log.info("║  Starting Deployment                             ║")
        log.info("╠══════════════════════════════════════════════════╣")
        log.info("║  Env:     %-39s ║", self.environment)
        log.info("║  SHA:     %-39s ║", self.sha[:12])
        log.info("║  Version: %-39s ║", self.version)
        log.info("║  Dry-run: %-39s ║", str(self.dry_run))
        log.info("╚══════════════════════════════════════════════════╝")

        # Stage 1: Config validation (abort before recording)
        if not self.stage_validate_config():
            log.error("Pre-deploy validation failed — deployment aborted")
            return EXIT_PRECONDITION

        # Record in-progress
        self.manifest.append(ReleaseRecord(
            environment  = self.environment,
            sha          = self.sha,
            version      = self.version,
            status       = DeployStatus.IN_PROGRESS,
            timestamp    = ReleaseRecord.now(),
            pipeline_run = get_pipeline_run_id(),
            triggered_by = get_triggered_by(),
        ))

        # Execute stages in order — first failure triggers rollback
        stages = [
            ("pre-checks",       self.stage_pre_checks),
            ("backup",           self.stage_backup),
            ("setup-user",       self.stage_setup_user),
            ("deploy-artifact",  self.stage_deploy_artifact),
            ("restart-service",  self.stage_restart_service),
            ("health-check",     self.stage_health_check),
        ]

        failed_stage: Optional[str] = None
        for stage_name, stage_fn in stages:
            log.info("")
            try:
                if not stage_fn():
                    failed_stage = stage_name
                    break
            except Exception as exc:
                log.error("Uncaught exception in stage '%s': %s", stage_name, exc)
                log.debug(traceback.format_exc())
                failed_stage = stage_name
                break

        duration = time.time() - self.start_time

        if failed_stage is None:
            # ── SUCCESS ───────────────────────────────────────────────────
            log.info("")
            log.info("✅ DEPLOYMENT SUCCESSFUL in %.1fs", duration)
            self.manifest.update_status(self.environment, self.sha, DeployStatus.SUCCESS,
                                        f"Deployed in {duration:.1f}s")
            self._write_deploy_log("success")
            return EXIT_SUCCESS

        else:
            # ── FAILURE → ROLLBACK ─────────────────────────────────────────
            log.error("")
            log.error("❌ DEPLOYMENT FAILED at stage: %s (after %.1fs)", failed_stage, duration)
            self.manifest.update_status(self.environment, self.sha, DeployStatus.FAILED,
                                        f"Failed at stage: {failed_stage}")
            self._write_deploy_log("failed")

            log.warning("Invoking automatic rollback...")
            rollback_exit = self._invoke_rollback()

            if rollback_exit == 0:
                log.info("Rollback completed successfully")
                return EXIT_DEPLOY_FAILED
            else:
                log.error("ROLLBACK ALSO FAILED — environment may be degraded!")
                return EXIT_ROLLBACK_FAILED

    def _invoke_rollback(self) -> int:
        """Invoke rollback.py as a subprocess to revert to last known good."""
        rollback_script = SCRIPTS_DIR / "rollback.py"
        cmd = [
            sys.executable, str(rollback_script),
            "--env", self.environment,
            "--failed-sha", self.sha,
        ]
        if self.dry_run:
            cmd.append("--dry-run")

        log.info("Running: %s", " ".join(cmd))
        result = subprocess.run(cmd, capture_output=False)  # stream to terminal
        return result.returncode


# ── CLI ────────────────────────────────────────────────────────────────────

def main() -> int:
    parser = argparse.ArgumentParser(
        description="Deploy to staging or production",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    parser.add_argument("--env",           required=True, choices=["staging", "production"],
                        help="Target environment")
    parser.add_argument("--sha",           default=None,
                        help="Git SHA to deploy (default: current HEAD)")
    parser.add_argument("--version",       default=None,
                        help="Artifact version (default: from APP_VERSION env or '0.0.0')")
    parser.add_argument("--dry-run",       action="store_true",
                        help="Print plan without executing")
    parser.add_argument("--break-for-demo", action="store_true",
                        help="Deliberately fail at artifact deploy stage to demonstrate rollback")
    parser.add_argument("--skip-backup",   action="store_true",
                        help="Skip pre-deploy backup (faster, use in CI)")
    args = parser.parse_args()

    sha     = args.sha     or get_git_sha()
    version = args.version or os.getenv("APP_VERSION", "0.0.0")

    pipeline = DeployPipeline(
        environment    = args.env,
        sha            = sha,
        version        = version,
        dry_run        = args.dry_run,
        break_for_demo = args.break_for_demo,
        skip_backup    = args.skip_backup,
    )

    return pipeline.run()


if __name__ == "__main__":
    sys.exit(main())
