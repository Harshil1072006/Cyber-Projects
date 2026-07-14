#!/usr/bin/env python3
"""
release_tracker.py — Write and read the deployment release manifest.

Maintains a JSON log (release_manifest.json) tracking every deployment:
  - Environment (staging / production)
  - Git commit SHA
  - Version
  - Timestamp (UTC ISO 8601)
  - Status (success / failed / rolled_back)
  - Pipeline run ID
  - Duration
  - Who triggered it

The manifest is the single source of truth for "what is currently deployed
where" and "what was the last known-good release to roll back to."

Usage:
  python release_tracker.py record --env staging --sha abc123 --version 1.2.3
  python release_tracker.py last-good --env staging
  python release_tracker.py list --env staging --limit 10
  python release_tracker.py status --env staging
"""

from __future__ import annotations

import json
import sys
import os
import argparse
import logging
import subprocess
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path
from typing import Optional

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    datefmt="%Y-%m-%dT%H:%M:%S",
)
log = logging.getLogger("release_tracker")

# ── Configuration ──────────────────────────────────────────────────────────
DEFAULT_MANIFEST_PATH = Path(
    os.getenv("RELEASE_MANIFEST_PATH",
              str(Path(__file__).parent.parent.parent / "release_manifest.json"))
)


class DeployStatus(str, Enum):
    SUCCESS      = "success"
    FAILED       = "failed"
    ROLLED_BACK  = "rolled_back"
    IN_PROGRESS  = "in_progress"
    ROLLBACK_OK  = "rollback_success"
    ROLLBACK_FAIL = "rollback_failed"


# ── Data model ─────────────────────────────────────────────────────────────

@dataclass
class ReleaseRecord:
    environment:  str
    sha:          str
    version:      str
    status:       str           # DeployStatus value
    timestamp:    str           # ISO 8601 UTC
    pipeline_run: str  = ""
    triggered_by: str  = ""
    duration_sec: float = 0.0
    notes:        str  = ""
    rollback_from: Optional[str] = None  # SHA we rolled back from (for rollback records)

    @classmethod
    def now(cls) -> str:
        return datetime.now(tz=timezone.utc).isoformat()


# ── Manifest I/O ───────────────────────────────────────────────────────────

class ReleaseManifest:
    def __init__(self, path: Path = DEFAULT_MANIFEST_PATH):
        self.path = path
        self._records: list[dict] = []
        self._load()

    def _load(self) -> None:
        if self.path.exists():
            try:
                data = json.loads(self.path.read_text(encoding="utf-8"))
                self._records = data if isinstance(data, list) else []
            except (json.JSONDecodeError, OSError) as exc:
                log.warning("Could not load manifest %s: %s — starting fresh", self.path, exc)
                self._records = []
        else:
            self._records = []

    def _save(self) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        # Atomic write via temp file
        tmp = self.path.with_suffix(".tmp")
        tmp.write_text(
            json.dumps(self._records, indent=2, default=str),
            encoding="utf-8",
        )
        tmp.replace(self.path)
        log.debug("Manifest saved: %s (%d records)", self.path, len(self._records))

    def append(self, record: ReleaseRecord) -> None:
        self._records.append(asdict(record))
        self._save()
        log.info("Release recorded: env=%s sha=%s status=%s",
                 record.environment, record.sha[:8], record.status)

    def update_status(self, environment: str, sha: str, status: str, notes: str = "") -> bool:
        """Update the status of the most recent matching record."""
        for rec in reversed(self._records):
            if rec.get("environment") == environment and rec.get("sha") == sha:
                rec["status"] = status
                if notes:
                    rec["notes"] = notes
                self._save()
                log.info("Updated release status: env=%s sha=%s → %s", environment, sha[:8], status)
                return True
        log.warning("No matching release found to update: env=%s sha=%s", environment, sha[:8])
        return False

    def for_env(self, environment: str) -> list[dict]:
        return [r for r in self._records if r.get("environment") == environment]

    def last_good(self, environment: str) -> Optional[dict]:
        """Return the most recent successful release for the environment."""
        for rec in reversed(self.for_env(environment)):
            if rec.get("status") in (DeployStatus.SUCCESS, DeployStatus.ROLLBACK_OK):
                return rec
        return None

    def current(self, environment: str) -> Optional[dict]:
        """Return the most recent release record for the environment (any status)."""
        env_records = self.for_env(environment)
        return env_records[-1] if env_records else None

    def list_recent(self, environment: str, limit: int = 10) -> list[dict]:
        return list(reversed(self.for_env(environment)))[:limit]


# ── Helpers ────────────────────────────────────────────────────────────────

def get_git_sha() -> str:
    try:
        return subprocess.check_output(
            ["git", "rev-parse", "HEAD"],
            stderr=subprocess.DEVNULL,
        ).decode().strip()
    except Exception:
        return os.getenv("GITHUB_SHA", "unknown")


def get_git_sha_short() -> str:
    sha = get_git_sha()
    return sha[:8] if sha != "unknown" else sha


def get_pipeline_run_id() -> str:
    return (
        os.getenv("GITHUB_RUN_ID") or
        os.getenv("PIPELINE_RUN_ID") or
        f"local-{datetime.now(tz=timezone.utc).strftime('%Y%m%d%H%M%S')}"
    )


def get_triggered_by() -> str:
    return (
        os.getenv("GITHUB_ACTOR") or
        os.getenv("USER") or
        "unknown"
    )


# ── CLI commands ───────────────────────────────────────────────────────────

def cmd_record(args: argparse.Namespace, manifest: ReleaseManifest) -> int:
    sha     = args.sha or get_git_sha()
    version = args.version or os.getenv("APP_VERSION", "unknown")

    record = ReleaseRecord(
        environment  = args.env,
        sha          = sha,
        version      = version,
        status       = args.status,
        timestamp    = ReleaseRecord.now(),
        pipeline_run = args.run_id or get_pipeline_run_id(),
        triggered_by = args.triggered_by or get_triggered_by(),
        duration_sec = args.duration or 0.0,
        notes        = args.notes or "",
        rollback_from= args.rollback_from,
    )
    manifest.append(record)

    print(json.dumps(asdict(record), indent=2))
    return 0


def cmd_update(args: argparse.Namespace, manifest: ReleaseManifest) -> int:
    sha = args.sha or get_git_sha()
    ok  = manifest.update_status(args.env, sha, args.status, args.notes or "")
    return 0 if ok else 1


def cmd_last_good(args: argparse.Namespace, manifest: ReleaseManifest) -> int:
    rec = manifest.last_good(args.env)
    if rec:
        print(json.dumps(rec, indent=2))
        return 0
    else:
        log.warning("No successful release found for environment: %s", args.env)
        return 1


def cmd_current(args: argparse.Namespace, manifest: ReleaseManifest) -> int:
    rec = manifest.current(args.env)
    if rec:
        print(json.dumps(rec, indent=2))
        return 0
    else:
        log.warning("No releases found for environment: %s", args.env)
        return 1


def cmd_list(args: argparse.Namespace, manifest: ReleaseManifest) -> int:
    records = manifest.list_recent(args.env, limit=args.limit)
    if not records:
        print(f"No releases found for environment: {args.env}")
        return 0

    print(f"\n{'─' * 85}")
    print(f"  {'TIMESTAMP':<25} {'SHA':<10} {'VERSION':<12} {'STATUS':<16} {'TRIGGERED BY'}")
    print(f"{'─' * 85}")
    for rec in records:
        ts   = rec.get("timestamp", "?")[:19].replace("T", " ")
        sha  = rec.get("sha", "?")[:8]
        ver  = rec.get("version", "?")[:12]
        stat = rec.get("status", "?")[:16]
        who  = rec.get("triggered_by", "?")[:20]
        marker = " ◀ current" if rec == manifest.current(args.env) else ""
        print(f"  {ts:<25} {sha:<10} {ver:<12} {stat:<16} {who}{marker}")
    print(f"{'─' * 85}\n")
    return 0


def cmd_status(args: argparse.Namespace, manifest: ReleaseManifest) -> int:
    """Print a human-readable status table for all environments."""
    environments = list({r.get("environment", "?") for r in manifest._records})
    if not environments:
        print("No deployments recorded yet.")
        return 0

    print(f"\n{'═' * 75}")
    print("  Deployment Status Summary")
    print(f"{'═' * 75}")
    for env in sorted(environments):
        current  = manifest.current(env)
        last_ok  = manifest.last_good(env)
        all_recs = manifest.for_env(env)

        print(f"\n  Environment: {env.upper()}")
        if current:
            print(f"    Current:   {current['sha'][:8]}  v{current.get('version','?')}  [{current['status']}]  {current['timestamp'][:19]}")
        else:
            print("    Current:   (no deployments)")

        if last_ok and last_ok != current:
            print(f"    Last Good: {last_ok['sha'][:8]}  v{last_ok.get('version','?')}  [{last_ok['status']}]  {last_ok['timestamp'][:19]}")
        elif last_ok:
            print(f"    Last Good: (same as current)")

        print(f"    Total releases: {len(all_recs)}")
    print(f"\n{'═' * 75}\n")
    return 0


# ── Main ───────────────────────────────────────────────────────────────────

def main() -> int:
    parser = argparse.ArgumentParser(
        description="Track deployment releases",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    parser.add_argument("--manifest", default=str(DEFAULT_MANIFEST_PATH),
                        help="Path to release manifest JSON file")

    sub = parser.add_subparsers(dest="command")

    # record
    p_record = sub.add_parser("record", help="Record a deployment event")
    p_record.add_argument("--env",          required=True)
    p_record.add_argument("--sha",          default=None)
    p_record.add_argument("--version",      default=None)
    p_record.add_argument("--status",       default=DeployStatus.SUCCESS, choices=[e.value for e in DeployStatus])
    p_record.add_argument("--run-id",       default=None)
    p_record.add_argument("--triggered-by", default=None)
    p_record.add_argument("--duration",     type=float, default=0.0)
    p_record.add_argument("--notes",        default="")
    p_record.add_argument("--rollback-from",default=None)

    # update
    p_update = sub.add_parser("update", help="Update status of existing record")
    p_update.add_argument("--env",    required=True)
    p_update.add_argument("--sha",    default=None)
    p_update.add_argument("--status", required=True, choices=[e.value for e in DeployStatus])
    p_update.add_argument("--notes",  default="")

    # last-good
    p_lastgood = sub.add_parser("last-good", help="Get last successful release for env")
    p_lastgood.add_argument("--env", required=True)

    # current
    p_current = sub.add_parser("current", help="Get most recent release for env")
    p_current.add_argument("--env", required=True)

    # list
    p_list = sub.add_parser("list", help="List recent releases")
    p_list.add_argument("--env",   required=True)
    p_list.add_argument("--limit", type=int, default=10)

    # status
    sub.add_parser("status", help="Show status summary for all environments")

    args = parser.parse_args()
    if not args.command:
        parser.print_help()
        return 1

    manifest = ReleaseManifest(Path(args.manifest))

    commands = {
        "record":    cmd_record,
        "update":    cmd_update,
        "last-good": cmd_last_good,
        "current":   cmd_current,
        "list":      cmd_list,
        "status":    cmd_status,
    }

    return commands[args.command](args, manifest)


if __name__ == "__main__":
    sys.exit(main())
