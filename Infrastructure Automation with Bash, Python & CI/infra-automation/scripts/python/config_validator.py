#!/usr/bin/env python3
"""
config_validator.py — Validate environment config files before deployment.

Reads an .env file and validates it against a schema:
  - Required keys must be present
  - Values must match type/regex constraints
  - Secrets must not be placeholder values (e.g. "CHANGEME", "TODO")
  - URL fields must be valid URLs
  - Port fields must be valid port numbers

Usage:
  python config_validator.py --env staging
  python config_validator.py --env-file environments/production.env
  python config_validator.py --env staging --strict   # fail on warnings too

Exit codes:
  0  Valid
  1  Invalid — abort deployment
  2  Warning-only (non-strict mode)
"""

from __future__ import annotations

import re
import sys
import argparse
import logging
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Optional
from urllib.parse import urlparse

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    datefmt="%Y-%m-%dT%H:%M:%S",
)
log = logging.getLogger("config_validator")

# ── Schema definition ──────────────────────────────────────────────────────

class Severity(Enum):
    ERROR   = "ERROR"
    WARNING = "WARNING"
    INFO    = "INFO"


@dataclass
class FieldRule:
    """Defines validation constraints for a single config field."""
    key:         str
    required:    bool   = True
    description: str    = ""
    field_type:  str    = "string"      # string | url | port | bool | path | secret
    pattern:     Optional[str] = None   # regex the value must match
    min_length:  int    = 0
    max_length:  int    = 4096
    allowed_values: list[str] = field(default_factory=list)
    forbidden_values: list[str] = field(default_factory=list)
    severity:    Severity = Severity.ERROR  # if required + missing → ERROR or WARNING


# Schema: all valid fields and their constraints
CONFIG_SCHEMA: list[FieldRule] = [

    # ── Application ──────────────────────────────────────────────────────
    FieldRule(
        key="APP_NAME", required=True,
        description="Application name (used for service management and logging)",
        pattern=r"^[a-z0-9][a-z0-9_-]{1,48}[a-z0-9]$",
    ),
    FieldRule(
        key="APP_VERSION", required=True,
        description="Semantic version of the artifact being deployed (e.g. 1.2.3)",
        pattern=r"^\d+\.\d+\.\d+(-[a-zA-Z0-9.]+)?$",
    ),
    FieldRule(
        key="APP_ENV", required=True,
        description="Target environment",
        allowed_values=["staging", "production", "development"],
    ),
    FieldRule(
        key="APP_PORT", required=True,
        description="Port the application listens on",
        field_type="port",
    ),
    FieldRule(
        key="APP_HEALTH_PATH", required=False,
        description="HTTP path for health checks",
        pattern=r"^/\S*$",
    ),
    FieldRule(
        key="APP_LOG_LEVEL", required=False,
        description="Application log level",
        allowed_values=["debug", "info", "warn", "warning", "error", "critical"],
    ),

    # ── Deployment ───────────────────────────────────────────────────────
    FieldRule(
        key="DEPLOY_USER", required=True,
        description="Linux user account the app runs as",
        pattern=r"^[a-z_][a-z0-9_-]{0,31}$",
    ),
    FieldRule(
        key="DEPLOY_DIR", required=True,
        description="Absolute path where the app is deployed",
        field_type="path",
        pattern=r"^/[^\0]+$",
    ),
    FieldRule(
        key="DEPLOY_BACKUP_DIR", required=False,
        description="Absolute path for deployment backups",
        field_type="path",
    ),
    FieldRule(
        key="ARTIFACT_URL", required=False,
        description="URL to download the deployment artifact",
        field_type="url",
    ),

    # ── Database / Services ───────────────────────────────────────────────
    FieldRule(
        key="DATABASE_URL", required=False,
        description="Database connection string",
        field_type="secret",
        severity=Severity.WARNING,
        forbidden_values=["CHANGEME", "TODO", "placeholder", "example"],
    ),
    FieldRule(
        key="REDIS_URL", required=False,
        description="Redis connection URL",
        field_type="url",
    ),

    # ── Secrets ───────────────────────────────────────────────────────────
    FieldRule(
        key="SECRET_KEY", required=True,
        description="Application secret key for signing (min 32 chars)",
        field_type="secret",
        min_length=32,
        forbidden_values=["CHANGEME", "TODO", "placeholder", "your-secret-here", "insecure"],
    ),
    FieldRule(
        key="SLACK_WEBHOOK_URL", required=False,
        description="Slack webhook for deployment notifications",
        field_type="url",
        severity=Severity.WARNING,
    ),

    # ── Infrastructure ────────────────────────────────────────────────────
    FieldRule(
        key="TARGET_HOST", required=True,
        description="Hostname or IP of the target server",
    ),
    FieldRule(
        key="SSH_KEY_PATH", required=False,
        description="Path to SSH private key for remote execution",
        field_type="path",
    ),
    FieldRule(
        key="MAX_DEPLOY_RETRIES", required=False,
        description="Number of deployment retry attempts",
        pattern=r"^\d+$",
    ),
    FieldRule(
        key="HEALTH_CHECK_TIMEOUT", required=False,
        description="Seconds to wait for health check after deploy",
        pattern=r"^\d+$",
    ),
]

# ── Validation logic ───────────────────────────────────────────────────────

@dataclass
class ValidationResult:
    key:     str
    severity: Severity
    message: str
    value:   Optional[str] = None


def load_env_file(path: Path) -> dict[str, str]:
    """Parse a .env file into a dict, ignoring comments and blank lines."""
    config: dict[str, str] = {}
    for line_num, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        if "=" not in stripped:
            log.warning("Line %d: ignoring malformed line (no '='): %s", line_num, stripped[:60])
            continue
        key, _, value = stripped.partition("=")
        key   = key.strip()
        value = value.strip().strip('"').strip("'")  # strip optional quotes
        config[key] = value
    return config


def validate_url(value: str) -> Optional[str]:
    """Returns error message if not a valid URL, None if OK."""
    try:
        parsed = urlparse(value)
        if parsed.scheme not in ("http", "https", "postgres", "postgresql", "redis", "mysql"):
            return f"URL scheme '{parsed.scheme}' not recognized"
        if not parsed.netloc:
            return "URL is missing hostname"
    except Exception as exc:
        return str(exc)
    return None


def validate_port(value: str) -> Optional[str]:
    """Returns error message if not a valid port number."""
    try:
        port = int(value)
        if not (1 <= port <= 65535):
            return f"Port {port} is out of range (1-65535)"
    except ValueError:
        return f"Port '{value}' is not an integer"
    return None


def validate_field(rule: FieldRule, value: Optional[str]) -> list[ValidationResult]:
    results: list[ValidationResult] = []

    # Required check
    if value is None or value == "":
        if rule.required:
            results.append(ValidationResult(
                key=rule.key,
                severity=rule.severity,
                message=f"Required field is missing or empty — {rule.description}",
            ))
        return results  # no further checks if missing

    # Forbidden values (placeholder check)
    for forbidden in rule.forbidden_values:
        if forbidden.lower() in value.lower():
            results.append(ValidationResult(
                key=rule.key, value=f"{value[:20]}...",
                severity=Severity.ERROR,
                message=f"Value contains forbidden placeholder '{forbidden}' — set a real value",
            ))

    # Type-specific validation
    if rule.field_type == "url":
        if (err := validate_url(value)):
            results.append(ValidationResult(
                key=rule.key, value=value[:40],
                severity=Severity.ERROR,
                message=f"Invalid URL: {err}",
            ))

    elif rule.field_type == "port":
        if (err := validate_port(value)):
            results.append(ValidationResult(
                key=rule.key, value=value,
                severity=Severity.ERROR,
                message=f"Invalid port: {err}",
            ))

    elif rule.field_type == "path":
        if not value.startswith("/"):
            results.append(ValidationResult(
                key=rule.key, value=value,
                severity=Severity.WARNING,
                message="Path should be absolute (start with '/')",
            ))

    elif rule.field_type == "secret":
        if len(value) < rule.min_length:
            results.append(ValidationResult(
                key=rule.key,
                severity=Severity.ERROR,
                message=f"Secret too short: {len(value)} chars < minimum {rule.min_length}",
            ))

    # Pattern validation
    if rule.pattern and not re.fullmatch(rule.pattern, value):
        results.append(ValidationResult(
            key=rule.key, value=value[:40],
            severity=Severity.ERROR,
            message=f"Value does not match required pattern: {rule.pattern}",
        ))

    # Allowed values
    if rule.allowed_values and value not in rule.allowed_values:
        results.append(ValidationResult(
            key=rule.key, value=value,
            severity=Severity.ERROR,
            message=f"Value '{value}' not in allowed set: {rule.allowed_values}",
        ))

    # Length checks
    if len(value) > rule.max_length:
        results.append(ValidationResult(
            key=rule.key,
            severity=Severity.WARNING,
            message=f"Value is unusually long: {len(value)} > {rule.max_length}",
        ))

    return results


def validate_config(config: dict[str, str], strict: bool = False) -> tuple[bool, list[ValidationResult]]:
    """
    Validate config against schema. Returns (is_valid, all_results).
    is_valid is False if any ERRORs (or any warnings in strict mode).
    """
    all_results: list[ValidationResult] = []

    for rule in CONFIG_SCHEMA:
        value = config.get(rule.key)
        results = validate_field(rule, value)
        all_results.extend(results)

    # Check for unknown keys (warn, not error)
    schema_keys = {r.key for r in CONFIG_SCHEMA}
    for key in config:
        if key not in schema_keys:
            all_results.append(ValidationResult(
                key=key,
                severity=Severity.INFO,
                message="Key not in schema — may be a custom or extra field (OK if intentional)",
            ))

    is_valid = not any(
        r.severity == Severity.ERROR or (strict and r.severity == Severity.WARNING)
        for r in all_results
    )
    return is_valid, all_results


def print_results(results: list[ValidationResult], config: dict[str, str]) -> None:
    """Pretty-print validation results grouped by severity."""
    errors   = [r for r in results if r.severity == Severity.ERROR]
    warnings = [r for r in results if r.severity == Severity.WARNING]
    infos    = [r for r in results if r.severity == Severity.INFO]

    icons = {Severity.ERROR: "✗", Severity.WARNING: "⚠", Severity.INFO: "ℹ"}

    for severity, group in [(Severity.ERROR, errors), (Severity.WARNING, warnings), (Severity.INFO, infos)]:
        for r in group:
            icon = icons[severity]
            val_hint = f" (value: {r.value!r})" if r.value else ""
            print(f"  {icon} [{severity.value}] {r.key}{val_hint}: {r.message}")

    print(f"\n  Summary: {len(errors)} errors, {len(warnings)} warnings, {len(infos)} info")

    # Show which required fields are present (quick status table)
    print("\n  Required fields status:")
    for rule in CONFIG_SCHEMA:
        if rule.required:
            present = rule.key in config and config[rule.key]
            status  = "✓" if present else "✗"
            print(f"    {status}  {rule.key}")


# ── CLI ────────────────────────────────────────────────────────────────────

def main() -> int:
    parser = argparse.ArgumentParser(
        description="Validate environment config before deployment",
    )
    parser.add_argument("--env",      default="staging",
                        help="Environment name (staging|production) — loads environments/{env}.env")
    parser.add_argument("--env-file", default=None,
                        help="Explicit path to .env file (overrides --env)")
    parser.add_argument("--strict",   action="store_true",
                        help="Treat warnings as errors")
    parser.add_argument("--quiet",    action="store_true",
                        help="Only print errors (no info/warnings)")
    args = parser.parse_args()

    # Resolve env file path
    if args.env_file:
        env_path = Path(args.env_file)
    else:
        env_path = Path(__file__).parent.parent.parent / "environments" / f"{args.env}.env"

    if not env_path.exists():
        log.error("Config file not found: %s", env_path)
        return 1

    log.info("Validating: %s (strict=%s)", env_path, args.strict)
    config = load_env_file(env_path)
    log.info("Loaded %d config keys", len(config))

    is_valid, results = validate_config(config, strict=args.strict)

    print(f"\n{'═' * 55}")
    print(f"  Config Validation: {env_path.name}")
    print(f"{'═' * 55}")
    print_results(results, config)
    print(f"{'═' * 55}")
    print(f"  Result: {'✓ VALID' if is_valid else '✗ INVALID — deployment blocked'}")
    print(f"{'═' * 55}\n")

    return 0 if is_valid else 1


if __name__ == "__main__":
    sys.exit(main())
