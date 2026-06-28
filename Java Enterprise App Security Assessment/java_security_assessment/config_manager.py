"""
Configuration Manager for the Java Enterprise App Security Assessment tool.
Loads and validates assessment configuration from YAML/JSON files.
"""

import os
import yaml
import json
from typing import Dict, Any, Optional
from dataclasses import dataclass, field
from pathlib import Path


@dataclass
class TargetConfig:
    url: str = ""
    api_base_path: str = "/api/v1"
    swagger_url: Optional[str] = None
    source_dir: Optional[str] = None


@dataclass
class AuthConfig:
    type: str = "none"  # none, basic, bearer, oauth2
    username: Optional[str] = None
    password: Optional[str] = None
    token: Optional[str] = None
    oauth_token_url: Optional[str] = None
    client_id: Optional[str] = None
    client_secret: Optional[str] = None
    headers: Dict[str, str] = field(default_factory=dict)


@dataclass
class ScanOptions:
    run_sast: bool = True
    run_sca: bool = True
    run_dast: bool = True
    max_depth: int = 3
    timeout: int = 30
    threads: int = 5
    semgrep_rules: str = "config/semgrep_rules.yaml"


@dataclass
class ReportConfig:
    format: str = "all"  # html, pdf, json, all
    output_dir: str = "reports"
    executive_summary: bool = True


@dataclass
class AssessmentConfig:
    target: TargetConfig = field(default_factory=TargetConfig)
    auth: AuthConfig = field(default_factory=AuthConfig)
    scan: ScanOptions = field(default_factory=ScanOptions)
    report: ReportConfig = field(default_factory=ReportConfig)


class ConfigManager:
    """Manages the loading, parsing, and validation of assessment configurations."""

    def __init__(self, config_path: str):
        self.config_path = config_path
        self.config = self._load_config()

    def _load_config(self) -> AssessmentConfig:
        """Loads configuration from a YAML or JSON file."""
        if not os.path.exists(self.config_path):
            raise FileNotFoundError(f"Configuration file not found: {self.config_path}")

        ext = Path(self.config_path).suffix.lower()
        with open(self.config_path, "r", encoding="utf-8") as f:
            if ext in [".yaml", ".yml"]:
                raw_config = yaml.safe_load(f)
            elif ext == ".json":
                raw_config = json.load(f)
            else:
                raise ValueError(f"Unsupported configuration file format: {ext}")

        if not raw_config:
            raw_config = {}

        return self._parse_config(raw_config)

    def _parse_config(self, raw_config: Dict[str, Any]) -> AssessmentConfig:
        """Parses the raw dictionary into an AssessmentConfig object."""
        target_data = raw_config.get("target", {})
        target = TargetConfig(
            url=target_data.get("url", ""),
            api_base_path=target_data.get("api_base_path", "/api/v1"),
            swagger_url=target_data.get("swagger_url"),
            source_dir=target_data.get("source_dir"),
        )

        auth_data = raw_config.get("auth", {})
        auth = AuthConfig(
            type=auth_data.get("type", "none"),
            username=auth_data.get("username"),
            password=auth_data.get("password"),
            token=auth_data.get("token"),
            oauth_token_url=auth_data.get("oauth_token_url"),
            client_id=auth_data.get("client_id"),
            client_secret=auth_data.get("client_secret"),
            headers=auth_data.get("headers", {}),
        )

        scan_data = raw_config.get("scan", {})
        scan = ScanOptions(
            run_sast=scan_data.get("run_sast", True),
            run_sca=scan_data.get("run_sca", True),
            run_dast=scan_data.get("run_dast", True),
            max_depth=scan_data.get("max_depth", 3),
            timeout=scan_data.get("timeout", 30),
            threads=scan_data.get("threads", 5),
            semgrep_rules=scan_data.get("semgrep_rules", "config/semgrep_rules.yaml"),
        )

        report_data = raw_config.get("report", {})
        report = ReportConfig(
            format=report_data.get("format", "all"),
            output_dir=report_data.get("output_dir", "reports"),
            executive_summary=report_data.get("executive_summary", True),
        )

        return AssessmentConfig(target=target, auth=auth, scan=scan, report=report)

    def get_config(self) -> AssessmentConfig:
        """Returns the loaded configuration object."""
        return self.config
