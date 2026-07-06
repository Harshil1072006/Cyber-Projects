"""
Configuration Manager for IDS Testing Framework.
Loads and validates settings from YAML/JSON files.
"""

import os
import yaml
import logging
from typing import Dict, Any, Optional
from pydantic import BaseModel, Field

class IDSConfig(BaseModel):
    suricata_socket: str = "/var/run/suricata.ipc"
    eve_log_path: str = "/var/log/suricata/eve.json"
    rules_path: str = "/etc/suricata/rules"

class NetworkConfig(BaseModel):
    interface: str = "eth0"
    target_ip: str = "127.0.0.1"
    target_mac: str = "00:00:00:00:00:00"
    gateway_ip: str = "192.168.1.1"

class ELKConfig(BaseModel):
    elasticsearch_url: str = "http://localhost:9200"
    index_prefix: str = "ids-tests-"
    username: Optional[str] = None
    password: Optional[str] = None

class TestConfig(BaseModel):
    test_cases_file: str = "config/test_cases.yaml"
    timeout_seconds: int = 60
    concurrent_attacks: bool = False
    log_level: str = "INFO"
    report_dir: str = "examples/reports"

class FrameworkConfig(BaseModel):
    ids: IDSConfig = Field(default_factory=IDSConfig)
    network: NetworkConfig = Field(default_factory=NetworkConfig)
    elk: ELKConfig = Field(default_factory=ELKConfig)
    testing: TestConfig = Field(default_factory=TestConfig)

class ConfigManager:
    """Manages all configuration loading and validation."""

    def __init__(self, config_path: str):
        """
        Initialize the ConfigManager.
        
        Args:
            config_path: Path to the main configuration YAML file.
        """
        self.config_path = config_path
        self.config = self._load_config()
        self._setup_logging()

    def _load_config(self) -> FrameworkConfig:
        """Loads and parses the YAML configuration file."""
        if not os.path.exists(self.config_path):
            logging.warning(f"Config file {self.config_path} not found. Using defaults.")
            return FrameworkConfig()

        try:
            with open(self.config_path, "r") as f:
                raw_config = yaml.safe_load(f) or {}
            
            return FrameworkConfig(**raw_config)
        except Exception as e:
            logging.error(f"Failed to load config from {self.config_path}: {e}")
            raise RuntimeError(f"Configuration error: {e}")

    def _setup_logging(self) -> None:
        """Configures the root logger based on settings."""
        log_level = getattr(logging, self.config.testing.log_level.upper(), logging.INFO)
        logging.basicConfig(
            level=log_level,
            format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
            handlers=[
                logging.StreamHandler(),
                logging.FileHandler("ids_testing.log")
            ]
        )
        logging.info("Configuration and logging initialized.")

    def get_config(self) -> FrameworkConfig:
        """Returns the fully validated configuration object."""
        return self.config
