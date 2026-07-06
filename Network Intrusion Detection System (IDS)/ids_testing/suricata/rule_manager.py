"""
Rule Manager.
Manages custom testing rules.
"""

import logging
import os
from typing import List

class RuleManager:
    """Manages Suricata rules for the testing framework."""

    def __init__(self, rules_path: str):
        """
        Initialize the RuleManager.
        
        Args:
            rules_path: Path to the suricata rules file/dir.
        """
        self.rules_path = rules_path
        self.logger = logging.getLogger(__name__)

    def inject_test_rules(self, rules: List[str]) -> bool:
        """
        Appends test rules to the configuration.
        """
        self.logger.info(f"Injecting {len(rules)} test rules into {self.rules_path}")
        try:
            with open(self.rules_path, "a") as f:
                for rule in rules:
                    f.write(f"\n{rule}")
            return True
        except Exception as e:
            self.logger.error(f"Failed to write rules: {e}")
            return False
