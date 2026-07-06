"""
Test Case Manager.
Loads and manages test cases from configuration files or predefined lists.
"""

import os
import yaml
import logging
from typing import List, Dict, Any

from .attack_test_cases import get_predefined_test_cases

class TestCaseManager:
    """Loads and returns test cases."""

    def __init__(self, config_path: str):
        """
        Initialize the TestCaseManager.
        
        Args:
            config_path: Path to the YAML file containing test case definitions.
        """
        self.config_path = config_path
        self.logger = logging.getLogger(__name__)

    def load_test_cases(self) -> List[Dict[str, Any]]:
        """
        Loads test cases from file, falling back to predefined if missing.
        
        Returns:
            List of test cases.
        """
        if not os.path.exists(self.config_path):
            self.logger.warning(f"Test case file {self.config_path} not found. Using predefined test cases.")
            return get_predefined_test_cases()
            
        try:
            with open(self.config_path, "r") as f:
                data = yaml.safe_load(f)
                
            if not data or "test_cases" not in data:
                self.logger.warning("No 'test_cases' key in YAML. Using predefined test cases.")
                return get_predefined_test_cases()
                
            return data["test_cases"]
        except Exception as e:
            self.logger.error(f"Failed to load test cases from {self.config_path}: {e}")
            return get_predefined_test_cases()
