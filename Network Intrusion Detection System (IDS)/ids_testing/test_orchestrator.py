"""
Test Orchestrator for Network IDS Testing Framework.
Coordinates the overall testing process.
"""

import logging
import time
from typing import List, Dict, Any, Optional

from .config_manager import ConfigManager
from .attack_simulator import AttackSimulator
from .alert_collector import AlertCollector

class TestOrchestrator:
    """Coordinates attack execution and alert collection."""

    def __init__(self, config_manager: ConfigManager):
        """
        Initialize the orchestrator.
        
        Args:
            config_manager: Initialized ConfigManager instance.
        """
        self.config = config_manager.get_config()
        self.logger = logging.getLogger(__name__)
        self.attack_simulator = AttackSimulator(self.config)
        self.alert_collector = AlertCollector(self.config)
        self.results: List[Dict[str, Any]] = []

    def run_tests(self, test_cases: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """
        Executes a series of test cases.
        
        Args:
            test_cases: List of test definitions (dicts).
            
        Returns:
            List of result dictionaries.
        """
        self.logger.info(f"Starting execution of {len(test_cases)} test cases.")
        
        # Start alert collection in the background
        self.alert_collector.start_collection()
        
        for idx, test_case in enumerate(test_cases):
            self.logger.info(f"Executing Test [{idx+1}/{len(test_cases)}]: {test_case.get('name', 'Unknown')}")
            
            try:
                result = self._execute_single_test(test_case)
                self.results.append(result)
            except Exception as e:
                self.logger.error(f"Test case failed: {e}")
                self.results.append({
                    "test_name": test_case.get("name"),
                    "status": "ERROR",
                    "error": str(e)
                })
                
            time.sleep(1)  # Brief pause between tests
            
        self.alert_collector.stop_collection()
        self.logger.info("Test execution completed.")
        return self.results

    def _execute_single_test(self, test_case: Dict[str, Any]) -> Dict[str, Any]:
        """Runs a single test case and verifies detection."""
        attack_type = test_case.get("type")
        params = test_case.get("parameters", {})
        expected_alerts = test_case.get("expected_alerts", [])
        
        start_time = time.time()
        
        # 1. Simulate the attack
        self.attack_simulator.simulate_attack(attack_type, params)
        
        # 2. Allow IDS processing time
        time.sleep(self.config.testing.timeout_seconds)
        
        # 3. Collect alerts generated during the time window
        alerts = self.alert_collector.get_alerts_since(start_time)
        
        # 4. Verify detection
        detected = self._verify_alerts(alerts, expected_alerts)
        
        return {
            "test_name": test_case.get("name"),
            "attack_type": attack_type,
            "status": "PASS" if detected else "FAIL",
            "alerts_found": len(alerts),
            "execution_time": time.time() - start_time
        }

    def _verify_alerts(self, actual_alerts: List[Dict[str, Any]], expected_signatures: List[str]) -> bool:
        """Verifies if the expected alerts were found in the actual alerts."""
        if not expected_signatures:
            return True
            
        found_signatures = [alert.get("alert", {}).get("signature") for alert in actual_alerts]
        
        # Simple verification: Check if at least one expected signature was found
        for expected in expected_signatures:
            if any(expected in signature for signature in found_signatures if signature):
                return True
                
        return False
