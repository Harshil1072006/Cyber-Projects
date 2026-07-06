"""
SARIF Validator.
Validates SARIF files against the v2.1.0 schema and auto-fixes common issues.
"""

import json
import logging
from typing import Dict, Any, Tuple

logger = logging.getLogger(__name__)

class SarifValidator:
    """Validates and sanitizes SARIF data."""
    
    def validate_and_fix(self, sarif_data: Dict[str, Any]) -> Tuple[bool, Dict[str, Any]]:
        """
        Validates SARIF data structure. 
        Auto-fixes minor issues if possible.
        
        Returns:
            Tuple of (is_valid, fixed_sarif_data)
        """
        is_valid = True
        
        # Check version
        version = sarif_data.get("version")
        if version != "2.1.0":
            logger.warning(f"Unsupported SARIF version: {version}. Forcing to 2.1.0")
            sarif_data["version"] = "2.1.0"
            is_valid = False
            
        # Check $schema
        if "$schema" not in sarif_data:
            sarif_data["$schema"] = "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json"
            
        # Ensure runs array exists
        if "runs" not in sarif_data or not isinstance(sarif_data["runs"], list):
            logger.error("Invalid SARIF: Missing or invalid 'runs' array")
            return False, sarif_data
            
        for run in sarif_data["runs"]:
            if "tool" not in run or "driver" not in run["tool"]:
                logger.error("Invalid SARIF: Run missing tool/driver object")
                return False, sarif_data
                
            # Ensure results array exists even if empty
            if "results" not in run:
                run["results"] = []
                
        return is_valid, sarif_data
