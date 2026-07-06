"""
Suricata Controller.
Manages Suricata processes.
"""

import logging
import subprocess
from typing import Optional
from ..config_manager import IDSConfig

class SuricataController:
    """Manages the Suricata IDS instance."""

    def __init__(self, config: IDSConfig):
        """
        Initialize the SuricataController.
        
        Args:
            config: Suricata specific configuration.
        """
        self.config = config
        self.logger = logging.getLogger(__name__)

    def reload_rules(self) -> bool:
        """
        Signals Suricata to reload rules (via suricatasc).
        
        Returns:
            True if successful, False otherwise.
        """
        self.logger.info("Reloading Suricata rules.")
        try:
            # Requires suricatasc utility
            result = subprocess.run(["suricatasc", "-c", "reload-rules"], capture_output=True, text=True)
            if result.returncode == 0:
                return True
            self.logger.error(f"Rule reload failed: {result.stderr}")
            return False
        except Exception as e:
            self.logger.error(f"Failed to execute suricatasc: {e}")
            return False
