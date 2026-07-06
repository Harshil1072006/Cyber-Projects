"""
EVE Reader.
Reads and tails Suricata's eve.json log file.
"""

import json
import logging
import os
import time
from typing import Generator, Dict, Any

class EveReader:
    """Reads Suricata EVE logs."""

    def __init__(self, eve_path: str):
        """
        Initialize the EveReader.
        
        Args:
            eve_path: Path to the eve.json file.
        """
        self.eve_path = eve_path
        self.logger = logging.getLogger(__name__)

    def tail(self) -> Generator[Dict[str, Any], None, None]:
        """
        Generator that continuously reads from the end of the EVE file.
        Yields parsed JSON objects.
        """
        if not os.path.exists(self.eve_path):
            self.logger.warning(f"EVE log {self.eve_path} does not exist. Waiting...")
            while not os.path.exists(self.eve_path):
                time.sleep(1)

        with open(self.eve_path, "r") as f:
            # Seek to end
            f.seek(0, 2)
            while True:
                line = f.readline()
                if not line:
                    time.sleep(0.1)
                    continue
                try:
                    yield json.loads(line)
                except json.JSONDecodeError:
                    self.logger.error("Failed to parse EVE line.")
                    continue
