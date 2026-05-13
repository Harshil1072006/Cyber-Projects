from abc import ABC, abstractmethod
from typing import List, Dict, Any

class BaseScanner(ABC):
    @abstractmethod
    async def scan(self, target_path: str, scan_id: int) -> List[Dict[str, Any]]:
        """
        Execute the scan against the target_path.
        Returns a list of standardized finding dictionaries:
        {
            "vulnerability_name": str,
            "severity": "Critical" | "High" | "Medium" | "Low" | "Info",
            "description": str,
            "file_path": str (optional),
            "line_number": int (optional),
            "raw_data": dict (original scanner tool output)
        }
        """
        pass
