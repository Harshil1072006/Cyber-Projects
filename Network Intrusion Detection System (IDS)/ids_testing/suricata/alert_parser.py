"""
Alert Parser.
Parses Suricata alerts.
"""

from typing import Dict, Any, Optional

class AlertParser:
    """Parses raw EVE JSON alerts into a standard format."""

    @staticmethod
    def parse(eve_event: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """
        Parses an event, returning None if not an alert.
        """
        if eve_event.get("event_type") != "alert":
            return None
            
        alert_data = eve_event.get("alert", {})
        
        return {
            "timestamp": eve_event.get("timestamp"),
            "src_ip": eve_event.get("src_ip"),
            "src_port": eve_event.get("src_port"),
            "dest_ip": eve_event.get("dest_ip"),
            "dest_port": eve_event.get("dest_port"),
            "signature": alert_data.get("signature"),
            "category": alert_data.get("category"),
            "severity": alert_data.get("severity"),
            "raw": eve_event
        }
