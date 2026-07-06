"""
ZAP Advanced Configurator.
Tunes ZAP active/passive scanning profiles.
"""

from typing import Dict, Any

class ZapConfigurator:
    """Configures OWASP ZAP for optimized pipeline execution."""
    
    def get_optimized_profile(self, is_api: bool = False) -> Dict[str, Any]:
        """
        Returns an optimized scanning profile.
        """
        profile = {
            "max_children_to_crawl": 100,
            "max_crawl_depth": 5,
            "ajax_spider": True,
            "passive_scan_enabled": True,
            "active_scan_enabled": True,
            "disabled_scanners": [] # IDs of noisy or irrelevant scanners
        }
        
        if is_api:
            # Optimize for API (disable DOM XSS, etc.)
            profile["ajax_spider"] = False
            profile["disabled_scanners"].extend([40012, 40014, 40016]) # Example DOM XSS scanner IDs
            
        return profile
