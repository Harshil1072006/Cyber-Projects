"""
DAST Orchestrator.
Intelligently manages dynamic application security testing (DAST) scans.
"""

from typing import Dict, Any, List
from .zap_advanced_options import ZapConfigurator
from .api_fuzzing import ApiFuzzer

class DastOrchestrator:
    """Manages context-aware DAST scans."""
    
    def __init__(self, target_url: str):
        self.target_url = target_url
        self.zap_config = ZapConfigurator()
        self.api_fuzzer = ApiFuzzer()
        
    def configure_scan(self, openapi_spec_url: str = None) -> Dict[str, Any]:
        """
        Configures the scan based on available metadata.
        """
        scan_plan = {
            "target": self.target_url,
            "crawling": "standard",
            "active_scan": True,
            "custom_policies": []
        }
        
        # If API spec is provided, switch to API mode
        if openapi_spec_url:
            scan_plan["crawling"] = "openapi"
            scan_plan["spec_url"] = openapi_spec_url
            scan_plan["fuzzing_endpoints"] = self.api_fuzzer.analyze_spec(openapi_spec_url)
            
        scan_plan["zap_options"] = self.zap_config.get_optimized_profile(is_api=bool(openapi_spec_url))
        
        return scan_plan
