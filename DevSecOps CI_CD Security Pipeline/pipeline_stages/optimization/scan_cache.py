"""
Scan Cache.
Caches tool execution results to speed up repeated runs when source code hasn't changed.
"""

import hashlib
import json
import logging
import os
from typing import Dict, Any, Optional

logger = logging.getLogger(__name__)

class ScanCache:
    """Manages caching of scan results."""
    
    def __init__(self, cache_dir: str = ".cache/sec_pipeline"):
        self.cache_dir = cache_dir
        os.makedirs(self.cache_dir, exist_ok=True)
        
    def _generate_cache_key(self, tool_name: str, file_hashes: Dict[str, str], config_hash: str) -> str:
        """Generates a unique cache key based on inputs."""
        # Combine hashes of all inputs deterministically
        combined = json.dumps({"files": file_hashes, "config": config_hash}, sort_keys=True)
        return f"{tool_name}_{hashlib.sha256(combined.encode()).hexdigest()}"
        
    def get(self, tool_name: str, file_hashes: Dict[str, str], config_hash: str) -> Optional[Dict[str, Any]]:
        """Retrieves cached results if they exist."""
        key = self._generate_cache_key(tool_name, file_hashes, config_hash)
        cache_path = os.path.join(self.cache_dir, f"{key}.json")
        
        if os.path.exists(cache_path):
            logger.info(f"Cache hit for {tool_name}")
            try:
                with open(cache_path, "r") as f:
                    return json.load(f)
            except Exception as e:
                logger.error(f"Failed to read cache: {e}")
                
        logger.info(f"Cache miss for {tool_name}")
        return None
        
    def set(self, tool_name: str, file_hashes: Dict[str, str], config_hash: str, results: Dict[str, Any]) -> None:
        """Stores results in the cache."""
        key = self._generate_cache_key(tool_name, file_hashes, config_hash)
        cache_path = os.path.join(self.cache_dir, f"{key}.json")
        
        try:
            with open(cache_path, "w") as f:
                json.dump(results, f)
        except Exception as e:
            logger.error(f"Failed to write cache: {e}")
