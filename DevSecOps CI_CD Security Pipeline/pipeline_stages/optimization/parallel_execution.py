"""
Parallel Execution Manager.
Orchestrates parallel execution of independent scanning tools.
"""

import concurrent.futures
import logging
from typing import List, Callable, Dict, Any

logger = logging.getLogger(__name__)

class ParallelExecutionManager:
    """Runs scanning tools in parallel to reduce pipeline duration."""
    
    def __init__(self, max_workers: int = 4):
        self.max_workers = max_workers
        
    def run_scanners(self, scanner_tasks: List[Dict[str, Any]]) -> List[Any]:
        """
        Executes a list of scanner callables in parallel.
        scanner_tasks format: [{"name": "tool_name", "func": callable, "args": ()}]
        """
        results = []
        
        with concurrent.futures.ThreadPoolExecutor(max_workers=self.max_workers) as executor:
            future_to_scanner = {
                executor.submit(task["func"], *task.get("args", [])): task["name"] 
                for task in scanner_tasks
            }
            
            for future in concurrent.futures.as_completed(future_to_scanner):
                scanner_name = future_to_scanner[future]
                try:
                    data = future.result()
                    results.append({"tool": scanner_name, "status": "success", "data": data})
                    logger.info(f"{scanner_name} completed successfully.")
                except Exception as exc:
                    logger.error(f"{scanner_name} generated an exception: {exc}")
                    results.append({"tool": scanner_name, "status": "failed", "error": str(exc)})
                    
        return results
