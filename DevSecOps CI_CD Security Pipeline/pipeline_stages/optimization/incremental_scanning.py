"""
Incremental Scanner.
Detects changes and only scans modified resources.
"""

import subprocess
import logging
from typing import List

logger = logging.getLogger(__name__)

class IncrementalScanner:
    """Calculates diffs to enable incremental security scanning."""
    
    def get_changed_files(self, base_commit: str = "HEAD~1") -> List[str]:
        """
        Uses git to determine which files have changed since the base commit.
        """
        try:
            result = subprocess.run(
                ["git", "diff", "--name-only", base_commit],
                capture_output=True,
                text=True,
                check=True
            )
            files = [f.strip() for f in result.stdout.splitlines() if f.strip()]
            logger.info(f"Detected {len(files)} changed files.")
            return files
        except subprocess.CalledProcessError as e:
            logger.error(f"Git diff failed: {e}")
            return []
            
    def filter_scannable_files(self, changed_files: List[str], extensions: List[str]) -> List[str]:
        """Filters files by extension."""
        return [f for f in changed_files if any(f.endswith(ext) for ext in extensions)]
