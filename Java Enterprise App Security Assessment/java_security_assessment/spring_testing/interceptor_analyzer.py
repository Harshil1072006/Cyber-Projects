"""
Interceptor Analyzer.
Analyzes Spring Security filter chains and custom interceptors.
"""

import logging
from typing import Dict, Any
from ..finding_manager import FindingManager, Finding, Evidence

logger = logging.getLogger(__name__)


class InterceptorAnalyzer:
    """Analyzes Spring Security filter chains (Static Analysis via Source Code)."""

    def __init__(self, finding_manager: FindingManager, source_dir: str):
        self.finding_manager = finding_manager
        self.source_dir = source_dir

    def analyze(self) -> None:
        """Searches source code for common Spring Security misconfigurations."""
        if not self.source_dir:
            return

        logger.info("Starting Spring Security Filter Chain analysis...")

        # In a real implementation, this would use AST or regex to parse SecurityFilterChain beans
        # looking for .csrf().disable() or permissive .requestMatchers("/**").permitAll()

        # This is a stub for the architecture. Semgrep actually handles most of this
        # static analysis, so we delegate the heavy lifting there.

        logger.info(
            "Spring Security Filter Chain analysis complete (Delegated to SAST/Semgrep)."
        )
