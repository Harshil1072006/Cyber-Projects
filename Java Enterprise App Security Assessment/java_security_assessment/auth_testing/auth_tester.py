"""
Main Authentication Tester orchestrator.
Coordinates testing across JWT, OAuth, and permissions.
"""

import logging
from typing import Dict, Any, List
from ..finding_manager import FindingManager
from ..enumeration.swagger_parser import ApiEndpoint
from .jwt_auditor import JwtAuditor
from .oauth_analyzer import OAuthAnalyzer
from .permission_checker import PermissionChecker

logger = logging.getLogger(__name__)


class AuthTester:
    """Coordinates authentication and authorization testing."""

    def __init__(self, finding_manager: FindingManager, config: Dict[str, Any]):
        self.finding_manager = finding_manager
        self.config = config
        self.target_url = config.get("target", {}).get("url", "")
        self.auth_config = config.get("auth", {})
        self.endpoints: List[ApiEndpoint] = []

    def set_endpoints(self, endpoints: List[ApiEndpoint]) -> None:
        """Sets the endpoints discovered in Phase 2."""
        self.endpoints = endpoints

    def run_tests(self) -> None:
        """Executes all authentication-related tests."""
        logger.info("Running Phase 4: Authentication & Authorization Testing")

        # 1. JWT Auditing
        token = self.auth_config.get("token")
        if token:
            logger.info("JWT Token found in config. Running JWT Auditor.")
            jwt_auditor = JwtAuditor(self.finding_manager, token)
            jwt_auditor.audit()

        # 2. OAuth2 Analysis
        if self.auth_config.get("type") == "oauth2":
            logger.info("OAuth2 config found. Running OAuth Analyzer.")
            oauth_analyzer = OAuthAnalyzer(self.finding_manager, self.auth_config)
            oauth_analyzer.analyze()

        # 3. Permission / Access Control Checking
        if self.endpoints:
            logger.info("Running Permission Checker against discovered endpoints.")
            # For testing missing auth, we explicitly pass empty auth headers
            permission_checker = PermissionChecker(
                self.finding_manager, self.target_url, {}
            )
            permission_checker.test_endpoints(self.endpoints)

        logger.info("Authentication & Authorization Testing complete.")
