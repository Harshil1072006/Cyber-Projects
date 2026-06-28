"""
Main endpoint discoverer for the Java Enterprise App Security Assessment tool.
Coordinates discovery via Swagger/OpenAPI, Source Code, and active probing.
"""

import logging
from typing import List, Optional
from urllib.parse import urlparse

from .swagger_parser import SwaggerParser, ApiEndpoint
from .spring_analyzer import SpringAnalyzer

logger = logging.getLogger(__name__)


class EndpointDiscoverer:
    """Coordinates the discovery of API endpoints across multiple methods."""

    def __init__(
        self,
        target_url: str,
        swagger_url: Optional[str] = None,
        source_dir: Optional[str] = None,
    ):
        self.target_url = target_url.rstrip("/")
        self.swagger_url = swagger_url
        self.source_dir = source_dir
        self.endpoints: List[ApiEndpoint] = []

        # Parsers
        self.swagger_parser = SwaggerParser()
        self.spring_analyzer = (
            SpringAnalyzer(self.source_dir) if self.source_dir else None
        )

    def discover(self) -> List[ApiEndpoint]:
        """Runs all configured discovery methods and aggregates the results."""
        logger.info("Starting API endpoint discovery...")

        # Method 1: Swagger/OpenAPI parsing
        if self.swagger_url:
            self._discover_via_swagger()
        else:
            # Try to guess common Swagger endpoints
            self._guess_swagger()

        # Method 2: Source Code Analysis
        if self.spring_analyzer:
            self._discover_via_source()

        # Deduplicate and merge findings
        self._deduplicate_endpoints()

        logger.info(
            f"Discovery complete. Found {len(self.endpoints)} unique endpoints."
        )
        return self.endpoints

    def _discover_via_swagger(self) -> None:
        """Discovers endpoints using the provided Swagger URL."""
        if not self.swagger_url:
            return

        logger.info(f"Attempting discovery via Swagger at {self.swagger_url}")
        swagger_endpoints = self.swagger_parser.fetch_and_parse(self.swagger_url)
        self.endpoints.extend(swagger_endpoints)

    def _guess_swagger(self) -> None:
        """Attempts to find Swagger definitions at common paths."""
        common_paths = [
            "/v2/api-docs",
            "/v3/api-docs",
            "/swagger.json",
            "/api-docs",
            "/swagger-ui/api-docs",
            "/swagger-resources",
        ]

        for path in common_paths:
            guess_url = f"{self.target_url}{path}"
            logger.debug(f"Guessing Swagger URL: {guess_url}")
            try:
                endpoints = self.swagger_parser.fetch_and_parse(guess_url)
                if endpoints:
                    logger.info(
                        f"Successfully discovered Swagger definition at {guess_url}"
                    )
                    self.endpoints.extend(endpoints)
                    return  # Stop guessing once found
            except Exception:
                pass  # Expected for incorrect guesses

    def _discover_via_source(self) -> None:
        """Discovers endpoints by analyzing the Spring Boot source code."""
        if not self.spring_analyzer:
            return

        logger.info("Attempting discovery via Source Code Analysis")
        source_endpoints = self.spring_analyzer.discover_endpoints()
        self.endpoints.extend(source_endpoints)

    def _deduplicate_endpoints(self) -> None:
        """
        Deduplicates endpoints based on Method + Path.
        Merges parameter information if duplicates are found.
        """
        unique_endpoints = {}

        for ep in self.endpoints:
            # Normalize path (e.g. remove trailing slashes unless root)
            normalized_path = ep.path.rstrip("/") if ep.path != "/" else "/"
            key = f"{ep.method}:{normalized_path}"

            if key not in unique_endpoints:
                unique_endpoints[key] = ep
            else:
                # Merge parameters (prioritize Swagger definitions as they often contain better schemas)
                existing_ep = unique_endpoints[key]

                # Simple merge: add parameters that don't exist by name
                existing_param_names = {p.name for p in existing_ep.parameters}
                for param in ep.parameters:
                    if param.name not in existing_param_names:
                        existing_ep.parameters.append(param)

                # Merge description if existing is empty
                if not existing_ep.description and ep.description:
                    existing_ep.description = ep.description

        self.endpoints = list(unique_endpoints.values())

    def get_endpoints(self) -> List[ApiEndpoint]:
        """Returns the discovered endpoints."""
        return self.endpoints
