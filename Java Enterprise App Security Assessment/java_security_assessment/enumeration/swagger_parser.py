"""
Swagger/OpenAPI parsing module.
Extracts endpoints, parameters, and security definitions from OpenAPI specs.
"""

import json
import logging
import requests
from typing import Dict, List, Any, Optional
from urllib.parse import urlparse

from .parameter_analyzer import ParameterAnalyzer, ApiParameter

logger = logging.getLogger(__name__)


class ApiEndpoint:
    """Represents a discovered API endpoint."""

    def __init__(self, path: str, method: str, description: str = ""):
        self.path = path
        self.method = method.upper()
        self.description = description
        self.parameters: List[ApiParameter] = []
        self.requires_auth: bool = False
        self.consumes: List[str] = []
        self.produces: List[str] = []

    def __str__(self):
        return f"{self.method} {self.path}"


class SwaggerParser:
    """Parses Swagger 2.0 and OpenAPI 3.0 specifications."""

    def __init__(self):
        self.parameter_analyzer = ParameterAnalyzer()
        self.endpoints: List[ApiEndpoint] = []
        self.base_path: str = ""
        self.host: str = ""
        self.security_schemes: Dict[str, Any] = {}

    def fetch_and_parse(self, url: str) -> List[ApiEndpoint]:
        """Fetches a Swagger/OpenAPI definition from a URL and parses it."""
        try:
            logger.info(f"Fetching Swagger definition from {url}")
            response = requests.get(url, timeout=10)
            response.raise_for_status()
            spec = response.json()
            return self.parse_spec(spec)
        except Exception as e:
            logger.error(f"Failed to fetch or parse Swagger URL {url}: {e}")
            return []

    def parse_spec(self, spec: Dict[str, Any]) -> List[ApiEndpoint]:
        """Parses a loaded OpenAPI/Swagger dictionary."""
        self.endpoints = []

        # Determine version
        is_openapi3 = "openapi" in spec
        is_swagger2 = "swagger" in spec

        if not (is_openapi3 or is_swagger2):
            logger.error("Provided JSON is not a recognized Swagger/OpenAPI format.")
            return []

        # Extract base path and host
        if is_swagger2:
            self.base_path = spec.get("basePath", "")
            self.host = spec.get("host", "")
        else:
            # OpenAPI 3 uses 'servers' array
            servers = spec.get("servers", [])
            if servers:
                server_url = servers[0].get("url", "")
                parsed_url = urlparse(server_url)
                self.host = parsed_url.netloc
                self.base_path = parsed_url.path

        # Extract security schemes
        self._extract_security_schemes(spec, is_openapi3)

        # Global security requirement
        global_security = spec.get("security", [])

        # Parse paths
        paths = spec.get("paths", {})
        for path, path_obj in paths.items():
            if not isinstance(path_obj, dict):
                continue

            full_path = self.base_path.rstrip("/") + "/" + path.lstrip("/")

            # Common parameters for all methods on this path
            path_parameters = path_obj.get("parameters", [])

            for method, operation in path_obj.items():
                if method.lower() not in [
                    "get",
                    "post",
                    "put",
                    "delete",
                    "patch",
                    "options",
                    "head",
                ]:
                    continue

                endpoint = ApiEndpoint(
                    path=full_path,
                    method=method,
                    description=operation.get(
                        "summary", operation.get("description", "")
                    ),
                )

                # Check for authentication requirements
                op_security = operation.get("security")
                if op_security is not None:
                    endpoint.requires_auth = len(op_security) > 0
                else:
                    endpoint.requires_auth = len(global_security) > 0

                # Process parameters (merging path-level and operation-level)
                all_raw_params = path_parameters + operation.get("parameters", [])
                for raw_param in all_raw_params:
                    # Handle references ($ref) - highly simplified for MVP
                    if "$ref" in raw_param:
                        resolved = self._resolve_ref(raw_param["$ref"], spec)
                        if resolved:
                            raw_param = resolved

                    param = self.parameter_analyzer.analyze_parameter(raw_param)
                    endpoint.parameters.append(param)

                # Process Request Body (OpenAPI 3)
                if is_openapi3 and "requestBody" in operation:
                    req_body = operation["requestBody"]
                    if "$ref" in req_body:
                        req_body = self._resolve_ref(req_body["$ref"], spec) or req_body

                    content = req_body.get("content", {})
                    for content_type, media_type_obj in content.items():
                        endpoint.consumes.append(content_type)
                        schema = media_type_obj.get("schema", {})
                        if "$ref" in schema:
                            schema = self._resolve_ref(schema["$ref"], spec) or schema

                        body_params = self.parameter_analyzer.analyze_body_schema(
                            schema
                        )
                        endpoint.parameters.extend(body_params)

                # Process Body Parameters (Swagger 2)
                elif is_swagger2 and "consumes" in operation:
                    endpoint.consumes.extend(operation["consumes"])
                    # In Swagger 2, body parameters are in the 'parameters' list with in='body'
                    # which is already handled above, though the schema parsing is simpler

                self.endpoints.append(endpoint)

        logger.info(
            f"Successfully parsed {len(self.endpoints)} endpoints from specification."
        )
        return self.endpoints

    def _extract_security_schemes(
        self, spec: Dict[str, Any], is_openapi3: bool
    ) -> None:
        """Extracts security definitions/schemes."""
        if is_openapi3:
            components = spec.get("components", {})
            self.security_schemes = components.get("securitySchemes", {})
        else:
            self.security_schemes = spec.get("securityDefinitions", {})

    def _resolve_ref(
        self, ref_string: str, spec: Dict[str, Any]
    ) -> Optional[Dict[str, Any]]:
        """Simplistic resolver for local references (e.g., #/components/schemas/User)."""
        if not ref_string.startswith("#/"):
            return None  # Only supporting local references

        parts = ref_string[2:].split("/")
        current = spec
        try:
            for part in parts:
                current = current[part]
            return current
        except KeyError:
            logger.warning(f"Failed to resolve reference: {ref_string}")
            return None
