"""
Spring Boot source code analyzer.
Extracts endpoints, annotations, and parameters directly from Java source code.
"""

import os
import re
import logging
from typing import List, Dict, Any, Optional

from .parameter_analyzer import ParameterAnalyzer, ApiParameter
from .swagger_parser import ApiEndpoint

logger = logging.getLogger(__name__)


class SpringAnalyzer:
    """Analyzes Spring Boot Java source code to discover endpoints and configuration."""

    def __init__(self, source_dir: str):
        self.source_dir = source_dir
        self.endpoints: List[ApiEndpoint] = []
        self.parameter_analyzer = ParameterAnalyzer()

    def discover_endpoints(self) -> List[ApiEndpoint]:
        """Scans the source directory for Spring Controllers and extracts endpoints."""
        if not self.source_dir or not os.path.exists(self.source_dir):
            logger.warning(f"Source directory not found: {self.source_dir}")
            return []

        logger.info(f"Scanning {self.source_dir} for Spring Boot controllers...")

        for root, _, files in os.walk(self.source_dir):
            for file in files:
                if file.endswith(".java"):
                    filepath = os.path.join(root, file)
                    self._analyze_java_file(filepath)

        logger.info(f"Discovered {len(self.endpoints)} endpoints from source code.")
        return self.endpoints

    def _analyze_java_file(self, filepath: str) -> None:
        """Parses a single Java file looking for @RestController and mapping annotations."""
        try:
            with open(filepath, "r", encoding="utf-8") as f:
                content = f.read()

            # Very basic check if it's a controller
            if "@RestController" not in content and "@Controller" not in content:
                return

            # Extract class-level @RequestMapping
            class_base_path = ""
            class_mapping_match = re.search(
                r'@RequestMapping\s*\(\s*(?:value\s*=\s*)?["\']([^"\']+)["\']', content
            )
            if class_mapping_match:
                class_base_path = class_mapping_match.group(1)

            # Find all methods with mapping annotations
            # Regex simplified for MVP; assumes annotation and method signature are reasonably close
            mapping_pattern = re.compile(
                r'@(Get|Post|Put|Delete|Patch|Request)Mapping\s*\(\s*(?:value\s*=\s*|path\s*=\s*)?["\']?([^"\')]+)?["\']?\s*\)'
                r".*?(public|protected|private)\s+[\w<>,\[\]\s]+\s+(\w+)\s*\((.*?)\)",
                re.DOTALL,
            )

            for match in mapping_pattern.finditer(content):
                mapping_type = match.group(1).upper()  # GET, POST, REQUEST
                method_path = match.group(2) or ""
                method_name = match.group(4)
                params_str = match.group(5)

                # Determine HTTP Method
                http_methods = [mapping_type]
                if mapping_type == "REQUEST":
                    # If it's @RequestMapping without explicit method, it theoretically accepts all,
                    # but usually there's a method=RequestMethod.GET. We'll default to GET for simplicity
                    # unless explicitly defined (regex is too simple to catch all variations).
                    http_methods = ["GET", "POST", "PUT", "DELETE"]

                full_path = class_base_path.rstrip("/") + "/" + method_path.lstrip("/")

                # Clean up path (sometimes they have brackets or quotes left over from simple regex)
                full_path = (
                    full_path.replace('"', "")
                    .replace("'", "")
                    .replace("{", "{")
                    .replace("}", "}")
                )
                if full_path == "/":
                    full_path = ""  # Avoid double slashes

                for http_method in http_methods:
                    endpoint = ApiEndpoint(
                        path=full_path,
                        method=http_method,
                        description=f"Method: {method_name} in {os.path.basename(filepath)}",
                    )

                    self._parse_method_parameters(params_str, endpoint)
                    self.endpoints.append(endpoint)

        except Exception as e:
            logger.debug(f"Error parsing {filepath}: {e}")

    def _parse_method_parameters(self, params_str: str, endpoint: ApiEndpoint) -> None:
        """Parses the method signature to extract Spring annotations like @RequestParam."""
        if not params_str.strip():
            return

        # Split by comma, but be careful of commas inside annotations (simplified approach)
        # For MVP, we'll use a basic regex to find annotated parameters

        param_pattern = re.compile(
            r"@(RequestParam|PathVariable|RequestBody|RequestHeader)\s*(?:\([^)]*\))?\s+([\w<>,\.\[\]]+)\s+(\w+)"
        )

        for match in param_pattern.finditer(params_str):
            annotation = match.group(1)
            data_type = match.group(2)
            param_name = match.group(3)

            # Map Spring annotation to location
            location_map = {
                "RequestParam": "query",
                "PathVariable": "path",
                "RequestBody": "body",
                "RequestHeader": "header",
            }
            location = location_map.get(annotation, "query")

            # Create a raw dict mimicking the OpenAPI format so we can reuse ParameterAnalyzer
            raw_param = {
                "name": param_name,
                "in": location,
                "required": (
                    True if annotation in ["PathVariable", "RequestBody"] else False
                ),  # Simplified
                "schema": {"type": self._map_java_type_to_openapi(data_type)},
            }

            # Use the ParameterAnalyzer to determine if it's a good injection candidate
            api_param = self.parameter_analyzer.analyze_parameter(raw_param)
            endpoint.parameters.append(api_param)

    def _map_java_type_to_openapi(self, java_type: str) -> str:
        """Maps common Java types to OpenAPI types."""
        t = java_type.lower()
        if "int" in t or "long" in t or "short" in t or "byte" in t:
            return "integer"
        if "float" in t or "double" in t:
            return "number"
        if "boolean" in t:
            return "boolean"
        if "list" in t or "set" in t or "[]" in t:
            return "array"
        if "map" in t or "node" in t or "object" in t:
            return "object"
        return "string"  # Default fallback
