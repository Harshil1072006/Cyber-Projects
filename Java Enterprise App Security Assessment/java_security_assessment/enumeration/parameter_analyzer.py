"""
Parameter Analyzer for API endpoints.
Analyzes parameter types, constraints, and identifies potential injection points.
"""

from typing import List, Dict, Any, Optional
from dataclasses import dataclass, field


@dataclass
class ApiParameter:
    name: str
    in_location: str  # query, path, header, body
    data_type: str
    required: bool = False
    description: str = ""
    default_value: Optional[Any] = None
    constraints: Dict[str, Any] = field(default_factory=dict)
    is_injection_candidate: bool = False


class ParameterAnalyzer:
    """Analyzes API parameters to determine types and identify vulnerability candidates."""

    # Parameter names commonly associated with specific vulnerabilities
    SQLI_CANDIDATES = {
        "id",
        "user",
        "name",
        "search",
        "query",
        "sort",
        "order",
        "email",
        "filter",
    }
    PATH_TRAVERSAL_CANDIDATES = {
        "file",
        "path",
        "dir",
        "folder",
        "document",
        "template",
    }
    SSRF_CANDIDATES = {"url", "uri", "host", "endpoint", "webhook", "target", "domain"}
    COMMAND_INJECTION_CANDIDATES = {"cmd", "exec", "command", "script", "action", "run"}

    def analyze_parameter(
        self, raw_param: Dict[str, Any], in_location: str = "query"
    ) -> ApiParameter:
        """
        Analyzes a raw parameter definition (e.g., from Swagger/OpenAPI)
        and returns an enriched ApiParameter object.
        """
        name = raw_param.get("name", "unknown")

        # Determine location (query, path, header, cookie)
        location = raw_param.get("in", in_location).lower()

        # Extract schema/type information
        schema = raw_param.get(
            "schema", raw_param
        )  # OpenAPI v3 uses 'schema', Swagger 2.0 might have type at root
        data_type = schema.get("type", "string")

        # Handle OpenAPI array type
        if data_type == "array":
            items = schema.get("items", {})
            item_type = items.get("type", "string")
            data_type = f"array[{item_type}]"

        required = raw_param.get("required", False)

        # Extract default values
        default_val = schema.get("default")

        # Extract constraints (minLength, maxLength, pattern, enum, etc.)
        constraints = {}
        for constraint_key in [
            "minLength",
            "maxLength",
            "pattern",
            "enum",
            "minimum",
            "maximum",
        ]:
            if constraint_key in schema:
                constraints[constraint_key] = schema[constraint_key]

        # Determine if this parameter is a good candidate for injection testing
        is_candidate = self._is_injection_candidate(name, data_type)

        return ApiParameter(
            name=name,
            in_location=location,
            data_type=data_type,
            required=required,
            description=raw_param.get("description", ""),
            default_value=default_val,
            constraints=constraints,
            is_injection_candidate=is_candidate,
        )

    def analyze_body_schema(self, schema: Dict[str, Any]) -> List[ApiParameter]:
        """
        Flattens a request body schema (JSON object) into a list of parameters for testing.
        This is a simplified approach; deep nested objects would require recursive traversal.
        """
        parameters = []

        if schema.get("type") == "object" and "properties" in schema:
            required_props = set(schema.get("required", []))
            for prop_name, prop_schema in schema["properties"].items():

                data_type = prop_schema.get("type", "string")
                if data_type == "object":
                    # Simplified: just flag the object itself as a potential complex injection point
                    data_type = "object"

                is_req = prop_name in required_props
                is_candidate = self._is_injection_candidate(prop_name, data_type)

                param = ApiParameter(
                    name=prop_name,
                    in_location="body",
                    data_type=data_type,
                    required=is_req,
                    is_injection_candidate=is_candidate,
                )
                parameters.append(param)

        return parameters

    def _is_injection_candidate(self, name: str, data_type: str) -> bool:
        """Determines if a parameter is worth fuzzing/testing based on name and type."""
        # Generally, string types are the most common injection vectors
        if "string" not in data_type.lower() and data_type != "unknown":
            # However, sometimes integers are used for SQLi if not properly typed on backend
            # For this MVP, we'll focus mostly on strings or untyped, plus specific name matches
            if data_type not in ["integer", "number"]:
                return True

        name_lower = name.lower()

        if name_lower in self.SQLI_CANDIDATES:
            return True
        if name_lower in self.PATH_TRAVERSAL_CANDIDATES:
            return True
        if name_lower in self.SSRF_CANDIDATES:
            return True
        if name_lower in self.COMMAND_INJECTION_CANDIDATES:
            return True

        # If it's a string, it's generally a candidate unless it has strict enums/patterns (checked elsewhere)
        if "string" in data_type.lower():
            return True

        return False
