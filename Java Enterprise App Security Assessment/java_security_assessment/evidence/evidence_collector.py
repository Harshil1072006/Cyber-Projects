"""
Evidence Collector.
Centralized utility to capture and format request/response data and code snippets.
"""

import requests
from typing import Dict, Any, Optional
from ..finding_manager import Evidence


class EvidenceCollector:
    """Helper methods to format evidence objects."""

    @staticmethod
    def capture_http(
        request: requests.PreparedRequest,
        response: requests.Response,
        description: str = "",
    ) -> Evidence:
        """Formats a full HTTP request and response into an Evidence object."""
        req_lines = [f"{request.method} {request.path_url} HTTP/1.1"]
        for k, v in request.headers.items():
            req_lines.append(f"{k}: {v}")
        req_lines.append("")
        if request.body:
            req_lines.append(
                request.body.decode("utf-8", errors="replace")
                if isinstance(request.body, bytes)
                else request.body
            )

        res_lines = [f"HTTP/1.1 {response.status_code} {response.reason}"]
        for k, v in response.headers.items():
            res_lines.append(f"{k}: {v}")
        res_lines.append("")
        res_lines.append(
            response.text[:1000] + ("..." if len(response.text) > 1000 else "")
        )

        content = (
            "--- REQUEST ---\n"
            + "\n".join(req_lines)
            + "\n\n--- RESPONSE ---\n"
            + "\n".join(res_lines)
        )

        return Evidence(
            type="request_response", content=content, description=description
        )

    @staticmethod
    def capture_code(
        filepath: str, line_num: int, snippet: str, description: str = ""
    ) -> Evidence:
        """Formats a source code snippet."""
        return Evidence(
            type="code_snippet",
            content=f"File: {filepath}:{line_num}\n\n{snippet}",
            description=description,
        )
