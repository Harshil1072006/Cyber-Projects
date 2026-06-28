"""
Proof of Concept Generator.
Generates reproducible step-by-step PoCs for findings.
"""

from typing import Dict, Any, List
from ..finding_manager import Finding, Evidence


class ProofOfConceptGenerator:
    """Generates Markdown-formatted Proof of Concept steps."""

    @staticmethod
    def generate_curl_command(
        method: str, url: str, headers: Dict[str, str], body: str = None
    ) -> str:
        """Generates a curl command to reproduce a request."""
        cmd = [f"curl -X {method}"]
        for k, v in headers.items():
            cmd.append(f"-H '{k}: {v}'")
        if body:
            # Escape single quotes in body
            safe_body = body.replace("'", "'\\''")
            cmd.append(f"-d '{safe_body}'")
        cmd.append(f"'{url}'")

        return " \\\n  ".join(cmd)

    @staticmethod
    def format_poc(finding: Finding) -> str:
        """Formats the evidence into a step-by-step PoC string."""
        poc = ["### Proof of Concept\n"]

        poc.append(
            "1. **Setup**: Ensure the target application is running and accessible."
        )

        step_num = 2
        for ev in finding.evidence:
            if ev.type == "request_response":
                poc.append(
                    f"{step_num}. **Execution**: Send the following payload/request to the application:"
                )
                poc.append("```http")

                # Split request and response to make it clearer
                parts = ev.content.split("--- RESPONSE ---")
                req_part = parts[0].replace("--- REQUEST ---", "").strip()
                poc.append(req_part)
                poc.append("```\n")

                poc.append(
                    f"{step_num+1}. **Observation**: Observe the server responds with the vulnerability indicator:"
                )
                poc.append("```http")
                if len(parts) > 1:
                    poc.append(parts[1].strip())
                poc.append("```\n")

                if ev.description:
                    poc.append(f"**Note**: {ev.description}")

                step_num += 2

            elif ev.type == "code_snippet":
                poc.append(
                    f"{step_num}. **Analysis**: The vulnerability is located in the source code:"
                )
                poc.append("```java")
                poc.append(ev.content)
                poc.append("```\n")
                if ev.description:
                    poc.append(f"**Note**: {ev.description}")
                step_num += 1

        if len(poc) == 2:
            poc.append("No automated reproduction steps available for this finding.")

        return "\n".join(poc)
