"""
Screenshot Capturer.
Placeholder for capturing screenshots or generating HTML representations of evidence.
"""

from typing import Any
from ..finding_manager import Evidence


class ScreenshotCapturer:
    """Helper to convert text evidence into visual formats (e.g., HTML blocks)."""

    @staticmethod
    def format_for_html(evidence: Evidence) -> str:
        """Wraps evidence in appropriate HTML tags for reporting."""
        if evidence.type == "request_response":
            return f'<div class="evidence-block"><pre><code class="language-http">{evidence.content}</code></pre></div>'
        elif evidence.type == "code_snippet":
            return f'<div class="evidence-block"><pre><code class="language-java">{evidence.content}</code></pre></div>'
        else:
            return f'<div class="evidence-block"><pre><code>{evidence.content}</code></pre></div>'
