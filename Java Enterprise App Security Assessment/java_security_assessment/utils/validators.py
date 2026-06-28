"""
Input validators.
"""

from urllib.parse import urlparse


class Validators:
    """Helper class for input validation."""

    @staticmethod
    def is_valid_url(url: str) -> bool:
        """Checks if a string is a valid URL."""
        try:
            result = urlparse(url)
            return all([result.scheme, result.netloc])
        except ValueError:
            return False
