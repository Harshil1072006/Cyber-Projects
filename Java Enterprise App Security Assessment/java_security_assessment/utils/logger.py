"""
Structured Logger.
Provides standardized logging configuration.
"""

import logging
import sys


def setup_logger(level: str = "INFO") -> logging.Logger:
    """Configures and returns the root logger."""
    numeric_level = getattr(logging, level.upper(), logging.INFO)

    logging.basicConfig(
        level=numeric_level,
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
        handlers=[logging.StreamHandler(sys.stdout)],
    )

    # Suppress verbose third-party loggers
    logging.getLogger("urllib3").setLevel(logging.WARNING)

    return logging.getLogger("java_security_assessment")
