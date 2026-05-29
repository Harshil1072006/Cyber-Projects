"""
sqlmap_runner.py — Thin wrapper that invokes sqlmap as a subprocess.

Designed for post-confirmation deep exploitation on authorized targets.
Requires sqlmap to be installed and on PATH (pip install sqlmap or apt).
"""

import subprocess
import os
from typing import Optional


OUTPUT_DIR = "./sqlmap_output"


def run_sqlmap(
    url: str,
    param: str,
    cookies: Optional[str] = None,
    post_data: Optional[str] = None,
    timeout: int = 300,
) -> str:
    """
    Run sqlmap against a single *url* + *param* combination.

    Parameters
    ----------
    url        : Target URL (may include query string).
    param      : Name of the parameter to test (-p flag).
    cookies    : Raw cookie string, e.g. "session=abc123; csrf=xyz".
    post_data  : URL-encoded POST body, e.g. "user=admin&pass=x".
    timeout    : Maximum seconds to wait for sqlmap (default 300).

    Returns
    -------
    stdout output of sqlmap as a string (empty string on error/timeout).
    """
    os.makedirs(OUTPUT_DIR, exist_ok=True)

    cmd: list[str] = [
        "sqlmap",
        "-u", url,
        "-p", param,
        "--batch",
        "--level=3",
        "--risk=2",
        "--dbs",
        f"--output-dir={OUTPUT_DIR}",
        "--format=JSON",
    ]

    if cookies:
        cmd += ["--cookie", cookies]

    if post_data:
        cmd += ["--data", post_data]

    try:
        result = subprocess.run(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,   # merge stderr into stdout
            text=True,
            timeout=timeout,
        )
        return result.stdout or ""
    except subprocess.TimeoutExpired:
        return f"[sqlmap_runner] Process timed out after {timeout} seconds."
    except FileNotFoundError:
        return (
            "[sqlmap_runner] sqlmap not found on PATH. "
            "Install it with: pip install sqlmap"
        )
    except Exception as exc:
        return f"[sqlmap_runner] Unexpected error: {exc}"
