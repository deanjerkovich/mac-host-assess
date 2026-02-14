"""Sensitive file discovery tool.

Searches for files that commonly contain credentials, secrets,
or sensitive configuration data.
"""

from __future__ import annotations

from langchain_core.tools import tool

from ..base import run_command


# Patterns for sensitive files
SENSITIVE_PATTERNS = [
    "*.pem",
    "*.key",
    "*.p12",
    "*.pfx",
    "*password*",
    "*credential*",
    "*.env",
    "*secret*",
    "*.keystore",
    "*.jks",
]


@tool
def find_sensitive_files(search_path: str = "~") -> str:
    """Search for potentially sensitive files (keys, configs, credentials).

    Searches for files with names indicating they may contain
    credentials, private keys, or other secrets.

    Args:
        search_path: Directory to search (default: home directory).

    Returns:
        List of potentially sensitive files found.
    """
    pattern_args = " ".join(f'-name "{p}"' for p in SENSITIVE_PATTERNS)
    cmd = f"find {search_path} -maxdepth 4 \\( {pattern_args} \\) 2>/dev/null | head -30"
    result = run_command(cmd, timeout=60)
    return result.stdout or "No sensitive files found"
