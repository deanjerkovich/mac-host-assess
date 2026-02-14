"""macOS Keychain discovery tool.

Discovers accessible keychains on the system. Keychains store passwords,
certificates, and other secrets that could be extracted by an attacker
with sufficient access.
"""

from __future__ import annotations

from langchain_core.tools import tool

from ..base import run_command


@tool
def list_keychains() -> str:
    """List all keychains accessible to the current user.

    Keychains contain passwords, certificates, and other secrets.
    An attacker with user access could potentially extract these.

    Returns:
        List of accessible keychain paths.
    """
    result = run_command("security list-keychains")
    return result.output
