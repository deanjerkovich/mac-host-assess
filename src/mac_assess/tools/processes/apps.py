"""Installed applications discovery tool.

Discovers installed applications which reveals the software
environment and potential targets for exploitation or data theft.
"""

from __future__ import annotations

from langchain_core.tools import tool

from ..base import run_command


@tool
def list_installed_apps() -> str:
    """List applications installed in /Applications.

    Installed applications reveal software environment and potential
    targets. Password managers, browsers, development tools, and
    business applications are high-value targets.

    Returns:
        List of installed applications.
    """
    result = run_command("ls -1 /Applications/ | head -30")
    return result.output
