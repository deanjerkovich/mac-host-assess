"""Running processes discovery tool.

Discovers currently running processes. This reveals active software,
services, and potential security tools or monitoring.
"""

from __future__ import annotations

from langchain_core.tools import tool

from ..base import run_command


@tool
def list_running_processes() -> str:
    """List running processes with their users.

    Running processes reveal active software and services.
    Security tools, monitoring agents, and sensitive applications
    can be identified from the process list.

    Returns:
        List of running processes with user and resource information.
    """
    result = run_command("ps aux | head -50")
    return result.output
