"""Persistence mechanism discovery tool.

Discovers LaunchAgents and LaunchDaemons which are common
persistence mechanisms on macOS. These can indicate both
legitimate software and potential malware.
"""

from __future__ import annotations

from langchain_core.tools import tool

from ..base import run_command


@tool
def list_launch_agents() -> str:
    """List user and system launch agents (persistence mechanisms).

    LaunchAgents automatically run at login and are common persistence
    mechanisms. Both legitimate software and malware use them.

    Returns:
        List of user and system LaunchAgents.
    """
    commands = [
        "echo '=== User Launch Agents ===' && ls -la ~/Library/LaunchAgents/ 2>/dev/null || echo 'None'",
        "echo '=== System Launch Agents ===' && ls -la /Library/LaunchAgents/ 2>/dev/null || echo 'None'",
    ]
    results = [run_command(cmd).stdout for cmd in commands]
    return "\n".join(results)
