"""Current user information tool.

Gathers information about the currently logged-in user, including
user ID, groups, and privileges.
"""

from __future__ import annotations

from langchain_core.tools import tool

from ..base import run_command


@tool
def get_current_user() -> str:
    """Get information about the currently logged-in user and their groups.

    Returns:
        User ID, username, and group memberships.
    """
    result = run_command("id && whoami && groups")
    return result.output
