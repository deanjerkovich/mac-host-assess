"""SSH key discovery tool.

Discovers SSH keys on the system. SSH keys provide authentication
to remote systems and are high-value targets for lateral movement.
"""

from __future__ import annotations

from langchain_core.tools import tool

from ..base import run_command


@tool
def find_ssh_keys() -> str:
    """Find SSH keys in common locations.

    SSH keys enable authentication to remote systems without passwords.
    Compromised SSH keys allow lateral movement to other systems.

    Returns:
        List of SSH keys found with their permissions.
    """
    result = run_command(
        "ls -la ~/.ssh/ 2>/dev/null || echo 'No .ssh directory found'"
    )
    return result.output
