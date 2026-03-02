"""Credential and secret discovery tools (post-exploitation style).

Scans for secrets stored insecurely on the endpoint — in shell history,
dotfiles, environment variables, and SSH agent memory.
"""

from __future__ import annotations

from typing import List

from langchain_core.tools import BaseTool

from .shell_history import scan_shell_history
from .profiles import scan_shell_profiles
from .ssh_agent import find_ssh_agent_exposure
from .communication_tokens import find_communication_tokens


def get_tools() -> List[BaseTool]:
    """Get all secret-scanning tools."""
    return [
        scan_shell_history,
        scan_shell_profiles,
        find_ssh_agent_exposure,
        find_communication_tokens,
    ]


__all__ = [
    "get_tools",
    "scan_shell_history",
    "scan_shell_profiles",
    "find_ssh_agent_exposure",
    "find_communication_tokens",
]
