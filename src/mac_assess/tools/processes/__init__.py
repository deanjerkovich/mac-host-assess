"""Process and application analysis tools.

Tools for analyzing running processes, installed applications,
and persistence mechanisms.
"""

from __future__ import annotations

from typing import List

from langchain_core.tools import BaseTool

from .running import list_running_processes
from .apps import list_installed_apps
from .persistence import list_launch_agents


def get_tools() -> List[BaseTool]:
    """Get all process analysis tools."""
    return [
        list_running_processes,
        list_installed_apps,
        list_launch_agents,
    ]


__all__ = [
    "get_tools",
    "list_running_processes",
    "list_installed_apps",
    "list_launch_agents",
]
