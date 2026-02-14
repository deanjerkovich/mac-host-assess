"""System information tools.

Tools for gathering system-level information about the macOS endpoint,
including hardware, OS version, and user context.
"""

from __future__ import annotations

from typing import List

from langchain_core.tools import BaseTool

from .info import get_system_info
from .user import get_current_user


def get_tools() -> List[BaseTool]:
    """Get all system information tools."""
    return [
        get_system_info,
        get_current_user,
    ]


__all__ = [
    "get_tools",
    "get_system_info",
    "get_current_user",
]
