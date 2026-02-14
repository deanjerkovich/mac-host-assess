"""Filesystem analysis tools.

Tools for analyzing the filesystem to discover sensitive files,
credentials, and data that could be exfiltrated.
"""

from __future__ import annotations

from typing import List

from langchain_core.tools import BaseTool

from .sensitive import find_sensitive_files


def get_tools() -> List[BaseTool]:
    """Get all filesystem analysis tools."""
    return [
        find_sensitive_files,
    ]


__all__ = [
    "get_tools",
    "find_sensitive_files",
]
