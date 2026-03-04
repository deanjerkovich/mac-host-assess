"""Browser data analysis tools.

Tools for discovering browser data including stored passwords,
cookies, history, and cached credentials.
"""

from __future__ import annotations

from typing import List

from langchain_core.tools import BaseTool

from .data import find_browser_data
from .passwords import find_browser_saved_passwords


def get_tools() -> List[BaseTool]:
    """Get all browser analysis tools."""
    return [
        find_browser_data,
        find_browser_saved_passwords,
    ]


__all__ = [
    "get_tools",
    "find_browser_data",
    "find_browser_saved_passwords",
]
