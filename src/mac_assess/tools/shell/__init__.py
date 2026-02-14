"""Generic shell command tools.

Provides a generic shell command execution capability for
commands not covered by specialized tools.
"""

from __future__ import annotations

from typing import List

from langchain_core.tools import BaseTool

from .command import run_shell_command


def get_tools() -> List[BaseTool]:
    """Get all shell tools."""
    return [
        run_shell_command,
    ]


__all__ = [
    "get_tools",
    "run_shell_command",
]
