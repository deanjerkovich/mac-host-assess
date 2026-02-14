"""Generic shell command execution tool.

Provides a fallback for executing arbitrary shell commands
when specialized tools don't cover the needed functionality.
"""

from __future__ import annotations

from langchain_core.tools import tool

from ..base import run_command, format_command_output


@tool
def run_shell_command(command: str) -> str:
    """Execute an arbitrary shell command.

    Use this for commands not covered by other specialized tools.
    Prefer using specialized tools when available as they provide
    better security context.

    Args:
        command: The shell command to execute.

    Returns:
        Command output including any errors.
    """
    result = run_command(command)
    return format_command_output(result)
