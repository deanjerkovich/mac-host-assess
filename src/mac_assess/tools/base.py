"""Base utilities for security assessment tools.

This module provides common functionality used across all tool modules,
including command execution, output parsing, and error handling.
"""

from __future__ import annotations

import subprocess
from dataclasses import dataclass
from typing import Any, Optional


@dataclass
class CommandResult:
    """Result of a shell command execution."""

    stdout: str
    stderr: str
    returncode: int

    @property
    def success(self) -> bool:
        """Check if command succeeded."""
        return self.returncode == 0

    @property
    def output(self) -> str:
        """Get combined output, preferring stdout."""
        return self.stdout or self.stderr

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary."""
        return {
            "stdout": self.stdout,
            "stderr": self.stderr,
            "returncode": self.returncode,
        }


def run_command(
    command: str,
    timeout: int = 30,
    shell: bool = True,
) -> CommandResult:
    """Execute a shell command and return structured output.

    Args:
        command: The shell command to execute.
        timeout: Maximum seconds to wait for command completion.
        shell: Whether to execute through shell (default True).

    Returns:
        CommandResult with stdout, stderr, and returncode.
    """
    try:
        result = subprocess.run(
            command,
            shell=shell,
            capture_output=True,
            text=True,
            timeout=timeout,
        )
        return CommandResult(
            stdout=result.stdout,
            stderr=result.stderr,
            returncode=result.returncode,
        )
    except subprocess.TimeoutExpired:
        return CommandResult(
            stdout="",
            stderr=f"Command timed out after {timeout}s",
            returncode=-1,
        )
    except Exception as e:
        return CommandResult(
            stdout="",
            stderr=str(e),
            returncode=-1,
        )


def run_commands(commands: dict[str, str], timeout: int = 30) -> dict[str, CommandResult]:
    """Execute multiple commands and return results.

    Args:
        commands: Dictionary mapping names to commands.
        timeout: Timeout per command.

    Returns:
        Dictionary mapping names to CommandResults.
    """
    results = {}
    for name, cmd in commands.items():
        results[name] = run_command(cmd, timeout=timeout)
    return results


def format_command_output(
    result: CommandResult,
    include_stderr: bool = True,
    include_returncode: bool = True,
) -> str:
    """Format command result for display.

    Args:
        result: The command result to format.
        include_stderr: Whether to include stderr in output.
        include_returncode: Whether to include return code on failure.

    Returns:
        Formatted string output.
    """
    output = result.stdout

    if include_stderr and result.stderr:
        if output:
            output += f"\nSTDERR: {result.stderr}"
        else:
            output = result.stderr

    if include_returncode and not result.success:
        output += f"\nReturn code: {result.returncode}"

    return output or "(no output)"


def check_path_exists(path: str) -> bool:
    """Check if a path exists.

    Args:
        path: Path to check (supports ~ expansion).

    Returns:
        True if path exists.
    """
    result = run_command(f"test -e {path} && echo 'exists'")
    return "exists" in result.stdout


def expand_path(path: str) -> str:
    """Expand a path with shell expansion.

    Args:
        path: Path to expand (supports ~, variables).

    Returns:
        Expanded path.
    """
    result = run_command(f"echo {path}")
    return result.stdout.strip()
