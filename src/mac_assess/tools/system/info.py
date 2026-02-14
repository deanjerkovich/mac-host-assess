"""System information tool.

Gathers basic macOS system information including version, hardware, and hostname.
This information helps establish context for the security assessment.
"""

from __future__ import annotations

from langchain_core.tools import tool

from ..base import run_command


@tool
def get_system_info() -> str:
    """Get basic macOS system information including version, hardware, and hostname.

    Returns:
        System information including hostname, OS version, and hardware details.
    """
    commands = {
        "hostname": "hostname",
        "os_version": "sw_vers",
        "hardware": "system_profiler SPHardwareDataType 2>/dev/null | head -20",
    }

    results = []
    for name, cmd in commands.items():
        output = run_command(cmd)
        results.append(f"=== {name} ===\n{output.stdout}")

    return "\n".join(results)
