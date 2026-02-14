"""Security assessment tools for macOS.

This package provides modular tools for assessing the security posture
of a macOS endpoint. Each tool category is organized into its own module
for independent development and testing.

Tool Categories:
- system: System information and user context
- credentials: Credential and secret discovery
- network: Network configuration and connections
- processes: Running processes and applications
- browser: Browser data and stored credentials
- filesystem: File system analysis and sensitive file discovery
- shell: Generic command execution
"""

from __future__ import annotations

from typing import List

from langchain_core.tools import BaseTool

# Import all tool modules to register them
from . import system
from . import credentials
from . import network
from . import processes
from . import browser
from . import filesystem
from . import shell


def get_all_tools() -> List[BaseTool]:
    """Get all registered security assessment tools.

    Returns:
        List of all available tools across all categories.
    """
    tools = []
    tools.extend(system.get_tools())
    tools.extend(credentials.get_tools())
    tools.extend(network.get_tools())
    tools.extend(processes.get_tools())
    tools.extend(browser.get_tools())
    tools.extend(filesystem.get_tools())
    tools.extend(shell.get_tools())
    return tools


def get_tools_by_category(category: str) -> List[BaseTool]:
    """Get tools for a specific category.

    Args:
        category: The tool category name.

    Returns:
        List of tools in the specified category.

    Raises:
        ValueError: If the category is not found.
    """
    categories = {
        "system": system.get_tools,
        "credentials": credentials.get_tools,
        "network": network.get_tools,
        "processes": processes.get_tools,
        "browser": browser.get_tools,
        "filesystem": filesystem.get_tools,
        "shell": shell.get_tools,
    }

    if category not in categories:
        raise ValueError(
            f"Unknown category: {category}. "
            f"Available: {', '.join(categories.keys())}"
        )

    return categories[category]()


# Convenience export for backwards compatibility
ALL_TOOLS = get_all_tools()
