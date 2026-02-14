"""Network connections discovery tool.

Discovers active network connections and listening ports.
This reveals what services are exposed and what external
connections exist.
"""

from __future__ import annotations

from langchain_core.tools import tool

from ..base import run_command


@tool
def get_network_connections() -> str:
    """List active network connections and listening ports.

    Active connections reveal communication with external systems.
    Listening ports show exposed services that could be attack vectors.

    Returns:
        List of established connections and listening ports.
    """
    result = run_command(
        "netstat -an | grep -E '(ESTABLISHED|LISTEN)' | head -50"
    )
    return result.output
