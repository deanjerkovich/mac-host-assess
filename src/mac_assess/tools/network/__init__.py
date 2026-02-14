"""Network analysis tools.

Tools for analyzing network configuration, connections, and potential
network-based attack vectors or lateral movement opportunities.
"""

from __future__ import annotations

from typing import List

from langchain_core.tools import BaseTool

from .connections import get_network_connections
from .interfaces import get_network_interfaces


def get_tools() -> List[BaseTool]:
    """Get all network analysis tools."""
    return [
        get_network_connections,
        get_network_interfaces,
    ]


__all__ = [
    "get_tools",
    "get_network_connections",
    "get_network_interfaces",
]
