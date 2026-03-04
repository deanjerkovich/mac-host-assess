"""Network analysis tools.

Tools for analyzing network configuration, connections, and potential
network-based attack vectors or lateral movement opportunities.
"""

from __future__ import annotations

from typing import List

from langchain_core.tools import BaseTool

from .connections import get_network_connections
from .interfaces import get_network_interfaces
from .lateral_targets import find_lateral_movement_targets
from .proxy_vpn import find_proxy_and_vpn_config


def get_tools() -> List[BaseTool]:
    """Get all network analysis tools."""
    return [
        get_network_connections,
        get_network_interfaces,
        find_lateral_movement_targets,
        find_proxy_and_vpn_config,
    ]


__all__ = [
    "get_tools",
    "get_network_connections",
    "get_network_interfaces",
    "find_lateral_movement_targets",
    "find_proxy_and_vpn_config",
]
