"""Network interface discovery tool.

Discovers network interface configuration including IP addresses,
which helps map the network position of the endpoint.
"""

from __future__ import annotations

from langchain_core.tools import tool

from ..base import run_command


@tool
def get_network_interfaces() -> str:
    """Get network interface configuration.

    Network interfaces reveal IP addresses and network positioning.
    This helps understand potential lateral movement paths.

    Returns:
        Network interface configuration with IP addresses.
    """
    result = run_command(
        "ifconfig | grep -E '(^[a-z]|inet )' | head -30"
    )
    return result.output
