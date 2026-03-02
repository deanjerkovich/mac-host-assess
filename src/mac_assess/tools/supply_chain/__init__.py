"""Supply chain risk assessment tools.

Tools for identifying ways an attacker on this endpoint could influence
other systems — injecting code into upstream repositories, publishing
malicious packages, or modifying cloud infrastructure.
"""

from __future__ import annotations

from typing import List

from langchain_core.tools import BaseTool

from .git_access import find_git_push_access
from .publishing import find_publishing_credentials
from .infrastructure import find_infrastructure_write_access
from .containers import find_container_access


def get_tools() -> List[BaseTool]:
    """Get all supply chain risk assessment tools."""
    return [
        find_git_push_access,
        find_publishing_credentials,
        find_infrastructure_write_access,
        find_container_access,
    ]


__all__ = [
    "get_tools",
    "find_git_push_access",
    "find_publishing_credentials",
    "find_infrastructure_write_access",
    "find_container_access",
]
