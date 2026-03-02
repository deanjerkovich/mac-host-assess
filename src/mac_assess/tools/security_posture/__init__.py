"""macOS security posture assessment tools.

Evaluates the host's own security controls and configuration — the foundational
layer that determines whether all other protections hold.
"""

from __future__ import annotations

from typing import List

from langchain_core.tools import BaseTool

from .macos_security import get_macos_security_config
from .tcc import find_tcc_permissions
from .privesc import find_privilege_escalation_vectors
from .remote_services import find_remote_access_services
from .mdm import find_mdm_enrollment
from .edr import find_edr_and_av_products


def get_tools() -> List[BaseTool]:
    """Get all security posture assessment tools."""
    return [
        get_macos_security_config,
        find_tcc_permissions,
        find_privilege_escalation_vectors,
        find_remote_access_services,
        find_mdm_enrollment,
        find_edr_and_av_products,
    ]


__all__ = [
    "get_tools",
    "get_macos_security_config",
    "find_tcc_permissions",
    "find_privilege_escalation_vectors",
    "find_remote_access_services",
    "find_mdm_enrollment",
    "find_edr_and_av_products",
]
