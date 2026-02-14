"""Credential and secret discovery tools.

Tools for discovering credentials, secrets, and authentication materials
that could be compromised if the endpoint is breached.
"""

from __future__ import annotations

from typing import List

from langchain_core.tools import BaseTool

from .keychain import list_keychains
from .ssh import find_ssh_keys
from .aws import find_aws_credentials
from .cloud import find_cloud_configs


def get_tools() -> List[BaseTool]:
    """Get all credential discovery tools."""
    return [
        list_keychains,
        find_ssh_keys,
        find_aws_credentials,
        find_cloud_configs,
    ]


__all__ = [
    "get_tools",
    "list_keychains",
    "find_ssh_keys",
    "find_aws_credentials",
    "find_cloud_configs",
]
