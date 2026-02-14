"""AWS credentials discovery tool.

Discovers AWS credentials and configuration files. AWS credentials
provide access to cloud infrastructure and can be extremely damaging
if compromised.
"""

from __future__ import annotations

from langchain_core.tools import tool

from ..base import run_command


@tool
def find_aws_credentials() -> str:
    """Check for AWS credential files.

    AWS credentials grant access to cloud infrastructure.
    Compromised credentials could expose sensitive data or allow
    resource manipulation.

    Returns:
        Information about AWS credential files found.
    """
    commands = [
        "ls -la ~/.aws/ 2>/dev/null || echo 'No .aws directory'",
        "cat ~/.aws/credentials 2>/dev/null | head -5 || echo 'No credentials file'",
    ]
    results = [run_command(cmd).stdout for cmd in commands]
    return "\n".join(results)
