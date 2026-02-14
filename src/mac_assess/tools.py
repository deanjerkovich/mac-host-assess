"""Security assessment tools for macOS.

This module defines tools the agent can use to assess the security posture
of a macOS endpoint. Tools are implemented as LangChain tools that can
execute shell commands and parse their output.

Add your custom tools here or import from external tool packages.
"""

from __future__ import annotations

import subprocess
import shlex
from typing import Any
from langchain_core.tools import tool


def run_command(command: str, timeout: int = 30) -> dict[str, Any]:
    """Execute a shell command and return structured output.

    Args:
        command: The shell command to execute.
        timeout: Maximum seconds to wait for command completion.

    Returns:
        Dict with 'stdout', 'stderr', 'returncode' keys.
    """
    try:
        result = subprocess.run(
            command,
            shell=True,
            capture_output=True,
            text=True,
            timeout=timeout,
        )
        return {
            "stdout": result.stdout,
            "stderr": result.stderr,
            "returncode": result.returncode,
        }
    except subprocess.TimeoutExpired:
        return {
            "stdout": "",
            "stderr": f"Command timed out after {timeout}s",
            "returncode": -1,
        }
    except Exception as e:
        return {
            "stdout": "",
            "stderr": str(e),
            "returncode": -1,
        }


# =============================================================================
# System Information Tools
# =============================================================================

@tool
def get_system_info() -> str:
    """Get basic macOS system information including version, hardware, and hostname."""
    commands = {
        "hostname": "hostname",
        "os_version": "sw_vers",
        "hardware": "system_profiler SPHardwareDataType 2>/dev/null | head -20",
    }
    results = []
    for name, cmd in commands.items():
        output = run_command(cmd)
        results.append(f"=== {name} ===\n{output['stdout']}")
    return "\n".join(results)


@tool
def get_current_user() -> str:
    """Get information about the currently logged-in user and their groups."""
    result = run_command("id && whoami && groups")
    return result["stdout"] or result["stderr"]


# =============================================================================
# Credential & Secret Discovery Tools
# =============================================================================

@tool
def list_keychains() -> str:
    """List all keychains accessible to the current user."""
    result = run_command("security list-keychains")
    return result["stdout"] or result["stderr"]


@tool
def find_ssh_keys() -> str:
    """Find SSH keys in common locations."""
    result = run_command("ls -la ~/.ssh/ 2>/dev/null || echo 'No .ssh directory found'")
    return result["stdout"] or result["stderr"]


@tool
def find_aws_credentials() -> str:
    """Check for AWS credential files."""
    commands = [
        "ls -la ~/.aws/ 2>/dev/null || echo 'No .aws directory'",
        "cat ~/.aws/credentials 2>/dev/null | head -5 || echo 'No credentials file'",
    ]
    results = [run_command(cmd)["stdout"] for cmd in commands]
    return "\n".join(results)


@tool
def find_cloud_configs() -> str:
    """Find cloud provider configuration files (AWS, GCP, Azure)."""
    paths = [
        "~/.aws",
        "~/.config/gcloud",
        "~/.azure",
        "~/.kube",
    ]
    results = []
    for path in paths:
        result = run_command(f"ls -la {path} 2>/dev/null")
        if result["returncode"] == 0:
            results.append(f"=== {path} ===\n{result['stdout']}")
    return "\n".join(results) if results else "No cloud config directories found"


# =============================================================================
# Network & Connectivity Tools
# =============================================================================

@tool
def get_network_connections() -> str:
    """List active network connections and listening ports."""
    result = run_command("netstat -an | grep -E '(ESTABLISHED|LISTEN)' | head -50")
    return result["stdout"] or result["stderr"]


@tool
def get_network_interfaces() -> str:
    """Get network interface configuration."""
    result = run_command("ifconfig | grep -E '(^[a-z]|inet )' | head -30")
    return result["stdout"] or result["stderr"]


# =============================================================================
# Process & Application Tools
# =============================================================================

@tool
def list_running_processes() -> str:
    """List running processes with their users."""
    result = run_command("ps aux | head -50")
    return result["stdout"] or result["stderr"]


@tool
def list_installed_apps() -> str:
    """List applications installed in /Applications."""
    result = run_command("ls -1 /Applications/ | head -30")
    return result["stdout"] or result["stderr"]


@tool
def list_launch_agents() -> str:
    """List user and system launch agents (persistence mechanisms)."""
    commands = [
        "echo '=== User Launch Agents ===' && ls -la ~/Library/LaunchAgents/ 2>/dev/null || echo 'None'",
        "echo '=== System Launch Agents ===' && ls -la /Library/LaunchAgents/ 2>/dev/null || echo 'None'",
    ]
    results = [run_command(cmd)["stdout"] for cmd in commands]
    return "\n".join(results)


# =============================================================================
# Browser & Application Data Tools
# =============================================================================

@tool
def find_browser_data() -> str:
    """Locate browser data directories (Chrome, Firefox, Safari)."""
    paths = [
        ("Chrome", "~/Library/Application Support/Google/Chrome"),
        ("Firefox", "~/Library/Application Support/Firefox"),
        ("Safari", "~/Library/Safari"),
    ]
    results = []
    for name, path in paths:
        result = run_command(f"ls -la {path} 2>/dev/null | head -10")
        if result["returncode"] == 0:
            results.append(f"=== {name} ===\n{result['stdout']}")
    return "\n".join(results) if results else "No browser data found"


# =============================================================================
# File System Tools
# =============================================================================

@tool
def find_sensitive_files(search_path: str = "~") -> str:
    """Search for potentially sensitive files (keys, configs, credentials).

    Args:
        search_path: Directory to search (default: home directory).
    """
    patterns = [
        "*.pem",
        "*.key",
        "*.p12",
        "*.pfx",
        "*password*",
        "*credential*",
        "*.env",
    ]
    pattern_args = " ".join(f'-name "{p}"' for p in patterns)
    cmd = f"find {search_path} -maxdepth 4 \\( {pattern_args} \\) 2>/dev/null | head -30"
    result = run_command(cmd, timeout=60)
    return result["stdout"] or "No sensitive files found"


@tool
def run_shell_command(command: str) -> str:
    """Execute an arbitrary shell command. Use for commands not covered by other tools.

    Args:
        command: The shell command to execute.
    """
    result = run_command(command)
    output = result["stdout"]
    if result["stderr"]:
        output += f"\nSTDERR: {result['stderr']}"
    if result["returncode"] != 0:
        output += f"\nReturn code: {result['returncode']}"
    return output


# =============================================================================
# Tool Registry
# =============================================================================

ALL_TOOLS = [
    # System
    get_system_info,
    get_current_user,
    # Credentials
    list_keychains,
    find_ssh_keys,
    find_aws_credentials,
    find_cloud_configs,
    # Network
    get_network_connections,
    get_network_interfaces,
    # Processes
    list_running_processes,
    list_installed_apps,
    list_launch_agents,
    # Browser
    find_browser_data,
    # Files
    find_sensitive_files,
    # Generic
    run_shell_command,
]
