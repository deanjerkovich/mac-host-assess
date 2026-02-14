"""Cloud provider configuration discovery tool.

Discovers configuration files for major cloud providers (AWS, GCP, Azure)
and container orchestration (Kubernetes). These files often contain
credentials or references to credential stores.
"""

from __future__ import annotations

from langchain_core.tools import tool

from ..base import run_command


# Cloud configuration paths to check
CLOUD_CONFIG_PATHS = [
    ("AWS", "~/.aws"),
    ("GCP", "~/.config/gcloud"),
    ("Azure", "~/.azure"),
    ("Kubernetes", "~/.kube"),
]


@tool
def find_cloud_configs() -> str:
    """Find cloud provider configuration files (AWS, GCP, Azure, Kubernetes).

    Cloud configuration files often contain credentials or references
    to credential stores. These provide access to cloud infrastructure.

    Returns:
        List of cloud configuration directories found with contents.
    """
    results = []

    for name, path in CLOUD_CONFIG_PATHS:
        result = run_command(f"ls -la {path} 2>/dev/null")
        if result.success:
            results.append(f"=== {name} ({path}) ===\n{result.stdout}")

    return "\n".join(results) if results else "No cloud config directories found"
