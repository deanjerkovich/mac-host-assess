"""Browser data discovery tool.

Discovers browser data directories for major browsers.
Browser data includes stored passwords, cookies, session tokens,
and browsing history - all valuable to attackers.
"""

from __future__ import annotations

from langchain_core.tools import tool

from ..base import run_command


# Browser data paths
BROWSER_PATHS = [
    ("Chrome", "~/Library/Application Support/Google/Chrome"),
    ("Firefox", "~/Library/Application Support/Firefox"),
    ("Safari", "~/Library/Safari"),
    ("Edge", "~/Library/Application Support/Microsoft Edge"),
    ("Brave", "~/Library/Application Support/BraveSoftware/Brave-Browser"),
]


@tool
def find_browser_data() -> str:
    """Locate browser data directories (Chrome, Firefox, Safari, Edge, Brave).

    Browser data contains stored passwords, cookies, session tokens,
    and history. This data can provide access to online accounts.

    Returns:
        List of browser data directories found with contents.
    """
    results = []

    for name, path in BROWSER_PATHS:
        result = run_command(f"ls -la {path} 2>/dev/null | head -10")
        if result.success:
            results.append(f"=== {name} ===\n{result.stdout}")

    return "\n".join(results) if results else "No browser data found"
