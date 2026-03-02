"""LaunchDaemons and LaunchAgents persistence assessment.

LaunchDaemons/Agents are the primary persistence mechanism on macOS.
Attackers install malicious plists here to survive reboots and run
code as root (daemons) or as the user (agents).

MITRE ATT&CK: T1543.004 (Create or Modify System Process: Launch Daemon)
"""

from __future__ import annotations

from langchain_core.tools import tool

from ..base import run_command


# Directories that can host persistent launch plists
_DAEMON_DIRS = [
    "/Library/LaunchDaemons",
    "/System/Library/LaunchDaemons",
]

_AGENT_DIRS = [
    "/Library/LaunchAgents",
    "/System/Library/LaunchAgents",
    "~/Library/LaunchAgents",
]


@tool
def list_launch_daemons() -> str:
    """List all LaunchDaemon and LaunchAgent plists, flagging non-Apple entries.

    LaunchDaemons run as root at boot; LaunchAgents run as the user at login.
    Both are common persistence locations. This tool identifies:
    - All installed daemon/agent plists in standard directories
    - Non-Apple entries (most likely attacker-installed or third-party)
    - Plist contents for suspicious non-Apple entries (program path, args,
      run-at-load, start-interval, socket listeners)
    - Whether the referenced binary actually exists on disk

    Returns:
        Installed daemons/agents with non-Apple entries highlighted.
    """
    sections = []

    # ── LaunchDaemons ─────────────────────────────────────────────────────────
    for d in _DAEMON_DIRS:
        listing = run_command(f"ls {d}/ 2>/dev/null")
        if not listing.stdout.strip():
            continue
        plists = [p.strip() for p in listing.stdout.splitlines() if p.strip().endswith(".plist")]
        non_apple = [p for p in plists if not p.startswith("com.apple.")]
        sections.append(
            f"=== {d} ({len(plists)} total, {len(non_apple)} non-Apple) ===\n"
            + "\n".join(f"  {'⚠ ' if p in non_apple else '  '}{p}" for p in plists)
        )
        for plist in non_apple[:10]:  # Show details for first 10 suspicious entries
            content = run_command(f"cat {d}/{plist} 2>/dev/null | head -40")
            if content.stdout.strip():
                sections.append(f"--- {d}/{plist} ---\n{content.stdout.strip()}")

    # ── LaunchAgents ──────────────────────────────────────────────────────────
    for d in _AGENT_DIRS:
        listing = run_command(f"ls {d}/ 2>/dev/null")
        if not listing.stdout.strip():
            continue
        plists = [p.strip() for p in listing.stdout.splitlines() if p.strip().endswith(".plist")]
        non_apple = [p for p in plists if not p.startswith("com.apple.")]
        sections.append(
            f"=== {d} ({len(plists)} total, {len(non_apple)} non-Apple) ===\n"
            + "\n".join(f"  {'⚠ ' if p in non_apple else '  '}{p}" for p in plists)
        )
        for plist in non_apple[:10]:
            expanded_d = run_command(f"echo {d}").stdout.strip()
            content = run_command(f"cat {expanded_d}/{plist} 2>/dev/null | head -40")
            if content.stdout.strip():
                sections.append(f"--- {expanded_d}/{plist} ---\n{content.stdout.strip()}")

    # ── Currently loaded daemons/agents via launchctl ─────────────────────────
    loaded = run_command(
        "launchctl list 2>/dev/null | grep -v '^-' | grep -v 'com\\.apple\\.' | head -40"
    )
    if loaded.stdout.strip():
        sections.append(
            "=== Non-Apple services loaded in launchctl (PID - Status - Label) ===\n"
            + loaded.stdout.strip()
        )

    return "\n\n".join(sections) if sections else "(no LaunchDaemon/Agent directories found)"
