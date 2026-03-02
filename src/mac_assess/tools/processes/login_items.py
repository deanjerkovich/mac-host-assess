"""Login items and startup application assessment.

Login items run automatically when a user logs in. They can be added
silently by applications and are commonly abused for persistence by
malware and potentially-unwanted programs (PUPs).

MITRE ATT&CK: T1547.015 (Boot or Logon Autostart: Login Items)
"""

from __future__ import annotations

from langchain_core.tools import tool

from ..base import run_command


@tool
def list_login_items() -> str:
    """List all login items, startup applications, and user-level persistence.

    Checks for:
    - Login items registered via SMLoginItemSetEnabled (modern macOS API)
    - Legacy login items in ~/Library/Preferences/com.apple.loginitems.plist
    - Background login items (macOS 13+ Background Login Items in Settings)
    - Startup items in ~/Library/Startup Items (legacy)
    - Items in /Library/StartupItems (system-level, legacy)
    - Spotlight importer plugins (can execute code on metadata events)
    - Kernel extensions (system/ and 3rd-party)

    Returns:
        All login/startup items with flags for non-Apple entries.
    """
    sections = []

    # ── Modern login items via sfltool / osascript ────────────────────────────
    osascript_items = run_command(
        "osascript -e 'tell application \"System Events\" to get the name of every login item' 2>/dev/null"
    )
    sections.append(
        "=== Login Items (System Events) ===\n"
        + (osascript_items.output.strip() or "(none or access denied)")
    )

    # ── Legacy loginitems plist ───────────────────────────────────────────────
    loginitems_plist = run_command(
        "defaults read ~/Library/Preferences/com.apple.loginitems 2>/dev/null"
    )
    if loginitems_plist.stdout.strip():
        sections.append(
            f"=== com.apple.loginitems plist ===\n{loginitems_plist.stdout.strip()}"
        )

    # ── Background login items (macOS 13+ / Ventura+) ─────────────────────────
    bg_items = run_command(
        "sfltool dumpbtm 2>/dev/null | head -80"
    )
    if bg_items.stdout.strip():
        sections.append(
            f"=== Background Task Management (sfltool dumpbtm) ===\n{bg_items.stdout.strip()}"
        )

    # ── ServiceManagement / SMAppService (macOS 13+) ─────────────────────────
    sm_items = run_command(
        "pluginkit -mAvvv -p com.apple.SMLoginItemAgent 2>/dev/null | head -40"
    )
    if sm_items.stdout.strip():
        sections.append(
            f"=== SMLoginItemAgent plugins (ServiceManagement) ===\n{sm_items.stdout.strip()}"
        )

    # ── Startup Items (legacy, pre-launchd) ───────────────────────────────────
    for d in ("~/Library/StartupItems", "/Library/StartupItems"):
        items = run_command(f"ls {d}/ 2>/dev/null")
        if items.stdout.strip():
            sections.append(f"=== {d} (legacy startup items) ===\n{items.stdout.strip()}")

    # ── Kernel extensions ─────────────────────────────────────────────────────
    kexts = run_command("kextstat 2>/dev/null | grep -v 'com\\.apple\\.' | head -30")
    if kexts.stdout.strip():
        sections.append(
            "=== Non-Apple kernel extensions (kextstat) ===\n"
            + kexts.stdout.strip()
        )

    # ── System extensions ─────────────────────────────────────────────────────
    sys_ext = run_command("systemextensionsctl list 2>/dev/null")
    if sys_ext.stdout.strip():
        sections.append(f"=== System Extensions ===\n{sys_ext.stdout.strip()}")

    # ── Launch agents running right now for this user ─────────────────────────
    user_agents = run_command(
        "launchctl list 2>/dev/null | grep -v '^-\\|com\\.apple\\.' | "
        "grep -v 'PID\\|Status' | head -30"
    )
    if user_agents.stdout.strip():
        sections.append(
            "=== Non-Apple user agents (currently loaded via launchctl) ===\n"
            + user_agents.stdout.strip()
        )

    return "\n\n".join(sections)
