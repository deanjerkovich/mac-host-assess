"""macOS Keychain credential enumeration.

The macOS Keychain is the system's canonical credential store and is the
primary target for macOS infostealers (Atomic Stealer, AMOS, XCSSET).
The login keychain stores internet passwords, generic passwords, and
application credentials. WiFi passwords are in the System keychain.

MITRE ATT&CK: T1555.001 (Credentials from Password Stores: Keychain)
"""

from __future__ import annotations

from langchain_core.tools import tool

from ..base import run_command


# High-value service patterns to check for in keychain
_HIGH_VALUE_SERVICES = [
    "github.com",
    "gitlab.com",
    "bitbucket.org",
    "npmjs.com",
    "pypi.org",
    "docker.io",
    "aws",
    "azure",
    "google",
    "heroku",
    "slack",
    "1password",
    "apple",
    "icloud",
    "dropbox",
    "stripe",
    "twilio",
    "sendgrid",
]


@tool
def query_keychain_passwords() -> str:
    """Enumerate macOS Keychain entries including internet passwords, generic passwords, and WiFi credentials.

    Enumerates credential metadata from the login and System keychains:
    - Full catalog of internet passwords (websites, services, accounts)
    - Generic passwords (application-stored credentials)
    - WiFi network passwords from the System keychain
    - Login keychain lock state (locked = protected; unlocked = accessible to any
      process running as this user without additional prompting)
    - 'Always Allow' keychain items (accessible without any user prompt)
    - High-value credential checks: GitHub, AWS, npm, PyPI, Slack, etc.

    Note: Metadata (service, account name, type) is readable without the Keychain
    password. Actual secrets require user approval per-item unless the item was
    created with kSecAttrAccessibleAlways.

    Returns:
        Keychain lock state, credential count by type, and enumerated entries.
    """
    sections = []

    # ── Login keychain lock state ──────────────────────────────────────────────
    lock_state = run_command(
        "security show-keychain-info ~/Library/Keychains/login.keychain-db 2>&1"
    )
    sections.append(
        "=== Login Keychain status ===\n"
        + (lock_state.output.strip() or "(unable to read keychain info)")
    )

    # ── List all keychains in search path ─────────────────────────────────────
    keychains = run_command("security list-keychains -d user 2>/dev/null")
    if keychains.stdout.strip():
        sections.append(f"=== Keychain search list ===\n{keychains.stdout.strip()}")

    # ── Full keychain dump (metadata only — no passwords) ─────────────────────
    dump = run_command(
        "security dump-keychain ~/Library/Keychains/login.keychain-db 2>/dev/null | head -300"
    )
    if dump.stdout.strip():
        sections.append(f"=== Login keychain item catalog (metadata) ===\n{dump.stdout.strip()}")

    # ── Internet password count ───────────────────────────────────────────────
    inet_count = run_command(
        "security dump-keychain ~/Library/Keychains/login.keychain-db 2>/dev/null "
        "| grep -c 'inet' 2>/dev/null"
    )
    genp_count = run_command(
        "security dump-keychain ~/Library/Keychains/login.keychain-db 2>/dev/null "
        "| grep -c 'genp' 2>/dev/null"
    )
    sections.append(
        "=== Keychain entry counts ===\n"
        f"Internet passwords (inet): {inet_count.stdout.strip() or '0'}\n"
        f"Generic passwords (genp):  {genp_count.stdout.strip() or '0'}"
    )

    # ── High-value service check ──────────────────────────────────────────────
    hv_hits: list[str] = []
    for service in _HIGH_VALUE_SERVICES:
        result = run_command(
            f"security find-internet-password -s '{service}' 2>/dev/null | "
            f"grep -E 'acct|svce|srvr|\"labl\"' | head -5"
        )
        if result.stdout.strip():
            hv_hits.append(f"  {service}:\n    {result.stdout.strip()}")
        # Also check generic password
        result2 = run_command(
            f"security find-generic-password -s '{service}' 2>/dev/null | "
            f"grep -E 'acct|svce|\"labl\"' | head -3"
        )
        if result2.stdout.strip() and result2.stdout.strip() not in (result.stdout.strip() or ""):
            hv_hits.append(f"  {service} (generic):\n    {result2.stdout.strip()}")

    sections.append(
        "=== High-value keychain entries (metadata only) ===\n"
        + ("\n".join(hv_hits) if hv_hits else "(none of the checked services found)")
    )

    # ── WiFi passwords (System keychain) ──────────────────────────────────────
    # List known WiFi networks (SSIDs) — requires reading System keychain
    wifi_networks = run_command(
        "security find-generic-password -D 'AirPort network password' 2>/dev/null | "
        "grep 'acct\\|svce' | head -20"
    )
    # Also try via networksetup for SSID names (no passwords)
    known_wifi = run_command(
        "networksetup -listpreferredwirelessnetworks en0 2>/dev/null | "
        "grep -v 'Preferred Networks' | head -30"
    )
    sections.append(
        "=== Known WiFi networks (SSIDs) ===\n"
        + (known_wifi.stdout.strip() or "(unable to list — interface may differ from en0)")
    )
    if wifi_networks.stdout.strip():
        sections.append(
            "=== WiFi passwords in System keychain (metadata) ===\n"
            + wifi_networks.stdout.strip()
        )

    # ── 'Always allow' items (no prompt needed) ───────────────────────────────
    always_allow = run_command(
        "security dump-keychain ~/Library/Keychains/login.keychain-db 2>/dev/null "
        "| grep -B5 'ALWA\\|always' | grep -E 'labl|acct|svce' | head -20"
    )
    if always_allow.stdout.strip():
        sections.append(
            "=== ⚠ 'Always allow' keychain items (no user prompt required) ===\n"
            + always_allow.stdout.strip()
        )

    # ── VS Code GitHub token (stored in Keychain by VS Code) ─────────────────
    vscode_gh = run_command(
        "security find-generic-password -s 'vscode.github-authentication' 2>&1 | "
        "grep -v 'SecKeychainSearchCopyNext\\|command not found'"
    )
    if vscode_gh.stdout.strip():
        sections.append(
            "=== VS Code GitHub authentication token (Keychain) ===\n"
            + vscode_gh.stdout.strip()
        )

    return "\n\n".join(sections)
