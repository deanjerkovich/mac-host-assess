"""Password manager CLI unlock state and installation detection.

Password managers are the master key to every other credential. If the
1Password CLI is unlocked (OP_SESSION_* env var set), an attacker can run
'op item list' and dump the entire vault. Bitwarden CLI with BW_SESSION set
is equally powerful. This tool detects unlock state and installed vaults.

MITRE ATT&CK: T1555 (Credentials from Password Stores),
              T1078 (Valid Accounts)
"""

from __future__ import annotations

from langchain_core.tools import tool

from ..base import run_command


@tool
def find_password_manager_exposure() -> str:
    """Detect password manager CLI unlock state and installed vault data.

    Checks for:
    - 1Password CLI (op): OP_SESSION_* env vars (means CLI is unlocked),
      connected accounts, ~/.config/op/ session state
    - Bitwarden CLI (bw): BW_SESSION env var (unlocked vault session key),
      bw status output (locked/unlocked/unauthenticated)
    - 1Password desktop app installation and vault presence
    - Bitwarden desktop app data
    - Dashlane, LastPass, KeePassXC installations
    - macOS Passwords app (Sequoia+) accessibility

    Risk: An unlocked CLI session token is equivalent to having the master
    password — it can enumerate and decrypt all vault items.

    Returns:
        Password manager presence, CLI unlock state, and account information.
    """
    sections = []

    # ── 1Password CLI ─────────────────────────────────────────────────────────
    op_session = run_command(
        "env 2>/dev/null | grep '^OP_SESSION' | head -5"
    )
    op_accounts = run_command("op account list 2>/dev/null")
    op_config = run_command("ls ~/.config/op/ 2>/dev/null")
    op_binary = run_command("which op 2>/dev/null")

    op_section = "=== 1Password CLI (op) ===\n"
    op_section += f"Binary:    {op_binary.stdout.strip() or '(not installed)'}\n"
    if op_session.stdout.strip():
        op_section += f"⚠ UNLOCKED — OP_SESSION env vars present:\n{op_session.stdout.strip()}\n"
        op_section += "  → 'op item list' would dump all vault items\n"
    if op_accounts.stdout.strip():
        op_section += f"Connected accounts:\n{op_accounts.stdout.strip()}\n"
    if op_config.stdout.strip():
        op_section += f"~/.config/op/ contents: {op_config.stdout.strip()}"
    sections.append(op_section)

    # ── 1Password desktop app ─────────────────────────────────────────────────
    op_desktop_paths = [
        "~/Library/Group Containers/2BUA8C4S2C.com.agilebits",
        "/Applications/1Password 7 - Password Manager.app",
        "/Applications/1Password.app",
    ]
    for p in op_desktop_paths:
        check = run_command(f"ls '{p}' 2>/dev/null | head -5")
        if check.stdout.strip():
            sections.append(
                f"=== 1Password desktop installation ===\n"
                f"Path: {p}\n{check.stdout.strip()}"
            )
            break

    # ── Bitwarden CLI ─────────────────────────────────────────────────────────
    bw_session = run_command("echo $BW_SESSION 2>/dev/null")
    bw_status = run_command("bw status 2>/dev/null")
    bw_binary = run_command("which bw 2>/dev/null")

    bw_section = "=== Bitwarden CLI (bw) ===\n"
    bw_section += f"Binary:    {bw_binary.stdout.strip() or '(not installed)'}\n"
    if bw_session.stdout.strip() and len(bw_session.stdout.strip()) > 10:
        preview = bw_session.stdout.strip()[:20] + "..."
        bw_section += f"⚠ UNLOCKED — BW_SESSION set: {preview}\n"
        bw_section += "  → 'bw list items' would dump all vault items\n"
    if bw_status.stdout.strip():
        bw_section += f"Status: {bw_status.stdout.strip()}"
    sections.append(bw_section)

    # ── Bitwarden desktop app ─────────────────────────────────────────────────
    bw_desktop = run_command(
        "ls ~/Library/Application\\ Support/Bitwarden/ 2>/dev/null | head -10"
    )
    if bw_desktop.stdout.strip():
        sections.append(
            "=== Bitwarden desktop data ===\n"
            + bw_desktop.stdout.strip()
        )

    # ── KeePassXC ─────────────────────────────────────────────────────────────
    keepass_dbs = run_command(
        "find ~ -maxdepth 5 -name '*.kdbx' -not -path '*/.git/*' 2>/dev/null | head -10",
        timeout=15,
    )
    keepass_app = run_command("ls /Applications/KeePassXC.app 2>/dev/null")
    if keepass_dbs.stdout.strip() or keepass_app.stdout.strip():
        sections.append(
            "=== KeePassXC ===\n"
            + (f"App: installed\n" if keepass_app.stdout.strip() else "")
            + (f"Database files:\n{keepass_dbs.stdout.strip()}" if keepass_dbs.stdout.strip() else "")
        )

    # ── Dashlane ─────────────────────────────────────────────────────────────
    dashlane = run_command(
        "ls ~/Library/Application\\ Support/Dashlane/ 2>/dev/null | head -5"
    )
    if dashlane.stdout.strip():
        sections.append(f"=== Dashlane installation detected ===\n{dashlane.stdout.strip()}")

    # ── LastPass ──────────────────────────────────────────────────────────────
    lastpass = run_command(
        "ls ~/Library/Application\\ Support/LastPass/ 2>/dev/null | head -5"
    )
    if lastpass.stdout.strip():
        sections.append(f"=== LastPass installation detected ===\n{lastpass.stdout.strip()}")

    # ── Secrets app (macOS) ───────────────────────────────────────────────────
    secrets_app = run_command(
        "ls /Applications/Secrets.app 2>/dev/null; "
        "ls /Applications/Secrets\\ 4.app 2>/dev/null"
    )
    if secrets_app.stdout.strip():
        sections.append("=== Secrets app installed ===")

    # ── macOS built-in Passwords app (Sequoia+) ───────────────────────────────
    passwords_app = run_command("ls /System/Applications/Passwords.app 2>/dev/null")
    if passwords_app.stdout.strip():
        sections.append(
            "=== macOS Passwords app (Sequoia+) ===\n"
            "(installed — contains iCloud Keychain passwords, accessible to authorized apps)"
        )

    return "\n\n".join(sections)
