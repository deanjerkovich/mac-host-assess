"""Shell profile and .env file credential scanning.

Developers commonly export API keys, tokens, and passwords directly in
~/.zshrc, ~/.bashrc, ~/.bash_profile, and .env files for convenience.
If committed to version control or accessed by a compromised process,
these provide immediate credential extraction.

MITRE ATT&CK: T1552.001 (Unsecured Credentials: Credentials In Files)
"""

from __future__ import annotations

from langchain_core.tools import tool

from ..base import run_command

# Shell profile files to scan
_PROFILE_FILES = [
    "~/.zshrc",
    "~/.zprofile",
    "~/.zshenv",
    "~/.bashrc",
    "~/.bash_profile",
    "~/.bash_login",
    "~/.profile",
    "~/.config/fish/config.fish",
    "~/.config/fish/conf.d/",
]

# Grep pattern: export lines containing secret-like variable names
_EXPORT_PATTERN = (
    r"(?i)(export\s+|^)[A-Z0-9_]*"
    r"(API[_\-]?KEY|SECRET|TOKEN|PASSWORD|PASSWD|CREDENTIAL|ACCESS_KEY|PRIVATE_KEY|AUTH)"
    r"[A-Z0-9_]*\s*[=:]"
)


def _scan_file(path: str) -> str:
    result = run_command(
        f"grep -nE '{_EXPORT_PATTERN}' {path} 2>/dev/null | grep -v '^\\s*#'",
        timeout=5,
    )
    return result.stdout.strip()


@tool
def scan_shell_profiles() -> str:
    """Scan shell profile files and .env files for hardcoded secrets.

    Checks for exported environment variables containing API keys, tokens,
    passwords, and other credentials in:
    - ~/.zshrc, ~/.zprofile, ~/.zshenv
    - ~/.bashrc, ~/.bash_profile, ~/.bash_login, ~/.profile
    - ~/.config/fish/config.fish
    - .env, .env.local, .env.production, .env.development files in
      the home directory and common project locations

    Also reports on whether any profile files are world-readable
    (leaking credentials to other local users).

    Returns:
        Credential-bearing lines from shell profiles and .env files.
    """
    sections = []

    # ── Shell profile files ───────────────────────────────────────────────────
    profile_hits: list[str] = []
    for path in _PROFILE_FILES:
        hits = _scan_file(path)
        if hits:
            profile_hits.append(f"--- {path} ---\n{hits}")

    sections.append(
        "=== Shell profile files with hardcoded secrets ===\n"
        + ("\n".join(profile_hits) if profile_hits else "(none found)")
    )

    # ── .env files ────────────────────────────────────────────────────────────
    env_files = run_command(
        "find ~ -maxdepth 5 \\( "
        "-name '.env' -o -name '.env.local' -o -name '.env.production' "
        "-o -name '.env.development' -o -name '.env.staging' -o -name '.env.test' "
        "\\) -not -path '*/.git/*' -not -path '*/node_modules/*' 2>/dev/null | head -30",
        timeout=15,
    )
    if env_files.stdout.strip():
        env_hits: list[str] = []
        for env_path in env_files.stdout.splitlines():
            env_path = env_path.strip()
            if not env_path:
                continue
            content = run_command(
                f"cat {env_path} 2>/dev/null | grep -vE '^\\s*#|^\\s*$' | head -30",
                timeout=5,
            )
            if content.stdout.strip():
                env_hits.append(f"--- {env_path} ---\n{content.stdout.strip()}")
        sections.append(
            "=== .env files found ===\n"
            + ("\n".join(env_hits) if env_hits else "(found files but all appear empty or commented)")
        )
    else:
        sections.append("=== .env files ===\n(none found in home directory tree)")

    # ── World-readable profile files ──────────────────────────────────────────
    world_readable = run_command(
        "ls -la ~/.zshrc ~/.zprofile ~/.bashrc ~/.bash_profile ~/.profile 2>/dev/null"
        " | awk '{if (substr($1,8,1) == \"r\") print \"WORLD-READABLE: \" $NF \" \" $1}'",
        timeout=5,
    )
    if world_readable.stdout.strip():
        sections.append(
            f"=== World-readable shell profiles (any local user can read) ===\n"
            + world_readable.stdout.strip()
        )

    # ── Secrets in current environment ───────────────────────────────────────
    # Shows what's actually live in the running process environment
    env_secrets = run_command(
        "env 2>/dev/null | grep -iE "
        "'(API[_-]?KEY|SECRET|TOKEN|PASSWORD|PASSWD|CREDENTIAL|ACCESS_KEY|AUTH)[^=]*=' "
        "| grep -v 'LESS_TERMCAP\\|TERM\\|COLOR' | head -30",
        timeout=5,
    )
    sections.append(
        "=== Live environment variables matching secret patterns ===\n"
        + (env_secrets.stdout.strip() or "(none found)")
    )

    return "\n\n".join(sections)
