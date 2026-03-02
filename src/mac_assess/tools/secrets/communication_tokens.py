"""Communication platform token discovery.

Slack, Discord, and Teams tokens are high-value corporate espionage targets.
A Slack user session token (xoxs-) grants access to all messages, files, and
channels the user can see — often including shared credentials, internal plans,
and security incident discussions. Discord tokens allow full account takeover.

MITRE ATT&CK: T1552.001 (Unsecured Credentials: Credentials In Files),
              T1078 (Valid Accounts)
"""

from __future__ import annotations

import re

from langchain_core.tools import tool

from ..base import run_command


# Token format patterns ordered by specificity / value
_TOKEN_PATTERNS: dict[str, str] = {
    "Slack user session (xoxs)": r"xoxs-[0-9A-Za-z\-]{40,}",
    "Slack bot token (xoxb)":    r"xoxb-[0-9A-Za-z\-]{40,}",
    "Slack OAuth token (xoxp)":  r"xoxp-[0-9A-Za-z\-]{40,}",
    "Slack workspace token (xoxa)": r"xoxa-2-[0-9A-Za-z\-]{40,}",
    "Discord user token":        r"[MNO][a-zA-Z0-9_-]{23}\.[a-zA-Z0-9_-]{6}\.[a-zA-Z0-9_-]{27}",
    "Notion API token":          r"secret_[A-Za-z0-9]{43}",
    "1Password service account": r"ops_[A-Za-z0-9]{64}",
    "Linear API key":            r"lin_api_[A-Za-z0-9]{40}",
    "Figma personal token":      r"figd_[A-Za-z0-9\-_]{40,}",
}

_COMPILED = {name: re.compile(pattern) for name, pattern in _TOKEN_PATTERNS.items()}

# Paths that commonly contain these tokens
_SCAN_PATHS = [
    # Slack desktop app storage
    "~/Library/Application Support/Slack/storage/",
    "~/Library/Application Support/Slack/Cookies",
    "~/Library/Application Support/Slack/Local Storage/leveldb/",
    # Discord
    "~/Library/Application Support/discord/Local Storage/leveldb/",
    "~/Library/Application Support/discord/Cookies",
    # Slack config files
    "~/.config/slack/",
    # Teams
    "~/Library/Application Support/Microsoft Teams/Local Storage/leveldb/",
    "~/Library/Application Support/Microsoft Teams/Cookies",
    # Generic app config locations
    "~/.notion/",
    "~/.config/linear/",
]


def _scan_path_for_tokens(path: str) -> list[str]:
    """Grep a path (file or directory) for communication token patterns."""
    hits: list[str] = []
    # Use grep -rl for directories, grep -l for files; then grep -oh to extract token
    result = run_command(
        f"grep -rl --include='*' "
        f"'xoxs-\\|xoxb-\\|xoxp-\\|xoxa-2-\\|secret_[A-Za-z0-9]\\{{43\\}}\\|ops_' "
        f"{path} 2>/dev/null | head -5",
        timeout=8,
    )
    if not result.stdout.strip():
        return hits

    for fpath in result.stdout.splitlines():
        fpath = fpath.strip()
        if not fpath:
            continue
        content = run_command(f"cat '{fpath}' 2>/dev/null | strings | head -200", timeout=5)
        if not content.stdout:
            continue
        for token_name, pattern in _COMPILED.items():
            for match in pattern.finditer(content.stdout):
                tok = match.group(0)
                # Truncate for safety — show prefix only
                preview = tok[:20] + "..." if len(tok) > 20 else tok
                hits.append(f"  ⚠ {token_name}: {preview} (in {fpath})")
    return hits


@tool
def find_communication_tokens() -> str:
    """Scan for Slack, Discord, Teams, and other communication platform tokens.

    Searches app data directories, LevelDB storage, and cookie files for:
    - Slack user session tokens (xoxs- prefix) — access to all channels/messages
    - Slack bot tokens (xoxb-) and OAuth tokens (xoxp-)
    - Discord user tokens — full account access
    - Microsoft Teams session cookies and MSAL tokens
    - Notion API tokens, 1Password service accounts, Linear API keys
    - Figma personal access tokens

    Also checks environment variables and shell history for token patterns.

    Returns:
        Discovered tokens with their type and source path.
    """
    sections: list[str] = []

    # ── App data directory scans ──────────────────────────────────────────────
    all_hits: list[str] = []
    for path in _SCAN_PATHS:
        hits = _scan_path_for_tokens(path)
        all_hits.extend(hits)

    sections.append(
        "=== Communication tokens in app data directories ===\n"
        + ("\n".join(all_hits) if all_hits else "(none found)")
    )

    # ── Environment variables ─────────────────────────────────────────────────
    env_tokens = run_command(
        "env 2>/dev/null | grep -iE "
        "'(SLACK|DISCORD|NOTION|LINEAR|FIGMA|TEAMS).*TOKEN\\|"
        "xox[sbpa]-\\|secret_[A-Za-z0-9]{10}'",
        timeout=5,
    )
    sections.append(
        "=== Communication tokens in live environment variables ===\n"
        + (env_tokens.stdout.strip() or "(none found)")
    )

    # ── Shell history patterns ────────────────────────────────────────────────
    # Look for Slack/Discord API calls in history
    history_hits = run_command(
        "cat ~/.zsh_history ~/.bash_history 2>/dev/null | "
        "sed 's/^: [0-9]*:[0-9]*;//' | "
        "grep -iE 'xoxs-|xoxb-|xoxp-|slack.*token|discord.*token|SLACK_TOKEN|DISCORD_TOKEN' "
        "| head -20",
        timeout=10,
    )
    if history_hits.stdout.strip():
        sections.append(
            "=== Communication tokens in shell history ===\n"
            + history_hits.stdout.strip()
        )

    # ── Slack config files ────────────────────────────────────────────────────
    slack_workspaces = run_command(
        "cat ~/Library/Application\\ Support/Slack/storage/slack-workspaces 2>/dev/null "
        "| python3 -c \"import sys,json; "
        "data=json.load(sys.stdin); "
        "[print(w.get('name','?'), w.get('domain','?')) for w in data] "
        "\" 2>/dev/null",
        timeout=5,
    )
    if slack_workspaces.stdout.strip():
        sections.append(
            "=== Slack workspace memberships ===\n"
            + slack_workspaces.stdout.strip()
        )
    else:
        # Fallback: check if Slack is installed at all
        slack_installed = run_command("ls ~/Library/Application\\ Support/Slack/ 2>/dev/null")
        if slack_installed.stdout.strip():
            sections.append(
                "=== Slack installation detected ===\n"
                + slack_installed.stdout.strip()
            )

    # ── Teams auth cookies ────────────────────────────────────────────────────
    teams_dir = run_command(
        "ls ~/Library/Application\\ Support/Microsoft\\ Teams/ 2>/dev/null"
    )
    if teams_dir.stdout.strip():
        sections.append(
            "=== Microsoft Teams app data (may contain MSAL auth tokens) ===\n"
            + teams_dir.stdout.strip()
        )

    return "\n\n".join(sections)
