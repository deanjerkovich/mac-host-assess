"""Clipboard content inspection.

The macOS clipboard (pasteboard) is a high-yield source of secrets on developer
machines. Developers routinely copy API keys, passwords, and tokens when
provisioning accounts or deploying services — and leave them on the clipboard.
The clipboard is readable by any process running as the current user.

MITRE ATT&CK: T1115 (Clipboard Data)
"""

from __future__ import annotations

import re

from langchain_core.tools import tool

from ..base import run_command


# Patterns for high-value content that might appear on the clipboard
_SECRET_PATTERNS = [
    (r"AKIA[0-9A-Z]{16}", "AWS access key"),
    (r"(?i)aws.*secret.*[A-Za-z0-9+/]{40}", "AWS secret key"),
    (r"gh[pousr]_[A-Za-z0-9_]{36,}", "GitHub token"),
    (r"glpat-[A-Za-z0-9\-_]{20,}", "GitLab token"),
    (r"xox[bspa]-[0-9A-Za-z\-]{20,}", "Slack token"),
    (r"sk-[A-Za-z0-9]{40,}", "OpenAI API key"),
    (r"sk-ant-[A-Za-z0-9\-_]{80,}", "Anthropic API key"),
    (r"[A-Za-z0-9+/]{40}={0,2}", "Possible base64 secret (≥40 chars)"),
    (r"(?i)password[:\s=]+\S{6,}", "Password pattern"),
    (r"(?i)(?:token|secret|api.?key)[:\s=]+\S{6,}", "Token/secret pattern"),
    (r"(?:postgresql|mysql|mongodb|redis)://[^\s@]+:[^\s@]+@", "DB connection string"),
    (r"BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY", "Private key material"),
    (r"eyJ[A-Za-z0-9\-_]+\.eyJ[A-Za-z0-9\-_]+\.[A-Za-z0-9\-_]+", "JWT token"),
    (r"[0-9a-f]{64}", "Possible hex secret (64 chars)"),
]

_COMPILED = [(re.compile(p), label) for p, label in _SECRET_PATTERNS]


@tool
def check_clipboard() -> str:
    """Inspect current clipboard contents for secrets and credentials.

    Reads the macOS clipboard (pasteboard) via pbpaste and scans for:
    - AWS access keys and secret keys
    - GitHub, GitLab, Slack tokens
    - OpenAI and Anthropic API keys
    - JWT tokens
    - Database connection strings with embedded credentials
    - Private key material (-----BEGIN ... PRIVATE KEY-----)
    - Generic password/token patterns
    - Large base64 or hex strings (common credential formats)

    The clipboard is readable by any process running as the current user.
    Developers frequently copy credentials when setting up services and
    forget to clear the clipboard.

    Returns:
        Clipboard content length, detected secret types, and redacted preview.
    """
    sections = []

    # ── Get clipboard contents ────────────────────────────────────────────────
    clipboard = run_command("pbpaste 2>/dev/null", timeout=5)
    content = clipboard.stdout if clipboard.stdout else ""

    if not content.strip():
        return "=== Clipboard ===\n(empty or non-text content)"

    char_count = len(content)
    line_count = content.count("\n") + 1

    sections.append(
        f"=== Clipboard contents ({char_count} chars, {line_count} lines) ===\n"
        f"First 200 chars: {content[:200].replace(chr(10), ' ')!r}"
    )

    # ── Secret pattern scan ───────────────────────────────────────────────────
    hits: list[str] = []
    for pattern, label in _COMPILED:
        matches = list(pattern.finditer(content))
        if matches:
            m = matches[0]
            val = m.group(0)
            # Redact middle of long strings
            if len(val) > 16:
                preview = val[:8] + "..." + val[-4:]
            else:
                preview = val[:8] + "..."
            hits.append(f"  ⚠ {label}: {preview} ({len(matches)} match(es))")

    sections.append(
        "=== Secret patterns detected in clipboard ===\n"
        + ("\n".join(hits) if hits else "(no secret patterns matched)")
    )

    # ── Multi-line content (private keys, config blocks) ─────────────────────
    if "BEGIN" in content and "PRIVATE KEY" in content:
        sections.append("=== ⚠ Private key material detected on clipboard ===")
    if "-----BEGIN CERTIFICATE" in content:
        sections.append("=== Certificate detected on clipboard ===")

    return "\n\n".join(sections)
