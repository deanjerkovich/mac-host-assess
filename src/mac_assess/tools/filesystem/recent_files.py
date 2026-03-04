"""Recently accessed files and download quarantine assessment.

Recently accessed files reveal what sensitive work was in progress.
The macOS quarantine database (LSQuarantine) records every file downloaded
from the internet with the source URL — a goldmine for forensics and
understanding what an attacker may have obtained access to.

MITRE ATT&CK: T1005 (Data from Local System),
              T1025 (Data from Removable Media)
"""

from __future__ import annotations

from langchain_core.tools import tool

from ..base import run_command


@tool
def find_recently_accessed_files() -> str:
    """Enumerate recently opened files, downloads, and the macOS quarantine database.

    Discovers:
    - macOS quarantine database (LSQuarantine): every file downloaded from the
      internet with source URL, timestamp, and application that downloaded it
    - Recent documents per application (NSDocumentRecentDocumentURLsKey from defaults)
    - Files modified in the last 7 days in sensitive locations (~/.ssh/, ~/.aws/,
      ~/.config/, ~/Documents/, ~/Desktop/)
    - Recently mounted disk images (.dmg files in /tmp, ~/Downloads)
    - Spotlight recent search terms (if accessible)
    - ~/Downloads directory contents

    Returns:
        Recently accessed sensitive files, downloads, and quarantine records.
    """
    sections = []

    # ── macOS Quarantine database ──────────────────────────────────────────────
    quarantine_db = "~/Library/Preferences/com.apple.LaunchServices.QuarantineEventsV2"
    quarantine = run_command(
        f"sqlite3 {quarantine_db} "
        f"\"SELECT datetime(LSQuarantineTimeStamp+978307200,'unixepoch','localtime'), "
        f"LSQuarantineAgentName, LSQuarantineOriginURLString, LSQuarantineDataURLString "
        f"FROM LSQuarantineEvent ORDER BY LSQuarantineTimeStamp DESC LIMIT 40\" "
        f"2>/dev/null",
        timeout=10,
    )
    sections.append(
        "=== Recent downloads (macOS quarantine database) ===\n"
        + (quarantine.stdout.strip() or "(not accessible or empty)")
    )

    # ── ~/Downloads directory ─────────────────────────────────────────────────
    downloads = run_command(
        "ls -lt ~/Downloads/ 2>/dev/null | head -30"
    )
    if downloads.stdout.strip():
        sections.append(f"=== ~/Downloads/ (newest first) ===\n{downloads.stdout.strip()}")

    # ── Recently modified files in sensitive dirs ─────────────────────────────
    sensitive_dirs = ["~/.ssh", "~/.aws", "~/.config", "~/.gnupg", "~/Library/Keychains"]
    for d in sensitive_dirs:
        recent = run_command(
            f"find {d} -type f -newer /tmp -mtime -7 2>/dev/null | head -15",
            timeout=8,
        )
        if recent.stdout.strip():
            sections.append(
                f"=== Files modified in last 7 days: {d} ===\n{recent.stdout.strip()}"
            )

    # ── Recently modified in home dir (top-level) ─────────────────────────────
    home_recent = run_command(
        "find ~ -maxdepth 3 -type f -mtime -1 "
        "-not -path '*/Library/Caches/*' "
        "-not -path '*/.Trash/*' "
        "-not -path '*/node_modules/*' "
        "-not -path '*/.git/*' "
        "2>/dev/null | head -30",
        timeout=15,
    )
    if home_recent.stdout.strip():
        sections.append(
            "=== Files modified in last 24 hours (home directory) ===\n"
            + home_recent.stdout.strip()
        )

    # ── Recent apps / documents via NSDocumentRecentDocumentURLsKey ───────────
    recent_docs = run_command(
        "defaults read -g NSDocumentRecentDocumentURLsKey 2>/dev/null | "
        "grep -oE '\"file://[^\"]+\"' | head -30"
    )
    if recent_docs.stdout.strip():
        sections.append(
            "=== Recently opened documents (NSDocumentRecentDocumentURLsKey) ===\n"
            + recent_docs.stdout.strip()
        )

    # ── Recent items from Finder ──────────────────────────────────────────────
    recent_items = run_command(
        "defaults read com.apple.recentitems 2>/dev/null | "
        "grep -oE '\"[^\"]+\\.(pdf|docx|xlsx|txt|key|pages|numbers|csv|sql|json|yaml|env|pem|p12)\"' "
        "| head -20"
    )
    if recent_items.stdout.strip():
        sections.append(
            "=== Recent files from Finder (sensitive extensions) ===\n"
            + recent_items.stdout.strip()
        )

    # ── Mounted disk images ────────────────────────────────────────────────────
    dmg_mounted = run_command("mount | grep -i 'disk image\\|\\.dmg\\|HFS\\|APFS' | grep -v 'disk1\\|disk2s' | head -10")
    dmg_recent = run_command("find ~/Downloads /tmp -name '*.dmg' -mtime -14 2>/dev/null | head -10")
    if dmg_mounted.stdout.strip() or dmg_recent.stdout.strip():
        sections.append(
            "=== Disk images ===\n"
            + (f"Currently mounted:\n{dmg_mounted.stdout.strip()}\n" if dmg_mounted.stdout.strip() else "")
            + (f"Recent .dmg files:\n{dmg_recent.stdout.strip()}" if dmg_recent.stdout.strip() else "")
        )

    # ── /tmp and /var/tmp sensitive files ─────────────────────────────────────
    tmp_files = run_command(
        "ls -lt /tmp/ /var/tmp/ 2>/dev/null | grep -vE '^total|^d' | head -20"
    )
    if tmp_files.stdout.strip():
        sections.append(f"=== /tmp and /var/tmp files ===\n{tmp_files.stdout.strip()}")

    return "\n\n".join(sections)
