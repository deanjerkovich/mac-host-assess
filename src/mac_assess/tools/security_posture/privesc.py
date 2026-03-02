"""Local privilege escalation surface assessment.

Identifies conditions that allow a user-level attacker to escalate to root
without additional exploitation: overly permissive sudo rules, writable PATH
directories, world-accessible SUID/SGID binaries, and group memberships.

MITRE ATT&CK: T1548.003 (Sudo and Sudo Caching), T1574.007 (Path Interception),
              T1548.001 (Setuid/Setgid)
"""

from __future__ import annotations

from langchain_core.tools import tool

from ..base import run_command


@tool
def find_privilege_escalation_vectors() -> str:
    """Find local privilege escalation vectors: sudo rules, PATH hijacking, SUID binaries.

    Checks for:
    - sudo -l: what commands the current user can run as root (NOPASSWD entries
      on binaries like python, vim, find, chmod, less = trivial root via GTFOBins)
    - sudoers configuration including /etc/sudoers.d/ drop-ins
    - Whether the current user is in the admin or wheel group
    - Writable directories in $PATH (enables binary hijacking)
    - Non-Apple SUID/SGID binaries in common third-party locations
    - Sudo timestamp caching window (how long until sudo needs re-auth)
    - Passwordless sudo indicator (NOPASSWD:ALL)

    Returns:
        Summary of privilege escalation vectors found.
    """
    sections = []

    # ── Current user identity and groups ──────────────────────────────────────
    whoami = run_command("id 2>/dev/null")
    groups = run_command("groups 2>/dev/null")
    sections.append(
        f"=== Current user identity ===\n"
        f"{whoami.output.strip()}\n"
        f"Groups: {groups.output.strip()}"
    )

    # ── sudo -l ───────────────────────────────────────────────────────────────
    # Note: on macOS this may prompt for a password if sudo cache has expired.
    # We use a short timeout and accept failure gracefully.
    sudo_l = run_command("sudo -ln 2>&1", timeout=8)  # -n = non-interactive
    sections.append(f"=== sudo permissions (sudo -ln) ===\n{sudo_l.output.strip() or '(could not determine)'}")

    # ── sudoers file ──────────────────────────────────────────────────────────
    sudoers = run_command("cat /etc/sudoers 2>/dev/null | grep -v '^#' | grep -v '^$'")
    sections.append(
        f"=== /etc/sudoers (non-comment lines) ===\n"
        + (sudoers.stdout.strip() or "(not readable without root)")
    )

    sudoers_d = run_command("ls /etc/sudoers.d/ 2>/dev/null")
    if sudoers_d.stdout.strip():
        sections.append(f"=== /etc/sudoers.d/ drop-ins ===\n{sudoers_d.stdout.strip()}")
        # Read each drop-in
        for entry in sudoers_d.stdout.splitlines():
            entry = entry.strip()
            if entry:
                content = run_command(
                    f"cat /etc/sudoers.d/{entry} 2>/dev/null | grep -v '^#' | grep -v '^$'"
                )
                if content.stdout.strip():
                    sections.append(f"--- /etc/sudoers.d/{entry} ---\n{content.stdout.strip()}")

    # ── sudo timestamp cache ──────────────────────────────────────────────────
    sudo_ts = run_command(
        "sudo -n true 2>/dev/null && echo 'sudo cache ACTIVE (no password needed right now)'"
        " || echo 'sudo cache expired'"
    )
    sections.append(f"=== sudo timestamp cache ===\n{sudo_ts.output.strip()}")

    # ── Writable directories in PATH ──────────────────────────────────────────
    path_check = run_command(
        r"""
        IFS=':' read -ra dirs <<< "$PATH"
        for dir in "${dirs[@]}"; do
            if [ -d "$dir" ] && [ -w "$dir" ]; then
                echo "WRITABLE: $dir"
            elif [ ! -d "$dir" ]; then
                echo "MISSING:  $dir  (can be created)"
            fi
        done
        """,
        timeout=5,
    )
    sections.append(
        f"=== Writable / missing directories in \$PATH ===\n"
        + (path_check.output.strip() or "(all PATH directories exist and are not writable by current user)")
    )

    # ── SUID/SGID binaries outside Apple's locations ─────────────────────────
    # Limit to /usr/local, /opt, /Applications (Apple's own are expected/benign)
    suid = run_command(
        "find /usr/local /opt /Applications -type f \\( -perm -4000 -o -perm -2000 \\)"
        " 2>/dev/null | head -30",
        timeout=20,
    )
    sections.append(
        f"=== Non-Apple SUID/SGID binaries (/usr/local, /opt, /Applications) ===\n"
        + (suid.output.strip() or "(none found)")
    )

    # Also quick check in user home
    suid_home = run_command(
        "find ~ -type f \\( -perm -4000 -o -perm -2000 \\) 2>/dev/null | head -10",
        timeout=10,
    )
    if suid_home.output.strip():
        sections.append(
            f"=== SUID/SGID binaries in home directory ===\n{suid_home.output.strip()}"
        )

    # ── Sudo cache timeout ────────────────────────────────────────────────────
    timestamp_timeout = run_command(
        "grep -r 'timestamp_timeout' /etc/sudoers /etc/sudoers.d/ 2>/dev/null"
    )
    if timestamp_timeout.stdout.strip():
        sections.append(
            f"=== Custom sudo timestamp timeout ===\n{timestamp_timeout.stdout.strip()}"
        )

    return "\n\n".join(sections)
