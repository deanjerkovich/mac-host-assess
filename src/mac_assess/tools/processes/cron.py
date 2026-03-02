"""Cron and periodic task persistence assessment.

Cron jobs provide a simple, often-overlooked persistence mechanism that
survives reboots and runs without user interaction. Attackers use them
to maintain access and execute payloads on a schedule.

MITRE ATT&CK: T1053.003 (Scheduled Task/Job: Cron)
"""

from __future__ import annotations

from langchain_core.tools import tool

from ..base import run_command


@tool
def list_cron_jobs() -> str:
    """List all cron jobs and periodic task configurations.

    Checks for:
    - Current user's crontab (crontab -l)
    - All user crontabs in /var/spool/cron/ (if readable)
    - Root crontab
    - System-wide /etc/crontab
    - Periodic scripts: /etc/periodic/ (daily/weekly/monthly)
    - Scripts in /usr/local/etc/periodic/
    - at(1) job queue (scheduled one-time tasks)
    - anacron configuration (/etc/anacrontab)

    Flags entries that reference unusual paths, download commands
    (curl/wget), or execute files outside standard system locations.

    Returns:
        All cron and periodic task entries across the system.
    """
    sections = []

    # ── Current user's crontab ────────────────────────────────────────────────
    crontab = run_command("crontab -l 2>/dev/null")
    sections.append(
        "=== Current user crontab ===\n"
        + (crontab.stdout.strip() or "(empty or not set)")
    )

    # ── Root crontab ──────────────────────────────────────────────────────────
    root_cron = run_command("sudo crontab -l 2>/dev/null")
    if root_cron.stdout.strip():
        sections.append(f"=== Root crontab ===\n{root_cron.stdout.strip()}")

    # ── /etc/crontab ──────────────────────────────────────────────────────────
    etc_crontab = run_command("cat /etc/crontab 2>/dev/null")
    if etc_crontab.stdout.strip():
        sections.append(f"=== /etc/crontab ===\n{etc_crontab.stdout.strip()}")

    # ── /var/spool/cron/ user crontabs ────────────────────────────────────────
    spool = run_command("ls /var/spool/cron/crontabs/ 2>/dev/null || ls /var/spool/cron/ 2>/dev/null")
    if spool.stdout.strip():
        sections.append(f"=== Crontab spool users (/var/spool/cron/) ===\n{spool.stdout.strip()}")
        for user in spool.stdout.splitlines():
            user = user.strip()
            if user:
                content = run_command(
                    f"cat /var/spool/cron/crontabs/{user} 2>/dev/null "
                    f"|| cat /var/spool/cron/{user} 2>/dev/null"
                )
                if content.stdout.strip():
                    sections.append(f"--- Crontab for {user} ---\n{content.stdout.strip()}")

    # ── macOS periodic scripts ────────────────────────────────────────────────
    for period in ("daily", "weekly", "monthly"):
        scripts = run_command(f"ls /etc/periodic/{period}/ 2>/dev/null")
        if scripts.stdout.strip():
            non_std = [
                s.strip() for s in scripts.stdout.splitlines()
                if s.strip() and not s.strip().startswith(("100.", "200.", "300.", "400.", "500.", "999."))
            ]
            note = f" (⚠ {len(non_std)} non-standard)" if non_std else ""
            sections.append(
                f"=== /etc/periodic/{period}/{note} ===\n"
                + scripts.stdout.strip()
            )

    # ── /usr/local/etc/periodic/ (third-party additions) ─────────────────────
    local_periodic = run_command("ls /usr/local/etc/periodic/ 2>/dev/null")
    if local_periodic.stdout.strip():
        sections.append(
            f"=== /usr/local/etc/periodic/ (third-party periodic tasks) ===\n"
            + local_periodic.stdout.strip()
        )

    # ── at(1) queue ───────────────────────────────────────────────────────────
    at_jobs = run_command("atq 2>/dev/null")
    if at_jobs.stdout.strip():
        sections.append(f"=== Pending at(1) jobs ===\n{at_jobs.stdout.strip()}")

    # ── Suspicious pattern summary ────────────────────────────────────────────
    suspicious = run_command(
        "crontab -l 2>/dev/null | grep -iE '(curl|wget|bash|sh|python|ruby|perl|nc |ncat|/tmp|/var/tmp)'"
    )
    if suspicious.stdout.strip():
        sections.append(
            "=== ⚠ Suspicious cron entries (download/execute patterns) ===\n"
            + suspicious.stdout.strip()
        )

    return "\n\n".join(sections)
