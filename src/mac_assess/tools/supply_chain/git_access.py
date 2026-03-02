"""Git repository and VCS push-access discovery.

Identifies local git repositories that have push-capable remotes, and
authenticated VCS CLI tools (gh, glab). An attacker with these could
inject malicious commits into upstream codebases.
"""

from __future__ import annotations

from langchain_core.tools import tool

from ..base import run_command


@tool
def find_git_push_access() -> str:
    """Find local git repositories with push-capable remotes and authenticated VCS CLIs.

    Looks for:
    - Local git clones with SSH or authenticated HTTPS push remotes
      (GitHub, GitLab, Bitbucket, Azure DevOps, etc.)
    - Authenticated GitHub CLI (gh) and GitLab CLI (glab) sessions
    - Git credential helpers that enable HTTPS pushing without a password
    - Global git identity (name/email) that would author malicious commits

    Returns:
        Summary of push-capable git access found on this system.
    """
    sections = []

    # ── 1. Find git repos and their push remotes ──────────────────────────────
    # Search common developer directories; cap depth and count to stay fast.
    find_result = run_command(
        "find ~ -maxdepth 7 -name '.git' -type d 2>/dev/null"
        " | grep -v '/.git/'    "  # exclude nested .git dirs inside a repo
        " | head -80",
        timeout=20,
    )

    git_dirs = [l.strip() for l in find_result.stdout.splitlines() if l.strip()]
    repo_paths = [d.removesuffix("/.git") for d in git_dirs if "/.git" in d]

    if repo_paths:
        push_remotes: list[str] = []
        for repo in repo_paths[:50]:  # cap processing at 50 repos
            remotes = run_command(
                f'git -C "{repo}" remote -v 2>/dev/null | grep "(push)"',
                timeout=5,
            )
            if remotes.stdout.strip():
                push_remotes.append(f"{repo}\n  {remotes.stdout.strip()}")

        if push_remotes:
            sections.append(
                f"=== Git Repos with Push Remotes ({len(push_remotes)} of {len(repo_paths)} scanned) ===\n"
                + "\n".join(push_remotes)
            )
        else:
            sections.append(
                f"=== Git Repos ({len(repo_paths)} found, none with push remotes) ==="
            )
    else:
        sections.append("=== No git repositories found ===")

    # ── 2. Authenticated VCS CLI tools ────────────────────────────────────────
    gh = run_command("gh auth status 2>&1", timeout=10)
    sections.append(f"=== GitHub CLI (gh) auth status ===\n{gh.output.strip() or '(not installed)'}")

    glab = run_command("glab auth status 2>&1", timeout=10)
    sections.append(f"=== GitLab CLI (glab) auth status ===\n{glab.output.strip() or '(not installed)'}")

    hub = run_command("hub api user 2>&1 | head -3", timeout=10)
    sections.append(f"=== hub CLI auth check ===\n{hub.output.strip() or '(not installed)'}")

    # ── 3. Git credential helper (enables password-free HTTPS pushes) ─────────
    helper = run_command("git config --global credential.helper 2>/dev/null")
    sections.append(
        f"=== Git credential helper ===\n{helper.output.strip() or '(none configured)'}"
    )

    # ── 4. SSH config entries for known git hosting services ──────────────────
    ssh_git_hosts = run_command(
        "cat ~/.ssh/config 2>/dev/null"
        " | grep -i -A4 'github\\|gitlab\\|bitbucket\\|azure\\|codecommit'",
        timeout=5,
    )
    sections.append(
        f"=== SSH config entries for git hosts ===\n"
        + (ssh_git_hosts.stdout.strip() or "(none found)")
    )

    # ── 5. Global git identity ────────────────────────────────────────────────
    name = run_command("git config --global user.name 2>/dev/null").output.strip()
    email = run_command("git config --global user.email 2>/dev/null").output.strip()
    if name or email:
        sections.append(f"=== Global git identity ===\nname:  {name}\nemail: {email}")

    return "\n\n".join(sections)
