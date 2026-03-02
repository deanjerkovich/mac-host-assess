"""SSH agent state and forwarding exposure assessment.

SSH agent hijacking is a silent, high-value lateral movement technique.
If an agent is running with ForwardAgent enabled, any host the user SSH's
to that is later compromised can silently use the forwarded agent socket
to impersonate the user on any system where their keys have access —
with no local trace and no re-authentication required.

MITRE ATT&CK: T1563.001 (Remote Service Session Hijacking: SSH Hijacking),
              T1550 (Use Alternate Authentication Material)
"""

from __future__ import annotations

from langchain_core.tools import tool

from ..base import run_command


@tool
def find_ssh_agent_exposure() -> str:
    """Assess SSH agent state, loaded keys, and agent forwarding configuration.

    Checks for:
    - Running SSH agent and the SSH_AUTH_SOCK socket path
    - Keys currently loaded in the agent (ssh-add -l)
    - ForwardAgent directives in ~/.ssh/config — if enabled, any host
      you SSH to with root access can silently use all agent keys
    - AllowAgentForwarding in sshd_config (server-side policy)
    - UseKeychain (macOS-specific: keys auto-loaded from Keychain on login)
    - IdentityFile entries across all SSH host configurations
    - Passphrase-less keys loaded vs passphrase-protected keys

    Risk: ForwardAgent + compromised bastion = silent lateral movement
    across every system accessible by any loaded key, without credentials.

    Returns:
        SSH agent state, loaded keys, and forwarding configuration.
    """
    sections = []

    # ── SSH agent socket ──────────────────────────────────────────────────────
    agent_sock = run_command("echo $SSH_AUTH_SOCK 2>/dev/null").output.strip()
    agent_pid = run_command("echo $SSH_AGENT_PID 2>/dev/null").output.strip()
    if agent_sock:
        sections.append(
            f"=== SSH Agent (RUNNING) ===\n"
            f"SSH_AUTH_SOCK: {agent_sock}\n"
            f"SSH_AGENT_PID: {agent_pid or '(not set)'}"
        )
    else:
        # Check if one is running even if socket not in env
        running = run_command("pgrep -la ssh-agent 2>/dev/null")
        sections.append(
            f"=== SSH Agent ===\n"
            + (f"Running (no socket in env): {running.stdout.strip()}" if running.stdout.strip()
               else "(not running)")
        )

    # ── Keys loaded in agent ──────────────────────────────────────────────────
    loaded_keys = run_command("ssh-add -l 2>&1", timeout=5)
    sections.append(
        f"=== Keys loaded in SSH agent (ssh-add -l) ===\n"
        + loaded_keys.output.strip()
    )

    # ── SSH config analysis ───────────────────────────────────────────────────
    ssh_config = run_command("cat ~/.ssh/config 2>/dev/null")
    if ssh_config.stdout.strip():
        sections.append(f"=== ~/.ssh/config ===\n{ssh_config.stdout.strip()}")

        # Highlight ForwardAgent entries specifically
        forward_agent = run_command(
            "grep -in 'forwardagent' ~/.ssh/config 2>/dev/null"
        )
        if forward_agent.stdout.strip():
            sections.append(
                f"=== ForwardAgent directives (⚠ agent hijacking risk) ===\n"
                + forward_agent.stdout.strip()
            )

        # UseKeychain (macOS: auto-loads keys from Keychain on login)
        use_keychain = run_command(
            "grep -in 'usekeychain\\|addkeystoagent' ~/.ssh/config 2>/dev/null"
        )
        if use_keychain.stdout.strip():
            sections.append(
                f"=== UseKeychain / AddKeysToAgent (keys auto-loaded at login) ===\n"
                + use_keychain.stdout.strip()
            )
    else:
        sections.append("=== ~/.ssh/config ===\n(not present)")

    # ── SSH private keys on disk ──────────────────────────────────────────────
    key_files = run_command(
        "find ~/.ssh -type f 2>/dev/null | head -30"
    )
    if key_files.stdout.strip():
        sections.append(f"=== Files in ~/.ssh/ ===\n{key_files.stdout.strip()}")

    # Check which keys lack a passphrase (high risk)
    passphrase_check = run_command(
        "for f in ~/.ssh/id_*; do "
        "  [ -f \"$f\" ] && ! echo '' | ssh-keygen -y -P '' -f \"$f\" >/dev/null 2>&1 "
        "  && echo \"PASSPHRASE-PROTECTED: $f\" "
        "  || ( [ -f \"$f\" ] && echo \"NO PASSPHRASE: $f\" ); "
        "done 2>/dev/null",
        timeout=10,
    )
    if passphrase_check.stdout.strip():
        sections.append(
            f"=== SSH key passphrase status ===\n{passphrase_check.stdout.strip()}"
        )

    # ── Server-side: AllowAgentForwarding in sshd_config ─────────────────────
    allow_forward = run_command(
        "grep -i 'allowagentforwarding' /etc/ssh/sshd_config 2>/dev/null"
    )
    sections.append(
        f"=== AllowAgentForwarding in sshd_config ===\n"
        + (allow_forward.stdout.strip() or "(not set — defaults to yes)")
    )

    return "\n\n".join(sections)
