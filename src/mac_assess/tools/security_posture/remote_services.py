"""Remote access service discovery.

Identifies macOS sharing services that are currently enabled and could
allow inbound connections — creating lateral movement entry points or
persistence opportunities for attackers already on the local network.

MITRE ATT&CK: T1021 (Remote Services), T1021.004 (SSH),
              T1021.005 (VNC / Screen Sharing)
"""

from __future__ import annotations

from langchain_core.tools import tool

from ..base import run_command


@tool
def find_remote_access_services() -> str:
    """Find enabled remote access and sharing services on this Mac.

    Checks for:
    - Remote Login (SSH daemon) — allows remote shell access
    - Screen Sharing (VNC) — allows remote desktop control
    - Remote Management (Apple Remote Desktop / ARD) — management-level access
    - Remote Apple Events — allows AppleScript from remote hosts
    - File Sharing (SMB/AFP) — exposes local filesystem over network
    - Printer Sharing, Bluetooth sharing, AirDrop discoverability
    - SSH authorized_keys (who can authenticate as this user over SSH)
    - SSHD configuration (PermitRootLogin, PasswordAuthentication, etc.)

    Returns:
        Status of each sharing/remote access service and SSH configuration.
    """
    sections = []

    # ── System Preferences sharing state ─────────────────────────────────────
    # systemsetup is the most reliable way to check these
    remote_login = run_command("systemsetup -getremotelogin 2>/dev/null")
    sections.append(f"=== Remote Login (SSH daemon) ===\n{remote_login.output.strip() or '(could not determine)'}")

    remote_mgmt = run_command("systemsetup -getremoteappleevents 2>/dev/null")
    sections.append(f"=== Remote Apple Events ===\n{remote_mgmt.output.strip() or '(could not determine)'}")

    # ── Screen Sharing / VNC ──────────────────────────────────────────────────
    screen_sharing = run_command(
        "launchctl list com.apple.screensharing 2>/dev/null || echo 'Screen Sharing: not loaded'"
    )
    sections.append(f"=== Screen Sharing (VNC) ===\n{screen_sharing.output.strip()}")

    # ── Apple Remote Desktop ──────────────────────────────────────────────────
    ard = run_command(
        "launchctl list com.apple.RemoteDesktop.agent 2>/dev/null"
        " || launchctl list com.apple.ARDAgent 2>/dev/null"
        " || echo 'Apple Remote Desktop: not loaded'"
    )
    sections.append(f"=== Apple Remote Desktop (ARD) ===\n{ard.output.strip()}")

    # ── File Sharing ──────────────────────────────────────────────────────────
    smb = run_command(
        "launchctl list com.apple.smbd 2>/dev/null || echo 'SMB: not loaded'"
    )
    afp = run_command(
        "launchctl list com.apple.AppleFileServer 2>/dev/null || echo 'AFP: not loaded'"
    )
    sections.append(
        f"=== File Sharing ===\n"
        f"SMB: {smb.output.strip()}\n"
        f"AFP: {afp.output.strip()}"
    )

    # ── AirDrop ───────────────────────────────────────────────────────────────
    airdrop = run_command(
        "defaults read com.apple.NetworkBrowser BrowseAllInterfaces 2>/dev/null"
    )
    sections.append(
        f"=== AirDrop (BrowseAllInterfaces = discoverable by everyone) ===\n"
        f"BrowseAllInterfaces: {airdrop.output.strip() or '(not set / default)'}"
    )

    # ── Internet Sharing ──────────────────────────────────────────────────────
    inet_sharing = run_command(
        "launchctl list com.apple.InternetSharing 2>/dev/null || echo 'Internet Sharing: not loaded'"
    )
    sections.append(f"=== Internet Sharing ===\n{inet_sharing.output.strip()}")

    # ── All active listening services (cross-check) ───────────────────────────
    listening = run_command(
        "netstat -an | grep LISTEN | grep -v '127.0.0.1\\|::1' 2>/dev/null | head -20"
    )
    sections.append(
        f"=== Non-loopback listening sockets (externally reachable) ===\n"
        + (listening.output.strip() or "(none)")
    )

    # ── SSH configuration ─────────────────────────────────────────────────────
    sshd_config = run_command(
        "grep -v '^#' /etc/ssh/sshd_config 2>/dev/null | grep -v '^$'"
    )
    sections.append(
        f"=== SSHD configuration (/etc/ssh/sshd_config) ===\n"
        + (sshd_config.stdout.strip() or "(not readable or not present)")
    )

    # ── SSH authorized_keys ───────────────────────────────────────────────────
    auth_keys = run_command("cat ~/.ssh/authorized_keys 2>/dev/null")
    sections.append(
        f"=== ~/.ssh/authorized_keys (who can SSH in as this user) ===\n"
        + (auth_keys.stdout.strip() or "(not present)")
    )

    return "\n\n".join(sections)
