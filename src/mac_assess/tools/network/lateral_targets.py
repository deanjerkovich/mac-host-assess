"""Network lateral movement target discovery.

Once an attacker has access to an endpoint, they enumerate reachable hosts
as candidate targets for lateral movement. This tool identifies the same
information an attacker would gather from this machine.

MITRE ATT&CK: T1135 (Network Share Discovery), T1018 (Remote System Discovery),
              T1049 (System Network Connections Discovery)
"""

from __future__ import annotations

from langchain_core.tools import tool

from ..base import run_command


@tool
def find_lateral_movement_targets() -> str:
    """Identify reachable hosts and shared resources for lateral movement.

    Discovers:
    - ARP cache — hosts recently communicated with (immediate reachability)
    - Routing table — networks reachable from this machine
    - Mounted network shares (SMB, NFS, AFP) and their server addresses
    - SSH known_hosts entries — servers this user has connected to before
    - /etc/hosts entries — curated internal hostnames
    - mDNS/Bonjour neighbours (dns-sd, avahi) — LAN service advertisements
    - Currently established SSH connections to remote hosts
    - VPN interfaces and their routes (indicates access to protected networks)
    - Configured SSH host aliases in ~/.ssh/config with hostnames

    Returns:
        All laterally reachable hosts and shared resources visible from this endpoint.
    """
    sections = []

    # ── ARP cache ─────────────────────────────────────────────────────────────
    arp = run_command("arp -a 2>/dev/null")
    sections.append(
        "=== ARP cache (recently contacted hosts) ===\n"
        + (arp.stdout.strip() or "(empty)")
    )

    # ── Routing table ─────────────────────────────────────────────────────────
    routes = run_command("netstat -rn 2>/dev/null | head -40")
    sections.append(f"=== Routing table ===\n{routes.stdout.strip()}")

    # ── Mounted network shares ────────────────────────────────────────────────
    mounts = run_command("mount 2>/dev/null | grep -E 'smb|nfs|afp|cifs|smbfs'")
    if mounts.stdout.strip():
        sections.append(
            "=== Mounted network shares (SMB/NFS/AFP) ===\n"
            + mounts.stdout.strip()
        )
    else:
        sections.append("=== Mounted network shares ===\n(none)")

    # ── /Volumes (macOS network mounts appear here) ───────────────────────────
    volumes = run_command("ls /Volumes/ 2>/dev/null")
    if volumes.stdout.strip():
        sections.append(f"=== /Volumes/ ===\n{volumes.stdout.strip()}")

    # ── SSH known_hosts ───────────────────────────────────────────────────────
    known_hosts = run_command(
        "cat ~/.ssh/known_hosts 2>/dev/null | awk '{print $1}' | sort -u | head -50"
    )
    sections.append(
        "=== SSH known_hosts (previously connected servers) ===\n"
        + (known_hosts.stdout.strip() or "(none)")
    )

    # ── SSH config host entries ───────────────────────────────────────────────
    ssh_hosts = run_command(
        "grep -E '^\\s*(Host|HostName)' ~/.ssh/config 2>/dev/null"
    )
    if ssh_hosts.stdout.strip():
        sections.append(
            "=== SSH config host entries ===\n"
            + ssh_hosts.stdout.strip()
        )

    # ── Active SSH connections outbound ───────────────────────────────────────
    ssh_connections = run_command(
        "netstat -an 2>/dev/null | grep ':22\\b' | grep ESTABLISHED"
    )
    if ssh_connections.stdout.strip():
        sections.append(
            "=== Active outbound SSH connections ===\n"
            + ssh_connections.stdout.strip()
        )

    # ── /etc/hosts ────────────────────────────────────────────────────────────
    etc_hosts = run_command(
        "cat /etc/hosts 2>/dev/null | grep -v '^#\\|^$\\|^127\\|^::1\\|^255' | head -30"
    )
    if etc_hosts.stdout.strip():
        sections.append(f"=== /etc/hosts (non-loopback entries) ===\n{etc_hosts.stdout.strip()}")

    # ── VPN interfaces ────────────────────────────────────────────────────────
    vpn_ifaces = run_command(
        "ifconfig 2>/dev/null | grep -E '^(utun|tun|ppp|ipsec|vpn)' | awk '{print $1}'"
    )
    if vpn_ifaces.stdout.strip():
        vpn_details = run_command(
            "ifconfig 2>/dev/null | grep -A4 -E '^(utun|tun|ppp)'"
        )
        sections.append(
            "=== VPN / tunnel interfaces (utun/tun/ppp) ===\n"
            + vpn_details.stdout.strip()
        )

    # ── Bonjour / mDNS services on the LAN ───────────────────────────────────
    bonjour = run_command(
        "dns-sd -B _ssh._tcp local 2>/dev/null &"
        "sleep 2 && kill %1 2>/dev/null; "
        "dns-sd -B _smb._tcp local 2>/dev/null &"
        "sleep 2 && kill %1 2>/dev/null",
        timeout=8,
    )
    # dns-sd is interactive; use a simpler passive check instead
    mdns_cache = run_command(
        "dscacheutil -cachedump -entries Host 2>/dev/null | head -30"
    )
    if mdns_cache.stdout.strip():
        sections.append(
            f"=== mDNS / DNS cache (dscacheutil) ===\n{mdns_cache.stdout.strip()}"
        )

    # ── Recent AFP/SMB connections from Finder sidebar prefs ─────────────────
    recent_servers = run_command(
        "defaults read com.apple.networkConnect 2>/dev/null | head -20"
    )
    if recent_servers.stdout.strip():
        sections.append(
            f"=== Recent network server connections ===\n{recent_servers.stdout.strip()}"
        )

    return "\n\n".join(sections)
