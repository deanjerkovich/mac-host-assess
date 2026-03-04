"""Network proxy and VPN configuration assessment.

System proxy settings and VPN configurations reveal both attack surface and
corporate network access. A configured proxy can MITM all traffic. VPN profiles
grant access to otherwise-unreachable protected networks. Charles Proxy and
mitmproxy interception configs can capture and replay credentials.

MITRE ATT&CK: T1090 (Proxy), T1572 (Protocol Tunneling),
              T1021 (Remote Services)
"""

from __future__ import annotations

from langchain_core.tools import tool

from ..base import run_command


@tool
def find_proxy_and_vpn_config() -> str:
    """Discover system proxy settings, VPN configurations, and traffic interception tools.

    Checks for:
    - macOS system HTTP/HTTPS/SOCKS proxy settings (networksetup)
    - PAC (proxy auto-config) file URL
    - Environment proxy variables (HTTP_PROXY, HTTPS_PROXY, ALL_PROXY)
    - Installed VPN configuration profiles
    - WireGuard configuration files (~/.config/wireguard/, /etc/wireguard/)
    - OpenVPN configuration files (*.ovpn)
    - Cisco AnyConnect, GlobalProtect, Pulse Secure installations
    - Built-in macOS VPN connections (System Preferences > VPN)
    - Charles Proxy, mitmproxy, Proxyman, Burp Suite installations
      (traffic interception tools that can capture credentials)
    - SSH SOCKS proxy usage patterns in ~/.ssh/config

    Returns:
        All proxy and VPN configuration details.
    """
    sections = []

    # ── System proxy settings ─────────────────────────────────────────────────
    # Get the active network service
    active_service = run_command(
        "networksetup -listnetworkserviceorder 2>/dev/null | "
        "grep -A1 'Wi-Fi\\|Ethernet\\|USB' | grep '(' | head -3"
    )

    # Check proxy settings for common interfaces
    for iface in ("Wi-Fi", "Ethernet", "USB 10/100/1000 LAN"):
        proxy = run_command(
            f"networksetup -getwebproxy '{iface}' 2>/dev/null; "
            f"networksetup -getsecurewebproxy '{iface}' 2>/dev/null; "
            f"networksetup -getsocksfirewallproxy '{iface}' 2>/dev/null"
        )
        if proxy.stdout.strip() and "Enabled: Yes" in proxy.stdout:
            sections.append(
                f"=== ⚠ Active proxy on {iface} ===\n{proxy.stdout.strip()}"
            )

    # PAC file
    pac = run_command(
        "networksetup -getautoproxyurl 'Wi-Fi' 2>/dev/null; "
        "networksetup -getautoproxyurl 'Ethernet' 2>/dev/null"
    )
    if pac.stdout.strip() and "Enabled: Yes" in pac.stdout:
        sections.append(f"=== PAC file (auto proxy config) ===\n{pac.stdout.strip()}")

    # Full proxy summary for all services
    all_proxies = run_command(
        "scutil --proxy 2>/dev/null"
    )
    sections.append(
        "=== System proxy configuration (scutil --proxy) ===\n"
        + (all_proxies.stdout.strip() or "(none configured)")
    )

    # ── Environment proxy variables ───────────────────────────────────────────
    env_proxy = run_command(
        "env 2>/dev/null | grep -iE '^(HTTP_PROXY|HTTPS_PROXY|ALL_PROXY|NO_PROXY|http_proxy|https_proxy|all_proxy)='"
    )
    sections.append(
        "=== Proxy environment variables ===\n"
        + (env_proxy.stdout.strip() or "(none set)")
    )

    # ── VPN configuration profiles ────────────────────────────────────────────
    vpn_profiles = run_command(
        "profiles -C -v 2>/dev/null | grep -A5 -i 'vpn\\|ipsec\\|ikev2' | head -40"
    )
    if vpn_profiles.stdout.strip():
        sections.append(
            f"=== VPN configuration profiles ===\n{vpn_profiles.stdout.strip()}"
        )

    # macOS built-in VPN connections
    vpn_services = run_command(
        "networksetup -listallnetworkservices 2>/dev/null | "
        "grep -iE 'vpn|ipsec|pptp|l2tp|ikev2|wireguard'"
    )
    if vpn_services.stdout.strip():
        sections.append(
            f"=== VPN network services ===\n{vpn_services.stdout.strip()}"
        )

    # ── WireGuard ─────────────────────────────────────────────────────────────
    wg_configs = run_command(
        "find ~/.config/wireguard/ /etc/wireguard/ /usr/local/etc/wireguard/ "
        "-name '*.conf' 2>/dev/null | head -10"
    )
    if wg_configs.stdout.strip():
        sections.append(
            f"=== WireGuard config files ===\n{wg_configs.stdout.strip()}"
        )
        for wg_conf in wg_configs.stdout.splitlines()[:3]:
            content = run_command(f"cat '{wg_conf.strip()}' 2>/dev/null | grep -v 'PrivateKey\\|PresharedKey'")
            if content.stdout.strip():
                sections.append(f"--- {wg_conf.strip()} (private keys redacted) ---\n{content.stdout.strip()}")

    # ── OpenVPN configs ───────────────────────────────────────────────────────
    ovpn_files = run_command(
        "find ~ /etc /usr/local/etc -maxdepth 5 -name '*.ovpn' -o -name '*.conf' "
        "2>/dev/null | xargs grep -l 'remote\\|client' 2>/dev/null | head -10",
        timeout=10,
    )
    if ovpn_files.stdout.strip():
        sections.append(
            f"=== OpenVPN config files ===\n{ovpn_files.stdout.strip()}"
        )

    # ── Enterprise VPN clients ────────────────────────────────────────────────
    enterprise_vpns = []
    vpn_apps = {
        "Cisco AnyConnect":    "/Applications/Cisco/Cisco AnyConnect Secure Mobility Client.app",
        "GlobalProtect":       "/Applications/GlobalProtect.app",
        "Pulse Secure":        "/Applications/Pulse Secure.app",
        "Tunnelblick":         "/Applications/Tunnelblick.app",
        "OpenVPN Connect":     "/Applications/OpenVPN Connect/OpenVPN Connect.app",
        "NordVPN":             "/Applications/NordVPN.app",
        "ExpressVPN":          "/Applications/ExpressVPN.app",
        "Mullvad":             "/Applications/Mullvad VPN.app",
        "Tailscale":           "/Applications/Tailscale.app",
        "ZeroTier One":        "/Applications/ZeroTier One.app",
    }
    for vpn_name, vpn_path in vpn_apps.items():
        check = run_command(f"ls '{vpn_path}' 2>/dev/null | head -1")
        if check.stdout.strip():
            enterprise_vpns.append(f"  ✓ {vpn_name}")

    # Also check running VPN processes
    vpn_procs = run_command(
        "ps aux 2>/dev/null | grep -iE 'anyconnect|globalprotect|pulse|tunnelblick|openvpn|tailscale|zerotier|wireguard' "
        "| grep -v grep | head -10"
    )
    if vpn_procs.stdout.strip():
        enterprise_vpns.append(f"Running VPN processes:\n{vpn_procs.stdout.strip()}")

    if enterprise_vpns:
        sections.append(
            "=== VPN client applications ===\n"
            + "\n".join(enterprise_vpns)
        )

    # ── Tailscale ─────────────────────────────────────────────────────────────
    tailscale_status = run_command("tailscale status 2>/dev/null | head -20")
    if tailscale_status.stdout.strip():
        sections.append(
            f"=== Tailscale network status ===\n{tailscale_status.stdout.strip()}"
        )

    # ── Traffic interception tools ────────────────────────────────────────────
    interception_tools = []
    for tool_name, check_cmd in [
        ("Charles Proxy",  "ls /Applications/Charles.app 2>/dev/null"),
        ("Proxyman",       "ls /Applications/Proxyman.app 2>/dev/null"),
        ("mitmproxy",      "which mitmproxy mitmdump 2>/dev/null"),
        ("Burp Suite",     "ls /Applications/Burp\\ Suite\\ Community\\ Edition.app /Applications/Burp\\ Suite\\ Professional.app 2>/dev/null"),
        ("Fiddler",        "ls /Applications/Fiddler\\ Everywhere.app 2>/dev/null"),
        ("Wireshark",      "ls /Applications/Wireshark.app 2>/dev/null"),
    ]:
        result = run_command(check_cmd)
        if result.stdout.strip():
            interception_tools.append(f"  ✓ {tool_name}")

    if interception_tools:
        sections.append(
            "=== Traffic interception / analysis tools installed ===\n"
            + "\n".join(interception_tools)
        )

    # ── SSH SOCKS proxies ─────────────────────────────────────────────────────
    ssh_proxies = run_command(
        "grep -inE 'DynamicForward|LocalForward|ProxyJump|ProxyCommand' "
        "~/.ssh/config 2>/dev/null"
    )
    if ssh_proxies.stdout.strip():
        sections.append(
            "=== SSH tunnel/proxy directives in ~/.ssh/config ===\n"
            + ssh_proxies.stdout.strip()
        )

    return "\n\n".join(sections)
