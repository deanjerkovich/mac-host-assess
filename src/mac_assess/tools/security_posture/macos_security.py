"""macOS host security configuration assessment.

Checks the core macOS security controls that determine whether an attacker
can persist, escalate, or bypass protections. A disabled or degraded control
here undermines many other defences.
"""

from __future__ import annotations

from langchain_core.tools import tool

from ..base import run_command


@tool
def get_macos_security_config() -> str:
    """Check macOS security configuration: SIP, Gatekeeper, FileVault, Firewall, XProtect.

    Assesses the state of macOS's core security controls:
    - System Integrity Protection (SIP) — if disabled, TCC and many other
      protections can be bypassed trivially (T1562.010)
    - Gatekeeper — controls execution of unsigned/unnotarised code (T1553.001)
    - FileVault — full-disk encryption; if off, physical access = data access
    - Application Firewall — inbound connection filtering
    - XProtect / MRT — Apple's built-in malware signatures
    - Automatic security updates — determines exposure window for patches
    - Secure Boot policy (Apple Silicon / T2)

    Returns:
        State of each macOS security control with risk notes.
    """
    sections = []

    # ── SIP ───────────────────────────────────────────────────────────────────
    sip = run_command("csrutil status 2>/dev/null")
    sections.append(f"=== System Integrity Protection (SIP) ===\n{sip.output.strip() or '(could not determine)'}")

    # ── Gatekeeper ────────────────────────────────────────────────────────────
    gk = run_command("spctl --status 2>/dev/null")
    sections.append(f"=== Gatekeeper ===\n{gk.output.strip() or '(could not determine)'}")

    # ── FileVault ─────────────────────────────────────────────────────────────
    fv = run_command("fdesetup status 2>/dev/null")
    sections.append(f"=== FileVault (full-disk encryption) ===\n{fv.output.strip() or '(could not determine)'}")

    # ── Application Firewall ──────────────────────────────────────────────────
    fw_state = run_command(
        "/usr/libexec/ApplicationFirewall/socketfilterfw --getglobalstate 2>/dev/null"
    )
    fw_stealth = run_command(
        "/usr/libexec/ApplicationFirewall/socketfilterfw --getstealthmode 2>/dev/null"
    )
    fw_apps = run_command(
        "/usr/libexec/ApplicationFirewall/socketfilterfw --listapps 2>/dev/null | head -30"
    )
    sections.append(
        f"=== Application Firewall ===\n"
        f"State:   {fw_state.output.strip() or '(could not determine)'}\n"
        f"Stealth: {fw_stealth.output.strip() or '(could not determine)'}\n"
        f"Allowed apps:\n{fw_apps.output.strip() or '(none listed)'}"
    )

    # ── XProtect / MRT ────────────────────────────────────────────────────────
    xprotect_ver = run_command(
        "defaults read /Library/Apple/System/Library/CoreServices/XProtect.bundle"
        "/Contents/Resources/XProtect.meta.plist Version 2>/dev/null"
    )
    mrt = run_command(
        "ls -la /Library/Apple/System/Library/CoreServices/MRT.app 2>/dev/null | head -2"
    )
    sections.append(
        f"=== XProtect / MRT (built-in malware signatures) ===\n"
        f"XProtect version: {xprotect_ver.output.strip() or '(could not read)'}\n"
        f"MRT.app: {mrt.output.strip() or '(not found)'}"
    )

    # ── Automatic Updates ─────────────────────────────────────────────────────
    auto_check = run_command(
        "defaults read /Library/Preferences/com.apple.SoftwareUpdate AutomaticCheckEnabled 2>/dev/null"
    )
    auto_download = run_command(
        "defaults read /Library/Preferences/com.apple.SoftwareUpdate AutomaticDownload 2>/dev/null"
    )
    auto_install = run_command(
        "defaults read /Library/Preferences/com.apple.SoftwareUpdate AutomaticallyInstallMacOSUpdates 2>/dev/null"
    )
    critical_updates = run_command(
        "defaults read /Library/Preferences/com.apple.SoftwareUpdate CriticalUpdateInstall 2>/dev/null"
    )
    sections.append(
        f"=== Automatic Security Updates ===\n"
        f"AutomaticCheckEnabled:            {auto_check.output.strip() or '(not set)'}\n"
        f"AutomaticDownload:                {auto_download.output.strip() or '(not set)'}\n"
        f"AutomaticallyInstallMacOSUpdates: {auto_install.output.strip() or '(not set)'}\n"
        f"CriticalUpdateInstall:            {critical_updates.output.strip() or '(not set)'}"
    )

    # ── Secure Boot (Apple Silicon / T2) ──────────────────────────────────────
    secure_boot = run_command("bputil -d 2>/dev/null | head -20")
    if secure_boot.stdout.strip():
        sections.append(f"=== Secure Boot Policy (bputil) ===\n{secure_boot.stdout.strip()}")
    else:
        # Fallback for Intel without T2
        nvram_sb = run_command(
            "nvram 94b73556-2197-4702-82a8-3e1337dafbfb:AppleSecureBootPolicy 2>/dev/null"
        )
        sections.append(
            f"=== Secure Boot Policy ===\n"
            + (nvram_sb.output.strip() or "(not available on this hardware)")
        )

    # ── macOS version ─────────────────────────────────────────────────────────
    sw_ver = run_command("sw_vers 2>/dev/null")
    sections.append(f"=== macOS Version ===\n{sw_ver.output.strip()}")

    return "\n\n".join(sections)
