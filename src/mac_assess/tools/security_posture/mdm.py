"""Enterprise MDM / Active Directory enrollment assessment.

An MDM-enrolled device is both protected and a risk: if the MDM infrastructure
or its management account credentials are compromised, an attacker gains
lateral movement to every enrolled device in the organisation.

MITRE ATT&CK: T1078 (Valid Accounts), T1072 (Software Deployment Tools)
Reference: WithSecure "Jamfing for Joy: Attacking macOS in Enterprise"
"""

from __future__ import annotations

from langchain_core.tools import tool

from ..base import run_command


@tool
def find_mdm_enrollment() -> str:
    """Find MDM enrollment, Active Directory membership, and management profiles.

    Checks for:
    - MDM enrollment status (profiles status -type enrollment)
    - All installed configuration profiles (could push malicious configs)
    - Active Directory / domain membership (dsconfigad)
    - JAMF binary presence and version (shared management account risk)
    - Management account names in the local directory (fleet-wide credentials)
    - Bootstrap token enrollment (MDM can escrow FileVault recovery keys)
    - Enterprise certificate authorities (MITM potential)

    Risk: Shared management account credentials on JAMF-managed machines can
    allow lateral SSH movement to every device in the fleet.

    Returns:
        MDM enrollment state, installed profiles, and enterprise directory details.
    """
    sections = []

    # ── MDM enrollment ────────────────────────────────────────────────────────
    enrollment = run_command("profiles status -type enrollment 2>/dev/null")
    sections.append(
        f"=== MDM Enrollment Status ===\n"
        + (enrollment.output.strip() or "(profiles command unavailable or not enrolled)")
    )

    # Bootstrap token (MDM can use this to unlock FileVault remotely)
    bootstrap = run_command("profiles status -type bootstraptoken 2>/dev/null")
    if bootstrap.output.strip():
        sections.append(f"=== Bootstrap Token Status ===\n{bootstrap.output.strip()}")

    # ── Installed configuration profiles ─────────────────────────────────────
    profiles = run_command("profiles -C -v 2>/dev/null | head -80")
    sections.append(
        f"=== Installed Configuration Profiles ===\n"
        + (profiles.output.strip() or "(none installed or command unavailable)")
    )

    # ── Active Directory ──────────────────────────────────────────────────────
    ad_status = run_command("dsconfigad -show 2>/dev/null")
    sections.append(
        f"=== Active Directory Membership ===\n"
        + (ad_status.output.strip() or "(not joined to Active Directory)")
    )

    # ── JAMF ──────────────────────────────────────────────────────────────────
    jamf_bin = run_command("which jamf 2>/dev/null || ls /usr/local/bin/jamf 2>/dev/null")
    jamf_ver = run_command("/usr/local/bin/jamf version 2>/dev/null")
    jamf_server = run_command(
        "defaults read /Library/Preferences/com.jamfsoftware.jamf.plist jss_url 2>/dev/null"
    )
    sections.append(
        f"=== JAMF Pro Agent ===\n"
        f"Binary:  {jamf_bin.output.strip() or '(not found)'}\n"
        f"Version: {jamf_ver.output.strip() or '(n/a)'}\n"
        f"JSS URL: {jamf_server.output.strip() or '(n/a)'}"
    )

    # ── Management accounts in local directory ────────────────────────────────
    # These shared accounts are the primary lateral movement risk
    all_users = run_command("dscl . list /Users | grep -v '^_' | grep -v '^daemon\\|^nobody\\|^root'")
    mgmt_accounts = run_command(
        "dscl . list /Users | grep -iv '^_' | grep -i 'manage\\|admin\\|jamf\\|mdm\\|it\\|corp'"
    )
    sections.append(
        f"=== Local user accounts ===\n{all_users.output.strip() or '(could not list)'}"
    )
    if mgmt_accounts.output.strip():
        sections.append(
            f"=== Possible management accounts (⚠ may be shared across fleet) ===\n"
            + mgmt_accounts.output.strip()
        )

    # ── Enterprise / corporate CAs ────────────────────────────────────────────
    # Installed CAs can enable TLS MITM on corporate networks
    corp_certs = run_command(
        "security find-certificate -a /Library/Keychains/System.keychain 2>/dev/null"
        " | grep 'labl' | grep -iv 'apple\\|digicert\\|comodo\\|let.s encrypt\\|globalsign\\|entrust\\|verisign' | head -20"
    )
    if corp_certs.output.strip():
        sections.append(
            f"=== Non-standard CA certificates in System keychain (⚠ MITM potential) ===\n"
            + corp_certs.output.strip()
        )

    # ── Other MDM solutions ───────────────────────────────────────────────────
    other_mdm = run_command(
        "ls /Library/Application\\ Support/JAMF/ 2>/dev/null;"
        "ls /Library/Application\\ Support/Mosyle/ 2>/dev/null;"
        "ls /Library/Kandji/ 2>/dev/null;"
        "ls /Library/Application\\ Support/com.microsoft.intune/ 2>/dev/null;"
        "ls /Library/Application\\ Support/Addigy/ 2>/dev/null"
    )
    if other_mdm.output.strip():
        sections.append(f"=== Other MDM agent files detected ===\n{other_mdm.output.strip()}")

    return "\n\n".join(sections)
