"""macOS TCC (Transparency, Consent & Control) permission database inspection.

TCC controls which processes can access privacy-sensitive resources.
An app granted Accessibility access is functionally a keylogger.
An app with Full Disk Access can read any file on the system.
Malware (e.g. XCSSET) specifically targets TCC to silently gain these rights.

MITRE ATT&CK: T1548.006 (TCC Manipulation), T1056 (Input Capture),
              T1113 (Screen Capture), T1123 (Audio Capture), T1125 (Video Capture)
"""

from __future__ import annotations

from langchain_core.tools import tool

from ..base import run_command


# Human-readable labels for TCC service identifiers
_SERVICE_LABELS = {
    "kTCCServiceAccessibility": "Accessibility (⚠ keylogging / UI control)",
    "kTCCServiceSystemPolicyAllFiles": "Full Disk Access (⚠ read any file)",
    "kTCCServiceScreenCapture": "Screen Recording",
    "kTCCServiceCamera": "Camera",
    "kTCCServiceMicrophone": "Microphone",
    "kTCCServiceLocation": "Location Services",
    "kTCCServiceAddressBook": "Contacts",
    "kTCCServiceCalendar": "Calendar",
    "kTCCServicePhotos": "Photos",
    "kTCCServicePhotosAdd": "Photos (add only)",
    "kTCCServiceReminders": "Reminders",
    "kTCCServiceDeveloperTool": "Developer Tools (debugging/injection)",
    "kTCCServiceAppleEvents": "AppleScript / Automation",
    "kTCCServiceSystemPolicySysAdminFiles": "Admin Files",
    "kTCCServiceSystemPolicyNetworkVolumes": "Network Volumes",
    "kTCCServiceSystemPolicyRemovableVolumes": "Removable Volumes",
    "kTCCServiceSpeechRecognition": "Speech Recognition",
    "kTCCServiceListenEvent": "Input Monitoring (⚠ keylogging)",
    "kTCCServiceMediaLibrary": "Media Library",
    "kTCCServiceBluetoothAlways": "Bluetooth",
    "kTCCServiceFocusStatus": "Focus Status",
    "kTCCServiceUserAvailability": "User Availability",
}

_HIGH_RISK = {
    "kTCCServiceAccessibility",
    "kTCCServiceSystemPolicyAllFiles",
    "kTCCServiceScreenCapture",
    "kTCCServiceListenEvent",
    "kTCCServiceDeveloperTool",
}

_QUERY = (
    "SELECT service, client, client_type, auth_value, auth_reason "
    "FROM access WHERE auth_value = 2 "  # 2 = Allowed
    "ORDER BY service, client;"
)


def _read_tcc_db(db_path: str) -> str:
    result = run_command(
        f'sqlite3 -separator "|" "{db_path}" "{_QUERY}" 2>/dev/null',
        timeout=10,
    )
    return result.stdout.strip()


def _format_tcc_output(raw: str, label: str) -> str:
    if not raw:
        return f"=== {label} ===\n(not readable or no grants found)"

    lines = raw.splitlines()
    high_risk_rows: list[str] = []
    other_rows: list[str] = []

    for line in lines:
        parts = line.split("|")
        if len(parts) < 2:
            continue
        service = parts[0].strip()
        client = parts[1].strip()
        friendly = _SERVICE_LABELS.get(service, service)
        row = f"  {client:50s}  {friendly}"
        if service in _HIGH_RISK:
            high_risk_rows.append("⚠ " + row)
        else:
            other_rows.append("  " + row)

    out_parts = [f"=== {label} ==="]
    if high_risk_rows:
        out_parts.append("HIGH-RISK grants:")
        out_parts.extend(high_risk_rows)
    if other_rows:
        out_parts.append("Other grants:")
        out_parts.extend(other_rows)
    return "\n".join(out_parts)


@tool
def find_tcc_permissions() -> str:
    """Inspect the macOS TCC database for dangerous permission grants.

    Reads both the system TCC database (/Library/Application Support/com.apple.TCC/TCC.db)
    and the user TCC database (~/Library/.../TCC.db) to identify which processes
    have been granted sensitive permissions.

    High-risk grants to watch for:
    - Accessibility: allows simulating keyboard/mouse input; functional keylogger
    - Full Disk Access: bypasses file-level protections; reads any file
    - Screen Recording: captures screen contents
    - Input Monitoring (ListenEvent): captures all keyboard input system-wide
    - Developer Tools: allows debugging and code injection into other processes

    Used by malware: XCSSET manipulated TCC to silently acquire permissions.

    Returns:
        List of processes with each TCC permission grant, highlighting high-risk entries.
    """
    sections = []

    # User TCC database (readable without elevated permissions)
    user_db = run_command("echo ~/Library/Application\\ Support/com.apple.TCC/TCC.db").stdout.strip()
    user_raw = _read_tcc_db(user_db)
    sections.append(_format_tcc_output(user_raw, "User TCC Database"))

    # System TCC database (requires Full Disk Access or root)
    system_raw = _read_tcc_db("/Library/Application Support/com.apple.TCC/TCC.db")
    sections.append(_format_tcc_output(system_raw, "System TCC Database"))

    # Also check if TCC itself has been disabled (SIP bypass indicator)
    tcc_disabled = run_command(
        "defaults read /Library/Preferences/com.apple.security_tcc.plist 2>/dev/null | head -5"
    )
    if tcc_disabled.stdout.strip():
        sections.append(f"=== TCC preferences override ===\n{tcc_disabled.stdout.strip()}")

    return "\n\n".join(sections)
