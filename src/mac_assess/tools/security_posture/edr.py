"""EDR, AV, and security product detection.

Post-compromise, attackers enumerate security tooling before executing noisy
payloads. Knowing whether CrowdStrike Falcon, SentinelOne, or Jamf Protect
is running determines whether actions will be logged and whether alerts will fire.

This tool also informs the assessment: a machine with mature EDR has a very
different risk profile than one with no endpoint security.

MITRE ATT&CK: T1518.001 (Software Discovery: Security Software Discovery),
              T1562 (Impair Defenses)
"""

from __future__ import annotations

from langchain_core.tools import tool

from ..base import run_command


# Known EDR/AV products: (display_name, process_patterns, directory_hints)
_EDR_PRODUCTS = [
    ("CrowdStrike Falcon",    ["falcond", "falcon-sensor"],  ["/Library/CS", "/opt/CrowdStrike", "/Applications/Falcon.app"]),
    ("SentinelOne",           ["sentineld", "SentinelAgent"], ["/Library/Sentinel", "/Applications/SentinelOne.app"]),
    ("Jamf Protect",          ["jamfProtect", "JamfProtect"], ["/Library/Application Support/JamfProtect"]),
    ("Carbon Black",          ["cbagentd", "cb.app"],        ["/Applications/VMware Carbon Black Cloud.app", "/Applications/Cb Defense.app"]),
    ("Malwarebytes",          ["MBAgent", "HelperTool"],     ["/Applications/Malwarebytes.app", "/Library/Application Support/Malwarebytes"]),
    ("ESET",                  ["eset_daemon", "EsetEdr"],    ["/Library/Application Support/ESET", "/Applications/ESET Endpoint Security.app"]),
    ("Sophos",                ["SophosScanD", "SophosAgent"],  ["/Library/Sophos", "/Applications/Sophos Home.app"]),
    ("BitDefender",           ["BDLDaemon", "EPIntegration"], ["/Library/Bitdefender", "/Applications/Bitdefender.app"]),
    ("Trend Micro",           ["iCoreService", "TmccMac"],   ["/Library/Application Support/TrendMicro", "/Applications/Trend Micro Security.app"]),
    ("Avast",                 ["avastd", "com.avast.av"],    ["/Library/Application Support/Avast", "/Applications/Avast Security.app"]),
    ("Norton/Symantec",       ["SymDaemon", "SIPAgent"],     ["/Library/Application Support/Symantec", "/Applications/Norton 360.app"]),
    ("Elastic Security",      ["elastic-agent", "EPSecurityExtension"], ["/opt/Elastic", "/Library/Elastic"]),
    ("Microsoft Defender",    ["mdatp", "com.microsoft.wdav"],  ["/Library/Application Support/Microsoft/Defender", "/Applications/Microsoft Defender.app"]),
    ("LuLu Firewall",         ["LuLu"],                     ["/Applications/LuLu.app", "/Library/Objective-See"]),
    ("Little Snitch",         ["littlesnitch"],              ["/Applications/Little Snitch.app", "/Library/Little Snitch"]),
    ("Objective-See tools",   ["BlockBlock", "KnockKnock", "TaskExplorer", "RansomWhere"], ["/Applications/BlockBlock.app", "/Applications/KnockKnock.app"]),
]


@tool
def find_edr_and_av_products() -> str:
    """Detect endpoint security products: EDR agents, antivirus, and host-based firewalls.

    Identifies security tooling by checking:
    - Running processes matching known EDR/AV agent names
    - Installed application bundles in /Applications
    - System Extensions registered by security vendors
      (definitive: modern EDRs register as System Extensions on macOS 11+)
    - LaunchDaemon plists for security product services
    - Known installation directories (/Library/CS/, /opt/CrowdStrike/, etc.)

    Products checked: CrowdStrike Falcon, SentinelOne, Jamf Protect,
    Carbon Black, Malwarebytes, ESET, Sophos, BitDefender, Trend Micro,
    Avast, Norton/Symantec, Elastic Security, Microsoft Defender,
    LuLu, Little Snitch, Objective-See tools.

    Returns:
        Detected security products and their running state.
    """
    sections = []
    detected: list[str] = []

    # ── Process-based detection ───────────────────────────────────────────────
    all_procs = run_command("ps aux 2>/dev/null")
    proc_list = all_procs.stdout.lower() if all_procs.stdout else ""

    proc_hits: list[str] = []
    for name, procs, _ in _EDR_PRODUCTS:
        for proc in procs:
            if proc.lower() in proc_list:
                hit = f"  ✓ {name}: process '{proc}' running"
                proc_hits.append(hit)
                if name not in detected:
                    detected.append(name)
                break

    sections.append(
        "=== Running security agent processes ===\n"
        + ("\n".join(proc_hits) if proc_hits else "(none detected)")
    )

    # ── System Extensions (most reliable on macOS 11+) ────────────────────────
    sys_ext = run_command("systemextensionsctl list 2>/dev/null")
    ext_output = sys_ext.stdout if sys_ext.stdout else ""

    ext_hits: list[str] = []
    security_ext_patterns = [
        "crowdstrike", "sentinel", "jamf", "carbonblack", "malwarebytes",
        "eset", "sophos", "bitdefender", "trendmicro", "avast", "symantec",
        "elastic", "microsoft.wdav", "littlesnitch", "lulu", "objective-see",
    ]
    for line in ext_output.splitlines():
        for pattern in security_ext_patterns:
            if pattern in line.lower():
                ext_hits.append(f"  {line.strip()}")
                break

    sections.append(
        "=== Security-related System Extensions ===\n"
        + ("\n".join(ext_hits) if ext_hits else "(none detected)")
    )

    # ── LaunchDaemon scan for security product plists ─────────────────────────
    daemon_list = run_command("ls /Library/LaunchDaemons/ 2>/dev/null")
    daemon_hits: list[str] = []
    if daemon_list.stdout:
        for line in daemon_list.stdout.splitlines():
            l = line.lower()
            if any(p in l for p in ["falcon", "sentinel", "jamfprotect", "carbonblack",
                                     "malwarebytes", "eset", "sophos", "bitdefender",
                                     "trend", "avast", "symantec", "elastic", "mdatp",
                                     "littlesnitch", "lulu"]):
                daemon_hits.append(f"  {line.strip()}")
    if daemon_hits:
        sections.append(
            "=== Security product LaunchDaemons ===\n"
            + "\n".join(daemon_hits)
        )

    # ── Directory-based detection ─────────────────────────────────────────────
    dir_hits: list[str] = []
    for name, _, dirs in _EDR_PRODUCTS:
        for d in dirs:
            result = run_command(f"ls '{d}' 2>/dev/null | head -3")
            if result.stdout.strip():
                dir_hits.append(f"  {name}: {d}")
                if name not in detected:
                    detected.append(name)
                break

    if dir_hits:
        sections.append(
            "=== Security product installation directories ===\n"
            + "\n".join(dir_hits)
        )

    # ── Summary ──────────────────────────────────────────────────────────────
    if detected:
        sections.insert(0,
            "=== ⚠ Security products detected (attacker evasion required) ===\n"
            + "\n".join(f"  • {name}" for name in detected)
        )
    else:
        sections.insert(0, "=== Security product summary ===\n(no EDR/AV products detected — low detection risk)")

    return "\n\n".join(sections)
