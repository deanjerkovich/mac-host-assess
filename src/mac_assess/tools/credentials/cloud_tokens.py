"""Cloud service account key file and token cache discovery.

GCP service account JSON key files are full long-lived credentials that bypass
MFA and allow impersonation of service accounts with potentially broad IAM
permissions. Azure service principals similarly. These key files are routinely
left in project directories, home directories, and developer laptops.

MITRE ATT&CK: T1552.001 (Unsecured Credentials: Credentials In Files),
              T1078.004 (Valid Accounts: Cloud Accounts)
"""

from __future__ import annotations

from langchain_core.tools import tool

from ..base import run_command


@tool
def find_cloud_service_account_keys() -> str:
    """Find GCP service account JSON keys, Azure service principals, and cloud token caches.

    Discovers:
    - GCP service account key files (*.json containing 'private_key' + 'client_email')
      — found anywhere in the home directory tree
    - GCP Application Default Credentials (~/.config/gcloud/application_default_credentials.json)
    - GCP CLI token cache and active account (~/.config/gcloud/)
    - Azure CLI token cache (~/.azure/accessTokens.json, ~/.azure/msal_token_cache.json)
    - Azure service principal credential files
    - AWS credential files with non-default profiles (secrets already covered
      by find_aws_credentials, but this checks for additional patterns)
    - DigitalOcean API tokens (~/.config/doctl/config.yaml)
    - Linode / Akamai CLI tokens
    - Cloudflare API tokens in config files
    - Vault token files (~/.vault-token)

    Returns:
        Cloud service account key files, token caches, and credential locations.
    """
    sections = []

    # ── GCP service account JSON key files ────────────────────────────────────
    # Service account key JSON files have specific fields
    gcp_keys = run_command(
        "find ~ -maxdepth 7 -name '*.json' "
        "-not -path '*/.git/*' "
        "-not -path '*/node_modules/*' "
        "-not -path '*/Library/Caches/*' "
        "2>/dev/null | head -100",
        timeout=20,
    )
    sa_hits: list[str] = []
    if gcp_keys.stdout.strip():
        for json_file in gcp_keys.stdout.splitlines():
            json_file = json_file.strip()
            if not json_file:
                continue
            # Check if it looks like a service account key
            check = run_command(
                f"python3 -c \"import json; d=json.load(open('{json_file}')); "
                f"print(d.get('type',''), d.get('project_id',''), "
                f"d.get('client_email','')[:50])\" 2>/dev/null"
            )
            output = check.stdout.strip()
            if output and "service_account" in output:
                sa_hits.append(f"  ⚠ {json_file}: {output}")

    sections.append(
        "=== GCP service account key files ===\n"
        + ("\n".join(sa_hits) if sa_hits else "(none found — searched *.json in home tree)")
    )

    # ── GCP Application Default Credentials ──────────────────────────────────
    adc = run_command(
        "cat ~/.config/gcloud/application_default_credentials.json 2>/dev/null"
    )
    if adc.stdout.strip():
        # Parse type but don't show the actual token
        adc_type = run_command(
            "python3 -c \"import json; d=json.load(open('\" "
            "\"$HOME/.config/gcloud/application_default_credentials.json')); "
            "print('type:', d.get('type','?'), '| account:', d.get('client_email', d.get('account','?')))\" "
            "2>/dev/null"
        )
        sections.append(
            "=== GCP Application Default Credentials ===\n"
            f"File present: ~/.config/gcloud/application_default_credentials.json\n"
            + (adc_type.stdout.strip() or f"Contents: {adc.stdout[:200].strip()}")
        )

    # ── GCP CLI config ────────────────────────────────────────────────────────
    gcloud_account = run_command("gcloud config get-value account 2>/dev/null")
    gcloud_project = run_command("gcloud config get-value project 2>/dev/null")
    gcloud_props = run_command("cat ~/.config/gcloud/properties 2>/dev/null")
    if gcloud_account.stdout.strip() or gcloud_props.stdout.strip():
        sections.append(
            "=== GCP CLI (gcloud) configuration ===\n"
            f"Active account: {gcloud_account.stdout.strip() or '(not set)'}\n"
            f"Active project: {gcloud_project.stdout.strip() or '(not set)'}\n"
            + (f"~/.config/gcloud/properties:\n{gcloud_props.stdout.strip()}" if gcloud_props.stdout.strip() else "")
        )

    # ── GCP service account impersonation configs ─────────────────────────────
    gcloud_configs = run_command("ls ~/.config/gcloud/configurations/ 2>/dev/null")
    if gcloud_configs.stdout.strip():
        sections.append(
            f"=== GCP named configurations ===\n{gcloud_configs.stdout.strip()}"
        )

    # ── Azure CLI token cache ─────────────────────────────────────────────────
    azure_cache = run_command("ls ~/.azure/ 2>/dev/null")
    if azure_cache.stdout.strip():
        sections.append(f"=== Azure CLI data (~/.azure/) ===\n{azure_cache.stdout.strip()}")

    # Parse MSAL token cache for account info (not tokens)
    msal = run_command(
        "python3 -c \""
        "import json; d=json.load(open('"
        "$HOME/.azure/msal_token_cache.json')); "
        "accts=d.get('Account',{}); "
        "[print(v.get('username','?'), v.get('environment','?'), v.get('realm','?')) "
        "for v in accts.values()]"
        "\" 2>/dev/null"
    )
    if msal.stdout.strip():
        sections.append(
            f"=== Azure MSAL token cache accounts ===\n{msal.stdout.strip()}"
        )

    # ── Azure service principal env vars ─────────────────────────────────────
    az_sp = run_command(
        "env 2>/dev/null | grep -iE '^(AZURE_CLIENT_ID|AZURE_CLIENT_SECRET|AZURE_TENANT_ID|ARM_CLIENT_SECRET)='"
    )
    if az_sp.stdout.strip():
        sections.append(
            f"=== ⚠ Azure service principal in environment ===\n{az_sp.stdout.strip()}"
        )

    # ── DigitalOcean ──────────────────────────────────────────────────────────
    do_token = run_command(
        "cat ~/.config/doctl/config.yaml 2>/dev/null | grep -E 'access-token|token' | head -5"
    )
    if do_token.stdout.strip():
        sections.append(
            f"=== DigitalOcean CLI token ===\n{do_token.stdout.strip()}"
        )

    # ── Cloudflare ────────────────────────────────────────────────────────────
    cf_token = run_command(
        "cat ~/.config/cloudflare.yaml ~/.config/cloudflare/config.yaml "
        "~/.cloudflare/cloudflare.conf 2>/dev/null | grep -iE 'token|key|api' | head -5"
    )
    if cf_token.stdout.strip():
        sections.append(
            f"=== Cloudflare API token ===\n{cf_token.stdout.strip()}"
        )

    # ── HashiCorp Vault token ─────────────────────────────────────────────────
    vault_token = run_command("cat ~/.vault-token 2>/dev/null")
    vault_addr = run_command("echo $VAULT_ADDR 2>/dev/null")
    if vault_token.stdout.strip():
        tok = vault_token.stdout.strip()
        preview = tok[:12] + "..." if len(tok) > 12 else tok
        sections.append(
            f"=== ⚠ HashiCorp Vault token (~/.vault-token) ===\n"
            f"Token: {preview}\n"
            f"VAULT_ADDR: {vault_addr.stdout.strip() or '(not set)'}"
        )

    # ── Linode CLI ────────────────────────────────────────────────────────────
    linode = run_command("cat ~/.config/linode-cli 2>/dev/null | grep token | head -3")
    if linode.stdout.strip():
        sections.append(f"=== Linode CLI token ===\n{linode.stdout.strip()}")

    return "\n\n".join(sections)
