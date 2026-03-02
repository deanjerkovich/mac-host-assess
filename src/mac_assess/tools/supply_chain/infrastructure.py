"""Infrastructure write-access discovery for supply chain assessment.

Identifies credentials and authenticated sessions that could let an attacker
modify cloud infrastructure, deploy to Kubernetes clusters, trigger CI/CD
pipelines, or alter IaC configurations — enabling supply chain compromise
beyond just injecting code.
"""

from __future__ import annotations

from langchain_core.tools import tool

from ..base import run_command


@tool
def find_infrastructure_write_access() -> str:
    """Find authenticated sessions and credentials for infrastructure systems.

    Checks for active write-capable access to:
    - Kubernetes clusters (kubectl contexts, accessible namespaces)
    - Cloud CLIs with active sessions: AWS (sts get-caller-identity),
      GCP (gcloud auth list), Azure (az account show)
    - Terraform Cloud / HCP tokens (~/.terraform.d/credentials.tfrc.json)
    - Pulumi Cloud tokens (~/.pulumi/credentials.json)
    - Serverless Framework credentials (~/.serverlessrc)
    - CI/CD platform credentials: CircleCI, Heroku, Vercel, Netlify,
      Railway, Fly.io, Render
    - Ansible inventory and configuration files
    - AWS CDK / SST bootstrap artefacts indicating deployed stacks
    - HashiCorp Vault tokens (~/.vault-token)

    Returns:
        Summary of infrastructure access found that could enable
        IaaS changes or CI/CD pipeline manipulation.
    """
    sections = []

    # ── Kubernetes ────────────────────────────────────────────────────────────
    kube_contexts = run_command(
        "kubectl config get-contexts 2>/dev/null", timeout=10
    )
    sections.append(
        f"=== Kubernetes contexts (kubectl) ===\n"
        + (kube_contexts.stdout.strip() or "(kubectl not installed or no contexts)")
    )

    kube_current = run_command(
        "kubectl config current-context 2>/dev/null", timeout=5
    )
    if kube_current.stdout.strip():
        # Check what namespaces are accessible in the current context
        namespaces = run_command(
            "kubectl get namespaces 2>/dev/null | head -20", timeout=10
        )
        sections.append(
            f"=== Kubernetes current context: {kube_current.stdout.strip()} ===\n"
            + (namespaces.stdout.strip() or "(could not list namespaces)")
        )

    helm_repos = run_command("helm repo list 2>/dev/null", timeout=8)
    if helm_repos.stdout.strip():
        sections.append(f"=== Helm chart repositories ===\n{helm_repos.stdout.strip()}")

    # ── Active cloud CLI sessions ─────────────────────────────────────────────
    # AWS — sts get-caller-identity proves an active, usable session
    aws_identity = run_command(
        "aws sts get-caller-identity 2>/dev/null", timeout=15
    )
    sections.append(
        f"=== AWS active session (sts get-caller-identity) ===\n"
        + (aws_identity.stdout.strip() or "(no active session or AWS CLI not installed)")
    )

    # AWS profiles available
    aws_profiles = run_command(
        "aws configure list-profiles 2>/dev/null", timeout=8
    )
    if aws_profiles.stdout.strip():
        sections.append(f"=== AWS profiles ===\n{aws_profiles.stdout.strip()}")

    # GCP
    gcloud_accounts = run_command(
        "gcloud auth list 2>/dev/null", timeout=15
    )
    sections.append(
        f"=== GCP active sessions (gcloud auth list) ===\n"
        + (gcloud_accounts.stdout.strip() or "(no active sessions or gcloud not installed)")
    )

    # Azure
    az_account = run_command(
        "az account show 2>/dev/null", timeout=15
    )
    sections.append(
        f"=== Azure active session (az account show) ===\n"
        + (az_account.stdout.strip() or "(no active session or az CLI not installed)")
    )

    # ── IaC tool tokens ───────────────────────────────────────────────────────
    tf_creds = run_command(
        "cat ~/.terraform.d/credentials.tfrc.json 2>/dev/null | python3 -c "
        "\"import json,sys; d=json.load(sys.stdin); "
        "hosts=list(d.get('credentials',{}).keys()); "
        "print('Terraform Cloud/Enterprise hosts:', hosts)\" 2>/dev/null",
        timeout=5,
    )
    sections.append(
        f"=== Terraform Cloud credentials ===\n"
        + (tf_creds.stdout.strip() or "(~/.terraform.d/credentials.tfrc.json not found)")
    )

    # Find local .tfstate files (shows what infra is managed from this machine)
    tfstate = run_command(
        "find ~ -maxdepth 8 -name 'terraform.tfstate' -not -path '*/.terraform/*' "
        "2>/dev/null | head -20",
        timeout=15,
    )
    if tfstate.stdout.strip():
        sections.append(
            f"=== Terraform state files (infra managed from this machine) ===\n"
            + tfstate.stdout.strip()
        )

    pulumi_creds = run_command(
        "cat ~/.pulumi/credentials.json 2>/dev/null | python3 -c "
        "\"import json,sys; d=json.load(sys.stdin); "
        "print('Pulumi backend:', d.get('current','(none)')); "
        "print('Accounts:', list(d.get('accounts',{}).keys()))\" 2>/dev/null",
        timeout=5,
    )
    sections.append(
        f"=== Pulumi credentials ===\n"
        + (pulumi_creds.stdout.strip() or "(~/.pulumi/credentials.json not found)")
    )

    serverless = run_command("cat ~/.serverlessrc 2>/dev/null | head -10", timeout=5)
    if serverless.stdout.strip():
        sections.append(f"=== Serverless Framework credentials ===\n{serverless.stdout.strip()}")

    vault_token = run_command("cat ~/.vault-token 2>/dev/null", timeout=5)
    if vault_token.stdout.strip():
        sections.append(
            f"=== HashiCorp Vault token ===\n"
            f"Token present: {vault_token.stdout.strip()[:8]}... (truncated)"
        )

    # ── CI/CD platform credentials ────────────────────────────────────────────
    circleci = run_command("cat ~/.circleci/cli.yml 2>/dev/null", timeout=5)
    sections.append(
        f"=== CircleCI CLI credentials ===\n"
        + (circleci.stdout.strip() or "(not found)")
    )

    heroku = run_command(
        "cat ~/.netrc 2>/dev/null | grep -A2 'heroku'", timeout=5
    )
    sections.append(
        f"=== Heroku credentials (~/.netrc) ===\n"
        + (heroku.stdout.strip() or "(not found)")
    )

    vercel = run_command(
        # Vercel CLI stores auth in different locations depending on version
        "cat ~/.local/share/com.vercel.cli/auth.json 2>/dev/null"
        " || cat ~/.config/configstore/update-notifier-vercel.json 2>/dev/null | head -5",
        timeout=5,
    )
    if vercel.stdout.strip():
        sections.append(f"=== Vercel credentials ===\n{vercel.stdout.strip()[:200]}")

    netlify = run_command(
        "cat ~/.netlify/config.json 2>/dev/null || cat ~/.config/netlify/config.json 2>/dev/null | head -10",
        timeout=5,
    )
    if netlify.stdout.strip():
        sections.append(f"=== Netlify credentials ===\n{netlify.stdout.strip()[:200]}")

    fly_config = run_command("cat ~/.fly/config.yml 2>/dev/null | head -5", timeout=5)
    if fly_config.stdout.strip():
        sections.append(f"=== Fly.io credentials ===\n{fly_config.stdout.strip()[:200]}")

    railway = run_command(
        "cat ~/.railway/config.json 2>/dev/null | head -5", timeout=5
    )
    if railway.stdout.strip():
        sections.append(f"=== Railway credentials ===\n{railway.stdout.strip()[:200]}")

    # ── Ansible ───────────────────────────────────────────────────────────────
    ansible_cfg = run_command(
        "find ~ -maxdepth 5 -name 'ansible.cfg' 2>/dev/null | head -5", timeout=10
    )
    ansible_inventory = run_command(
        "find ~ -maxdepth 5 -name 'inventory' -o -name 'hosts.ini' -o -name 'inventory.yml' 2>/dev/null | head -5",
        timeout=10,
    )
    if ansible_cfg.stdout.strip() or ansible_inventory.stdout.strip():
        sections.append(
            f"=== Ansible configuration and inventory files ===\n"
            f"Configs: {ansible_cfg.stdout.strip() or '(none)'}\n"
            f"Inventory: {ansible_inventory.stdout.strip() or '(none)'}"
        )

    # ── AWS CDK / SST ─────────────────────────────────────────────────────────
    cdk_stacks = run_command(
        "find ~ -maxdepth 6 -name 'cdk.json' -not -path '*node_modules*' 2>/dev/null | head -10",
        timeout=10,
    )
    if cdk_stacks.stdout.strip():
        sections.append(
            f"=== AWS CDK projects (use AWS credentials above) ===\n"
            + cdk_stacks.stdout.strip()
        )

    return "\n\n".join(sections)
