"""Container and virtualisation environment supply chain risk assessment.

Docker, Kubernetes, and container runtimes are ubiquitous in dev environments.
An attacker with access to Docker can escape to the host, pivot to registries,
inject malicious images, or access cluster secrets stored in the environment.

MITRE ATT&CK: T1611 (Escape to Host), T1552.007 (Container API),
              T1610 (Deploy Container)
"""

from __future__ import annotations

from langchain_core.tools import tool

from ..base import run_command


@tool
def find_container_access() -> str:
    """Assess Docker, container runtime, and cluster access for supply chain risk.

    Checks for:
    - Docker daemon socket access (root-equivalent privilege)
    - Docker context and currently connected daemons
    - Running containers (names, images, exposed ports, mounts)
    - Docker registry credentials in ~/.docker/config.json (registry list only)
    - Docker Swarm membership
    - Podman socket / rootless container runtime
    - containerd / nerdctl access
    - Lima VM instances (macOS container VMs)
    - OrbStack instances
    - Whether the current user is in the 'docker' group

    Returns:
        Container runtime access and configuration details.
    """
    sections = []

    # ── Docker daemon socket ──────────────────────────────────────────────────
    docker_sock = run_command("ls -la /var/run/docker.sock 2>/dev/null")
    sections.append(
        "=== Docker socket (/var/run/docker.sock) ===\n"
        + (docker_sock.stdout.strip() or "(not present — Docker not running or not installed)")
    )

    # ── Docker group membership ───────────────────────────────────────────────
    docker_group = run_command("groups 2>/dev/null | tr ' ' '\\n' | grep docker")
    if docker_group.stdout.strip():
        sections.append(
            "=== ⚠ Current user is in 'docker' group (root-equivalent on Linux) ===\n"
            + docker_group.stdout.strip()
        )

    # ── Docker version and context ────────────────────────────────────────────
    docker_ver = run_command("docker version --format '{{.Server.Version}}' 2>/dev/null")
    docker_ctx = run_command("docker context ls 2>/dev/null")
    if docker_ver.stdout.strip() or docker_ctx.stdout.strip():
        sections.append(
            f"=== Docker daemon ===\n"
            f"Server version: {docker_ver.stdout.strip() or '(unreachable)'}\n"
            + (docker_ctx.stdout.strip() or "")
        )

    # ── Running containers ────────────────────────────────────────────────────
    containers = run_command(
        "docker ps --format 'table {{.Names}}\\t{{.Image}}\\t{{.Ports}}\\t{{.Mounts}}' 2>/dev/null"
    )
    if containers.stdout.strip() and "NAMES" in containers.stdout:
        sections.append(f"=== Running containers ===\n{containers.stdout.strip()}")

    # ── Privileged / dangerous containers ────────────────────────────────────
    privileged = run_command(
        "docker ps -q 2>/dev/null | xargs -I{} docker inspect {} "
        "--format '{{.Name}} privileged={{.HostConfig.Privileged}} "
        "pid={{.HostConfig.PidMode}} network={{.HostConfig.NetworkMode}}' 2>/dev/null | head -20"
    )
    if privileged.stdout.strip():
        sections.append(
            "=== Container security flags (privileged/PID/network mode) ===\n"
            + privileged.stdout.strip()
        )

    # ── Docker images (large attack surface if pushed to registry) ────────────
    images = run_command(
        "docker images --format '{{.Repository}}:{{.Tag}}\\t{{.Size}}' 2>/dev/null | head -30"
    )
    if images.stdout.strip():
        sections.append(f"=== Local Docker images ===\n{images.stdout.strip()}")

    # ── Docker registry credentials (show hostnames only, not tokens) ─────────
    docker_creds = run_command(
        "cat ~/.docker/config.json 2>/dev/null | "
        "python3 -c \"import sys,json; cfg=json.load(sys.stdin); "
        "auths=cfg.get('auths',{}); "
        "[print(k) for k in auths]; "
        "ch=cfg.get('credHelpers',{}); "
        "[print(k,'(credHelper:',v,')') for k,v in ch.items()]\" 2>/dev/null"
    )
    sections.append(
        "=== Docker registry credentials (~/.docker/config.json) ===\n"
        + (docker_creds.stdout.strip() or "(none configured)")
    )

    # ── Docker Swarm ──────────────────────────────────────────────────────────
    swarm = run_command("docker info --format '{{.Swarm.LocalNodeState}}' 2>/dev/null")
    if swarm.stdout.strip() and swarm.stdout.strip() not in ("inactive", ""):
        sections.append(f"=== Docker Swarm state ===\n{swarm.stdout.strip()}")

    # ── Podman ────────────────────────────────────────────────────────────────
    podman = run_command("podman version 2>/dev/null | head -5")
    if podman.stdout.strip():
        podman_ps = run_command("podman ps 2>/dev/null")
        sections.append(
            f"=== Podman runtime ===\n{podman.stdout.strip()}\n"
            + (podman_ps.stdout.strip() or "(no running containers)")
        )

    # ── Lima VMs (macOS container VMs) ────────────────────────────────────────
    lima = run_command("limactl list 2>/dev/null")
    if lima.stdout.strip():
        sections.append(f"=== Lima VMs ===\n{lima.stdout.strip()}")

    # ── OrbStack ──────────────────────────────────────────────────────────────
    orbstack = run_command("orb list 2>/dev/null || orbctl list 2>/dev/null")
    if orbstack.stdout.strip():
        sections.append(f"=== OrbStack instances ===\n{orbstack.stdout.strip()}")

    # ── containerd / nerdctl ─────────────────────────────────────────────────
    nerdctl = run_command("nerdctl ps 2>/dev/null")
    if nerdctl.stdout.strip():
        sections.append(f"=== containerd/nerdctl containers ===\n{nerdctl.stdout.strip()}")

    # ── Docker compose projects ───────────────────────────────────────────────
    compose_projects = run_command(
        "docker compose ls 2>/dev/null || docker-compose ls 2>/dev/null"
    )
    if compose_projects.stdout.strip() and "NAME" in compose_projects.stdout:
        sections.append(f"=== Docker Compose projects ===\n{compose_projects.stdout.strip()}")

    return "\n\n".join(sections)
