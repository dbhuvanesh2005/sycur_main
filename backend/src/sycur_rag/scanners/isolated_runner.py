from __future__ import annotations

import subprocess
from pathlib import Path
from uuid import uuid4


def run_isolated_command(
    *,
    workspace: str | Path,
    image: str,
    command: list[str],
    timeout_seconds: int = 60,
) -> subprocess.CompletedProcess[str]:
    """
    Execute a trusted scanner command inside
    a restricted Colima/Docker container.

    Only the supplied workspace is mounted.
    GitHub credentials are not forwarded.
    """

    root = Path(workspace).expanduser().resolve(strict=True)

    if not root.is_dir():
        raise ValueError("Workspace must be a directory.")

    if any(char in str(root) for char in (",", "\n", "\r")):
        raise ValueError("Unsupported workspace path.")

    if not isinstance(image, str) or not image.strip():
        raise ValueError("Container image is required.")

    if image.startswith("-"):
        raise ValueError("Invalid container image.")

    if (
        not isinstance(command, list)
        or not command
        or not all(
            isinstance(arg, str) and arg
            for arg in command
        )
    ):
        raise ValueError("Command must be a non-empty list.")

    if type(timeout_seconds) is not int or timeout_seconds <= 0:
        raise ValueError("Invalid timeout.")

    container_name = f"sycur-scan-{uuid4().hex[:16]}"

    docker_command = [
        "docker",
        "--context", "colima",
        "run",
        "--rm",
        "--name", container_name,
        "--pull", "never",

        # Isolation
        "--network", "none",
        "--read-only",
        "--cap-drop", "ALL",
        "--security-opt", "no-new-privileges=true",
        "--user", "65534:65534",

        # Resource limits
        "--cpus", "1",
        "--memory", "512m",
        "--memory-swap", "512m",
        "--pids-limit", "64",

        # Read-only workspace
        "--mount",
        f"type=bind,source={root},target=/workspace,readonly",

        # Restricted temporary storage
        "--tmpfs",
        "/tmp:rw,noexec,nosuid,size=64m",

        "--workdir", "/workspace",
        "--env", "HOME=/tmp",
        "--env", "PYTHONDONTWRITEBYTECODE=1",

        image,
        *command,
    ]

    try:
        result = subprocess.run(
            docker_command,
            capture_output=True,
            text=True,
            timeout=timeout_seconds,
            check=False,
        )

        if result.returncode != 0:
            raise RuntimeError(
                "Isolated command failed: "
                + result.stderr[-2000:]
            )

        return result

    except subprocess.TimeoutExpired as exc:
        raise RuntimeError(
            "Isolated scanner exceeded its timeout."
        ) from exc

    finally:
        # Best-effort cleanup, including after timeouts.
        try:
            subprocess.run(
                [
                    "docker",
                    "--context", "colima",
                    "rm", "-f", container_name,
                ],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                timeout=10,
                check=False,
            )
        except (OSError, subprocess.TimeoutExpired):
            pass
