"""Command-line entry point for the local API tunnel."""

import os


def main() -> None:
    os.execvp(
        "cloudflared",
        ["cloudflared", "tunnel", "--url", "http://localhost:8000"],
    )


def tailscale_main() -> None:
    os.execvp(
        "tailscale",
        ["tailscale", "funnel", "8000"],
    )
