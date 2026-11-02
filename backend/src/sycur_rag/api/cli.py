"""Command-line entry point for the SYCUR API server."""

import uvicorn


def main() -> None:
    uvicorn.run(
        "sycur_rag.api.main:app",
        host="127.0.0.1",
        port=8000,
        reload=True,
    )
