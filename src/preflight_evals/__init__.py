"""Disclosure-safe evaluation tooling for Agentic Preflight."""

from importlib.metadata import PackageNotFoundError, version

try:
    __version__ = version("preflight-eval-reference")
except PackageNotFoundError:  # pragma: no cover - source checkout without installation
    __version__ = "0+unknown"

__all__ = ["__version__"]
