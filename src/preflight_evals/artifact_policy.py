"""Tracked-file policy for private and raw artifact roots."""

from __future__ import annotations

import subprocess
from pathlib import Path, PurePosixPath
from typing import Literal

type ArtifactRootClass = Literal["ephemeral", "resumable", "raw_traces", "aggregate_reports"]

ALLOWED_CONFIGURED_ROOTS: dict[ArtifactRootClass, tuple[str, ...]] = {
    "ephemeral": (
        "artifacts/repositories",
        "artifacts/worktrees",
        "artifacts/materialized",
        "artifacts/bundles",
        "artifacts/tmp",
    ),
    "resumable": (
        "artifacts/runs",
        "artifacts/requests",
        "artifacts/responses",
        "artifacts/curator-imports",
    ),
    "raw_traces": (
        "artifacts/traces",
        "artifacts/provider-traces",
    ),
    "aggregate_reports": ("reports/aggregate",),
}

FORBIDDEN_TRACKED_PREFIXES = (
    "artifacts/",
    "reports/private/",
    "reports/cases/",
    "reports/per-case/",
    "reports/raw/",
    "credentials/",
    "secrets/",
)


def configured_root_is_allowed(path: PurePosixPath, root_class: ArtifactRootClass) -> bool:
    """Return whether *path* stays within an approved root for its retention class."""

    candidate = path.as_posix()
    return any(
        candidate == prefix or candidate.startswith(f"{prefix}/")
        for prefix in ALLOWED_CONFIGURED_ROOTS[root_class]
    )


def tracked_paths(repository: Path) -> tuple[str, ...]:
    """Return tracked paths without shell expansion or file-content access."""

    result = subprocess.run(
        ["git", "ls-files", "-z"],
        cwd=repository,
        check=True,
        capture_output=True,
    )
    return tuple(path for path in result.stdout.decode("utf-8").split("\0") if path)


def forbidden_paths(paths: tuple[str, ...]) -> tuple[str, ...]:
    """Select paths that violate the tracked-artifact invariant."""

    return tuple(
        path
        for path in paths
        if any(path.startswith(prefix) for prefix in FORBIDDEN_TRACKED_PREFIXES)
    )
