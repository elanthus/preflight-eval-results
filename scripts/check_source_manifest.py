"""Verify exported provenance, public replay assets and historical report bytes."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]


def _check_files(root: Path, entries: list[dict[str, Any]], seen: set[str]) -> None:
    for entry in entries:
        path = entry["path"]
        resolved = (root / path).resolve()
        if not resolved.is_relative_to(root) or path in seen:
            raise SystemExit(f"invalid or duplicate manifest path: {path}")
        seen.add(path)
        actual = hashlib.sha256(resolved.read_bytes()).hexdigest()
        if actual != entry["sha256"]:
            raise SystemExit(f"manifest digest mismatch: {path}")


def verify(root: Path = ROOT) -> int:
    root = root.resolve()
    manifest = json.loads((root / "source-manifest.json").read_text())
    if manifest["version"] != 2:
        raise SystemExit("unsupported source manifest version")
    seen: set[str] = set()
    _check_files(root, manifest["files"], seen)
    _check_files(root, manifest["public_files"], seen)
    # A removed entry must not silently turn a shipped asset into an unchecked file.
    required = {
        path.relative_to(root).as_posix()
        for pattern in (
            "src/**/*.py",
            "schemas/**/*.json",
            "examples/**/*.json",
            "scripts/*.py",
            "tests/**/*.py",
            "tests/fixtures/**/*.json",
            "tests/fixtures/**/*.md",
        )
        for path in root.glob(pattern)
    }
    if missing := required - seen:
        raise SystemExit(f"unlisted implementation assets: {', '.join(sorted(missing))}")
    historical = json.loads((root / "methods/historical-artifacts.json").read_text())
    _check_files(root, historical["files"], set())
    return len(seen)


def main() -> None:
    print(f"Verified {verify()} implementation assets and unchanged historical reports")


if __name__ == "__main__":
    main()
