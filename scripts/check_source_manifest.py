"""Verify the declared bytes of exported source and synthetic test fixtures."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def main() -> None:
    manifest = json.loads((ROOT / "source-manifest.json").read_text())
    seen: set[str] = set()
    for entry in manifest["files"]:
        path = entry["path"]
        resolved = (ROOT / path).resolve()
        if not resolved.is_relative_to(ROOT) or path in seen:
            raise SystemExit(f"invalid or duplicate manifest path: {path}")
        seen.add(path)
        actual = hashlib.sha256(resolved.read_bytes()).hexdigest()
        if actual != entry["sha256"]:
            raise SystemExit(f"export digest mismatch: {path}")
    historical = json.loads((ROOT / "methods/historical-artifacts.json").read_text())
    for entry in historical["files"]:
        actual = hashlib.sha256((ROOT / entry["path"]).read_bytes()).hexdigest()
        if actual != entry["sha256"]:
            raise SystemExit(f"historical artifact changed: {entry['path']}")
    print(f"Verified {len(seen)} exported files and unchanged historical reports")


if __name__ == "__main__":
    main()
