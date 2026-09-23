"""Verify that modifying or unlisting shipped replay assets fails the integrity check."""

from __future__ import annotations

import json
import shutil
from pathlib import Path

import pytest

from scripts.check_source_manifest import ROOT, verify


def _copy_assets(destination: Path) -> None:
    for name in ("source-manifest.json", "methods/historical-artifacts.json"):
        path = destination / name
        path.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(ROOT / name, path)
    source = json.loads((ROOT / "source-manifest.json").read_text())
    historical = json.loads((ROOT / "methods/historical-artifacts.json").read_text())
    for entry in source["files"] + source["public_files"] + historical["files"]:
        path = destination / entry["path"]
        path.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(ROOT / entry["path"], path)


@pytest.mark.parametrize(
    "asset",
    [
        "src/preflight_evals/public_replay.py",
        "examples/synthetic-v1/inputs.json",
        "examples/synthetic-v1/expected.json",
    ],
)
@pytest.mark.parametrize("tamper", ["bytes", "unlist"])
def test_manifest_rejects_replay_asset_drift(tmp_path: Path, asset: str, tamper: str) -> None:
    _copy_assets(tmp_path)
    verify(tmp_path)
    if tamper == "bytes":
        with (tmp_path / asset).open("ab") as stream:
            stream.write(b"\n")
        message = "digest mismatch"
    else:
        path = tmp_path / "source-manifest.json"
        manifest = json.loads(path.read_text())
        manifest["public_files"] = [
            entry for entry in manifest["public_files"] if entry["path"] != asset
        ]
        path.write_text(json.dumps(manifest))
        message = "unlisted implementation assets"
    with pytest.raises(SystemExit, match=message):
        verify(tmp_path)


@pytest.mark.parametrize(
    ("field", "value", "message"),
    [
        ("current_sha256", "0" * 64, "replacement record is stale"),
        ("current_content_digest", "sha256:" + "0" * 64, "replacement content digest is stale"),
    ],
)
def test_manifest_rejects_a_stale_replacement_record(
    tmp_path: Path, field: str, value: str, message: str
) -> None:
    _copy_assets(tmp_path)
    verify(tmp_path)
    path = tmp_path / "methods/historical-artifacts.json"
    historical = json.loads(path.read_text())
    historical["replacements"][0][field] = value
    path.write_text(json.dumps(historical))
    with pytest.raises(SystemExit, match=message):
        verify(tmp_path)


def test_manifest_rejects_a_replacement_whose_report_json_is_unpinned(tmp_path: Path) -> None:
    _copy_assets(tmp_path)
    path = tmp_path / "methods/historical-artifacts.json"
    historical = json.loads(path.read_text())
    report = Path(historical["replacements"][0]["path"]).with_suffix(".json").as_posix()
    historical["files"] = [entry for entry in historical["files"] if entry["path"] != report]
    path.write_text(json.dumps(historical))
    # The JSON stays on disk: presence alone must not satisfy the check.
    assert (tmp_path / report).is_file()
    with pytest.raises(SystemExit, match="report JSON is not pinned"):
        verify(tmp_path)
