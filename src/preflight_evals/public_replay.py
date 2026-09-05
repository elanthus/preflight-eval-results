"""Offline, byte-stable replay through the published scorer and statistics engine."""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
from typing import Any, cast

from preflight_evals.canonical import JsonValue, canonical_json_bytes
from preflight_evals.errors import PreflightEvalsError
from preflight_evals.pricing import PriceTable
from preflight_evals.run_models import ExperimentManifest, RunRecord
from preflight_evals.score import score_experiment
from preflight_evals.scorer_models import AdjudicationRecord, GoldRecord
from preflight_evals.statistics import calculate_statistics

METHOD = "synthetic-replay-v1"


def example_directory() -> Path:
    installed = Path(__file__).parent / "example_data"
    if installed.is_dir():
        return installed
    return Path(__file__).resolve().parents[2] / "examples" / "synthetic-v1"


def replay(inputs: bytes) -> bytes:
    document: dict[str, Any] = json.loads(inputs)
    expected_keys = {
        "method_version",
        "synthetic",
        "experiment",
        "run_records",
        "gold_records",
        "adjudications",
        "price_table",
    }
    if set(document) != expected_keys or document["method_version"] != METHOD:
        raise ValueError("unsupported replay contract")
    if document["synthetic"] is not True:
        raise ValueError("this demonstration accepts explicitly synthetic inputs only")
    experiment = ExperimentManifest.from_dict(document["experiment"])
    records = tuple(RunRecord.from_dict(r) for r in document["run_records"])
    gold = tuple(GoldRecord.from_dict(g) for g in document["gold_records"])
    decisions = tuple(AdjudicationRecord.from_dict(a) for a in document["adjudications"])
    scoring = score_experiment(experiment, records, gold, decisions)
    statistics = calculate_statistics(
        experiment,
        scoring,
        records,
        gold,
        PriceTable.from_dict(document["price_table"]),
        provider="synthetic",
    )
    result = {
        "method_version": METHOD,
        "evidence_kind": "synthetic_replay",
        "provider_calls": 0,
        "adjudicator_kind": "scripted_fixture",
        "input_sha256": hashlib.sha256(inputs).hexdigest(),
        "scoring": scoring.to_dict(),
        "statistics": statistics.to_dict(),
    }
    return canonical_json_bytes(cast(JsonValue, result))


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--inputs", type=Path, default=example_directory() / "inputs.json")
    parser.add_argument("--out", type=Path, default=Path("replay-output"))
    parser.add_argument("--check", type=Path, help="require byte equality with this expected JSON")
    args = parser.parse_args(argv)
    try:
        result = replay(args.inputs.read_bytes())
        if args.check is not None and args.check.read_bytes() != result:
            raise ValueError("replay output differs from the expected bytes")
        args.out.mkdir(parents=True, exist_ok=True)
        destination = args.out / "report.json"
        destination.write_bytes(result)
        digest = hashlib.sha256(result).hexdigest()
        (args.out / "SHA256SUMS").write_text(f"{digest}  report.json\n", encoding="ascii")
    except (OSError, ValueError, KeyError, TypeError, PreflightEvalsError) as exc:
        parser.exit(2, f"replay failed: {exc}\n")
    print(json.dumps({"report": str(destination), "sha256": digest, "provider_calls": 0}))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
