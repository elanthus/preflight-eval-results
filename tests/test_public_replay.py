from __future__ import annotations

import hashlib
import json
from pathlib import Path

import pytest

from preflight_evals.public_replay import example_directory, main, replay


def test_replay_is_byte_stable_and_matches_hand_calculated_paired_effects() -> None:
    inputs = (example_directory() / "inputs.json").read_bytes()
    first = replay(inputs)
    assert first == replay(inputs) == (example_directory() / "expected.json").read_bytes()
    result = json.loads(first)
    assert result["provider_calls"] == 0
    assert result["adjudicator_kind"] == "scripted_fixture"
    assert result["input_sha256"] == hashlib.sha256(inputs).hexdigest()
    primary = next(m for m in result["statistics"]["modes"] if m["mode"] == "primary")
    # Case one adds two catches; case two adds two false positives. Four paired
    # observations per snapshot: lift 2/4, harm 2/4, net 0/4.
    for metric, numerator in (
        ("vulnerable_lift", 2),
        ("fixed_false_positive_increase", 2),
        ("net_useful_lift", 0),
    ):
        effect = primary["differences"][metric]
        assert (effect["numerator"], effect["denominator"]) == (numerator, 4)
    assert primary["intervals"]["net_useful_lift"] == {"lower": -1.0, "upper": 1.0}


def test_check_failure_does_not_publish_output(tmp_path: Path) -> None:
    expected = tmp_path / "wrong.json"
    expected.write_text("{}")
    out = tmp_path / "result"
    with pytest.raises(SystemExit) as exc:
        main(["--out", str(out), "--check", str(expected)])
    assert exc.value.code == 2
    assert not out.exists()


@pytest.mark.parametrize("change", [{"synthetic": False}, {"method_version": "future"}])
def test_replay_rejects_unversioned_or_non_synthetic_inputs(change: dict[str, object]) -> None:
    document = json.loads((example_directory() / "inputs.json").read_bytes())
    document.update(change)
    with pytest.raises(ValueError):
        replay(json.dumps(document).encode())


def test_malformed_contract_exits_cleanly_without_a_traceback(tmp_path: Path, capsys) -> None:
    document = json.loads((example_directory() / "inputs.json").read_bytes())
    document["experiment"]["schema_version"] = "invalid"
    inputs = tmp_path / "bad.json"
    inputs.write_text(json.dumps(document))
    with pytest.raises(SystemExit) as exc:
        main(["--inputs", str(inputs), "--out", str(tmp_path / "out")])
    assert exc.value.code == 2
    assert "Traceback" not in capsys.readouterr().err
