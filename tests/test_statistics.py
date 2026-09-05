from __future__ import annotations

from collections.abc import Mapping
from dataclasses import replace
from datetime import UTC, datetime
from pathlib import Path
from typing import cast

import pytest

from preflight_evals.adapter import AdapterCapabilities
from preflight_evals.canonical import JsonValue, canonical_digest
from preflight_evals.contract_models import load_typed_contract
from preflight_evals.errors import SchemaError
from preflight_evals.execution import freeze_recovery_experiment
from preflight_evals.pricing import PriceTable
from preflight_evals.reviewer_models import Finding, ReviewerOutput
from preflight_evals.run_models import (
    ExperimentCase,
    ExperimentManifest,
    PlannedRun,
    PriceProjection,
    RetryEvent,
    RunRecord,
)
from preflight_evals.schema import ContractName, load_contract_document
from preflight_evals.score import ScoredMechanism, ScoringResult, score_experiment
from preflight_evals.scorer_models import AdjudicationRecord, GoldRecord
from preflight_evals.statistics import _quality_metrics, calculate_statistics

FIXTURES = Path(__file__).parent / "fixtures" / "contracts"


def _contract(name: str) -> object:
    return load_typed_contract(cast(ContractName, name), FIXTURES / name / "full.json")


def _experiment() -> ExperimentManifest:
    base = _contract("experiment")
    assert isinstance(base, ExperimentManifest)
    base_case = base.cases[0]
    cases = (
        replace(base_case, case_id="repo-one-pr1-f001"),
        replace(base_case, case_id="repo-two-pr2-f001"),
    )
    execution: list[PlannedRun] = []
    seed = 100
    for case in cases:
        for repetition in range(1, 3):
            for snapshot in ("vulnerable", "fixed"):
                seed += 1
                for condition in ("baseline", "candidate"):
                    run_digest = canonical_digest(
                        {
                            "case": case.case_id,
                            "snapshot": snapshot,
                            "condition": condition,
                            "repetition": repetition,
                        }
                    )
                    execution.append(
                        PlannedRun(
                            run_id=f"run-{run_digest.removeprefix('sha256:')[:32]}",
                            case_id=case.case_id,
                            snapshot=snapshot,
                            condition=condition,
                            repetition=repetition,
                            request_seed=seed,
                            estimated_input_tokens=(1_000 if case is cases[0] else 3_000),
                        )
                    )
    planned_count = len(execution)
    maximum_calls = planned_count * base.retry_policy.maximum_attempts
    projection = PriceProjection(
        price_table_version="synthetic-prices-v1",
        currency="USD",
        input_usd_per_million_tokens=2.5,
        output_usd_per_million_tokens=15.0,
        maximum_input_tokens=maximum_calls * base.reviewer_config.input_token_limit,
        maximum_output_tokens=maximum_calls * base.reviewer_config.output_token_limit,
        contingency_rate=0.2,
        projected_cost_usd=1.92,
    )
    case_checksum = canonical_digest(
        {
            "schema_version": "1",
            "cases": [
                {"case_id": case.case_id, "role": case.role}
                for case in sorted(cases, key=lambda item: item.case_id)
            ],
        }
    )
    draft = replace(
        base,
        experiment_id="experiment-draft",
        cases=cases,
        case_manifest_checksum=case_checksum,
        price_projection=projection,
        repetitions=2,
        execution_order=tuple(reversed(execution)),
        planned_run_count=planned_count,
        content_digest=None,
    )
    digest = canonical_digest(draft.deterministic_content())
    frozen = replace(
        draft,
        experiment_id=f"experiment-{digest.removeprefix('sha256:')[:32]}",
        content_digest=digest,
    )
    return ExperimentManifest.from_dict(frozen.to_dict())


def _gold(case: ExperimentCase) -> GoldRecord:
    base = _contract("gold")
    assert isinstance(base, GoldRecord)
    return replace(base, case_id=case.case_id)


def _finding() -> Finding:
    finding = _contract("finding")
    assert isinstance(finding, Finding)
    return finding


def _record(
    experiment: ExperimentManifest,
    planned: PlannedRun,
    *,
    positive: bool,
    status: str = "succeeded",
) -> RunRecord:
    base = _contract("run-record")
    assert isinstance(base, RunRecord)
    assert base.identity is not None
    case = next(item for item in experiment.cases if item.case_id == planned.case_id)
    source_commit = (
        case.vulnerable_snapshot if planned.snapshot == "vulnerable" else case.fixed_snapshot
    )
    profile_digest = (
        experiment.baseline_profile.digest
        if planned.condition == "baseline"
        else experiment.candidate_profile.digest
    )
    output = (
        ReviewerOutput(
            schema_version="1.0",
            findings=(_finding(),) if positive else (),
        )
        if status == "succeeded"
        else None
    )
    attempt = 1 if status == "succeeded" else experiment.retry_policy.maximum_attempts
    identity = replace(
        base.identity,
        experiment_content_digest=experiment.content_digest or "",
        source_commit=source_commit or "",
        request_id=f"request-{planned.run_id}",
        profile_digest=profile_digest,
        reviewer_output_digest=(canonical_digest(output.to_dict()) if output is not None else None),
    )
    draft = replace(
        base,
        run_id=planned.run_id,
        experiment_id=experiment.experiment_id,
        attempt=attempt,
        status=status,
        seed=planned.request_seed,
        reviewer_output=output,
        validation_errors=(() if output is not None else ("INVALID_OUTPUT",)),
        price_table_version="synthetic-prices-v1",
        retry_history=tuple(
            RetryEvent(attempt=index, classification="invalid_output")
            for index in range(1, attempt)
        ),
        identity=identity,
        content_digest=None,
    )
    record = replace(draft, content_digest=draft.digest_without_self())
    return RunRecord.from_dict(record.to_dict())


def _adjudication(run_id: str) -> AdjudicationRecord:
    return AdjudicationRecord.from_dict(
        {
            "schema_version": "1.0",
            "adjudication_id": f"adjudication-{run_id}",
            "run_id": run_id,
            "finding_id": "F002",
            "expected_mechanism_id": "mechanism-synthetic",
            "decision": "match",
            "rubric_version": "1.0",
            "adjudicator": "synthetic-adjudicator",
            "timestamp": datetime(2026, 8, 19, tzinfo=UTC).isoformat(),
            "rationale": "Synthetic scoring decision",
            "supersedes": None,
        }
    )


def _price_table() -> PriceTable:
    return PriceTable.from_dict(
        {
            "schema_version": "1.0",
            "version": "synthetic-prices-v1",
            "effective_date": "2026-08-18",
            "currency": "USD",
            "source": "https://example.invalid/prices",
            "entries": [
                {
                    "provider": "synthetic",
                    "model": "synthetic-model",
                    "input_usd_per_million_tokens": 2.5,
                    "cached_input_usd_per_million_tokens": 0.25,
                    "output_usd_per_million_tokens": 15.0,
                    "reasoning_billing": "included_in_output",
                    "long_context": None,
                }
            ],
        }
    )


def _inputs(
    *, unresolved_run_id: str | None = None
) -> tuple[ExperimentManifest, tuple[RunRecord, ...], tuple[GoldRecord, ...], ScoringResult]:
    experiment = _experiment()
    records: list[RunRecord] = []
    adjudications: list[AdjudicationRecord] = []
    for planned in experiment.execution_order:
        # Case one gains vulnerable detections with no fixed regression. Case two
        # preserves vulnerable detections but adds fixed false positives.
        positive = (
            (
                planned.case_id == "repo-one-pr1-f001"
                and planned.snapshot == "vulnerable"
                and planned.condition == "candidate"
            )
            or (planned.case_id == "repo-two-pr2-f001" and planned.snapshot == "vulnerable")
            or (
                planned.case_id == "repo-two-pr2-f001"
                and planned.snapshot == "fixed"
                and planned.condition == "candidate"
            )
        )
        status = "invalid_output" if planned.run_id == unresolved_run_id else "succeeded"
        record = _record(experiment, planned, positive=positive, status=status)
        records.append(record)
        if positive and status == "succeeded":
            adjudications.append(_adjudication(planned.run_id))
    gold = tuple(_gold(case) for case in experiment.cases)
    scoring = score_experiment(
        experiment,
        tuple(records),
        gold,
        tuple(adjudications),
    )
    return experiment, tuple(records), gold, scoring


def _mode(document: Mapping[str, object], name: str) -> dict[str, object]:
    modes = document["modes"]
    assert isinstance(modes, list)
    return next(item for item in modes if isinstance(item, dict) and item["mode"] == name)


def _redigest_scoring(scoring: ScoringResult) -> ScoringResult:
    draft = replace(scoring, content_digest="")
    result = replace(draft, content_digest=canonical_digest(draft.deterministic_content()))
    return ScoringResult.from_dict(result.to_dict())


def _redigest_record(record: RunRecord) -> RunRecord:
    draft = replace(record, content_digest=None)
    return RunRecord.from_dict(replace(draft, content_digest=draft.digest_without_self()).to_dict())


def _bind_execution_identity(experiment: ExperimentManifest, record: RunRecord) -> RunRecord:
    assert experiment.adapter_capabilities is not None
    assert record.identity is not None
    return _redigest_record(
        replace(
            record,
            identity=replace(
                record.identity,
                reviewer_config_digest=canonical_digest(experiment.to_dict()["reviewer_config"]),
                adapter_capabilities_digest=experiment.adapter_capabilities.content_digest,
            ),
        )
    )


def test_golden_paired_metrics_cluster_repetitions_by_case() -> None:
    experiment, records, gold, scoring = _inputs()

    result = calculate_statistics(
        experiment,
        scoring,
        records,
        gold,
        _price_table(),
        provider="synthetic",
    ).to_dict()

    assert result["primary_paired_unit"] == "case"
    assert result["case_count"] == 2
    assert result["repetitions"] == 2
    primary = _mode(result, "primary")
    differences = primary["differences"]
    assert isinstance(differences, dict)
    assert differences == {
        "vulnerable_lift": {
            "candidate_positive": 4,
            "baseline_positive": 2,
            "numerator": 2,
            "denominator": 4,
            "unresolved": 0,
            "value": 0.5,
        },
        "fixed_false_positive_increase": {
            "candidate_positive": 2,
            "baseline_positive": 0,
            "numerator": 2,
            "denominator": 4,
            "unresolved": 0,
            "value": 0.5,
        },
        "net_useful_lift": {
            "candidate_positive": 4,
            "baseline_positive": 4,
            "numerator": 0,
            "denominator": 4,
            "unresolved": 0,
            "value": 0.0,
        },
    }
    intervals = primary["intervals"]
    assert isinstance(intervals, dict)
    assert intervals["vulnerable_lift"] == {"lower": 0.0, "upper": 1.0}
    assert intervals["fixed_false_positive_increase"] == {"lower": 0.0, "upper": 1.0}
    assert intervals["net_useful_lift"] == {"lower": -1.0, "upper": 1.0}
    method = result["interval_method"]
    assert isinstance(method, dict)
    assert method == {
        "name": "paired-case-percentile-bootstrap-nearest-rank",
        "confidence_level": 0.95,
        "resamples": 100_000,
        "generator": "numpy.PCG64",
        "seed": 2_026_081_802,
    }
    stability = cast(list[dict[str, JsonValue]], result["repetition_stability"])
    assert all(item["discordant_cases"] == 0 for item in stability)
    operations = cast(list[dict[str, JsonValue]], result["operations"])
    all_operations = next(item for item in operations if item["condition"] == "all")
    provider_tokens = cast(dict[str, JsonValue], all_operations["provider_input_tokens"])
    estimated_tokens = cast(
        dict[str, JsonValue], all_operations["tokenizer_estimated_input_tokens"]
    )
    assert provider_tokens["source"] == "provider_reported"
    assert estimated_tokens["source"] == "tokenizer_estimate"
    cost = result["cost"]
    assert isinstance(cost, dict)
    assert cost["actual_cost_usd"] is not None
    assert cost["projected_remaining_cost_usd"] == 0.0
    assert cost["price_effective_date"] == "2026-08-18"
    assert result["terminal_status_counts"] == {"succeeded": 16}
    assert "adoption" not in result
    assert "threshold" not in result


def test_gold_2_breakdowns_use_primary_mechanism_constraints() -> None:
    experiment, records, _legacy_gold, _legacy_scoring = _inputs()
    document = load_contract_document(Path(__file__).parent / "fixtures" / "gold-v2.json")
    model = GoldRecord.from_dict(document)
    gold = tuple(replace(model, case_id=case.case_id) for case in experiment.cases)
    adjudications = tuple(
        _adjudication(record.run_id)
        for record in records
        if record.reviewer_output is not None and record.reviewer_output.findings
    )
    scoring = score_experiment(experiment, records, gold, adjudications)

    result = calculate_statistics(
        experiment,
        scoring,
        records,
        gold,
        _price_table(),
        provider="synthetic",
    ).to_dict()
    breakdowns = cast(list[dict[str, JsonValue]], result["exploratory_breakdowns"])
    category_values = {
        cast(str, item["value"]) for item in breakdowns if item["dimension"] == "category"
    }
    severity_values = {
        cast(str, item["value"]) for item in breakdowns if item["dimension"] == "severity"
    }

    assert category_values == {"correctness", "operational_contract"}
    assert severity_values == {"medium-to-critical"}


def test_unresolved_primary_is_suppressed_and_sensitivity_modes_are_labeled() -> None:
    experiment = _experiment()
    unresolved = next(
        run.run_id
        for run in experiment.execution_order
        if run.case_id == "repo-one-pr1-f001"
        and run.snapshot == "vulnerable"
        and run.condition == "candidate"
    )
    experiment, records, gold, scoring = _inputs(unresolved_run_id=unresolved)

    result = calculate_statistics(
        experiment,
        scoring,
        records,
        gold,
        _price_table(),
        provider="synthetic",
    ).to_dict()

    primary = _mode(result, "primary")
    assert primary["complete"] is False
    differences = primary["differences"]
    intervals = primary["intervals"]
    assert isinstance(differences, dict)
    assert isinstance(intervals, dict)
    assert differences["vulnerable_lift"]["value"] is None
    assert intervals["vulnerable_lift"] == {"lower": None, "upper": None}
    assert _mode(result, "pessimistic")["complete"] is True
    assert _mode(result, "optimistic")["complete"] is True


def test_quality_keeps_path_and_any_match_semantics_separate_from_other_evidence() -> None:
    _experiment_model, _records, _gold_records, scoring = _inputs()
    run = next(item for item in scoring.runs if item.findings)
    finding = run.findings[0]
    edge_finding = replace(
        finding,
        location_match=False,
        mechanisms=tuple(
            sorted(
                (
                    *finding.mechanisms,
                    ScoredMechanism(
                        mechanism_id="mechanism-unresolved-alternative",
                        decision="unadjudicated",
                        adjudication_digest=None,
                    ),
                ),
                key=lambda item: item.mechanism_id,
            )
        ),
    )

    quality = _quality_metrics((replace(run, findings=(edge_finding,)),), "all")

    assert quality.acceptable_path.to_dict()["value"] == 1.0
    assert quality.mechanism.to_dict() == {
        "correct": 1,
        "incorrect": 0,
        "unresolved": 0,
        "total": 1,
        "value": 1.0,
    }


def test_input_order_is_canonical_and_provenance_mismatches_fail_closed() -> None:
    experiment, records, gold, scoring = _inputs()
    forward = calculate_statistics(
        experiment,
        scoring,
        records,
        gold,
        _price_table(),
        provider="synthetic",
    ).to_dict()
    reverse = calculate_statistics(
        experiment,
        scoring,
        tuple(reversed(records)),
        tuple(reversed(gold)),
        _price_table(),
        provider="synthetic",
    ).to_dict()
    assert reverse == forward

    with pytest.raises(SchemaError, match="complete frozen score"):
        calculate_statistics(
            experiment,
            scoring,
            records[:-1],
            gold,
            _price_table(),
            provider="synthetic",
        )

    target = scoring.runs[0]
    bad_plan = _redigest_scoring(
        replace(
            scoring,
            runs=tuple(
                replace(run, planned_run_digest="sha256:" + "0" * 64)
                if run.run_id == target.run_id
                else run
                for run in scoring.runs
            ),
        )
    )
    with pytest.raises(SchemaError, match="provenance"):
        calculate_statistics(
            experiment,
            bad_plan,
            records,
            gold,
            _price_table(),
            provider="synthetic",
        )

    record = next(item for item in records if item.run_id == target.run_id)
    assert record.identity is not None
    forged_draft = replace(
        record,
        identity=replace(record.identity, source_commit="3" * 40),
        content_digest=None,
    )
    forged_record = replace(
        forged_draft,
        content_digest=forged_draft.digest_without_self(),
    )
    forged_scoring = _redigest_scoring(
        replace(
            scoring,
            runs=tuple(
                replace(run, run_record_digest=forged_record.content_digest or "")
                if run.run_id == target.run_id
                else run
                for run in scoring.runs
            ),
        )
    )
    forged_records = tuple(
        forged_record if item.run_id == target.run_id else item for item in records
    )
    with pytest.raises(SchemaError, match="frozen execution identity"):
        calculate_statistics(
            experiment,
            forged_scoring,
            forged_records,
            gold,
            _price_table(),
            provider="synthetic",
        )


def test_statistics_accept_linked_recovery_and_use_effective_records() -> None:
    experiment, successful_records, gold, _scoring = _inputs()
    target = next(
        planned
        for planned in experiment.execution_order
        if planned.snapshot == "fixed" and planned.condition == "baseline"
    )
    source_records = tuple(
        _bind_execution_identity(
            experiment,
            _redigest_record(
                replace(
                    record,
                    status="adapter_error",
                    attempt=1,
                    reviewer_output=None,
                    validation_errors=("OUTPUT_LIMIT_EXCEEDED",),
                    retry_history=(),
                    identity=(
                        replace(record.identity, reviewer_output_digest=None)
                        if record.identity is not None
                        else None
                    ),
                ),
            ),
        )
        if record.run_id == target.run_id
        else _bind_execution_identity(experiment, record)
        for record in successful_records
    )
    assert experiment.adapter_capabilities is not None
    capability_document = experiment.adapter_capabilities.to_dict()
    capability_document["maximum_stdout_bytes"] = 16_000_000
    capability_document.pop("content_digest")
    recovery_capabilities = AdapterCapabilities.from_dict(
        {
            **capability_document,
            "content_digest": canonical_digest(cast(JsonValue, capability_document)),
        }
    )
    recovery = freeze_recovery_experiment(
        experiment,
        source_records,
        recovery_capabilities,
        maximum_attempts=2,
        code_revision="1" * 40,
        environment_lock_digest=f"sha256:{'2' * 64}",
        created_at=datetime(2026, 8, 20, tzinfo=UTC),
        approved_by="synthetic-operator",
        approved_at=datetime(2026, 8, 20, 0, 1, tzinfo=UTC),
        expected_output_limit_failures=1,
        expected_invalid_output_failures=0,
    )
    recovered = _record(recovery, recovery.execution_order[0], positive=False)
    assert recovered.identity is not None
    recovered = _bind_execution_identity(
        recovery,
        replace(
            recovered,
            monotonic_latency_ms=9876.0,
        ),
    )
    adjudications = tuple(
        _adjudication(record.run_id)
        for record in successful_records
        if record.reviewer_output is not None and record.reviewer_output.findings
    )
    scoring = score_experiment(
        experiment,
        source_records,
        gold,
        adjudications,
        recovery_experiment=recovery,
        recovery_records=(recovered,),
    )

    result = calculate_statistics(
        experiment,
        scoring,
        source_records,
        gold,
        _price_table(),
        provider="synthetic",
        recovery_experiment=recovery,
        recovery_records=(recovered,),
    )

    assert dict(result.terminal_status_counts) == {"succeeded": len(source_records)}
    all_operations = next(item for item in result.operations if item.condition == "all")
    assert all_operations.latency_ms.maximum == 9876.0
    assert result.cost.completed_runs == len(source_records)
    assert result.cost.unfinished_runs == 0
    assert result.cost.actual_cost_usd is not None
    assert result.cost.unaccounted_retry_attempts == 0
    assert experiment.price_projection is not None
    assert recovery.price_projection is not None
    assert result.cost.frozen_worst_case_cost_usd == pytest.approx(
        experiment.price_projection.projected_cost_usd
        + recovery.price_projection.projected_cost_usd
    )

    assert recovered.identity is not None
    failed_recovery = _redigest_record(
        replace(
            recovered,
            status="adapter_error",
            reviewer_output=None,
            validation_errors=("OUTPUT_LIMIT_EXCEEDED", "STDOUT_LIMIT_EXCEEDED"),
            identity=replace(recovered.identity, reviewer_output_digest=None),
        )
    )
    failed_scoring = score_experiment(
        experiment,
        source_records,
        gold,
        adjudications,
        recovery_experiment=recovery,
        recovery_records=(failed_recovery,),
    )
    source_target = next(record for record in source_records if record.run_id == target.run_id)
    failed_target = next(run for run in failed_scoring.runs if run.run_id == target.run_id)
    assert failed_target.terminal_status == source_target.status
    assert failed_target.run_record_digest != source_target.content_digest
    calculate_statistics(
        experiment,
        failed_scoring,
        source_records,
        gold,
        _price_table(),
        provider="synthetic",
        recovery_experiment=recovery,
        recovery_records=(failed_recovery,),
    )

    with pytest.raises(SchemaError, match="one recovery record per selected"):
        calculate_statistics(
            experiment,
            scoring,
            source_records,
            gold,
            _price_table(),
            provider="synthetic",
            recovery_experiment=recovery,
        )
