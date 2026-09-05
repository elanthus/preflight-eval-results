from __future__ import annotations

import ast
import copy
from dataclasses import replace
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, cast

import pytest

from preflight_evals.adapter import AdapterCapabilities
from preflight_evals.canonical import JsonValue, canonical_digest
from preflight_evals.contract_models import parse_typed_contract
from preflight_evals.errors import SchemaError
from preflight_evals.execution import freeze_recovery_experiment
from preflight_evals.reviewer_models import Finding, ReviewerOutput
from preflight_evals.run_models import ExperimentManifest, PlannedRun, RetryEvent, RunRecord
from preflight_evals.schema import ContractName, load_contract_document, validate_contract
from preflight_evals.score import ScoringResult, _validate_scored_run, score_experiment
from preflight_evals.scorer_models import AdjudicationRecord, GoldRecord

FIXTURES = Path(__file__).parent / "fixtures" / "contracts"
PACKAGE = Path(__file__).resolve().parents[1] / "src" / "preflight_evals"


def _model(name: str, variant: str = "full") -> object:
    return parse_typed_contract(
        cast(ContractName, name),
        load_contract_document(FIXTURES / name / f"{variant}.json"),
    )


def _experiment() -> ExperimentManifest:
    model = _model("experiment")
    assert isinstance(model, ExperimentManifest)
    return model


def _gold() -> GoldRecord:
    model = _model("gold")
    assert isinstance(model, GoldRecord)
    return model


def _gold_v2() -> GoldRecord:
    model = parse_typed_contract("gold", load_contract_document(FIXTURES.parent / "gold-v2.json"))
    assert isinstance(model, GoldRecord)
    return model


def _finding(
    finding_id: str,
    *,
    path: str = "src/example.py",
    start_line: int | None = 4,
    end_line: int | None = 8,
    severity: str = "medium",
    category: str = "correctness",
    mechanism: str = "Synthetic failure mechanism",
) -> Finding:
    document = load_contract_document(FIXTURES / "finding" / "full.json")
    document.update(
        {
            "finding_id": finding_id,
            "file_path": path,
            "severity": severity,
            "defect_category": category,
            "failure_mechanism": mechanism,
        }
    )
    if start_line is None:
        document.pop("start_line", None)
        document.pop("end_line", None)
    else:
        document["start_line"] = start_line
        if end_line is None:
            document.pop("end_line", None)
        else:
            document["end_line"] = end_line
    return Finding.from_dict(document)


def _record(
    experiment: ExperimentManifest,
    planned: PlannedRun,
    findings: tuple[Finding, ...] = (),
    *,
    status: str = "succeeded",
    attempt: int = 1,
) -> RunRecord:
    model = _model("run-record")
    assert isinstance(model, RunRecord)
    assert model.identity is not None
    experiment_case = next(case for case in experiment.cases if case.case_id == planned.case_id)
    source_commit = (
        experiment_case.vulnerable_snapshot
        if planned.snapshot == "vulnerable"
        else experiment_case.fixed_snapshot
    )
    profile_digest = (
        experiment.baseline_profile.digest
        if planned.condition == "baseline"
        else experiment.candidate_profile.digest
    )
    config = experiment.reviewer_config
    reviewer_config_digest = canonical_digest(
        {
            "model": config.model,
            "tool_policy": config.tool_policy,
            "input_token_limit": config.input_token_limit,
            "output_token_limit": config.output_token_limit,
            "output_schema_version": config.output_schema_version,
            "adapter_version": config.adapter_version,
            "timeout_seconds": config.timeout_seconds,
            "temperature": config.temperature,
        }
    )
    assert experiment.adapter_capabilities is not None
    output = (
        ReviewerOutput(schema_version="1.0", findings=findings) if status == "succeeded" else None
    )
    identity = replace(
        model.identity,
        experiment_content_digest=experiment.content_digest or "",
        source_commit=source_commit or "",
        request_id=f"request-{planned.run_id.removeprefix('run-')}",
        profile_digest=profile_digest,
        reviewer_config_digest=reviewer_config_digest,
        adapter_capabilities_digest=experiment.adapter_capabilities.content_digest,
        reviewer_output_digest=(canonical_digest(output.to_dict()) if output is not None else None),
    )
    draft = replace(
        model,
        run_id=planned.run_id,
        experiment_id=experiment.experiment_id,
        attempt=attempt,
        status=status,
        seed=planned.request_seed,
        reviewer_output=output,
        validation_errors=(() if output is not None else ("INVALID_OUTPUT",)),
        retry_history=tuple(
            RetryEvent(attempt=prior_attempt, classification=status)
            for prior_attempt in range(1, attempt)
        ),
        identity=identity,
        content_digest=None,
    )
    return replace(draft, content_digest=draft.digest_without_self())


def _redigest(record: RunRecord) -> RunRecord:
    draft = replace(record, content_digest=None)
    return replace(draft, content_digest=draft.digest_without_self())


def _redigest_score_document(document: dict[str, Any]) -> None:
    content = {key: value for key, value in document.items() if key != "content_digest"}
    document["content_digest"] = canonical_digest(cast(JsonValue, content))


def _adjudication(
    run_id: str,
    finding_id: str,
    decision: str,
    *,
    suffix: str | None = None,
    supersedes: str | None = None,
    mechanism_id: str = "mechanism-synthetic",
) -> AdjudicationRecord:
    identity = suffix or f"{run_id.removeprefix('run-')}-{finding_id.lower()}"
    return AdjudicationRecord.from_dict(
        {
            "schema_version": "1.0",
            "adjudication_id": f"adjudication-{identity}",
            "run_id": run_id,
            "finding_id": finding_id,
            "expected_mechanism_id": mechanism_id,
            "decision": decision,
            "rubric_version": "1.0",
            "adjudicator": "synthetic-adjudicator",
            "timestamp": datetime(2026, 8, 19, tzinfo=UTC).isoformat(),
            "rationale": "Synthetic scoring decision",
            "supersedes": supersedes,
        }
    )


def _golden_inputs() -> tuple[
    ExperimentManifest,
    tuple[RunRecord, ...],
    tuple[GoldRecord, ...],
    tuple[AdjudicationRecord, ...],
]:
    experiment = _experiment()
    runs: list[RunRecord] = []
    adjudications: list[AdjudicationRecord] = []
    for planned in experiment.execution_order:
        findings: tuple[Finding, ...]
        if planned.snapshot == "vulnerable" and planned.condition == "baseline":
            exact = _finding("F001")
            duplicate = _finding("F002")
            alias = _finding("F003", path="legacy/example.py", start_line=8, end_line=8)
            missing_location = _finding("F004", start_line=None)
            below_severity = _finding("F005", severity="low")
            unrelated = _finding(
                "F006",
                path="src/unrelated.py",
                severity="low",
                category="security",
                mechanism="An unrelated mechanism",
            )
            findings = (
                unrelated,
                below_severity,
                missing_location,
                alias,
                duplicate,
                exact,
            )
            adjudications.extend(
                _adjudication(planned.run_id, finding.finding_id, decision)
                for finding, decision in (
                    (exact, "match"),
                    (duplicate, "match"),
                    (alias, "match"),
                    (missing_location, "match"),
                    (below_severity, "match"),
                    (unrelated, "no_match"),
                )
            )
        elif planned.snapshot == "fixed" and planned.condition == "baseline":
            unrelated = _finding(
                "F001", path="src/unrelated.py", mechanism="A different fixed defect"
            )
            findings = (unrelated,)
            adjudications.append(_adjudication(planned.run_id, "F001", "no_match"))
        elif planned.snapshot == "fixed" and planned.condition == "candidate":
            repaired_claim = _finding(
                "F001",
                path="src/elsewhere.py",
                severity="low",
                category="security",
            )
            findings = (repaired_claim,)
            adjudications.append(_adjudication(planned.run_id, "F001", "match"))
        else:
            findings = ()
        runs.append(_record(experiment, planned, findings))
    return experiment, tuple(runs), (_gold(),), tuple(adjudications)


def _run(result: ScoringResult, *, snapshot: str, condition: str) -> dict[str, Any]:
    return cast(
        dict[str, Any],
        next(
            run.to_dict()
            for run in result.runs
            if run.snapshot == snapshot and run.condition == condition
        ),
    )


def test_golden_scoring_preserves_matches_partials_duplicates_and_unrelated_findings() -> None:
    experiment, records, gold, adjudications = _golden_inputs()

    result = score_experiment(experiment, records, gold, adjudications)

    vulnerable = _run(result, snapshot="vulnerable", condition="baseline")
    assert vulnerable["outcome"] == {
        "name": "vulnerable_detection",
        "primary": True,
        "pessimistic": True,
        "optimistic": True,
    }
    findings = {finding["finding_id"]: finding for finding in vulnerable["findings"]}
    assert findings["F001"]["disposition"] == "matched"
    assert findings["F002"]["disposition"] == "duplicate"
    assert findings["F002"]["duplicate_of"] == "F001"
    assert findings["F003"]["checks"]["path"] == "alias"
    assert findings["F003"]["disposition"] == "matched"
    assert findings["F004"]["checks"]["location"] is False
    assert findings["F004"]["disposition"] == "partial"
    assert findings["F005"]["checks"]["severity"] is False
    assert findings["F005"]["disposition"] == "partial"
    assert findings["F006"]["disposition"] == "unmatched"

    empty = _run(result, snapshot="vulnerable", condition="candidate")
    assert empty["outcome"]["primary"] is False

    fixed_unrelated = _run(result, snapshot="fixed", condition="baseline")
    assert fixed_unrelated["outcome"]["primary"] is False
    assert fixed_unrelated["findings"][0]["disposition"] == "unrelated"

    fixed_claim = _run(result, snapshot="fixed", condition="candidate")
    assert fixed_claim["outcome"]["primary"] is True
    assert fixed_claim["findings"][0]["disposition"] == "repaired_mechanism_claim"


def test_gold_2_supplemental_match_does_not_change_primary_fixed_outcome() -> None:
    experiment = _experiment()
    gold = (_gold_v2(),)
    records: list[RunRecord] = []
    adjudications: list[AdjudicationRecord] = []
    target_run_id = ""
    for planned in experiment.execution_order:
        if planned.snapshot == "fixed" and planned.condition == "baseline":
            finding = _finding(
                "F001",
                path="src/supplemental.py",
                start_line=None,
                severity="high",
                category="security",
                mechanism="Synthetic supplemental mechanism",
            )
            records.append(_record(experiment, planned, (finding,)))
            target_run_id = planned.run_id
            adjudications.extend(
                (
                    _adjudication(planned.run_id, "F001", "no_match"),
                    _adjudication(
                        planned.run_id,
                        "F001",
                        "match",
                        suffix=f"{planned.run_id}-f001-supplemental",
                        mechanism_id="mechanism-supplemental",
                    ),
                )
            )
        else:
            records.append(_record(experiment, planned))

    result = score_experiment(experiment, tuple(records), gold, tuple(adjudications))
    target = next(run for run in result.runs if run.run_id == target_run_id)

    assert result.schema_version == "2.0"
    assert target.primary_outcome is False
    assert target.findings[0].disposition == "unrelated"
    supplemental = next(
        mechanism
        for mechanism in target.findings[0].mechanisms
        if mechanism.mechanism_id == "mechanism-supplemental"
    )
    assert supplemental.disposition == "expected_match"
    mechanism_classes = {
        outcome.mechanism_id: outcome.classification for outcome in target.mechanism_outcomes
    }
    assert mechanism_classes == {
        "mechanism-supplemental": "true_positive",
        "mechanism-synthetic": "true_negative",
    }
    assert ScoringResult.from_dict(result.to_dict()).canonical_bytes() == result.canonical_bytes()

    missing_outcomes = copy.deepcopy(result.to_dict())
    cast(list[dict[str, Any]], missing_outcomes["runs"])[0].pop("mechanism_outcomes")
    with pytest.raises(SchemaError, match="required"):
        validate_contract("score-result", missing_outcomes)

    mislabeled_legacy = copy.deepcopy(result.to_dict())
    mislabeled_legacy["schema_version"] = "1.0"
    with pytest.raises(SchemaError, match="not"):
        validate_contract("score-result", mislabeled_legacy)

    mutations: tuple[tuple[str, Any], ...] = (
        (
            "unique and ordered",
            lambda run: run["mechanism_outcomes"].reverse(),
        ),
        (
            "exactly one primary",
            lambda run: run["mechanism_outcomes"][0].update({"evaluation_role": "primary"}),
        ),
        (
            "path decision is inconsistent",
            lambda run: run["findings"][0]["mechanisms"][0]["checks"].update({"path": "none"}),
        ),
        (
            "disposition is inconsistent",
            lambda run: run["findings"][0]["mechanisms"][0].update({"disposition": "unmatched"}),
        ),
        (
            "outcome is inconsistent with its scored findings",
            lambda run: next(
                outcome
                for outcome in run["mechanism_outcomes"]
                if outcome["mechanism_id"] == "mechanism-supplemental"
            ).update({"classification": "false_negative"}),
        ),
        (
            "outcomes must cover every scored finding mechanism",
            lambda run: run["mechanism_outcomes"].pop(0),
        ),
    )
    for message, mutate in mutations:
        document = copy.deepcopy(result.to_dict())
        run = next(
            item
            for item in cast(list[dict[str, Any]], document["runs"])
            if item["run_id"] == target_run_id
        )
        mutate(run)
        _redigest_score_document(document)
        with pytest.raises(SchemaError, match=message):
            ScoringResult.from_dict(document)

    incomplete_mechanism = replace(
        target.findings[0].mechanisms[0],
        evaluation_role=None,
        expected_status=None,
        path_match=None,
        accepted_path=None,
        location_match=None,
        category_match=None,
        severity_match=None,
        disposition=None,
    )
    incomplete_finding = replace(
        target.findings[0],
        mechanisms=(incomplete_mechanism, *target.findings[0].mechanisms[1:]),
    )
    with pytest.raises(SchemaError, match="detail does not match"):
        _validate_scored_run(replace(target, findings=(incomplete_finding,)), schema_version="2.0")


def test_gold_2_failed_run_uses_primary_mechanism_for_sensitivity_bounds() -> None:
    experiment = _experiment()
    failed_plan = experiment.execution_order[0]
    records = tuple(
        _record(
            experiment,
            planned,
            status="invalid_output" if planned == failed_plan else "succeeded",
            attempt=2 if planned == failed_plan else 1,
        )
        for planned in experiment.execution_order
    )

    result = score_experiment(experiment, records, (_gold_v2(),), ())
    failed = next(run for run in result.runs if run.run_id == failed_plan.run_id)

    assert failed.primary_outcome is None
    assert (failed.pessimistic_outcome, failed.optimistic_outcome) == (
        failed.snapshot == "fixed",
        failed.snapshot == "vulnerable",
    )
    assert ScoringResult.from_dict(result.to_dict()).canonical_bytes() == result.canonical_bytes()


def test_linked_recovery_outputs_complete_source_scoring_without_rewriting_source_records() -> None:
    experiment, successful_records, gold, adjudications = _golden_inputs()
    output_limit_run, invalid_run = experiment.execution_order[:2]
    successful_by_id = {record.run_id: record for record in successful_records}
    source_records = tuple(
        _record(
            experiment,
            planned,
            status=(
                "adapter_error"
                if planned == output_limit_run
                else "invalid_output"
                if planned == invalid_run
                else "succeeded"
            ),
            attempt=2 if planned == invalid_run else 1,
            findings=(
                cast(ReviewerOutput, successful_by_id[planned.run_id].reviewer_output).findings
                if planned not in {output_limit_run, invalid_run}
                and successful_by_id[planned.run_id].reviewer_output is not None
                else ()
            ),
        )
        for planned in experiment.execution_order
    )
    source_records = tuple(
        _redigest(
            replace(
                record,
                validation_errors=(
                    ("OUTPUT_LIMIT_EXCEEDED",)
                    if record.run_id == output_limit_run.run_id
                    else ("OUTPUT_SCHEMA_INVALID",)
                    if record.run_id == invalid_run.run_id
                    else record.validation_errors
                ),
            )
        )
        for record in source_records
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
        expected_invalid_output_failures=1,
    )
    recovered_records = []
    for planned in recovery.execution_order:
        original = successful_by_id[planned.run_id]
        assert original.reviewer_output is not None
        recovered = _record(recovery, planned, original.reviewer_output.findings)
        assert recovered.identity is not None
        recovered_records.append(
            _redigest(
                replace(
                    recovered,
                    identity=replace(
                        recovered.identity,
                        adapter_capabilities_digest=recovery_capabilities.content_digest,
                    ),
                )
            )
        )

    result = score_experiment(
        experiment,
        source_records,
        gold,
        adjudications,
        recovery_experiment=recovery,
        recovery_records=tuple(recovered_records),
    )

    recovered_ids = {run.run_id for run in recovery.execution_order}
    assert all(
        run.terminal_status == "succeeded" for run in result.runs if run.run_id in recovered_ids
    )
    assert all(run.primary_outcome is not None for run in result.runs)

    with pytest.raises(SchemaError, match="require a linked recovery"):
        score_experiment(
            experiment,
            source_records,
            gold,
            adjudications,
            recovery_records=tuple(recovered_records),
        )
    with pytest.raises(SchemaError, match="one recovery record"):
        score_experiment(
            experiment,
            source_records,
            gold,
            adjudications,
            recovery_experiment=recovery,
            recovery_records=tuple(recovered_records[:-1]),
        )
    nonterminal_draft = replace(
        recovered_records[0],
        status="provider_error",
        attempt=1,
        reviewer_output=None,
        content_digest=None,
    )
    nonterminal = replace(nonterminal_draft, content_digest=nonterminal_draft.digest_without_self())
    with pytest.raises(SchemaError, match="must be terminal"):
        score_experiment(
            experiment,
            source_records,
            gold,
            adjudications,
            recovery_experiment=recovery,
            recovery_records=(nonterminal, *recovered_records[1:]),
        )
    wrong_identity_draft = replace(
        recovered_records[0], experiment_id="experiment-wrong", content_digest=None
    )
    wrong_identity = replace(
        wrong_identity_draft, content_digest=wrong_identity_draft.digest_without_self()
    )
    with pytest.raises(SchemaError, match="does not match"):
        score_experiment(
            experiment,
            source_records,
            gold,
            adjudications,
            recovery_experiment=recovery,
            recovery_records=(wrong_identity, *recovered_records[1:]),
        )


def test_fixed_on_target_findings_preserve_mechanism_based_dispositions() -> None:
    experiment, records, gold, adjudications = _golden_inputs()
    fixed_baseline = next(
        run
        for run in experiment.execution_order
        if run.snapshot == "fixed" and run.condition == "baseline"
    )
    fixed_candidate = next(
        run
        for run in experiment.execution_order
        if run.snapshot == "fixed" and run.condition == "candidate"
    )
    replacements = {
        fixed_baseline.run_id: _record(experiment, fixed_baseline, (_finding("F001"),)),
        fixed_candidate.run_id: _record(experiment, fixed_candidate, (_finding("F001"),)),
    }
    records = tuple(replacements.get(record.run_id, record) for record in records)

    result = score_experiment(experiment, records, gold, adjudications)
    on_target_no_match = next(run for run in result.runs if run.run_id == fixed_baseline.run_id)
    on_target_match = next(run for run in result.runs if run.run_id == fixed_candidate.run_id)

    assert on_target_no_match.primary_outcome is False
    assert on_target_no_match.findings[0].disposition == "partial"
    assert on_target_match.primary_outcome is True
    assert on_target_match.findings[0].disposition == "repaired_mechanism_claim"


def test_duplicate_cannot_flip_primary_outcome_or_make_it_unresolved() -> None:
    experiment, records, gold, adjudications = _golden_inputs()
    planned = next(
        run
        for run in experiment.execution_order
        if run.snapshot == "vulnerable" and run.condition == "candidate"
    )
    original = _finding("F001")
    duplicate = _finding("F002")
    replacement = _record(experiment, planned, (original, duplicate))
    records = tuple(
        replacement if record.run_id == planned.run_id else record for record in records
    )
    adjudications = (
        *adjudications,
        _adjudication(planned.run_id, "F001", "no_match"),
        _adjudication(planned.run_id, "F002", "match"),
    )

    result = score_experiment(experiment, records, gold, adjudications)
    run = next(item for item in result.runs if item.run_id == planned.run_id)

    assert run.primary_outcome is False
    assert run.pessimistic_outcome is False
    assert run.optimistic_outcome is False
    assert run.findings[1].duplicate_of == "F001"
    assert run.findings[1].disposition == "duplicate"


def test_boundary_severities_and_line_overlap_are_inclusive() -> None:
    experiment, records, gold, adjudications = _golden_inputs()
    accepted = gold[0].acceptable_locations[0]
    gold = (
        replace(
            gold[0],
            acceptable_locations=(replace(accepted, start_line=20, end_line=30), accepted),
        ),
    )
    planned = next(
        run
        for run in experiment.execution_order
        if run.snapshot == "vulnerable" and run.condition == "candidate"
    )
    boundary_findings = (
        _finding("F001", start_line=8, end_line=None, severity="medium"),
        _finding("F002", start_line=4, end_line=4, severity="critical"),
    )
    replacement = _record(experiment, planned, boundary_findings)
    records = tuple(
        replacement if record.run_id == planned.run_id else record for record in records
    )
    adjudications = (
        *adjudications,
        _adjudication(planned.run_id, "F001", "match"),
        _adjudication(planned.run_id, "F002", "match"),
    )

    result = score_experiment(experiment, records, gold, adjudications)
    run = _run(result, snapshot="vulnerable", condition="candidate")

    assert run["outcome"]["primary"] is True
    assert all(finding["disposition"] == "matched" for finding in run["findings"])


def test_unbounded_gold_location_accepts_a_path_only_finding() -> None:
    experiment, records, gold, adjudications = _golden_inputs()
    planned = next(
        run
        for run in experiment.execution_order
        if run.snapshot == "vulnerable" and run.condition == "candidate"
    )
    path_only = _finding("F001", start_line=None)
    replacement = _record(experiment, planned, (path_only,))
    records = tuple(
        replacement if record.run_id == planned.run_id else record for record in records
    )
    accepted = gold[0].acceptable_locations[0]
    gold = (
        replace(gold[0], acceptable_locations=(replace(accepted, start_line=None, end_line=None),)),
    )
    adjudications = (*adjudications, _adjudication(planned.run_id, "F001", "match"))

    result = score_experiment(experiment, records, gold, adjudications)
    run = next(item for item in result.runs if item.run_id == planned.run_id)

    assert run.primary_outcome is True
    assert run.findings[0].location_match is True


def test_terminal_invalid_output_uses_frozen_primary_and_sensitivity_policy() -> None:
    experiment, records, gold, adjudications = _golden_inputs()
    vulnerable = next(run for run in experiment.execution_order if run.snapshot == "vulnerable")
    fixed = next(run for run in experiment.execution_order if run.snapshot == "fixed")
    maximum_attempts = experiment.retry_policy.maximum_attempts
    replacements = {
        vulnerable.run_id: _record(
            experiment,
            vulnerable,
            status="invalid_output",
            attempt=maximum_attempts,
        ),
        fixed.run_id: _record(
            experiment,
            fixed,
            status="invalid_output",
            attempt=maximum_attempts,
        ),
    }
    records = tuple(replacements.get(record.run_id, record) for record in records)
    adjudications = tuple(
        decision for decision in adjudications if decision.run_id not in replacements
    )

    result = score_experiment(experiment, records, gold, adjudications)
    vulnerable_result = next(run for run in result.runs if run.run_id == vulnerable.run_id)
    fixed_result = next(run for run in result.runs if run.run_id == fixed.run_id)

    assert vulnerable_result.primary_outcome is None
    assert vulnerable_result.pessimistic_outcome is False
    assert vulnerable_result.optimistic_outcome is True
    assert fixed_result.primary_outcome is None
    assert fixed_result.pessimistic_outcome is True
    assert fixed_result.optimistic_outcome is False


def test_retryable_failed_attempt_is_rejected_until_retry_budget_is_exhausted() -> None:
    experiment, records, gold, adjudications = _golden_inputs()
    planned = experiment.execution_order[0]
    retryable = _record(experiment, planned, status="invalid_output", attempt=1)
    records = tuple(retryable if record.run_id == planned.run_id else record for record in records)
    adjudications = tuple(
        decision for decision in adjudications if decision.run_id != planned.run_id
    )

    with pytest.raises(SchemaError, match="exhaust their frozen retry policy"):
        score_experiment(experiment, records, gold, adjudications)


def test_uncertain_mechanism_is_unresolved_without_becoming_no_findings() -> None:
    experiment, records, gold, adjudications = _golden_inputs()
    planned = next(
        run
        for run in experiment.execution_order
        if run.snapshot == "vulnerable" and run.condition == "baseline"
    )
    adjudications = tuple(
        replace(decision, decision="uncertain")
        if decision.run_id == planned.run_id and decision.finding_id in {"F001", "F002", "F003"}
        else decision
        for decision in adjudications
    )

    result = score_experiment(experiment, records, gold, adjudications)
    run = next(item for item in result.runs if item.run_id == planned.run_id)

    assert run.primary_outcome is None
    assert run.pessimistic_outcome is False
    assert run.optimistic_outcome is True
    assert len(run.findings) == 6


def test_unadjudicated_vulnerable_partial_match_keeps_primary_unresolved() -> None:
    experiment, records, gold, adjudications = _golden_inputs()
    planned = next(
        run
        for run in experiment.execution_order
        if run.snapshot == "vulnerable" and run.condition == "candidate"
    )
    partial = _finding(
        "F001",
        path="src/unrelated.py",
        severity="low",
        category="security",
    )
    replacement = _record(experiment, planned, (partial,))
    records = tuple(
        replacement if record.run_id == planned.run_id else record for record in records
    )

    result = score_experiment(experiment, records, gold, adjudications)
    run = next(item for item in result.runs if item.run_id == planned.run_id)

    assert run.primary_outcome is None
    assert run.pessimistic_outcome is False
    assert run.optimistic_outcome is True
    assert run.findings[0].deterministic_match is False
    assert run.findings[0].mechanism_unresolved is True


def test_latest_adjudication_amendment_controls_scoring_independent_of_input_order() -> None:
    experiment, records, gold, adjudications = _golden_inputs()
    planned = next(
        run
        for run in experiment.execution_order
        if run.snapshot == "vulnerable" and run.condition == "baseline"
    )
    original = next(
        decision
        for decision in adjudications
        if decision.run_id == planned.run_id and decision.finding_id == "F001"
    )
    amended = _adjudication(
        planned.run_id,
        "F001",
        "no_match",
        suffix="amended-decision",
        supersedes=original.adjudication_id,
    )
    remaining = tuple(
        replace(decision, decision="no_match")
        if decision.run_id == planned.run_id and decision.finding_id in {"F002", "F003"}
        else decision
        for decision in adjudications
    )

    first = score_experiment(experiment, records, gold, (*remaining, amended))
    second = score_experiment(experiment, records, gold, tuple(reversed((*remaining, amended))))

    run = next(item for item in first.runs if item.run_id == planned.run_id)
    assert run.primary_outcome is False
    assert first.canonical_bytes() == second.canonical_bytes()


def test_input_collection_reordering_and_repeated_scoring_are_byte_identical() -> None:
    experiment, records, gold, adjudications = _golden_inputs()

    expected = score_experiment(experiment, records, gold, adjudications).canonical_bytes()
    reordered = score_experiment(
        experiment,
        tuple(reversed(records)),
        tuple(reversed(gold)),
        tuple(reversed(adjudications)),
    ).canonical_bytes()
    repeated = score_experiment(experiment, records, gold, adjudications).canonical_bytes()

    assert reordered == expected
    assert repeated == expected


def test_result_traces_every_run_to_run_gold_plan_and_adjudication_digests() -> None:
    experiment, records, gold, adjudications = _golden_inputs()

    result = score_experiment(experiment, records, gold, adjudications)
    document = cast(dict[str, Any], result.to_dict())

    assert result.content_digest == canonical_digest(result.deterministic_content())
    assert document["experiment_digest"] == experiment.content_digest
    assert all(
        set(run["input_digests"]) == {"run_record", "planned_run", "gold", "adjudications"}
        for run in document["runs"]
    )


def test_result_reload_rejects_outcomes_and_dispositions_that_contradict_evidence() -> None:
    experiment, records, gold, adjudications = _golden_inputs()
    result = score_experiment(experiment, records, gold, adjudications)

    outcome_document = cast(dict[str, Any], result.to_dict())
    fixed = next(
        cast(dict[str, Any], run)
        for run in cast(list[object], outcome_document["runs"])
        if cast(dict[str, Any], run)["snapshot"] == "fixed"
        and cast(dict[str, Any], run)["condition"] == "candidate"
    )
    fixed["outcome"] = {
        "name": "fixed_repaired_mechanism_false_positive",
        "primary": False,
        "pessimistic": False,
        "optimistic": False,
    }
    _redigest_score_document(outcome_document)
    with pytest.raises(SchemaError, match="primary outcome is inconsistent"):
        ScoringResult.from_dict(outcome_document)

    disposition_document = cast(dict[str, Any], result.to_dict())
    fixed = next(
        cast(dict[str, Any], run)
        for run in cast(list[object], disposition_document["runs"])
        if cast(dict[str, Any], run)["snapshot"] == "fixed"
        and cast(dict[str, Any], run)["condition"] == "candidate"
    )
    finding = cast(dict[str, Any], cast(list[object], fixed["findings"])[0])
    finding["disposition"] = "unrelated"
    _redigest_score_document(disposition_document)
    with pytest.raises(SchemaError, match="disposition is inconsistent"):
        ScoringResult.from_dict(disposition_document)


def test_invalid_scoring_relationships_fail_closed() -> None:
    experiment, records, gold, adjudications = _golden_inputs()

    with pytest.raises(SchemaError, match="identifiers must be unique"):
        score_experiment(experiment, (*records, records[0]), gold, adjudications)

    bad_record = replace(records[0], experiment_id="experiment-other")
    bad_records = (bad_record, *records[1:])
    with pytest.raises(SchemaError, match="frozen scoring tuple"):
        score_experiment(experiment, bad_records, gold, adjudications)

    bad_adjudication = replace(adjudications[0], finding_id="F999")
    with pytest.raises(SchemaError, match="unavailable finding"):
        score_experiment(experiment, records, gold, (bad_adjudication, *adjudications[1:]))


def test_frozen_input_completeness_and_identity_mismatches_fail_closed() -> None:
    experiment, records, gold, adjudications = _golden_inputs()

    with pytest.raises(SchemaError, match="completely frozen"):
        score_experiment(replace(experiment, frozen=False), records, gold, adjudications)
    with pytest.raises(SchemaError, match="invalid-output policy"):
        score_experiment(
            replace(experiment, invalid_output_policy="unsupported"),
            records,
            gold,
            adjudications,
        )
    with pytest.raises(SchemaError, match="one terminal record"):
        score_experiment(experiment, records[:-1], gold, adjudications)
    with pytest.raises(SchemaError, match="one gold record"):
        score_experiment(experiment, records, (), adjudications)

    stale = replace(records[0], content_digest="sha256:" + "0" * 64)
    with pytest.raises(SchemaError, match="content digest changed"):
        score_experiment(experiment, (stale, *records[1:]), gold, adjudications)

    assert records[0].identity is not None
    without_identity = _redigest(replace(records[0], identity=None))
    with pytest.raises(SchemaError, match="complete execution identity"):
        score_experiment(experiment, (without_identity, *records[1:]), gold, adjudications)

    wrong_source = _redigest(
        replace(records[0], identity=replace(records[0].identity, source_commit="0" * 40))
    )
    with pytest.raises(SchemaError, match="source does not match"):
        score_experiment(experiment, (wrong_source, *records[1:]), gold, adjudications)

    wrong_experiment = _redigest(
        replace(
            records[0],
            identity=replace(
                records[0].identity,
                experiment_content_digest="sha256:" + "0" * 64,
            ),
        )
    )
    with pytest.raises(SchemaError, match="different frozen experiment"):
        score_experiment(experiment, (wrong_experiment, *records[1:]), gold, adjudications)

    wrong_profile = _redigest(
        replace(
            records[0],
            identity=replace(records[0].identity, profile_digest="sha256:" + "0" * 64),
        )
    )
    with pytest.raises(SchemaError, match="profile does not match"):
        score_experiment(experiment, (wrong_profile, *records[1:]), gold, adjudications)

    wrong_seed = _redigest(replace(records[0], seed=999))
    with pytest.raises(SchemaError, match="seed does not match"):
        score_experiment(experiment, (wrong_seed, *records[1:]), gold, adjudications)

    assert records[0].identity is not None
    missing_output = _redigest(
        replace(
            records[0],
            reviewer_output=None,
            identity=replace(records[0].identity, reviewer_output_digest=None),
        )
    )
    remaining_adjudications = tuple(
        decision for decision in adjudications if decision.run_id != missing_output.run_id
    )
    with pytest.raises(SchemaError, match="missing reviewer output"):
        score_experiment(
            experiment,
            (missing_output, *records[1:]),
            gold,
            remaining_adjudications,
        )


def test_adjudication_supersession_and_target_invariants_fail_closed() -> None:
    experiment, records, gold, adjudications = _golden_inputs()
    original = adjudications[0]

    missing_prior = _adjudication(
        original.run_id,
        original.finding_id,
        "match",
        suffix="missing-prior",
        supersedes="adjudication-unavailable",
    )
    with pytest.raises(SchemaError, match="supersedes an unavailable"):
        score_experiment(experiment, records, gold, (*adjudications, missing_prior))

    cross_identity = _adjudication(
        original.run_id,
        "F002",
        "match",
        suffix="cross-identity",
        supersedes=original.adjudication_id,
    )
    with pytest.raises(SchemaError, match="changes its scoring identity"):
        score_experiment(experiment, records, gold, (*adjudications, cross_identity))

    fork_one = _adjudication(
        original.run_id,
        original.finding_id,
        "match",
        suffix="fork-one",
        supersedes=original.adjudication_id,
    )
    fork_two = _adjudication(
        original.run_id,
        original.finding_id,
        "no_match",
        suffix="fork-two",
        supersedes=original.adjudication_id,
    )
    with pytest.raises(SchemaError, match="multiple current decisions"):
        score_experiment(experiment, records, gold, (*adjudications, fork_one, fork_two))

    unknown_run = replace(original, run_id="run-unavailable")
    with pytest.raises(SchemaError, match="unavailable successful run"):
        score_experiment(experiment, records, gold, (unknown_run, *adjudications[1:]))

    unknown_mechanism = replace(original, expected_mechanism_id="mechanism-unavailable")
    with pytest.raises(SchemaError, match="unavailable expected mechanism"):
        score_experiment(experiment, records, gold, (unknown_mechanism, *adjudications[1:]))


def test_scoring_module_cannot_import_or_invoke_reviewer_boundaries() -> None:
    tree = ast.parse((PACKAGE / "score.py").read_text(), filename="score.py")
    imported: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            imported.update(alias.name for alias in node.names)
        elif isinstance(node, ast.ImportFrom) and node.module is not None:
            imported.add(node.module)

    assert imported.isdisjoint(
        {
            "preflight_evals.adapter",
            "preflight_evals.execution",
            "preflight_evals.reviewer",
        }
    )
