"""Pure deterministic scoring for frozen reviewer results."""

from __future__ import annotations

from collections.abc import Callable, Mapping
from dataclasses import dataclass, replace
from typing import Any, Literal, cast

from preflight_evals.canonical import JsonValue, canonical_digest, canonical_json_bytes
from preflight_evals.errors import SchemaError
from preflight_evals.model_types import (
    SEVERITY_ORDER,
    Condition,
    SnapshotName,
    object_list,
    object_mapping,
)
from preflight_evals.recovery import overlaid_run_record_digest, overlay_recovery_records
from preflight_evals.reviewer_models import Finding
from preflight_evals.run_models import ExperimentManifest, PlannedRun, RunRecord
from preflight_evals.schema import validate_contract
from preflight_evals.scorer_models import (
    AcceptableLocation,
    AdjudicationRecord,
    GoldRecord,
    SnapshotExpectation,
)

type PathMatch = Literal["exact", "alias", "none"]
type MechanismDecision = Literal["match", "no_match", "uncertain", "unadjudicated"]
type FindingDisposition = Literal[
    "matched",
    "repaired_mechanism_claim",
    "partial",
    "duplicate",
    "unrelated",
    "unmatched",
]
type MechanismDisposition = Literal[
    "expected_match",
    "unexpected_claim",
    "partial",
    "unresolved",
    "unrelated",
    "unmatched",
    "unscored",
]
type MechanismOutcomeName = Literal[
    "true_positive",
    "false_positive",
    "false_negative",
    "true_negative",
    "unresolved",
    "unverified",
]


@dataclass(frozen=True, slots=True)
class ScoredMechanism:
    mechanism_id: str
    decision: MechanismDecision
    adjudication_digest: str | None
    evaluation_role: str | None = None
    expected_status: SnapshotExpectation | None = None
    path_match: PathMatch | None = None
    accepted_path: str | None = None
    location_match: bool | None = None
    category_match: bool | None = None
    severity_match: bool | None = None
    disposition: MechanismDisposition | None = None

    @property
    def deterministic_match(self) -> bool:
        return (
            self.path_match != "none"
            and self.path_match is not None
            and self.location_match is True
            and self.category_match is True
            and self.severity_match is True
        )

    def to_dict(self) -> dict[str, JsonValue]:
        document: dict[str, JsonValue] = {
            "mechanism_id": self.mechanism_id,
            "decision": self.decision,
            "adjudication_digest": self.adjudication_digest,
        }
        if self.expected_status is not None:
            document.update(
                {
                    "evaluation_role": self.evaluation_role,
                    "expected_status": self.expected_status,
                    "checks": {
                        "path": self.path_match,
                        "accepted_path": self.accepted_path,
                        "location": self.location_match,
                        "category": self.category_match,
                        "severity": self.severity_match,
                    },
                    "disposition": self.disposition,
                }
            )
        return document


@dataclass(frozen=True, slots=True)
class ScoredMechanismOutcome:
    mechanism_id: str
    evaluation_role: str
    expected_status: SnapshotExpectation
    classification: MechanismOutcomeName

    def to_dict(self) -> dict[str, JsonValue]:
        return {
            "mechanism_id": self.mechanism_id,
            "evaluation_role": self.evaluation_role,
            "expected_status": self.expected_status,
            "classification": self.classification,
        }


@dataclass(frozen=True, slots=True)
class ScoredFinding:
    finding_id: str
    finding_digest: str
    duplicate_of: str | None
    path_match: PathMatch
    accepted_path: str | None
    location_match: bool
    category_match: bool
    severity_match: bool
    mechanisms: tuple[ScoredMechanism, ...]
    disposition: FindingDisposition

    @property
    def deterministic_match(self) -> bool:
        return (
            self.path_match != "none"
            and self.location_match
            and self.category_match
            and self.severity_match
        )

    @property
    def mechanism_match(self) -> bool:
        mechanisms = tuple(
            mechanism
            for mechanism in self.mechanisms
            if mechanism.evaluation_role in {None, "primary"}
        )
        return any(mechanism.decision == "match" for mechanism in mechanisms)

    @property
    def mechanism_unresolved(self) -> bool:
        mechanisms = tuple(
            mechanism
            for mechanism in self.mechanisms
            if mechanism.evaluation_role in {None, "primary"}
        )
        return any(mechanism.decision in {"uncertain", "unadjudicated"} for mechanism in mechanisms)

    def to_dict(self) -> dict[str, JsonValue]:
        return {
            "finding_id": self.finding_id,
            "finding_digest": self.finding_digest,
            "duplicate_of": self.duplicate_of,
            "checks": {
                "path": self.path_match,
                "accepted_path": self.accepted_path,
                "location": self.location_match,
                "category": self.category_match,
                "severity": self.severity_match,
            },
            "mechanisms": [mechanism.to_dict() for mechanism in self.mechanisms],
            "disposition": self.disposition,
        }


@dataclass(frozen=True, slots=True)
class ScoredRun:
    run_id: str
    case_id: str
    snapshot: SnapshotName
    condition: Condition
    repetition: int
    run_record_digest: str
    planned_run_digest: str
    gold_digest: str
    adjudication_set_digest: str
    terminal_status: str
    outcome_name: str
    primary_outcome: bool | None
    pessimistic_outcome: bool
    optimistic_outcome: bool
    findings: tuple[ScoredFinding, ...]
    mechanism_outcomes: tuple[ScoredMechanismOutcome, ...]

    def to_dict(self) -> dict[str, JsonValue]:
        document: dict[str, JsonValue] = {
            "run_id": self.run_id,
            "case_id": self.case_id,
            "snapshot": self.snapshot,
            "condition": self.condition,
            "repetition": self.repetition,
            "input_digests": {
                "run_record": self.run_record_digest,
                "planned_run": self.planned_run_digest,
                "gold": self.gold_digest,
                "adjudications": self.adjudication_set_digest,
            },
            "terminal_status": self.terminal_status,
            "outcome": {
                "name": self.outcome_name,
                "primary": self.primary_outcome,
                "pessimistic": self.pessimistic_outcome,
                "optimistic": self.optimistic_outcome,
            },
            "findings": [finding.to_dict() for finding in self.findings],
        }
        if self.mechanism_outcomes:
            document["mechanism_outcomes"] = [
                outcome.to_dict() for outcome in self.mechanism_outcomes
            ]
        return document


@dataclass(frozen=True, slots=True)
class ScoringResult:
    schema_version: str
    experiment_id: str
    experiment_digest: str
    invalid_output_policy: str
    runs: tuple[ScoredRun, ...]
    content_digest: str

    @classmethod
    def from_dict(cls, document: Mapping[str, Any]) -> ScoringResult:
        data = validate_contract("score-result", dict(document))
        result = cls(
            schema_version=cast(str, data["schema_version"]),
            experiment_id=cast(str, data["experiment_id"]),
            experiment_digest=cast(str, data["experiment_digest"]),
            invalid_output_policy=cast(str, data["invalid_output_policy"]),
            runs=tuple(_scored_run(object_mapping(item)) for item in object_list(data["runs"])),
            content_digest=cast(str, data["content_digest"]),
        )
        result._validate_relationships()
        return result

    def deterministic_content(self) -> dict[str, JsonValue]:
        return {
            "schema_version": self.schema_version,
            "experiment_id": self.experiment_id,
            "experiment_digest": self.experiment_digest,
            "invalid_output_policy": self.invalid_output_policy,
            "runs": [run.to_dict() for run in self.runs],
        }

    def to_dict(self) -> dict[str, JsonValue]:
        document = self.deterministic_content()
        document["content_digest"] = self.content_digest
        return document

    def canonical_bytes(self) -> bytes:
        return canonical_json_bytes(self.to_dict())

    def _validate_relationships(self) -> None:
        if self.content_digest != canonical_digest(self.deterministic_content()):
            raise SchemaError("score result content digest does not match its content")
        expected_order = sorted(
            self.runs,
            key=lambda run: (
                run.case_id,
                run.repetition,
                run.snapshot,
                run.condition,
                run.run_id,
            ),
        )
        if list(self.runs) != expected_order:
            raise SchemaError("score result runs must be in canonical scoring order")
        run_ids = [run.run_id for run in self.runs]
        if len(run_ids) != len(set(run_ids)):
            raise SchemaError("score result run identifiers must be unique")
        for run in self.runs:
            _validate_scored_run(run, schema_version=self.schema_version)
        if self.schema_version == "2.0":
            for case_id in sorted({run.case_id for run in self.runs}):
                case_runs = tuple(run for run in self.runs if run.case_id == case_id)
                identities = [
                    tuple(
                        (outcome.mechanism_id, outcome.evaluation_role)
                        for outcome in run.mechanism_outcomes
                    )
                    for run in case_runs
                ]
                if any(identity != identities[0] for identity in identities[1:]):
                    raise SchemaError(
                        "score 2.0 mechanism outcome identities must be complete per case"
                    )
                for snapshot in ("vulnerable", "fixed"):
                    snapshot_runs = tuple(run for run in case_runs if run.snapshot == snapshot)
                    statuses = [
                        tuple(
                            (outcome.mechanism_id, outcome.expected_status)
                            for outcome in run.mechanism_outcomes
                        )
                        for run in snapshot_runs
                    ]
                    if statuses and any(status != statuses[0] for status in statuses[1:]):
                        raise SchemaError(
                            "score 2.0 mechanism expectations must be stable per snapshot"
                        )


def score_experiment(
    experiment: ExperimentManifest,
    run_records: tuple[RunRecord, ...],
    gold_records: tuple[GoldRecord, ...],
    adjudications: tuple[AdjudicationRecord, ...],
    *,
    recovery_experiment: ExperimentManifest | None = None,
    recovery_records: tuple[RunRecord, ...] = (),
) -> ScoringResult:
    """Score one complete frozen experiment without external effects."""

    if not experiment.frozen or experiment.content_digest is None:
        raise SchemaError("scoring requires a completely frozen experiment")
    if experiment.invalid_output_policy != "retry_then_fail":
        raise SchemaError("scoring does not support the frozen invalid-output policy")

    runs_by_id = _unique_by(run_records, key=lambda record: record.run_id, kind="run")
    planned_by_id = {run.run_id: run for run in experiment.execution_order}
    if set(runs_by_id) != set(planned_by_id):
        raise SchemaError("scoring requires exactly one terminal record per frozen run")
    if any(not _is_terminal_record(experiment, record) for record in runs_by_id.values()):
        raise SchemaError(
            "scoring requires failed run records to exhaust their frozen retry policy"
        )

    effective_by_id = dict(runs_by_id)
    recovered_by_id: dict[str, RunRecord] = {}
    if recovery_experiment is None:
        if recovery_records:
            raise SchemaError("recovery records require a linked recovery experiment")
    else:
        effective_by_id = overlay_recovery_records(
            experiment,
            run_records,
            recovery_experiment,
            recovery_records,
        )
        recovered_by_id = {record.run_id: record for record in recovery_records}

    gold_by_case = _unique_by(gold_records, key=lambda gold: gold.case_id, kind="gold")
    expected_cases = {case.case_id for case in experiment.cases}
    if set(gold_by_case) != expected_cases:
        raise SchemaError("scoring requires exactly one gold record per frozen case")
    gold_versions = {gold.schema_version for gold in gold_records}
    if "2.0" in gold_versions and gold_versions != {"2.0"}:
        raise SchemaError("scoring cannot mix gold 2.0 with legacy gold records")
    result_schema_version = "2.0" if gold_versions == {"2.0"} else "1.0"

    current_adjudications = _resolve_adjudications(adjudications)
    _validate_adjudication_targets(
        current_adjudications,
        runs_by_id=effective_by_id,
        gold_by_case=gold_by_case,
        planned_by_id=planned_by_id,
    )

    scored_runs = tuple(
        _score_run(
            experiment,
            planned,
            runs_by_id[planned.run_id],
            effective_by_id[planned.run_id],
            recovered_by_id.get(planned.run_id),
            gold_by_case[planned.case_id],
            tuple(record for record in adjudications if record.run_id == planned.run_id),
            current_adjudications,
        )
        for planned in sorted(
            experiment.execution_order,
            key=lambda run: (
                run.case_id,
                run.repetition,
                run.snapshot,
                run.condition,
                run.run_id,
            ),
        )
    )
    draft = ScoringResult(
        schema_version=result_schema_version,
        experiment_id=experiment.experiment_id,
        experiment_digest=experiment.content_digest,
        invalid_output_policy=experiment.invalid_output_policy,
        runs=scored_runs,
        content_digest="",
    )
    result = ScoringResult(
        schema_version=draft.schema_version,
        experiment_id=draft.experiment_id,
        experiment_digest=draft.experiment_digest,
        invalid_output_policy=draft.invalid_output_policy,
        runs=draft.runs,
        content_digest=canonical_digest(draft.deterministic_content()),
    )
    return ScoringResult.from_dict(result.to_dict())


def score_combined_holdout_experiment(
    experiment: ExperimentManifest,
    development_records: tuple[RunRecord, ...],
    holdout_experiment: ExperimentManifest,
    holdout_records: tuple[RunRecord, ...],
    gold_records: tuple[GoldRecord, ...],
    adjudications: tuple[AdjudicationRecord, ...],
    *,
    recovery_experiment: ExperimentManifest,
    recovery_records: tuple[RunRecord, ...],
    allow_frozen_m31_legacy: bool = False,
) -> ScoringResult:
    """Score one frozen experiment assembled from linked development and holdout stages."""

    from preflight_evals.holdout import validate_holdout_source

    if not experiment.frozen or experiment.content_digest is None:
        raise SchemaError("combined scoring requires a completely frozen experiment")
    if experiment.invalid_output_policy != "retry_then_fail":
        raise SchemaError("combined scoring does not support the frozen invalid-output policy")
    validate_holdout_source(holdout_experiment, experiment, development_records)
    effective_holdout = overlay_recovery_records(
        holdout_experiment,
        holdout_records,
        recovery_experiment,
        recovery_records,
        allow_frozen_m31_legacy=allow_frozen_m31_legacy,
    )
    roles = {case.case_id: case.role for case in experiment.cases}
    development_plan = {
        run.run_id: run for run in experiment.execution_order if roles[run.case_id] == "development"
    }
    holdout_plan = {run.run_id: run for run in holdout_experiment.execution_order}
    planned_by_id = {run.run_id: run for run in experiment.execution_order}
    development_by_id = _unique_by(
        development_records, key=lambda record: record.run_id, kind="development run"
    )
    holdout_by_id = _unique_by(
        holdout_records, key=lambda record: record.run_id, kind="holdout run"
    )
    recovered_by_id = _unique_by(
        recovery_records, key=lambda record: record.run_id, kind="holdout recovery run"
    )
    if (
        set(development_by_id) != set(development_plan)
        or set(holdout_by_id) != set(holdout_plan)
        or set(development_plan) | set(holdout_plan) != set(planned_by_id)
        or set(development_plan).intersection(holdout_plan)
    ):
        raise SchemaError("combined scoring requires every frozen development and holdout run")

    effective_by_id = {**development_by_id, **effective_holdout}
    gold_by_case = _unique_by(gold_records, key=lambda gold: gold.case_id, kind="gold")
    if set(gold_by_case) != {case.case_id for case in experiment.cases}:
        raise SchemaError("combined scoring requires exactly one gold record per frozen case")
    gold_versions = {gold.schema_version for gold in gold_records}
    if "2.0" in gold_versions and gold_versions != {"2.0"}:
        raise SchemaError("combined scoring cannot mix gold 2.0 with legacy gold records")
    result_schema_version = "2.0" if gold_versions == {"2.0"} else "1.0"

    current_adjudications = _resolve_adjudications(adjudications)
    _validate_adjudication_targets(
        current_adjudications,
        runs_by_id=effective_by_id,
        gold_by_case=gold_by_case,
        planned_by_id=planned_by_id,
    )
    scored_runs = tuple(
        _score_run(
            experiment,
            planned,
            (
                development_by_id[planned.run_id]
                if planned.run_id in development_by_id
                else holdout_by_id[planned.run_id]
            ),
            effective_by_id[planned.run_id],
            recovered_by_id.get(planned.run_id),
            gold_by_case[planned.case_id],
            tuple(record for record in adjudications if record.run_id == planned.run_id),
            current_adjudications,
            record_experiment=(
                experiment if planned.run_id in development_by_id else holdout_experiment
            ),
        )
        for planned in sorted(
            experiment.execution_order,
            key=lambda run: (
                run.case_id,
                run.repetition,
                run.snapshot,
                run.condition,
                run.run_id,
            ),
        )
    )
    draft = ScoringResult(
        schema_version=result_schema_version,
        experiment_id=experiment.experiment_id,
        experiment_digest=experiment.content_digest,
        invalid_output_policy=experiment.invalid_output_policy,
        runs=scored_runs,
        content_digest="",
    )
    result = ScoringResult(
        schema_version=draft.schema_version,
        experiment_id=draft.experiment_id,
        experiment_digest=draft.experiment_digest,
        invalid_output_policy=draft.invalid_output_policy,
        runs=draft.runs,
        content_digest=canonical_digest(draft.deterministic_content()),
    )
    return ScoringResult.from_dict(result.to_dict())


def resolve_current_adjudications(
    adjudications: tuple[AdjudicationRecord, ...],
) -> tuple[AdjudicationRecord, ...]:
    """Return the active append-only adjudication projection in stable key order."""

    current = _resolve_adjudications(adjudications)
    return tuple(current[key] for key in sorted(current))


def _score_run(
    experiment: ExperimentManifest,
    planned: PlannedRun,
    source_record: RunRecord,
    effective_record: RunRecord,
    recovery_record: RunRecord | None,
    gold: GoldRecord,
    run_adjudications: tuple[AdjudicationRecord, ...],
    current_adjudications: dict[tuple[str, str, str], AdjudicationRecord],
    *,
    record_experiment: ExperimentManifest | None = None,
) -> ScoredRun:
    _validate_run_identity(record_experiment or experiment, planned, source_record, gold)
    record_digest = overlaid_run_record_digest(source_record, recovery_record)
    planned_digest = canonical_digest(_planned_run_dict(planned))
    gold_digest = canonical_digest(gold.to_dict())
    adjudication_documents: list[JsonValue] = [
        adjudication.to_dict()
        for adjudication in sorted(
            run_adjudications, key=lambda adjudication: adjudication.adjudication_id
        )
    ]
    adjudication_set_digest = canonical_digest(
        {"schema_version": "1", "records": adjudication_documents}
    )

    if effective_record.status != "succeeded":
        outcome_name = _outcome_name(planned.snapshot)
        mechanism_outcomes = (
            _failed_mechanism_outcomes(gold, planned.snapshot)
            if gold.schema_version == "2.0"
            else ()
        )
        pessimistic, optimistic = _outcome_bounds(planned.snapshot, gold, None)
        return ScoredRun(
            run_id=planned.run_id,
            case_id=planned.case_id,
            snapshot=planned.snapshot,
            condition=planned.condition,
            repetition=planned.repetition,
            run_record_digest=record_digest,
            planned_run_digest=planned_digest,
            gold_digest=gold_digest,
            adjudication_set_digest=adjudication_set_digest,
            terminal_status=effective_record.status,
            outcome_name=outcome_name,
            primary_outcome=None,
            pessimistic_outcome=pessimistic,
            optimistic_outcome=optimistic,
            findings=(),
            mechanism_outcomes=mechanism_outcomes,
        )

    if effective_record.reviewer_output is None:
        raise SchemaError("successful scoring input is missing reviewer output")
    duplicates = _duplicate_finding_map(effective_record.reviewer_output.findings)
    findings = tuple(
        _score_finding(
            planned,
            finding,
            gold,
            duplicate_of=duplicates[finding.finding_id],
            current_adjudications=current_adjudications,
        )
        for finding in sorted(
            effective_record.reviewer_output.findings, key=lambda item: item.finding_id
        )
    )
    mechanism_outcomes = (
        _mechanism_outcomes(gold, planned.snapshot, findings)
        if gold.schema_version == "2.0"
        else ()
    )
    primary = _primary_outcome(planned.snapshot, findings, mechanism_outcomes)
    pessimistic, optimistic = _outcome_bounds(
        planned.snapshot,
        gold,
        primary,
    )
    return ScoredRun(
        run_id=planned.run_id,
        case_id=planned.case_id,
        snapshot=planned.snapshot,
        condition=planned.condition,
        repetition=planned.repetition,
        run_record_digest=record_digest,
        planned_run_digest=planned_digest,
        gold_digest=gold_digest,
        adjudication_set_digest=adjudication_set_digest,
        terminal_status=effective_record.status,
        outcome_name=_outcome_name(planned.snapshot),
        primary_outcome=primary,
        pessimistic_outcome=pessimistic,
        optimistic_outcome=optimistic,
        findings=findings,
        mechanism_outcomes=mechanism_outcomes,
    )


def _score_finding(
    planned: PlannedRun,
    finding: Finding,
    gold: GoldRecord,
    *,
    duplicate_of: str | None,
    current_adjudications: dict[tuple[str, str, str], AdjudicationRecord],
) -> ScoredFinding:
    mechanisms: list[ScoredMechanism] = []
    for expected in sorted(gold.expected_mechanisms, key=lambda item: item.mechanism_id):
        adjudication = current_adjudications.get(
            (planned.run_id, finding.finding_id, expected.mechanism_id)
        )
        decision = (
            "unadjudicated"
            if adjudication is None
            else _adjudication_decision(adjudication.decision)
        )
        locations = (
            expected.acceptable_locations
            if gold.schema_version == "2.0"
            else gold.acceptable_locations
        )
        categories = (
            expected.accepted_defect_categories
            if gold.schema_version == "2.0"
            else gold.accepted_defect_categories
        )
        severity_range = (
            expected.severity_range if gold.schema_version == "2.0" else gold.severity_range
        )
        path_match, accepted_location, location_match = _match_location(finding, locations)
        category_match = finding.defect_category in categories
        severity_match = (
            SEVERITY_ORDER[severity_range.minimum]
            <= SEVERITY_ORDER[finding.severity]
            <= SEVERITY_ORDER[severity_range.maximum]
        )
        expected_status = expected.snapshot_expectations.for_snapshot(planned.snapshot)
        detailed = gold.schema_version == "2.0"
        mechanisms.append(
            ScoredMechanism(
                mechanism_id=expected.mechanism_id,
                decision=decision,
                adjudication_digest=(
                    canonical_digest(adjudication.to_dict()) if adjudication is not None else None
                ),
                evaluation_role=expected.evaluation_role if detailed else None,
                expected_status=expected_status if detailed else None,
                path_match=path_match if detailed else None,
                accepted_path=(
                    accepted_location.path.as_posix()
                    if detailed and accepted_location is not None
                    else None
                ),
                location_match=location_match if detailed else None,
                category_match=category_match if detailed else None,
                severity_match=severity_match if detailed else None,
                disposition=(
                    _mechanism_disposition(
                        expected_status,
                        decision,
                        deterministic_match=(
                            path_match != "none"
                            and location_match
                            and category_match
                            and severity_match
                        ),
                    )
                    if detailed
                    else None
                ),
            )
        )
    primary_expected = next(
        mechanism
        for mechanism in sorted(gold.expected_mechanisms, key=lambda item: item.mechanism_id)
        if mechanism.evaluation_role == "primary"
    )
    primary_locations = (
        primary_expected.acceptable_locations
        if gold.schema_version == "2.0"
        else gold.acceptable_locations
    )
    primary_categories = (
        primary_expected.accepted_defect_categories
        if gold.schema_version == "2.0"
        else gold.accepted_defect_categories
    )
    primary_severity = (
        primary_expected.severity_range if gold.schema_version == "2.0" else gold.severity_range
    )
    path_match, accepted_location, location_match = _match_location(finding, primary_locations)
    category_match = finding.defect_category in primary_categories
    severity_match = (
        SEVERITY_ORDER[primary_severity.minimum]
        <= SEVERITY_ORDER[finding.severity]
        <= SEVERITY_ORDER[primary_severity.maximum]
    )
    scored = ScoredFinding(
        finding_id=finding.finding_id,
        finding_digest=canonical_digest(finding.to_dict()),
        duplicate_of=duplicate_of,
        path_match=path_match,
        accepted_path=(
            accepted_location.path.as_posix() if accepted_location is not None else None
        ),
        location_match=location_match,
        category_match=category_match,
        severity_match=severity_match,
        mechanisms=tuple(mechanisms),
        disposition="unmatched",
    )
    return replace(scored, disposition=_finding_disposition(planned.snapshot, scored))


def _is_terminal_record(experiment: ExperimentManifest, record: RunRecord) -> bool:
    if record.status == "succeeded":
        return True
    if record.status in {"configuration_error", "adapter_error"}:
        return True
    if record.attempt >= experiment.retry_policy.maximum_attempts:
        return True
    if record.status == "invalid_output" and experiment.invalid_output_policy == "fail_run":
        return True
    return record.status not in experiment.retry_policy.retryable_failures


def _primary_outcome(
    snapshot: SnapshotName,
    findings: tuple[ScoredFinding, ...],
    mechanism_outcomes: tuple[ScoredMechanismOutcome, ...] = (),
) -> bool | None:
    if mechanism_outcomes:
        primary = [
            outcome for outcome in mechanism_outcomes if outcome.evaluation_role == "primary"
        ]
        positives = {"true_positive", "false_positive"}
        return (
            True
            if any(outcome.classification in positives for outcome in primary)
            else None
            if any(outcome.classification == "unresolved" for outcome in primary)
            else False
        )
    unique_findings = tuple(finding for finding in findings if finding.duplicate_of is None)
    if snapshot == "vulnerable":
        matched = any(
            finding.deterministic_match and finding.mechanism_match for finding in unique_findings
        )
    else:
        matched = any(finding.mechanism_match for finding in unique_findings)
    unresolved = any(finding.mechanism_unresolved for finding in unique_findings)
    return True if matched else None if unresolved else False


def _mechanism_disposition(
    expected_status: SnapshotExpectation,
    decision: MechanismDecision,
    *,
    deterministic_match: bool,
) -> MechanismDisposition:
    if expected_status == "unverified":
        return "unscored"
    if decision in {"uncertain", "unadjudicated"}:
        return "unresolved"
    if expected_status == "absent":
        return "unexpected_claim" if decision == "match" else "unrelated"
    if decision != "match":
        return "unmatched"
    return "expected_match" if deterministic_match else "partial"


def _mechanism_outcomes(
    gold: GoldRecord,
    snapshot: SnapshotName,
    findings: tuple[ScoredFinding, ...],
) -> tuple[ScoredMechanismOutcome, ...]:
    unique = tuple(finding for finding in findings if finding.duplicate_of is None)
    outcomes: list[ScoredMechanismOutcome] = []
    for expected in sorted(gold.expected_mechanisms, key=lambda item: item.mechanism_id):
        status = expected.snapshot_expectations.for_snapshot(snapshot)
        scored = tuple(
            mechanism
            for finding in unique
            for mechanism in finding.mechanisms
            if mechanism.mechanism_id == expected.mechanism_id
        )
        classification = _mechanism_classification(status, scored)
        outcomes.append(
            ScoredMechanismOutcome(
                mechanism_id=expected.mechanism_id,
                evaluation_role=expected.evaluation_role,
                expected_status=status,
                classification=classification,
            )
        )
    return tuple(outcomes)


def _mechanism_classification(
    status: SnapshotExpectation, mechanisms: tuple[ScoredMechanism, ...]
) -> MechanismOutcomeName:
    if status == "unverified":
        return "unverified"
    if status == "present":
        return (
            "true_positive"
            if any(item.disposition == "expected_match" for item in mechanisms)
            else "unresolved"
            if any(item.disposition == "unresolved" for item in mechanisms)
            else "false_negative"
        )
    return (
        "false_positive"
        if any(item.disposition == "unexpected_claim" for item in mechanisms)
        else "unresolved"
        if any(item.disposition == "unresolved" for item in mechanisms)
        else "true_negative"
    )


def _failed_mechanism_outcomes(
    gold: GoldRecord, snapshot: SnapshotName
) -> tuple[ScoredMechanismOutcome, ...]:
    return tuple(
        ScoredMechanismOutcome(
            mechanism_id=expected.mechanism_id,
            evaluation_role=expected.evaluation_role,
            expected_status=expected.snapshot_expectations.for_snapshot(snapshot),
            classification=(
                "unverified"
                if expected.snapshot_expectations.for_snapshot(snapshot) == "unverified"
                else "unresolved"
            ),
        )
        for expected in sorted(gold.expected_mechanisms, key=lambda item: item.mechanism_id)
    )


def _outcome_bounds(
    snapshot: SnapshotName, gold: GoldRecord, primary: bool | None
) -> tuple[bool, bool]:
    if primary is not None:
        return primary, primary
    if gold.schema_version != "2.0":
        return snapshot == "fixed", snapshot == "vulnerable"
    mechanism = next(item for item in gold.expected_mechanisms if item.evaluation_role == "primary")
    expected = mechanism.snapshot_expectations.for_snapshot(snapshot)
    return (expected == "absent", expected == "present")


def _finding_disposition(snapshot: SnapshotName, finding: ScoredFinding) -> FindingDisposition:
    if finding.duplicate_of is not None:
        return "duplicate"
    if finding.mechanism_match and snapshot == "fixed":
        return "repaired_mechanism_claim"
    if finding.mechanism_match and finding.deterministic_match:
        return "matched"
    primary_mechanisms = tuple(
        mechanism
        for mechanism in finding.mechanisms
        if mechanism.evaluation_role in {None, "primary"}
    )
    if (
        all(mechanism.decision == "no_match" for mechanism in primary_mechanisms)
        and snapshot == "fixed"
        and not finding.deterministic_match
    ):
        return "unrelated"
    if any(
        (
            finding.path_match != "none",
            finding.location_match,
            finding.category_match,
            finding.severity_match,
        )
    ):
        return "partial"
    return "unmatched"


def _match_location(
    finding: Finding, locations: tuple[AcceptableLocation, ...]
) -> tuple[PathMatch, AcceptableLocation | None, bool]:
    exact = tuple(location for location in locations if finding.file_path == location.path)
    if exact:
        accepted = next(
            (location for location in exact if _line_regions_overlap(finding, location)),
            exact[0],
        )
        return "exact", accepted, _line_regions_overlap(finding, accepted)
    aliases = tuple(location for location in locations if finding.file_path in location.aliases)
    if aliases:
        accepted = next(
            (location for location in aliases if _line_regions_overlap(finding, location)),
            aliases[0],
        )
        return "alias", accepted, _line_regions_overlap(finding, accepted)
    return "none", None, False


def _line_regions_overlap(finding: Finding, location: AcceptableLocation) -> bool:
    if location.start_line is None:
        return True
    if finding.start_line is None:
        return False
    finding_end = finding.end_line or finding.start_line
    location_end = location.end_line or location.start_line
    return finding.start_line <= location_end and finding_end >= location.start_line


def _duplicate_finding_map(findings: tuple[Finding, ...]) -> dict[str, str | None]:
    first_by_digest: dict[str, str] = {}
    duplicates: dict[str, str | None] = {}
    for finding in sorted(findings, key=lambda item: item.finding_id):
        document = finding.to_dict()
        document.pop("finding_id")
        signature = canonical_digest(document)
        duplicates[finding.finding_id] = first_by_digest.get(signature)
        first_by_digest.setdefault(signature, finding.finding_id)
    return duplicates


def _resolve_adjudications(
    adjudications: tuple[AdjudicationRecord, ...],
) -> dict[tuple[str, str, str], AdjudicationRecord]:
    by_id = _unique_by(
        adjudications, key=lambda record: record.adjudication_id, kind="adjudication"
    )
    superseded: set[str] = set()
    for record in adjudications:
        if record.supersedes is None:
            continue
        prior = by_id.get(record.supersedes)
        if prior is None:
            raise SchemaError("adjudication supersedes an unavailable record")
        if _adjudication_key(prior) != _adjudication_key(record):
            raise SchemaError("adjudication amendment changes its scoring identity")
        superseded.add(prior.adjudication_id)
        seen = {record.adjudication_id}
        cursor = prior
        while cursor.supersedes is not None:
            if cursor.adjudication_id in seen:
                raise SchemaError("adjudication supersession chain contains a cycle")
            seen.add(cursor.adjudication_id)
            next_record = by_id.get(cursor.supersedes)
            if next_record is None:
                raise SchemaError("adjudication supersedes an unavailable record")
            cursor = next_record

    current: dict[tuple[str, str, str], AdjudicationRecord] = {}
    for record in adjudications:
        if record.adjudication_id in superseded:
            continue
        key = _adjudication_key(record)
        if key in current:
            raise SchemaError("adjudication identity has multiple current decisions")
        current[key] = record
    return current


def _validate_adjudication_targets(
    adjudications: dict[tuple[str, str, str], AdjudicationRecord],
    *,
    runs_by_id: dict[str, RunRecord],
    gold_by_case: dict[str, GoldRecord],
    planned_by_id: dict[str, PlannedRun],
) -> None:
    for (run_id, finding_id, mechanism_id), _record in adjudications.items():
        run = runs_by_id.get(run_id)
        if run is None or run.reviewer_output is None:
            raise SchemaError("adjudication targets an unavailable successful run")
        if finding_id not in {finding.finding_id for finding in run.reviewer_output.findings}:
            raise SchemaError("adjudication targets an unavailable finding")
        gold = gold_by_case[planned_by_id[run_id].case_id]
        planned = planned_by_id[run_id]
        mechanisms = {mechanism.mechanism_id: mechanism for mechanism in gold.expected_mechanisms}
        mechanism = mechanisms.get(mechanism_id)
        if mechanism is None:
            raise SchemaError("adjudication targets an unavailable expected mechanism")
        if mechanism.snapshot_expectations.for_snapshot(planned.snapshot) == "unverified":
            raise SchemaError("adjudication targets an unverified snapshot expectation")


def _validate_run_identity(
    experiment: ExperimentManifest,
    planned: PlannedRun,
    record: RunRecord,
    gold: GoldRecord,
) -> None:
    if record.run_id != planned.run_id or record.experiment_id != experiment.experiment_id:
        raise SchemaError("run record does not belong to the frozen scoring tuple")
    if gold.case_id != planned.case_id:
        raise SchemaError("gold record does not belong to the frozen scoring tuple")
    if record.content_digest is not None and record.content_digest != record.digest_without_self():
        raise SchemaError("run record content digest changed before scoring")
    if record.identity is None:
        raise SchemaError("scoring requires a run record with complete execution identity")
    if record.identity.experiment_content_digest != experiment.content_digest:
        raise SchemaError("run record is bound to a different frozen experiment")
    experiment_case = next(case for case in experiment.cases if case.case_id == planned.case_id)
    expected_source = (
        experiment_case.vulnerable_snapshot
        if planned.snapshot == "vulnerable"
        else experiment_case.fixed_snapshot
    )
    if record.identity.source_commit != expected_source:
        raise SchemaError("run record source does not match the frozen snapshot")
    expected_profile = (
        experiment.baseline_profile.digest
        if planned.condition == "baseline"
        else experiment.candidate_profile.digest
    )
    if record.identity.profile_digest != expected_profile:
        raise SchemaError("run record profile does not match the frozen condition")
    if record.seed != planned.request_seed:
        raise SchemaError("run record seed does not match the frozen plan")


def _unique_by[T](values: tuple[T, ...], *, key: Callable[[T], str], kind: str) -> dict[str, T]:
    result: dict[str, T] = {}
    for value in values:
        identifier = key(value)
        if identifier in result:
            raise SchemaError(f"scoring {kind} identifiers must be unique")
        result[identifier] = value
    return result


def _planned_run_dict(run: PlannedRun) -> dict[str, JsonValue]:
    return {
        "run_id": run.run_id,
        "case_id": run.case_id,
        "snapshot": run.snapshot,
        "condition": run.condition,
        "repetition": run.repetition,
        "request_seed": run.request_seed,
        "estimated_input_tokens": run.estimated_input_tokens,
    }


def _adjudication_key(record: AdjudicationRecord) -> tuple[str, str, str]:
    return (record.run_id, record.finding_id, record.expected_mechanism_id)


def _adjudication_decision(value: str) -> MechanismDecision:
    if value not in {"match", "no_match", "uncertain"}:
        raise SchemaError("adjudication decision is unsupported")
    return cast(MechanismDecision, value)


def _outcome_name(snapshot: SnapshotName) -> str:
    return (
        "vulnerable_detection"
        if snapshot == "vulnerable"
        else "fixed_repaired_mechanism_false_positive"
    )


def _scored_run(data: Mapping[str, Any]) -> ScoredRun:
    digests = object_mapping(data["input_digests"])
    outcome = object_mapping(data["outcome"])
    return ScoredRun(
        run_id=cast(str, data["run_id"]),
        case_id=cast(str, data["case_id"]),
        snapshot=cast(SnapshotName, data["snapshot"]),
        condition=cast(Condition, data["condition"]),
        repetition=cast(int, data["repetition"]),
        run_record_digest=cast(str, digests["run_record"]),
        planned_run_digest=cast(str, digests["planned_run"]),
        gold_digest=cast(str, digests["gold"]),
        adjudication_set_digest=cast(str, digests["adjudications"]),
        terminal_status=cast(str, data["terminal_status"]),
        outcome_name=cast(str, outcome["name"]),
        primary_outcome=cast(bool | None, outcome["primary"]),
        pessimistic_outcome=cast(bool, outcome["pessimistic"]),
        optimistic_outcome=cast(bool, outcome["optimistic"]),
        findings=tuple(
            _scored_finding(object_mapping(item)) for item in object_list(data["findings"])
        ),
        mechanism_outcomes=tuple(
            _scored_mechanism_outcome(object_mapping(item))
            for item in object_list(data.get("mechanism_outcomes", []))
        ),
    )


def _scored_finding(data: Mapping[str, Any]) -> ScoredFinding:
    checks = object_mapping(data["checks"])
    return ScoredFinding(
        finding_id=cast(str, data["finding_id"]),
        finding_digest=cast(str, data["finding_digest"]),
        duplicate_of=cast(str | None, data["duplicate_of"]),
        path_match=cast(PathMatch, checks["path"]),
        accepted_path=cast(str | None, checks["accepted_path"]),
        location_match=cast(bool, checks["location"]),
        category_match=cast(bool, checks["category"]),
        severity_match=cast(bool, checks["severity"]),
        mechanisms=tuple(
            _scored_mechanism(object_mapping(item)) for item in object_list(data["mechanisms"])
        ),
        disposition=cast(FindingDisposition, data["disposition"]),
    )


def _scored_mechanism(data: Mapping[str, Any]) -> ScoredMechanism:
    checks = object_mapping(data["checks"]) if "checks" in data else None
    return ScoredMechanism(
        mechanism_id=cast(str, data["mechanism_id"]),
        decision=cast(MechanismDecision, data["decision"]),
        adjudication_digest=cast(str | None, data["adjudication_digest"]),
        evaluation_role=cast(str | None, data.get("evaluation_role")),
        expected_status=cast(SnapshotExpectation | None, data.get("expected_status")),
        path_match=(cast(PathMatch, checks["path"]) if checks is not None else None),
        accepted_path=(cast(str | None, checks["accepted_path"]) if checks is not None else None),
        location_match=(cast(bool, checks["location"]) if checks is not None else None),
        category_match=(cast(bool, checks["category"]) if checks is not None else None),
        severity_match=(cast(bool, checks["severity"]) if checks is not None else None),
        disposition=cast(MechanismDisposition | None, data.get("disposition")),
    )


def _scored_mechanism_outcome(data: Mapping[str, Any]) -> ScoredMechanismOutcome:
    return ScoredMechanismOutcome(
        mechanism_id=cast(str, data["mechanism_id"]),
        evaluation_role=cast(str, data["evaluation_role"]),
        expected_status=cast(SnapshotExpectation, data["expected_status"]),
        classification=cast(MechanismOutcomeName, data["classification"]),
    )


def _validate_scored_run(run: ScoredRun, *, schema_version: str) -> None:
    if run.outcome_name != _outcome_name(run.snapshot):
        raise SchemaError("score result outcome does not match its snapshot")
    if run.primary_outcome is None:
        if schema_version == "2.0":
            primary = next(
                (
                    outcome
                    for outcome in run.mechanism_outcomes
                    if outcome.evaluation_role == "primary"
                ),
                None,
            )
            expected_bounds = (
                primary is not None and primary.expected_status == "absent",
                primary is not None and primary.expected_status == "present",
            )
        else:
            expected_bounds = (run.snapshot == "fixed", run.snapshot == "vulnerable")
        if (run.pessimistic_outcome, run.optimistic_outcome) != expected_bounds:
            raise SchemaError("unresolved score result has invalid sensitivity bounds")
    elif (
        run.pessimistic_outcome != run.primary_outcome
        or run.optimistic_outcome != run.primary_outcome
    ):
        raise SchemaError("resolved score result has inconsistent sensitivity bounds")
    if run.terminal_status != "succeeded" and (run.primary_outcome is not None or run.findings):
        raise SchemaError("failed score result cannot contain a primary outcome or findings")
    if schema_version == "1.0" and run.mechanism_outcomes:
        raise SchemaError("legacy score result cannot contain mechanism outcomes")
    if schema_version == "2.0":
        outcome_ids = [outcome.mechanism_id for outcome in run.mechanism_outcomes]
        if (
            not outcome_ids
            or outcome_ids != sorted(outcome_ids)
            or len(outcome_ids) != len(set(outcome_ids))
        ):
            raise SchemaError("score 2.0 mechanism outcomes must be unique and ordered")
        if sum(outcome.evaluation_role == "primary" for outcome in run.mechanism_outcomes) != 1:
            raise SchemaError("score 2.0 requires exactly one primary mechanism outcome")
    finding_ids = [finding.finding_id for finding in run.findings]
    if finding_ids != sorted(finding_ids) or len(finding_ids) != len(set(finding_ids)):
        raise SchemaError("scored findings must have unique identifiers in canonical order")
    for finding in run.findings:
        if (finding.path_match == "none") != (finding.accepted_path is None):
            raise SchemaError("scored finding path decision is inconsistent")
        if finding.duplicate_of is not None and finding.duplicate_of not in finding_ids:
            raise SchemaError("scored finding duplicate target is unavailable")
        if finding.duplicate_of is not None and finding.duplicate_of >= finding.finding_id:
            raise SchemaError("scored finding duplicate target must precede the duplicate")
        mechanism_ids = [mechanism.mechanism_id for mechanism in finding.mechanisms]
        if mechanism_ids != sorted(mechanism_ids) or len(mechanism_ids) != len(set(mechanism_ids)):
            raise SchemaError("scored mechanisms must be unique and canonically ordered")
        if schema_version == "2.0" and mechanism_ids != outcome_ids:
            raise SchemaError(
                "score 2.0 mechanism outcomes must cover every scored finding mechanism"
            )
        for mechanism in finding.mechanisms:
            if (mechanism.decision == "unadjudicated") != (mechanism.adjudication_digest is None):
                raise SchemaError("scored mechanism adjudication provenance is inconsistent")
            detailed = mechanism.expected_status is not None
            if detailed != (schema_version == "2.0"):
                raise SchemaError("scored mechanism detail does not match score version")
            if detailed:
                outcome = next(
                    item
                    for item in run.mechanism_outcomes
                    if item.mechanism_id == mechanism.mechanism_id
                )
                if (
                    mechanism.evaluation_role != outcome.evaluation_role
                    or mechanism.expected_status != outcome.expected_status
                ):
                    raise SchemaError(
                        "score 2.0 mechanism outcomes do not match scored finding labels"
                    )
                if (mechanism.path_match == "none") != (mechanism.accepted_path is None):
                    raise SchemaError("scored mechanism path decision is inconsistent")
                expected_disposition = _mechanism_disposition(
                    mechanism.expected_status,
                    mechanism.decision,
                    deterministic_match=mechanism.deterministic_match,
                )
                if mechanism.disposition != expected_disposition:
                    raise SchemaError("scored mechanism disposition is inconsistent")
        if finding.disposition != _finding_disposition(run.snapshot, finding):
            raise SchemaError("scored finding disposition is inconsistent with its evidence")
    if schema_version == "2.0":
        unique_findings = tuple(finding for finding in run.findings if finding.duplicate_of is None)
        for outcome in run.mechanism_outcomes:
            mechanisms = tuple(
                mechanism
                for finding in unique_findings
                for mechanism in finding.mechanisms
                if mechanism.mechanism_id == outcome.mechanism_id
            )
            expected_classification = (
                _mechanism_classification(outcome.expected_status, mechanisms)
                if run.terminal_status == "succeeded"
                else "unverified"
                if outcome.expected_status == "unverified"
                else "unresolved"
            )
            if outcome.classification != expected_classification:
                raise SchemaError(
                    "score 2.0 mechanism outcome is inconsistent with its scored findings"
                )
    if run.terminal_status == "succeeded" and run.primary_outcome != _primary_outcome(
        run.snapshot, run.findings, run.mechanism_outcomes
    ):
        raise SchemaError("score result primary outcome is inconsistent with its findings")
