"""Case-clustered paired metrics, frozen bootstrap uncertainty, and operations summaries."""

from __future__ import annotations

import math
import re
from collections.abc import Callable, Iterable, Mapping, Sequence
from dataclasses import dataclass
from decimal import Decimal
from statistics import NormalDist
from typing import Literal, cast

import numpy as np
from numpy.typing import NDArray

from preflight_evals.attempt_metadata import AttemptMetadata
from preflight_evals.canonical import JsonValue, canonical_digest
from preflight_evals.errors import SchemaError
from preflight_evals.pricing import CostAccounting, PriceTable, account_costs
from preflight_evals.recovery import overlaid_run_record_digest, overlay_recovery_records
from preflight_evals.run_models import ExperimentManifest, PlannedRun, RunRecord
from preflight_evals.score import ScoredFinding, ScoredRun, ScoringResult
from preflight_evals.scorer_models import GoldRecord

type AnalysisMode = Literal["primary", "pessimistic", "optimistic"]

BOOTSTRAP_RESAMPLES = 100_000
BOOTSTRAP_SEED = 2_026_081_802
BOOTSTRAP_LEVEL = 0.95

_CELL_ORDER = (
    ("vulnerable", "baseline"),
    ("vulnerable", "candidate"),
    ("fixed", "baseline"),
    ("fixed", "candidate"),
)
_MODES: tuple[AnalysisMode, ...] = ("primary", "pessimistic", "optimistic")


@dataclass(frozen=True, slots=True)
class OutcomeCounts:
    positive: int
    negative: int
    unresolved: int
    total: int

    @property
    def value(self) -> float | None:
        return self.positive / self.total if self.total and not self.unresolved else None

    def to_dict(self) -> dict[str, JsonValue]:
        return {
            "positive": self.positive,
            "negative": self.negative,
            "unresolved": self.unresolved,
            "total": self.total,
            "value": self.value,
        }


@dataclass(frozen=True, slots=True)
class DifferenceCounts:
    candidate_positive: int
    baseline_positive: int
    numerator: int
    denominator: int
    unresolved: int

    @property
    def value(self) -> float | None:
        return (
            self.numerator / self.denominator if self.denominator and not self.unresolved else None
        )

    def to_dict(self) -> dict[str, JsonValue]:
        return {
            "candidate_positive": self.candidate_positive,
            "baseline_positive": self.baseline_positive,
            "numerator": self.numerator,
            "denominator": self.denominator,
            "unresolved": self.unresolved,
            "value": self.value,
        }


@dataclass(frozen=True, slots=True)
class Discordance:
    both_positive: int
    candidate_only: int
    baseline_only: int
    both_negative: int
    unresolved: int
    total_pairs: int

    def to_dict(self) -> dict[str, JsonValue]:
        return {
            "both_positive": self.both_positive,
            "candidate_only": self.candidate_only,
            "baseline_only": self.baseline_only,
            "both_negative": self.both_negative,
            "unresolved": self.unresolved,
            "total_pairs": self.total_pairs,
        }


@dataclass(frozen=True, slots=True)
class ConfidenceInterval:
    lower: float | None
    upper: float | None

    def to_dict(self) -> dict[str, JsonValue]:
        return {"lower": self.lower, "upper": self.upper}


@dataclass(frozen=True, slots=True)
class ProjectClusteredEffect:
    estimate: float | None
    standard_error: float | None
    lower_bound: float | None
    upper_bound: float | None

    def to_dict(self) -> dict[str, JsonValue]:
        return {
            "estimate": self.estimate,
            "standard_error": self.standard_error,
            "lower_bound": self.lower_bound,
            "upper_bound": self.upper_bound,
        }


@dataclass(frozen=True, slots=True)
class CaseWeightedCR1Statistic:
    case_count: int
    project_count: int
    unresolved_cases: int
    one_sided_alpha: float
    critical_value: float
    vulnerable_lift: ProjectClusteredEffect
    fixed_false_positive_increase: ProjectClusteredEffect

    @property
    def complete(self) -> bool:
        return self.unresolved_cases == 0

    def to_dict(self) -> dict[str, JsonValue]:
        return {
            "analysis_method": "case-weighted-cr1-project-clustered-normal-bound-v1",
            "case_count": self.case_count,
            "project_count": self.project_count,
            "unresolved_cases": self.unresolved_cases,
            "complete": self.complete,
            "one_sided_alpha": self.one_sided_alpha,
            "critical_value": self.critical_value,
            "vulnerable_lift": self.vulnerable_lift.to_dict(),
            "fixed_false_positive_increase": (self.fixed_false_positive_increase.to_dict()),
        }


@dataclass(frozen=True, slots=True)
class ModeMetrics:
    mode: AnalysisMode
    complete: bool
    vulnerable_baseline: OutcomeCounts
    vulnerable_candidate: OutcomeCounts
    fixed_baseline: OutcomeCounts
    fixed_candidate: OutcomeCounts
    vulnerable_lift: DifferenceCounts
    fixed_false_positive_increase: DifferenceCounts
    net_useful_lift: DifferenceCounts
    vulnerable_discordance: Discordance
    fixed_discordance: Discordance
    intervals: tuple[tuple[str, ConfidenceInterval], ...]

    def to_dict(self) -> dict[str, JsonValue]:
        return {
            "mode": self.mode,
            "complete": self.complete,
            "rates": {
                "vulnerable_baseline": self.vulnerable_baseline.to_dict(),
                "vulnerable_candidate": self.vulnerable_candidate.to_dict(),
                "fixed_baseline": self.fixed_baseline.to_dict(),
                "fixed_candidate": self.fixed_candidate.to_dict(),
            },
            "differences": {
                "vulnerable_lift": self.vulnerable_lift.to_dict(),
                "fixed_false_positive_increase": self.fixed_false_positive_increase.to_dict(),
                "net_useful_lift": self.net_useful_lift.to_dict(),
            },
            "discordance": {
                "vulnerable": self.vulnerable_discordance.to_dict(),
                "fixed": self.fixed_discordance.to_dict(),
            },
            "intervals": {name: interval.to_dict() for name, interval in self.intervals},
        }


@dataclass(frozen=True, slots=True)
class RepetitionStability:
    snapshot: str
    condition: str
    case_count: int
    repetitions: int
    complete_cases: int
    unresolved_cases: int
    discordant_cases: int
    mean_within_case_variance: float | None

    def to_dict(self) -> dict[str, JsonValue]:
        return {
            "snapshot": self.snapshot,
            "condition": self.condition,
            "case_count": self.case_count,
            "repetitions": self.repetitions,
            "complete_cases": self.complete_cases,
            "unresolved_cases": self.unresolved_cases,
            "discordant_cases": self.discordant_cases,
            "mean_within_case_variance": self.mean_within_case_variance,
        }


@dataclass(frozen=True, slots=True)
class AccuracyCounts:
    correct: int
    incorrect: int
    unresolved: int

    @property
    def total(self) -> int:
        return self.correct + self.incorrect + self.unresolved

    @property
    def value(self) -> float | None:
        denominator = self.correct + self.incorrect
        return self.correct / denominator if denominator else None

    def to_dict(self) -> dict[str, JsonValue]:
        return {
            "correct": self.correct,
            "incorrect": self.incorrect,
            "unresolved": self.unresolved,
            "total": self.total,
            "value": self.value,
        }


@dataclass(frozen=True, slots=True)
class QualityMetrics:
    condition: str
    valid_output: AccuracyCounts
    acceptable_path: AccuracyCounts
    category: AccuracyCounts
    mechanism: AccuracyCounts
    severity: AccuracyCounts

    def to_dict(self) -> dict[str, JsonValue]:
        return {
            "condition": self.condition,
            "valid_output": self.valid_output.to_dict(),
            "acceptable_path": self.acceptable_path.to_dict(),
            "category": self.category.to_dict(),
            "mechanism": self.mechanism.to_dict(),
            "severity": self.severity.to_dict(),
        }


@dataclass(frozen=True, slots=True)
class Distribution:
    source: str
    observations: int
    missing: int
    minimum: float | None
    median: float | None
    p95: float | None
    maximum: float | None
    mean: float | None
    total: float | None

    def to_dict(self) -> dict[str, JsonValue]:
        return {
            "source": self.source,
            "observations": self.observations,
            "missing": self.missing,
            "minimum": self.minimum,
            "median": self.median,
            "p95": self.p95,
            "maximum": self.maximum,
            "mean": self.mean,
            "total": self.total,
        }


@dataclass(frozen=True, slots=True)
class OperationalMetrics:
    condition: str
    latency_ms: Distribution
    provider_input_tokens: Distribution
    provider_cached_input_tokens: Distribution
    provider_output_tokens: Distribution
    provider_reasoning_tokens: Distribution
    tokenizer_estimated_input_tokens: Distribution

    def to_dict(self) -> dict[str, JsonValue]:
        return {
            "condition": self.condition,
            "latency_ms": self.latency_ms.to_dict(),
            "provider_input_tokens": self.provider_input_tokens.to_dict(),
            "provider_cached_input_tokens": self.provider_cached_input_tokens.to_dict(),
            "provider_output_tokens": self.provider_output_tokens.to_dict(),
            "provider_reasoning_tokens": self.provider_reasoning_tokens.to_dict(),
            "tokenizer_estimated_input_tokens": self.tokenizer_estimated_input_tokens.to_dict(),
        }


@dataclass(frozen=True, slots=True)
class ExploratoryBreakdown:
    dimension: str
    value: str
    case_count: int
    modes: tuple[ModeMetrics, ...]

    def to_dict(self) -> dict[str, JsonValue]:
        return {
            "dimension": self.dimension,
            "value": self.value,
            "case_count": self.case_count,
            "exploratory": True,
            "modes": [mode.to_dict() for mode in self.modes],
        }


@dataclass(frozen=True, slots=True)
class StatisticsResult:
    experiment_id: str
    experiment_digest: str
    score_result_digest: str
    case_count: int
    repetitions: int
    modes: tuple[ModeMetrics, ...]
    repetition_stability: tuple[RepetitionStability, ...]
    quality: tuple[QualityMetrics, ...]
    operations: tuple[OperationalMetrics, ...]
    exploratory_breakdowns: tuple[ExploratoryBreakdown, ...]
    terminal_status_counts: tuple[tuple[str, int], ...]
    cost: CostAccounting
    small_context_max_tokens: int
    medium_context_max_tokens: int

    def to_dict(self) -> dict[str, JsonValue]:
        return {
            "experiment_id": self.experiment_id,
            "experiment_digest": self.experiment_digest,
            "score_result_digest": self.score_result_digest,
            "primary_paired_unit": "case",
            "case_count": self.case_count,
            "repetitions": self.repetitions,
            "interval_method": {
                "name": "paired-case-percentile-bootstrap-nearest-rank",
                "confidence_level": BOOTSTRAP_LEVEL,
                "resamples": BOOTSTRAP_RESAMPLES,
                "generator": "numpy.PCG64",
                "seed": BOOTSTRAP_SEED,
            },
            "context_size_bands": {
                "small_max_tokens": self.small_context_max_tokens,
                "medium_max_tokens": self.medium_context_max_tokens,
            },
            "modes": [mode.to_dict() for mode in self.modes],
            "repetition_stability": [item.to_dict() for item in self.repetition_stability],
            "quality": [item.to_dict() for item in self.quality],
            "operations": [item.to_dict() for item in self.operations],
            "exploratory_breakdowns": [item.to_dict() for item in self.exploratory_breakdowns],
            "terminal_status_counts": {
                status: count for status, count in self.terminal_status_counts
            },
            "cost": self.cost.to_dict(),
        }


@dataclass(frozen=True, slots=True)
class _CaseOutcomes:
    case_id: str
    cells: Mapping[tuple[str, str], tuple[ScoredRun, ...]]


def calculate_statistics(
    experiment: ExperimentManifest,
    scoring: ScoringResult,
    run_records: Sequence[RunRecord],
    gold_records: Sequence[GoldRecord],
    price_table: PriceTable,
    *,
    provider: str,
    small_context_max_tokens: int = 2_000,
    medium_context_max_tokens: int = 8_000,
    recovery_experiment: ExperimentManifest | None = None,
    recovery_records: Sequence[RunRecord] = (),
    attempt_metadata: Sequence[AttemptMetadata] | None = None,
    recovery_attempt_metadata: Sequence[AttemptMetadata] | None = None,
    allow_frozen_m31_legacy: bool = False,
) -> StatisticsResult:
    """Calculate deterministic primary/sensitivity metrics over case-clustered outcomes."""

    experiment = ExperimentManifest.from_dict(experiment.to_dict())
    scoring = ScoringResult.from_dict(scoring.to_dict())
    run_records = tuple(RunRecord.from_dict(record.to_dict()) for record in run_records)
    gold_records = tuple(GoldRecord.from_dict(record.to_dict()) for record in gold_records)
    recovery_experiment = (
        ExperimentManifest.from_dict(recovery_experiment.to_dict())
        if recovery_experiment is not None
        else None
    )
    recovery_records = tuple(RunRecord.from_dict(record.to_dict()) for record in recovery_records)
    if (
        not experiment.frozen
        or experiment.content_digest is None
        or scoring.experiment_id != experiment.experiment_id
        or scoring.experiment_digest != experiment.content_digest
        or scoring.invalid_output_policy != experiment.invalid_output_policy
    ):
        raise SchemaError("statistics inputs do not match one frozen experiment")
    if small_context_max_tokens < 1 or medium_context_max_tokens <= small_context_max_tokens:
        raise SchemaError("statistics context-size bands are invalid")
    records_by_id = _unique(run_records, key=lambda item: item.run_id, kind="run record")
    effective_by_id = records_by_id
    recovered_by_id: dict[str, RunRecord] = {}
    if recovery_experiment is None:
        if recovery_records:
            raise SchemaError("statistics recovery records require a linked recovery experiment")
    else:
        effective_by_id = overlay_recovery_records(
            experiment,
            run_records,
            recovery_experiment,
            recovery_records,
            allow_frozen_m31_legacy=allow_frozen_m31_legacy,
        )
        recovered_by_id = {record.run_id: record for record in recovery_records}
    gold_by_case = _unique(gold_records, key=lambda item: item.case_id, kind="gold record")
    planned_by_id = {item.run_id: item for item in experiment.execution_order}
    scored_by_id = {item.run_id: item for item in scoring.runs}
    expected_cases = {item.case_id for item in experiment.cases}
    if (
        set(scored_by_id) != set(planned_by_id)
        or set(records_by_id) != set(scored_by_id)
        or set(gold_by_case) != expected_cases
    ):
        raise SchemaError("statistics require the complete frozen score and record set")
    for run_id, scored in scored_by_id.items():
        planned = planned_by_id[run_id]
        record = records_by_id[run_id]
        effective_record = effective_by_id[run_id]
        gold = gold_by_case[planned.case_id]
        _validate_execution_identity(experiment, planned, record)
        if (
            (scored.case_id, scored.snapshot, scored.condition, scored.repetition)
            != (planned.case_id, planned.snapshot, planned.condition, planned.repetition)
            or scored.run_record_digest
            != overlaid_run_record_digest(record, recovered_by_id.get(run_id))
            or scored.planned_run_digest != canonical_digest(_planned_run_dict(planned))
            or scored.gold_digest != canonical_digest(gold.to_dict())
            or scored.terminal_status != effective_record.status
        ):
            raise SchemaError("statistics input provenance does not match the scored run")
    cases = _case_outcomes(experiment, scoring)
    modes = _primary_modes(cases)
    return StatisticsResult(
        experiment_id=experiment.experiment_id,
        experiment_digest=experiment.content_digest,
        score_result_digest=scoring.content_digest,
        case_count=len(cases),
        repetitions=experiment.repetitions,
        modes=modes,
        repetition_stability=_repetition_stability(cases, experiment.repetitions),
        quality=tuple(
            _quality_metrics(scoring.runs, condition)
            for condition in ("all", "baseline", "candidate")
        ),
        operations=tuple(
            _operational_metrics(
                experiment,
                effective_by_id,
                condition,
            )
            for condition in ("all", "baseline", "candidate")
        ),
        exploratory_breakdowns=_breakdowns(
            experiment,
            cases,
            gold_by_case,
            small_context_max_tokens=small_context_max_tokens,
            medium_context_max_tokens=medium_context_max_tokens,
        ),
        terminal_status_counts=tuple(
            sorted(
                {
                    status: sum(run.terminal_status == status for run in scoring.runs)
                    for status in {run.terminal_status for run in scoring.runs}
                }.items()
            )
        ),
        cost=account_costs(
            experiment,
            run_records,
            price_table,
            provider=provider,
            recovery_experiment=recovery_experiment,
            recovery_records=recovery_records,
            attempt_metadata=attempt_metadata,
            recovery_attempt_metadata=recovery_attempt_metadata,
            allow_frozen_m31_legacy=allow_frozen_m31_legacy,
        ),
        small_context_max_tokens=small_context_max_tokens,
        medium_context_max_tokens=medium_context_max_tokens,
    )


def calculate_combined_holdout_statistics(
    experiment: ExperimentManifest,
    scoring: ScoringResult,
    development_records: Sequence[RunRecord],
    holdout_experiment: ExperimentManifest,
    holdout_records: Sequence[RunRecord],
    gold_records: Sequence[GoldRecord],
    price_table: PriceTable,
    *,
    provider: str,
    recovery_experiment: ExperimentManifest,
    recovery_records: Sequence[RunRecord],
    development_attempt_metadata: Sequence[AttemptMetadata] | None = None,
    holdout_attempt_metadata: Sequence[AttemptMetadata] | None = None,
    recovery_attempt_metadata: Sequence[AttemptMetadata] | None = None,
    allow_frozen_m31_legacy: bool = False,
    recovery_attempt_ceiling: int | None = None,
    small_context_max_tokens: int = 2_000,
    medium_context_max_tokens: int = 8_000,
) -> StatisticsResult:
    """Calculate one combined statistic over linked development, holdout, and retry stages."""

    from preflight_evals.holdout import validate_holdout_source

    experiment = ExperimentManifest.from_dict(experiment.to_dict())
    scoring = ScoringResult.from_dict(scoring.to_dict())
    development_records = tuple(
        RunRecord.from_dict(record.to_dict()) for record in development_records
    )
    holdout_experiment = ExperimentManifest.from_dict(holdout_experiment.to_dict())
    holdout_records = tuple(RunRecord.from_dict(record.to_dict()) for record in holdout_records)
    recovery_experiment = ExperimentManifest.from_dict(recovery_experiment.to_dict())
    recovery_records = tuple(RunRecord.from_dict(record.to_dict()) for record in recovery_records)
    gold_records = tuple(GoldRecord.from_dict(record.to_dict()) for record in gold_records)
    if (
        not experiment.frozen
        or experiment.content_digest is None
        or scoring.experiment_id != experiment.experiment_id
        or scoring.experiment_digest != experiment.content_digest
        or scoring.invalid_output_policy != experiment.invalid_output_policy
        or small_context_max_tokens < 1
        or medium_context_max_tokens <= small_context_max_tokens
    ):
        raise SchemaError("combined statistics inputs do not match one frozen experiment")
    validate_holdout_source(holdout_experiment, experiment, development_records)
    effective_holdout = overlay_recovery_records(
        holdout_experiment,
        holdout_records,
        recovery_experiment,
        recovery_records,
        allow_frozen_m31_legacy=allow_frozen_m31_legacy,
    )
    roles = {case.case_id: case.role for case in experiment.cases}
    planned_by_id = {run.run_id: run for run in experiment.execution_order}
    development_plan = {
        run.run_id: run for run in experiment.execution_order if roles[run.case_id] == "development"
    }
    holdout_plan = {run.run_id: run for run in holdout_experiment.execution_order}
    development_by_id = _unique(
        development_records, key=lambda item: item.run_id, kind="development run record"
    )
    holdout_by_id = _unique(
        holdout_records, key=lambda item: item.run_id, kind="holdout run record"
    )
    recovered_by_id = _unique(
        recovery_records, key=lambda item: item.run_id, kind="holdout recovery run record"
    )
    gold_by_case = _unique(gold_records, key=lambda item: item.case_id, kind="gold record")
    scored_by_id = {item.run_id: item for item in scoring.runs}
    if (
        set(development_by_id) != set(development_plan)
        or set(holdout_by_id) != set(holdout_plan)
        or set(development_plan) | set(holdout_plan) != set(planned_by_id)
        or set(scored_by_id) != set(planned_by_id)
        or set(gold_by_case) != {case.case_id for case in experiment.cases}
    ):
        raise SchemaError("combined statistics require every frozen run and gold record")
    effective_by_id = {**development_by_id, **effective_holdout}
    for run_id, scored in scored_by_id.items():
        planned = planned_by_id[run_id]
        is_development = run_id in development_by_id
        source_record = development_by_id[run_id] if is_development else holdout_by_id[run_id]
        effective_record = effective_by_id[run_id]
        gold = gold_by_case[planned.case_id]
        _validate_execution_identity(
            experiment if is_development else holdout_experiment,
            planned,
            source_record,
        )
        if (
            (scored.case_id, scored.snapshot, scored.condition, scored.repetition)
            != (planned.case_id, planned.snapshot, planned.condition, planned.repetition)
            or scored.run_record_digest
            != overlaid_run_record_digest(source_record, recovered_by_id.get(run_id))
            or scored.planned_run_digest != canonical_digest(_planned_run_dict(planned))
            or scored.gold_digest != canonical_digest(gold.to_dict())
            or scored.terminal_status != effective_record.status
        ):
            raise SchemaError("combined statistics provenance does not match the scored run")

    cost = _combined_stage_costs(
        experiment,
        development_records,
        holdout_experiment,
        holdout_records,
        recovery_experiment,
        recovery_records,
        price_table,
        provider=provider,
        development_attempt_metadata=development_attempt_metadata,
        holdout_attempt_metadata=holdout_attempt_metadata,
        recovery_attempt_metadata=recovery_attempt_metadata,
        allow_frozen_m31_legacy=allow_frozen_m31_legacy,
        recovery_attempt_ceiling=recovery_attempt_ceiling,
    )
    cases = _case_outcomes(experiment, scoring)
    modes = _primary_modes(cases)
    return StatisticsResult(
        experiment_id=experiment.experiment_id,
        experiment_digest=experiment.content_digest,
        score_result_digest=scoring.content_digest,
        case_count=len(cases),
        repetitions=experiment.repetitions,
        modes=modes,
        repetition_stability=_repetition_stability(cases, experiment.repetitions),
        quality=tuple(
            _quality_metrics(scoring.runs, condition)
            for condition in ("all", "baseline", "candidate")
        ),
        operations=tuple(
            _operational_metrics(experiment, effective_by_id, condition)
            for condition in ("all", "baseline", "candidate")
        ),
        exploratory_breakdowns=_breakdowns(
            experiment,
            cases,
            gold_by_case,
            small_context_max_tokens=small_context_max_tokens,
            medium_context_max_tokens=medium_context_max_tokens,
        ),
        terminal_status_counts=tuple(
            sorted(
                {
                    status: sum(run.terminal_status == status for run in scoring.runs)
                    for status in {run.terminal_status for run in scoring.runs}
                }.items()
            )
        ),
        cost=cost,
        small_context_max_tokens=small_context_max_tokens,
        medium_context_max_tokens=medium_context_max_tokens,
    )


def calculate_case_weighted_cr1(
    experiment: ExperimentManifest,
    scoring: ScoringResult,
    project_by_case: Mapping[str, str],
    *,
    one_sided_alpha: float = 0.025,
) -> CaseWeightedCR1Statistic:
    """Calculate the frozen case-weighted CR1 project-clustered normal bounds."""

    if (
        scoring.experiment_id != experiment.experiment_id
        or scoring.experiment_digest != experiment.content_digest
        or set(project_by_case) != {case.case_id for case in experiment.cases}
        or any(not project for project in project_by_case.values())
        or not 0 < one_sided_alpha < 0.5
    ):
        raise SchemaError("project-clustered statistic inputs do not match the experiment")
    cases = _case_outcomes(experiment, scoring)
    projects = sorted(set(project_by_case.values()))
    if len(projects) < 2:
        raise SchemaError("project-clustered statistics require at least two projects")
    project_index = {project: index for index, project in enumerate(projects)}
    clusters = np.asarray(
        [project_index[project_by_case[case.case_id]] for case in cases], dtype=np.int64
    )
    values = {
        cell: [_cell_values(case.cells[cell], "primary") for case in cases] for cell in _CELL_ORDER
    }
    effects = _case_effects(values)
    unresolved = sum(
        any(value is None for effect in effects.values() for value in (effect[index],))
        for index in range(len(cases))
    )
    critical = NormalDist().inv_cdf(1 - one_sided_alpha)
    if unresolved:
        unavailable = ProjectClusteredEffect(None, None, None, None)
        return CaseWeightedCR1Statistic(
            case_count=len(cases),
            project_count=len(projects),
            unresolved_cases=unresolved,
            one_sided_alpha=one_sided_alpha,
            critical_value=critical,
            vulnerable_lift=unavailable,
            fixed_false_positive_increase=unavailable,
        )
    return CaseWeightedCR1Statistic(
        case_count=len(cases),
        project_count=len(projects),
        unresolved_cases=0,
        one_sided_alpha=one_sided_alpha,
        critical_value=critical,
        vulnerable_lift=_clustered_effect(
            cast(Sequence[float], effects["vulnerable_lift"]), clusters, critical
        ),
        fixed_false_positive_increase=_clustered_effect(
            cast(Sequence[float], effects["fixed_false_positive_increase"]),
            clusters,
            critical,
        ),
    )


def _combined_stage_costs(
    experiment: ExperimentManifest,
    development_records: Sequence[RunRecord],
    holdout_experiment: ExperimentManifest,
    holdout_records: Sequence[RunRecord],
    recovery_experiment: ExperimentManifest,
    recovery_records: Sequence[RunRecord],
    price_table: PriceTable,
    *,
    provider: str,
    development_attempt_metadata: Sequence[AttemptMetadata] | None,
    holdout_attempt_metadata: Sequence[AttemptMetadata] | None,
    recovery_attempt_metadata: Sequence[AttemptMetadata] | None,
    allow_frozen_m31_legacy: bool = False,
    recovery_attempt_ceiling: int | None = None,
) -> CostAccounting:
    development = account_costs(
        experiment,
        development_records,
        price_table,
        provider=provider,
        attempt_metadata=development_attempt_metadata,
    )
    holdout = account_costs(
        holdout_experiment,
        holdout_records,
        price_table,
        provider=provider,
        recovery_experiment=recovery_experiment,
        recovery_records=recovery_records,
        attempt_metadata=holdout_attempt_metadata,
        recovery_attempt_metadata=recovery_attempt_metadata,
        allow_frozen_m31_legacy=allow_frozen_m31_legacy,
    )
    if (
        development.price_table_version != holdout.price_table_version
        or development.price_effective_date != holdout.price_effective_date
        or development.price_source != holdout.price_source
        or development.provider != holdout.provider
        or development.model != holdout.model
    ):
        raise SchemaError("combined cost stages do not use one frozen price identity")
    unknown = development.unknown_usage_or_price_runs + holdout.unknown_usage_or_price_runs
    unaccounted = development.unaccounted_retry_attempts + holdout.unaccounted_retry_attempts
    known = (
        _stable_sum(
            [
                development.known_terminal_cost_usd,
                holdout.known_terminal_cost_usd,
            ]
        )
        if development.known_terminal_cost_usd is not None
        and holdout.known_terminal_cost_usd is not None
        else None
    )
    actual = known if unknown == 0 and unaccounted == 0 else None
    source_projection = experiment.price_projection
    recovery_projection = recovery_experiment.price_projection
    recovery_projected_cost = None
    if recovery_projection is not None:
        recovery_projected_cost = recovery_projection.projected_cost_usd
        if recovery_attempt_ceiling is not None:
            maximum_provider_calls = (
                recovery_experiment.planned_run_count * recovery_attempt_ceiling
            )
            recovery_projected_cost = (
                (
                    maximum_provider_calls
                    * recovery_experiment.reviewer_config.input_token_limit
                    * recovery_projection.input_usd_per_million_tokens
                    + maximum_provider_calls
                    * recovery_experiment.reviewer_config.output_token_limit
                    * recovery_projection.output_usd_per_million_tokens
                )
                / 1_000_000
                * (1 + recovery_projection.contingency_rate)
            )
    frozen_worst_case = (
        _stable_sum([source_projection.projected_cost_usd, recovery_projected_cost])
        if source_projection is not None and recovery_projected_cost is not None
        else None
    )
    return CostAccounting(
        price_table_version=development.price_table_version,
        price_effective_date=development.price_effective_date,
        price_source=development.price_source,
        provider=development.provider,
        model=development.model,
        completed_runs=len(development_records) + len(holdout_records),
        unfinished_runs=0,
        provider_usage_runs=(development.provider_usage_runs + holdout.provider_usage_runs),
        unknown_usage_or_price_runs=unknown,
        unaccounted_retry_attempts=unaccounted,
        known_terminal_cost_usd=known,
        actual_cost_usd=actual,
        projected_remaining_cost_usd=0.0,
        projected_total_cost_usd=actual,
        frozen_worst_case_cost_usd=frozen_worst_case,
        projection_method=(
            "combined-development-holdout-linked-retry-effective-terminal-"
            "plus-unaccounted-prior-attempts"
        ),
    )


def _clustered_effect(
    values: Sequence[float], project_index: np.ndarray, critical: float
) -> ProjectClusteredEffect:
    array = np.asarray(values, dtype=np.float64)
    if array.ndim != 1 or project_index.shape != array.shape:
        raise SchemaError("project membership must identify every case effect")
    projects = int(np.max(project_index)) + 1
    if projects < 2 or set(project_index.tolist()) != set(range(projects)):
        raise SchemaError("project membership must be contiguous and contain two projects")
    estimate = float(np.mean(array))
    centered = array - estimate
    cluster_scores = np.asarray(
        [np.sum(centered[project_index == project]) for project in range(projects)],
        dtype=np.float64,
    )
    variance = projects / (projects - 1) * float(np.sum(cluster_scores**2)) / len(array) ** 2
    standard_error = math.sqrt(max(variance, 0.0))
    return ProjectClusteredEffect(
        estimate=estimate,
        standard_error=standard_error,
        lower_bound=estimate - critical * standard_error,
        upper_bound=estimate + critical * standard_error,
    )


def _case_outcomes(
    experiment: ExperimentManifest, scoring: ScoringResult
) -> tuple[_CaseOutcomes, ...]:
    runs_by_case: dict[str, list[ScoredRun]] = {}
    for run in scoring.runs:
        runs_by_case.setdefault(run.case_id, []).append(run)
    cases: list[_CaseOutcomes] = []
    for case_id in sorted(runs_by_case):
        cells: dict[tuple[str, str], tuple[ScoredRun, ...]] = {}
        for snapshot, condition in _CELL_ORDER:
            cell = tuple(
                sorted(
                    (
                        run
                        for run in runs_by_case[case_id]
                        if run.snapshot == snapshot and run.condition == condition
                    ),
                    key=lambda item: item.repetition,
                )
            )
            if [run.repetition for run in cell] != list(range(1, experiment.repetitions + 1)):
                raise SchemaError("statistics require every repetition in each paired case cell")
            cells[(snapshot, condition)] = cell
        cases.append(_CaseOutcomes(case_id=case_id, cells=cells))
    return tuple(cases)


def _validate_execution_identity(
    experiment: ExperimentManifest, planned: PlannedRun, record: RunRecord
) -> None:
    identity = record.identity
    experiment_case = next(case for case in experiment.cases if case.case_id == planned.case_id)
    expected_source = (
        experiment_case.vulnerable_snapshot
        if planned.snapshot == "vulnerable"
        else experiment_case.fixed_snapshot
    )
    expected_profile = (
        experiment.baseline_profile.digest
        if planned.condition == "baseline"
        else experiment.candidate_profile.digest
    )
    if (
        record.experiment_id != experiment.experiment_id
        or identity is None
        or identity.experiment_content_digest != experiment.content_digest
        or identity.source_commit != expected_source
        or identity.profile_digest != expected_profile
        or record.seed != planned.request_seed
    ):
        raise SchemaError("statistics run record does not match the frozen execution identity")


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


def _resample_indices(case_count: int) -> NDArray[np.int64]:
    generator = np.random.Generator(np.random.PCG64(BOOTSTRAP_SEED))
    indices = generator.integers(
        0, case_count, size=(BOOTSTRAP_RESAMPLES, case_count), dtype=np.int64
    )
    indices.setflags(write=False)
    return indices


def _primary_modes(cases: Sequence[_CaseOutcomes]) -> tuple[ModeMetrics, ...]:
    # Share lazily within one calculation; do not retain large matrices globally.
    cached: NDArray[np.int64] | None = None

    def indices() -> NDArray[np.int64]:
        nonlocal cached
        if cached is None:
            cached = _resample_indices(len(cases))
        return cached

    return tuple(
        _mode_metrics(cases, mode, bootstrap=True, resample_indices=indices) for mode in _MODES
    )


def _mode_metrics(
    cases: Sequence[_CaseOutcomes],
    mode: AnalysisMode,
    *,
    bootstrap: bool,
    resample_indices: Callable[[], NDArray[np.int64]] | None = None,
) -> ModeMetrics:
    cell_values = {
        cell: [_cell_values(case.cells[cell], mode) for case in cases] for cell in _CELL_ORDER
    }
    rates = {cell: _outcome_counts(_flatten(values)) for cell, values in cell_values.items()}
    vulnerable_lift = _difference_counts(
        cell_values[("vulnerable", "baseline")],
        cell_values[("vulnerable", "candidate")],
    )
    fixed_increase = _difference_counts(
        cell_values[("fixed", "baseline")],
        cell_values[("fixed", "candidate")],
    )
    net = DifferenceCounts(
        candidate_positive=(
            rates[("vulnerable", "candidate")].positive + rates[("fixed", "baseline")].positive
        ),
        baseline_positive=(
            rates[("vulnerable", "baseline")].positive + rates[("fixed", "candidate")].positive
        ),
        numerator=vulnerable_lift.numerator - fixed_increase.numerator,
        denominator=vulnerable_lift.denominator,
        unresolved=vulnerable_lift.unresolved + fixed_increase.unresolved,
    )
    effects = _case_effects(cell_values)
    intervals = (
        _bootstrap_intervals(effects, resample_indices=resample_indices)
        if bootstrap and all(value is not None for values in effects.values() for value in values)
        else tuple(
            (name, ConfidenceInterval(lower=None, upper=None))
            for name in (
                "vulnerable_lift",
                "fixed_false_positive_increase",
                "net_useful_lift",
            )
        )
    )
    unresolved = sum(rate.unresolved for rate in rates.values())
    return ModeMetrics(
        mode=mode,
        complete=unresolved == 0,
        vulnerable_baseline=rates[("vulnerable", "baseline")],
        vulnerable_candidate=rates[("vulnerable", "candidate")],
        fixed_baseline=rates[("fixed", "baseline")],
        fixed_candidate=rates[("fixed", "candidate")],
        vulnerable_lift=vulnerable_lift,
        fixed_false_positive_increase=fixed_increase,
        net_useful_lift=net,
        vulnerable_discordance=_discordance(
            cell_values[("vulnerable", "baseline")],
            cell_values[("vulnerable", "candidate")],
        ),
        fixed_discordance=_discordance(
            cell_values[("fixed", "baseline")],
            cell_values[("fixed", "candidate")],
        ),
        intervals=intervals,
    )


def _cell_values(runs: Sequence[ScoredRun], mode: AnalysisMode) -> tuple[bool | None, ...]:
    if mode == "primary":
        return tuple(run.primary_outcome for run in runs)
    if mode == "pessimistic":
        return tuple(run.pessimistic_outcome for run in runs)
    return tuple(run.optimistic_outcome for run in runs)


def _outcome_counts(values: Sequence[bool | None]) -> OutcomeCounts:
    positive = sum(value is True for value in values)
    negative = sum(value is False for value in values)
    return OutcomeCounts(
        positive=positive,
        negative=negative,
        unresolved=len(values) - positive - negative,
        total=len(values),
    )


def _difference_counts(
    baseline: Sequence[Sequence[bool | None]],
    candidate: Sequence[Sequence[bool | None]],
) -> DifferenceCounts:
    baseline_values = tuple(_flatten(baseline))
    candidate_values = tuple(_flatten(candidate))
    baseline_counts = _outcome_counts(baseline_values)
    candidate_counts = _outcome_counts(candidate_values)
    return DifferenceCounts(
        candidate_positive=candidate_counts.positive,
        baseline_positive=baseline_counts.positive,
        numerator=candidate_counts.positive - baseline_counts.positive,
        denominator=len(baseline_values),
        unresolved=baseline_counts.unresolved + candidate_counts.unresolved,
    )


def _discordance(
    baseline: Sequence[Sequence[bool | None]],
    candidate: Sequence[Sequence[bool | None]],
) -> Discordance:
    pairs = list(zip(_flatten(baseline), _flatten(candidate), strict=True))
    return Discordance(
        both_positive=sum(left is True and right is True for left, right in pairs),
        candidate_only=sum(left is False and right is True for left, right in pairs),
        baseline_only=sum(left is True and right is False for left, right in pairs),
        both_negative=sum(left is False and right is False for left, right in pairs),
        unresolved=sum(left is None or right is None for left, right in pairs),
        total_pairs=len(pairs),
    )


def _case_effects(
    values: Mapping[tuple[str, str], Sequence[Sequence[bool | None]]],
) -> dict[str, list[float | None]]:
    effects: dict[str, list[float | None]] = {
        "vulnerable_lift": [],
        "fixed_false_positive_increase": [],
        "net_useful_lift": [],
    }
    for index in range(len(values[("vulnerable", "baseline")])):
        means = {cell: _optional_mean(values[cell][index]) for cell in _CELL_ORDER}
        vulnerable = _optional_difference(
            means[("vulnerable", "candidate")], means[("vulnerable", "baseline")]
        )
        fixed = _optional_difference(means[("fixed", "candidate")], means[("fixed", "baseline")])
        effects["vulnerable_lift"].append(vulnerable)
        effects["fixed_false_positive_increase"].append(fixed)
        effects["net_useful_lift"].append(
            vulnerable - fixed if vulnerable is not None and fixed is not None else None
        )
    return effects


def _bootstrap_intervals(
    effects: Mapping[str, Sequence[float | None]],
    *,
    resample_indices: Callable[[], NDArray[np.int64]] | None = None,
) -> tuple[tuple[str, ConfidenceInterval], ...]:
    case_count = len(next(iter(effects.values())))
    indices = resample_indices() if resample_indices is not None else _resample_indices(case_count)
    intervals: list[tuple[str, ConfidenceInterval]] = []
    for name in (
        "vulnerable_lift",
        "fixed_false_positive_increase",
        "net_useful_lift",
    ):
        array = np.asarray(cast(Sequence[float], effects[name]), dtype=np.float64)
        samples = np.mean(array[indices], axis=1)
        ordered = np.sort(samples)
        intervals.append(
            (
                name,
                ConfidenceInterval(
                    lower=float(ordered[_nearest_rank_index(0.025, BOOTSTRAP_RESAMPLES)]),
                    upper=float(ordered[_nearest_rank_index(0.975, BOOTSTRAP_RESAMPLES)]),
                ),
            )
        )
    return tuple(intervals)


def _nearest_rank_index(probability: float, count: int) -> int:
    return max(0, min(count - 1, math.ceil(probability * count) - 1))


def _repetition_stability(
    cases: Sequence[_CaseOutcomes], repetitions: int
) -> tuple[RepetitionStability, ...]:
    results: list[RepetitionStability] = []
    for snapshot, condition in _CELL_ORDER:
        values = [_cell_values(case.cells[(snapshot, condition)], "primary") for case in cases]
        complete = [item for item in values if all(value is not None for value in item)]
        variances = [
            float(np.var(np.asarray(cast(tuple[bool, ...], item), dtype=np.float64)))
            for item in complete
        ]
        results.append(
            RepetitionStability(
                snapshot=snapshot,
                condition=condition,
                case_count=len(cases),
                repetitions=repetitions,
                complete_cases=len(complete),
                unresolved_cases=len(cases) - len(complete),
                discordant_cases=sum(len(set(item)) > 1 for item in complete),
                mean_within_case_variance=(_stable_mean(variances) if variances else None),
            )
        )
    return tuple(results)


def _quality_metrics(runs: Sequence[ScoredRun], condition: str) -> QualityMetrics:
    selected = [run for run in runs if condition == "all" or run.condition == condition]
    findings = [
        finding for run in selected for finding in run.findings if finding.duplicate_of is None
    ]
    valid = AccuracyCounts(
        correct=sum(run.terminal_status == "succeeded" for run in selected),
        incorrect=sum(run.terminal_status != "succeeded" for run in selected),
        unresolved=0,
    )
    return QualityMetrics(
        condition=condition,
        valid_output=valid,
        acceptable_path=_finding_accuracy(findings, lambda finding: finding.path_match != "none"),
        category=_finding_accuracy(findings, lambda finding: finding.category_match),
        mechanism=_mechanism_accuracy(findings),
        severity=_finding_accuracy(findings, lambda finding: finding.severity_match),
    )


def _finding_accuracy(
    findings: Sequence[ScoredFinding], predicate: Callable[[ScoredFinding], bool]
) -> AccuracyCounts:
    correct = sum(predicate(finding) for finding in findings)
    return AccuracyCounts(correct=correct, incorrect=len(findings) - correct, unresolved=0)


def _mechanism_accuracy(findings: Sequence[ScoredFinding]) -> AccuracyCounts:
    correct = 0
    incorrect = 0
    unresolved = 0
    for finding in findings:
        decisions = {mechanism.decision for mechanism in finding.mechanisms}
        if "match" in decisions:
            correct += 1
        elif decisions.intersection({"uncertain", "unadjudicated"}):
            unresolved += 1
        else:
            incorrect += 1
    return AccuracyCounts(correct=correct, incorrect=incorrect, unresolved=unresolved)


def _operational_metrics(
    experiment: ExperimentManifest,
    records_by_id: Mapping[str, RunRecord],
    condition: str,
) -> OperationalMetrics:
    planned = [
        item
        for item in experiment.execution_order
        if condition == "all" or item.condition == condition
    ]
    records = [records_by_id[item.run_id] for item in planned]
    return OperationalMetrics(
        condition=condition,
        latency_ms=_distribution(
            [record.monotonic_latency_ms for record in records],
            expected=len(records),
            source="measured",
        ),
        provider_input_tokens=_distribution(
            [record.usage.input_tokens for record in records],
            expected=len(records),
            source="provider_reported",
        ),
        provider_cached_input_tokens=_distribution(
            [record.usage.cached_input_tokens for record in records],
            expected=len(records),
            source="provider_reported",
        ),
        provider_output_tokens=_distribution(
            [record.usage.output_tokens for record in records],
            expected=len(records),
            source="provider_reported",
        ),
        provider_reasoning_tokens=_distribution(
            [record.usage.reasoning_tokens for record in records],
            expected=len(records),
            source="provider_reported",
        ),
        tokenizer_estimated_input_tokens=_distribution(
            [item.estimated_input_tokens for item in planned],
            expected=len(planned),
            source="tokenizer_estimate",
        ),
    )


def _distribution(
    values: Sequence[int | float | None], *, expected: int, source: str
) -> Distribution:
    observed = sorted(float(value) for value in values if value is not None)
    if not observed:
        return Distribution(
            source=source,
            observations=0,
            missing=expected,
            minimum=None,
            median=None,
            p95=None,
            maximum=None,
            mean=None,
            total=None,
        )
    total = _stable_sum(observed)
    return Distribution(
        source=source,
        observations=len(observed),
        missing=expected - len(observed),
        minimum=observed[0],
        median=_linear_median(observed),
        p95=observed[_nearest_rank_index(0.95, len(observed))],
        maximum=observed[-1],
        mean=total / len(observed),
        total=total,
    )


def _breakdowns(
    experiment: ExperimentManifest,
    cases: Sequence[_CaseOutcomes],
    gold_by_case: Mapping[str, GoldRecord],
    *,
    small_context_max_tokens: int,
    medium_context_max_tokens: int,
) -> tuple[ExploratoryBreakdown, ...]:
    tags: dict[tuple[str, str], set[str]] = {}
    planned_by_case: dict[str, list[PlannedRun]] = {}
    for planned in experiment.execution_order:
        planned_by_case.setdefault(planned.case_id, []).append(planned)
    for case in cases:
        gold = gold_by_case[case.case_id]
        if gold.schema_version == "2.0":
            primary = next(
                mechanism
                for mechanism in gold.expected_mechanisms
                if mechanism.evaluation_role == "primary"
            )
            categories = primary.accepted_defect_categories
            severity_range = primary.severity_range
        else:
            categories = gold.accepted_defect_categories
            severity_range = gold.severity_range
        _tag(tags, "repository", _repository(case.case_id), case.case_id)
        for category in categories:
            _tag(tags, "category", category, case.case_id)
        severity = (
            severity_range.minimum
            if severity_range.minimum == severity_range.maximum
            else f"{severity_range.minimum}-to-{severity_range.maximum}"
        )
        _tag(tags, "severity", severity, case.case_id)
        estimates = [
            planned.estimated_input_tokens
            for planned in planned_by_case[case.case_id]
            if planned.estimated_input_tokens is not None
        ]
        context = (
            _context_band(
                max(estimates),
                small_context_max_tokens=small_context_max_tokens,
                medium_context_max_tokens=medium_context_max_tokens,
            )
            if estimates
            else "unknown"
        )
        _tag(tags, "context_size", context, case.case_id)
    case_by_id = {case.case_id: case for case in cases}
    return tuple(
        ExploratoryBreakdown(
            dimension=dimension,
            value=value,
            case_count=len(case_ids),
            modes=tuple(
                _mode_metrics(
                    [case_by_id[case_id] for case_id in sorted(case_ids)],
                    mode,
                    bootstrap=False,
                )
                for mode in _MODES
            ),
        )
        for (dimension, value), case_ids in sorted(tags.items())
    )


def _tag(tags: dict[tuple[str, str], set[str]], dimension: str, value: str, case_id: str) -> None:
    tags.setdefault((dimension, value), set()).add(case_id)


def _repository(case_id: str) -> str:
    match = re.fullmatch(r"(.+)-pr[0-9]+-f[0-9]+", case_id)
    return match.group(1) if match is not None else "unknown"


def _context_band(
    tokens: int, *, small_context_max_tokens: int, medium_context_max_tokens: int
) -> str:
    if tokens <= small_context_max_tokens:
        return "small"
    if tokens <= medium_context_max_tokens:
        return "medium"
    return "large"


def _optional_mean(values: Sequence[bool | None]) -> float | None:
    return (
        sum(cast(bool, value) for value in values) / len(values)
        if values and all(value is not None for value in values)
        else None
    )


def _optional_difference(left: float | None, right: float | None) -> float | None:
    return left - right if left is not None and right is not None else None


def _flatten[T](values: Iterable[Iterable[T]]) -> list[T]:
    return [item for group in values for item in group]


def _linear_median(values: Sequence[float]) -> float:
    middle = len(values) // 2
    return values[middle] if len(values) % 2 else (values[middle - 1] + values[middle]) / 2


def _stable_sum(values: Sequence[float]) -> float:
    return float(sum((Decimal(str(value)) for value in values), start=Decimal(0)))


def _stable_mean(values: Sequence[float]) -> float:
    return _stable_sum(values) / len(values)


def _unique[T](values: Sequence[T], *, key: Callable[[T], str], kind: str) -> dict[str, T]:
    result: dict[str, T] = {}
    for value in values:
        identifier = key(value)
        if identifier in result:
            raise SchemaError(f"statistics {kind} identifiers must be unique")
        result[identifier] = value
    return result
