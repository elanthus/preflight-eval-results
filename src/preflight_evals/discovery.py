"""Deterministic supplemental mechanism discovery aggregates."""

from __future__ import annotations

from collections import defaultdict
from collections.abc import Iterable
from typing import Literal, cast

from preflight_evals.canonical import JsonValue
from preflight_evals.errors import SchemaError
from preflight_evals.score import ScoredFinding, ScoredMechanismOutcome, ScoringResult

type CellKey = tuple[str, str]
type UnitKey = tuple[str, str, str, str]
type FindingClass = Literal[
    "true_positive", "false_positive", "unresolved", "unverified", "unrelated"
]

_CELL_ORDER: tuple[CellKey, ...] = (
    ("baseline", "vulnerable"),
    ("baseline", "fixed"),
    ("candidate", "vulnerable"),
    ("candidate", "fixed"),
)
_ADDITIVE_FIELDS = (
    "finding_instances",
    "duplicate_findings_excluded",
    "unverified_findings_excluded",
    "unrelated_findings_excluded",
    "true_positive_findings",
    "false_positive_findings",
    "unresolved_findings",
    "precision_denominator",
    "verified_mechanism_units",
    "resolved_mechanism_units",
    "unresolved_mechanism_units",
    "unverified_mechanism_units",
    "expected_present_units",
    "detected_present_units",
    "missed_present_units",
    "recall_denominator",
    "expected_absent_units",
    "unexpected_claim_units",
    "clear_absence_units",
)


def build_mechanism_discovery(scoring: ScoringResult) -> dict[str, JsonValue]:
    """Aggregate score-result 2.0 without exposing run, case, finding, or mechanism IDs."""

    scoring = ScoringResult.from_dict(scoring.to_dict())
    if scoring.schema_version != "2.0":
        raise SchemaError("mechanism discovery requires score-result 2.0")

    runs_by_cell = {
        key: tuple(run for run in scoring.runs if (run.condition, run.snapshot) == key)
        for key in _CELL_ORDER
    }
    if any(not runs for runs in runs_by_cell.values()):
        raise SchemaError("mechanism discovery requires all condition and snapshot cells")

    cells: list[dict[str, JsonValue]] = []
    for condition, snapshot in _CELL_ORDER:
        runs = runs_by_cell[(condition, snapshot)]
        counts = _empty_counts()
        for run in runs:
            for finding in run.findings:
                if finding.duplicate_of is not None:
                    counts["duplicate_findings_excluded"] += 1
                    continue
                counts["finding_instances"] += 1
                classification = _classify_finding(finding)
                counts[
                    {
                        "true_positive": "true_positive_findings",
                        "false_positive": "false_positive_findings",
                        "unresolved": "unresolved_findings",
                        "unverified": "unverified_findings_excluded",
                        "unrelated": "unrelated_findings_excluded",
                    }[classification]
                ] += 1

        units: dict[UnitKey, list[ScoredMechanismOutcome]] = defaultdict(list)
        for run in runs:
            for outcome in run.mechanism_outcomes:
                if outcome.evaluation_role != "supplemental":
                    continue
                units[(condition, snapshot, run.case_id, outcome.mechanism_id)].append(outcome)
        for outcomes in units.values():
            _classify_mechanism_unit(outcomes, counts)

        cells.append(
            {
                "condition": condition,
                "snapshot": snapshot,
                "case_count": len({run.case_id for run in runs}),
                **_finish_counts(counts),
            }
        )

    totals = _empty_counts()
    for cell in cells:
        for field in _ADDITIVE_FIELDS:
            totals[field] += cast(int, cell[field])
    return {
        "schema_version": "1.0",
        "statistical_unit": "condition-snapshot-case-mechanism",
        "precision_unit": "nonduplicate-finding-per-run",
        "duplicate_policy": "exclude-in-run-duplicate-findings",
        "repetition_policy": "collapse-to-one-case-mechanism-unit-conservatively",
        "unresolved_policy": "exclude-from-rate-denominators-and-report",
        "unverified_policy": "exclude-from-rate-denominators-and-report",
        "case_count": len({run.case_id for run in scoring.runs}),
        **_finish_counts(totals),
        "cells": cast(JsonValue, cells),
    }


def _empty_counts() -> dict[str, int]:
    return {field: 0 for field in _ADDITIVE_FIELDS}


def _classify_finding(finding: ScoredFinding) -> FindingClass:
    supplemental = tuple(
        mechanism for mechanism in finding.mechanisms if mechanism.evaluation_role == "supplemental"
    )
    verified = tuple(
        mechanism for mechanism in supplemental if mechanism.expected_status != "unverified"
    )
    if not verified:
        return "unverified" if supplemental else "unrelated"

    dispositions = {mechanism.disposition for mechanism in verified}
    if "unresolved" in dispositions:
        return "unresolved"
    has_true_positive = "expected_match" in dispositions
    has_false_positive = bool({"unexpected_claim", "partial"} & dispositions)
    if has_true_positive and has_false_positive:
        return "unresolved"
    if has_true_positive:
        return "true_positive"
    if has_false_positive:
        return "false_positive"
    return "unrelated"


def _classify_mechanism_unit(
    outcomes: Iterable[ScoredMechanismOutcome], counts: dict[str, int]
) -> None:
    values = tuple(outcomes)
    statuses = {outcome.expected_status for outcome in values}
    if len(statuses) != 1:
        raise SchemaError("mechanism discovery unit has inconsistent expectations")
    status = statuses.pop()
    classifications = {outcome.classification for outcome in values}
    if status == "unverified":
        if classifications != {"unverified"}:
            raise SchemaError("unverified mechanism discovery unit has scored outcomes")
        counts["unverified_mechanism_units"] += 1
        return

    counts["verified_mechanism_units"] += 1
    if "unresolved" in classifications:
        counts["unresolved_mechanism_units"] += 1
        return
    counts["resolved_mechanism_units"] += 1
    if status == "present":
        counts["expected_present_units"] += 1
        if "true_positive" in classifications:
            counts["detected_present_units"] += 1
        else:
            counts["missed_present_units"] += 1
    else:
        counts["expected_absent_units"] += 1
        if "false_positive" in classifications:
            counts["unexpected_claim_units"] += 1
        else:
            counts["clear_absence_units"] += 1


def _finish_counts(counts: dict[str, int]) -> dict[str, JsonValue]:
    result: dict[str, JsonValue] = dict(counts)
    precision_denominator = counts["true_positive_findings"] + counts["false_positive_findings"]
    recall_denominator = counts["detected_present_units"] + counts["missed_present_units"]
    counts["precision_denominator"] = precision_denominator
    counts["recall_denominator"] = recall_denominator
    precision = (
        counts["true_positive_findings"] / precision_denominator if precision_denominator else None
    )
    recall = counts["detected_present_units"] / recall_denominator if recall_denominator else None
    coverage = (
        counts["resolved_mechanism_units"] / counts["verified_mechanism_units"]
        if counts["verified_mechanism_units"]
        else None
    )
    f1 = (
        2 * precision * recall / (precision + recall)
        if precision is not None and recall is not None and precision + recall
        else 0.0
        if precision == 0.0 and recall == 0.0
        else None
    )
    result.update(
        {
            "precision_denominator": precision_denominator,
            "precision": precision,
            "recall_denominator": recall_denominator,
            "recall": recall,
            "f1": f1,
            "expected_mechanism_coverage": coverage,
        }
    )
    return result
