"""Deterministic M2 scoring, statistics, and aggregate-report orchestration."""

from __future__ import annotations

import hashlib
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any, Literal, cast

from preflight_evals.adjudicate import AdjudicationPacket, PacketMapping
from preflight_evals.attempt_metadata import AttemptMetadata
from preflight_evals.canonical import JsonValue, canonical_digest, canonical_json_bytes
from preflight_evals.errors import ExecutionError, SchemaError
from preflight_evals.model_types import iso_datetime, object_list, object_mapping
from preflight_evals.pricing import PriceTable
from preflight_evals.report import AggregateReport, build_aggregate_report, render_markdown
from preflight_evals.run_models import ExperimentManifest, RunRecord
from preflight_evals.schema import validate_contract
from preflight_evals.score import ScoringResult, score_experiment
from preflight_evals.scorer_models import AdjudicationRecord, GoldRecord
from preflight_evals.statistics import StatisticsResult, calculate_statistics

type M2MechanismDecision = Literal["match", "no_match", "uncertain"]
type M2ValidityDecision = Literal["valid", "false_positive", "uncertain"]
type M2IssueKind = Literal["code", "documentation", "uncertain"]


@dataclass(frozen=True, slots=True)
class M2FindingAssessment:
    """One blinded finding judgment for the directional M2 comparison."""

    assignment_id: str
    mechanism_decision: M2MechanismDecision
    validity: M2ValidityDecision
    issue_kind: M2IssueKind
    additional_issue_group: str | None
    rationale: str

    def to_dict(self) -> dict[str, JsonValue]:
        return {
            "assignment_id": self.assignment_id,
            "mechanism_decision": self.mechanism_decision,
            "validity": self.validity,
            "issue_kind": self.issue_kind,
            "additional_issue_group": self.additional_issue_group,
            "rationale": self.rationale,
        }


@dataclass(frozen=True, slots=True)
class M2AssessmentBatch:
    """Complete single-adjudicator assessment of one blinded M2 packet."""

    schema_version: str
    packet_id: str
    packet_digest: str
    adjudicator: str
    assessed_at: datetime
    assessments: tuple[M2FindingAssessment, ...]
    content_digest: str

    @classmethod
    def from_dict(cls, document: Mapping[str, Any]) -> M2AssessmentBatch:
        """Normalize an operator submission and bind it to a canonical digest."""

        raw = dict(document)
        supplied_digest = raw.pop("content_digest", None)
        try:
            assessed_at = iso_datetime(cast(str, raw["assessed_at"]), field="assessed_at")
            raw["assessed_at"] = _iso_string(assessed_at)
            raw["assessments"] = sorted(
                (dict(object_mapping(item)) for item in object_list(raw["assessments"])),
                key=lambda item: cast(str, item.get("assignment_id", "")),
            )
        except (KeyError, TypeError, ValueError, SchemaError) as exc:
            raise SchemaError("M2 finding assessment is invalid") from exc
        derived_digest = canonical_digest(cast(dict[str, JsonValue], raw))
        if supplied_digest is not None and supplied_digest != derived_digest:
            raise SchemaError("M2 finding assessment content digest does not match its content")
        normalized = {**raw, "content_digest": derived_digest}
        data = validate_contract("m2-finding-assessment", normalized)
        assessments = tuple(
            M2FindingAssessment(
                assignment_id=cast(str, item["assignment_id"]),
                mechanism_decision=cast(M2MechanismDecision, item["mechanism_decision"]),
                validity=cast(M2ValidityDecision, item["validity"]),
                issue_kind=cast(M2IssueKind, item["issue_kind"]),
                additional_issue_group=cast(str | None, item["additional_issue_group"]),
                rationale=cast(str, item["rationale"]),
            )
            for item in (object_mapping(value) for value in object_list(data["assessments"]))
        )
        identifiers = [item.assignment_id for item in assessments]
        if len(identifiers) != len(set(identifiers)):
            raise SchemaError("M2 finding assessment contains duplicate assignments")
        for item in assessments:
            has_group = item.additional_issue_group is not None
            requires_group = item.validity == "valid" and item.mechanism_decision == "no_match"
            if has_group != requires_group:
                raise SchemaError(
                    "only additional valid M2 issues must carry an additional issue group"
                )
            if (item.mechanism_decision == "uncertain") != (item.validity == "uncertain"):
                raise SchemaError("M2 finding uncertainty must cover mechanism and validity")
            if (item.issue_kind == "uncertain") != (item.validity == "uncertain"):
                raise SchemaError("M2 finding uncertainty must include its issue kind")
            if item.mechanism_decision == "match" and item.issue_kind != "code":
                raise SchemaError("known M2 source-mechanism matches must be code issues")
        return cls(
            schema_version=cast(str, data["schema_version"]),
            packet_id=cast(str, data["packet_id"]),
            packet_digest=cast(str, data["packet_digest"]),
            adjudicator=cast(str, data["adjudicator"]),
            assessed_at=iso_datetime(cast(str, data["assessed_at"]), field="assessed_at"),
            assessments=assessments,
            content_digest=cast(str, data["content_digest"]),
        )

    def to_dict(self) -> dict[str, JsonValue]:
        return {
            "schema_version": self.schema_version,
            "packet_id": self.packet_id,
            "packet_digest": self.packet_digest,
            "adjudicator": self.adjudicator,
            "assessed_at": _iso_string(self.assessed_at),
            "assessments": [item.to_dict() for item in self.assessments],
            "content_digest": self.content_digest,
        }

    def canonical_bytes(self) -> bytes:
        return canonical_json_bytes(self.to_dict())


@dataclass(frozen=True, slots=True)
class M2AnalysisOutputs:
    """One deterministic score/statistics/report projection over frozen private inputs."""

    score: ScoringResult
    statistics: StatisticsResult
    report: AggregateReport
    markdown: str
    adjudication_summary: Mapping[str, JsonValue]

    def public_summary(self) -> dict[str, JsonValue]:
        """Return a count-and-digest-only proof summary safe for operational logs."""

        report = self.report.to_dict()
        completeness = cast(dict[str, JsonValue], report["completeness"])
        cost = cast(dict[str, JsonValue], report["cost"])
        base: dict[str, JsonValue] = {
            "schema_version": "1.0",
            "experiment_id": self.score.experiment_id,
            "experiment_digest": self.score.experiment_digest,
            "score_result_digest": self.score.content_digest,
            "statistics_digest": cast(
                str, cast(dict[str, JsonValue], report["digests"])["statistics"]
            ),
            "report_id": cast(str, report["report_id"]),
            "report_digest": cast(str, report["content_digest"]),
            "markdown_sha256": "sha256:"
            + hashlib.sha256(self.markdown.encode("utf-8")).hexdigest(),
            "runs": len(self.score.runs),
            "invalid_outputs": cast(int, completeness["invalid_outputs"]),
            "actual_cost_known": cost["actual_cost_usd"] is not None,
            "decision": cast(str, cast(dict[str, JsonValue], report["decision"])["value"]),
            "adjudication": dict(self.adjudication_summary),
        }
        return {**base, "content_digest": canonical_digest(base)}


def validate_eight_case_mvp_scope(experiment: ExperimentManifest) -> None:
    """Require the exact one-repetition development-only M2 gate shape."""

    if (
        len(experiment.cases) != 8
        or experiment.repetitions != 1
        or experiment.planned_run_count != 32
        or any(case.role != "development" for case in experiment.cases)
        or experiment.snapshot_set != ("vulnerable", "fixed")
        or experiment.holdout_access_enabled
    ):
        raise ExecutionError("M2 validation requires the frozen eight-case development MVP")


def assess_m2_findings(
    experiment: ExperimentManifest,
    packet: AdjudicationPacket,
    mapping: PacketMapping,
    assessment: M2AssessmentBatch,
) -> tuple[tuple[AdjudicationRecord, ...], dict[str, JsonValue]]:
    """Derive scorer decisions and disclosure-safe discovery counts from one human assessment."""

    if (
        assessment.packet_id != packet.packet_id
        or assessment.packet_digest != packet.content_digest
        or mapping.packet_id != packet.packet_id
        or mapping.packet_digest != packet.content_digest
        or mapping.experiment_id != experiment.experiment_id
        or mapping.experiment_digest != experiment.content_digest
        or assessment.adjudicator != mapping.primary_adjudicator
    ):
        raise ExecutionError("M2 finding assessment is stale or targets a different packet")
    if assessment.assessed_at < packet.exported_at:
        raise ExecutionError("M2 finding assessment predates its blinded packet")
    if packet.calibration_size != 0 or any(item.calibration for item in mapping.items):
        raise ExecutionError("M2 directional validation requires single-adjudicator mode")
    rubrics_by_case: dict[str, int] = {}
    for rubric in mapping.rubrics:
        rubrics_by_case[rubric.case_id] = rubrics_by_case.get(rubric.case_id, 0) + 1
    if set(rubrics_by_case) != {case.case_id for case in experiment.cases} or any(
        count != 1 for count in rubrics_by_case.values()
    ):
        raise ExecutionError("M2 directional validation requires one frozen source rubric per case")

    mapping_by_assignment = {item.assignment_id: item for item in mapping.items}
    assessment_by_assignment = {item.assignment_id: item for item in assessment.assessments}
    if set(mapping_by_assignment) != set(assessment_by_assignment):
        raise ExecutionError(
            "M2 finding assessment does not cover every blinded finding exactly once"
        )
    finding_keys = [(item.run_id, item.finding_id) for item in mapping.items]
    if len(finding_keys) != len(set(finding_keys)):
        raise ExecutionError("M2 finding packet contains more than one rubric per finding")

    planned_by_id = {run.run_id: run for run in experiment.execution_order}
    cell_counts: dict[tuple[str, str], dict[str, int | set[str]]] = {
        (condition, snapshot): _empty_discovery_counts()
        for condition in ("baseline", "candidate")
        for snapshot in ("vulnerable", "fixed")
    }
    overall = _empty_discovery_counts()
    records: list[AdjudicationRecord] = []
    for item in assessment.assessments:
        bound = mapping_by_assignment[item.assignment_id]
        planned = planned_by_id.get(bound.run_id)
        if planned is None:
            raise ExecutionError("M2 finding assessment targets an unavailable run")
        decision = item.mechanism_decision
        if item.mechanism_decision == "match" and (
            (planned.snapshot == "vulnerable" and item.validity != "valid")
            or (planned.snapshot == "fixed" and item.validity != "false_positive")
        ):
            raise ExecutionError(
                "M2 known-mechanism validity contradicts the approved vulnerable/fixed pair"
            )
        identity = canonical_digest(
            {
                "assessment_digest": assessment.content_digest,
                "assignment_id": item.assignment_id,
            }
        )
        records.append(
            AdjudicationRecord.from_dict(
                {
                    "schema_version": "1.0",
                    "adjudication_id": f"adjudication-{identity.removeprefix('sha256:')[:32]}",
                    "run_id": bound.run_id,
                    "finding_id": bound.finding_id,
                    "expected_mechanism_id": bound.expected_mechanism_id,
                    "decision": decision,
                    "rubric_version": packet.rubric_version,
                    "adjudicator": assessment.adjudicator,
                    "timestamp": _iso_string(assessment.assessed_at),
                    "rationale": item.rationale,
                    "supersedes": None,
                }
            )
        )
        issue_key = (
            f"known:{bound.case_id}:{bound.expected_mechanism_id}"
            if item.validity == "valid" and item.mechanism_decision == "match"
            else (
                f"{item.issue_kind}:{bound.case_id}:{item.additional_issue_group}"
                if item.additional_issue_group is not None
                else None
            )
        )
        _record_discovery(overall, item, issue_key, snapshot=planned.snapshot)
        _record_discovery(
            cell_counts[(planned.condition, planned.snapshot)],
            item,
            issue_key,
            snapshot=planned.snapshot,
        )

    summary = _discovery_summary(assessment.content_digest, overall, cell_counts)
    return tuple(records), summary


def m2_assessment_template(
    packet: AdjudicationPacket,
    *,
    adjudicator: str,
    assessed_at: datetime,
) -> dict[str, JsonValue]:
    """Return an editable, private single-adjudicator assessment submission."""

    if not adjudicator or len(adjudicator) > 120:
        raise ExecutionError("M2 adjudicator identity is invalid")
    if packet.calibration_size != 0:
        raise ExecutionError("M2 assessment templates require a single-adjudicator packet")
    return {
        "schema_version": "1.0",
        "packet_id": packet.packet_id,
        "packet_digest": packet.content_digest,
        "adjudicator": adjudicator,
        "assessed_at": _iso_string(assessed_at),
        "assessments": [
            {
                "assignment_id": item.assignment_id,
                "mechanism_decision": "uncertain",
                "validity": "uncertain",
                "issue_kind": "uncertain",
                "additional_issue_group": None,
                "rationale": "Pending independent human assessment.",
            }
            for item in sorted(packet.items, key=lambda value: value.assignment_id)
        ],
    }


def analyze_frozen_outputs(
    experiment: ExperimentManifest,
    run_records: Sequence[RunRecord],
    gold_records: Sequence[GoldRecord],
    adjudications: Sequence[AdjudicationRecord],
    price_table: PriceTable,
    *,
    provider: str,
    minimum_public_cell_size: int,
    rationale: str,
    adjudication_summary: Mapping[str, JsonValue],
    limitations: Sequence[str],
    exclusions: Sequence[str] = (),
    protocol_deviations: Sequence[str] = (),
    attempt_metadata: Sequence[AttemptMetadata] | None = None,
) -> M2AnalysisOutputs:
    """Score and report frozen outputs without provider, clock, or filesystem effects."""

    scoring = score_experiment(
        experiment,
        tuple(run_records),
        tuple(gold_records),
        tuple(adjudications),
    )
    if any(
        mechanism.expected_status != "unverified"
        and (
            mechanism.decision not in {"match", "no_match"} or mechanism.adjudication_digest is None
        )
        for run in scoring.runs
        for finding in run.findings
        for mechanism in finding.mechanisms
    ):
        raise SchemaError("M2 scoring requires active adjudication provenance for every mechanism")
    scored_findings = [finding for run in scoring.runs for finding in run.findings]
    vulnerable_matches = sum(
        finding.mechanism_match
        for run in scoring.runs
        if run.snapshot == "vulnerable"
        for finding in run.findings
    )
    fixed_matches = sum(
        finding.mechanism_match
        for run in scoring.runs
        if run.snapshot == "fixed"
        for finding in run.findings
    )
    if (
        adjudication_summary.get("total_findings") != len(scored_findings)
        or adjudication_summary.get("known_issue_instances") != vulnerable_matches
        or adjudication_summary.get("repaired_mechanism_false_positives") != fixed_matches
        or adjudication_summary.get("uncertain_findings") != 0
    ):
        raise SchemaError("M2 issue-discovery summary does not match scored finding evidence")
    statistics = calculate_statistics(
        experiment,
        scoring,
        run_records,
        gold_records,
        price_table,
        provider=provider,
        attempt_metadata=attempt_metadata,
    )
    report = build_aggregate_report(
        experiment,
        statistics,
        visibility="public",
        decision="insufficient evidence",
        rationale=rationale,
        minimum_public_cell_size=minimum_public_cell_size,
        limitations=limitations,
        exclusions=exclusions,
        protocol_deviations=protocol_deviations,
        issue_discovery=adjudication_summary,
        scoring_result=scoring if scoring.schema_version == "2.0" else None,
    )
    markdown = render_markdown(report.canonical_bytes())
    return M2AnalysisOutputs(
        score=scoring,
        statistics=statistics,
        report=report,
        markdown=markdown,
        adjudication_summary=dict(adjudication_summary),
    )


def _empty_discovery_counts() -> dict[str, int | set[str]]:
    return {
        "total_findings": 0,
        "valid_finding_instances": 0,
        "known_issue_instances": 0,
        "additional_valid_issue_instances": 0,
        "false_positive_findings": 0,
        "repaired_mechanism_false_positives": 0,
        "other_false_positive_findings": 0,
        "code_finding_instances": 0,
        "documentation_finding_instances": 0,
        "valid_code_issue_instances": 0,
        "valid_documentation_issue_instances": 0,
        "code_false_positive_findings": 0,
        "documentation_false_positive_findings": 0,
        "uncertain_findings": 0,
        "valid_issue_keys": set(),
        "known_issue_keys": set(),
        "additional_issue_keys": set(),
        "valid_code_issue_keys": set(),
        "valid_documentation_issue_keys": set(),
    }


def _record_discovery(
    counts: dict[str, int | set[str]],
    assessment: M2FindingAssessment,
    issue_key: str | None,
    *,
    snapshot: str,
) -> None:
    counts["total_findings"] = cast(int, counts["total_findings"]) + 1
    if assessment.issue_kind == "code":
        counts["code_finding_instances"] = cast(int, counts["code_finding_instances"]) + 1
    elif assessment.issue_kind == "documentation":
        counts["documentation_finding_instances"] = (
            cast(int, counts["documentation_finding_instances"]) + 1
        )
    if assessment.validity == "valid":
        counts["valid_finding_instances"] = cast(int, counts["valid_finding_instances"]) + 1
        cast(set[str], counts["valid_issue_keys"]).add(cast(str, issue_key))
        if assessment.issue_kind == "code":
            counts["valid_code_issue_instances"] = (
                cast(int, counts["valid_code_issue_instances"]) + 1
            )
            cast(set[str], counts["valid_code_issue_keys"]).add(cast(str, issue_key))
        else:
            counts["valid_documentation_issue_instances"] = (
                cast(int, counts["valid_documentation_issue_instances"]) + 1
            )
            cast(set[str], counts["valid_documentation_issue_keys"]).add(cast(str, issue_key))
        if assessment.mechanism_decision == "match":
            counts["known_issue_instances"] = cast(int, counts["known_issue_instances"]) + 1
            cast(set[str], counts["known_issue_keys"]).add(cast(str, issue_key))
        else:
            counts["additional_valid_issue_instances"] = (
                cast(int, counts["additional_valid_issue_instances"]) + 1
            )
            cast(set[str], counts["additional_issue_keys"]).add(cast(str, issue_key))
    elif assessment.validity == "false_positive":
        counts["false_positive_findings"] = cast(int, counts["false_positive_findings"]) + 1
        false_positive_key = (
            "code_false_positive_findings"
            if assessment.issue_kind == "code"
            else "documentation_false_positive_findings"
        )
        counts[false_positive_key] = cast(int, counts[false_positive_key]) + 1
        if snapshot == "fixed" and assessment.mechanism_decision == "match":
            counts["repaired_mechanism_false_positives"] = (
                cast(int, counts["repaired_mechanism_false_positives"]) + 1
            )
        else:
            counts["other_false_positive_findings"] = (
                cast(int, counts["other_false_positive_findings"]) + 1
            )
    else:
        counts["uncertain_findings"] = cast(int, counts["uncertain_findings"]) + 1


def _discovery_counts(counts: Mapping[str, int | set[str]]) -> dict[str, JsonValue]:
    total = cast(int, counts["total_findings"])
    valid = cast(int, counts["valid_finding_instances"])
    false_positives = cast(int, counts["false_positive_findings"])
    resolved = total - cast(int, counts["uncertain_findings"])
    return {
        "total_findings": total,
        "valid_finding_instances": valid,
        "unique_valid_issues": len(cast(set[str], counts["valid_issue_keys"])),
        "known_issue_instances": cast(int, counts["known_issue_instances"]),
        "unique_known_issues": len(cast(set[str], counts["known_issue_keys"])),
        "additional_valid_issue_instances": cast(int, counts["additional_valid_issue_instances"]),
        "unique_additional_valid_issues": len(cast(set[str], counts["additional_issue_keys"])),
        "false_positive_findings": false_positives,
        "repaired_mechanism_false_positives": cast(
            int, counts["repaired_mechanism_false_positives"]
        ),
        "other_false_positive_findings": cast(int, counts["other_false_positive_findings"]),
        "code_finding_instances": cast(int, counts["code_finding_instances"]),
        "documentation_finding_instances": cast(int, counts["documentation_finding_instances"]),
        "valid_code_issue_instances": cast(int, counts["valid_code_issue_instances"]),
        "unique_valid_code_issues": len(cast(set[str], counts["valid_code_issue_keys"])),
        "valid_documentation_issue_instances": cast(
            int, counts["valid_documentation_issue_instances"]
        ),
        "unique_valid_documentation_issues": len(
            cast(set[str], counts["valid_documentation_issue_keys"])
        ),
        "code_false_positive_findings": cast(int, counts["code_false_positive_findings"]),
        "documentation_false_positive_findings": cast(
            int, counts["documentation_false_positive_findings"]
        ),
        "uncertain_findings": cast(int, counts["uncertain_findings"]),
        "resolved_precision": valid / resolved if resolved else None,
        "false_positive_rate": false_positives / resolved if resolved else None,
    }


def _discovery_summary(
    assessment_digest: str,
    overall: Mapping[str, int | set[str]],
    cells: Mapping[tuple[str, str], Mapping[str, int | set[str]]],
) -> dict[str, JsonValue]:
    return {
        "schema_version": "1.0",
        "assessment_digest": assessment_digest,
        **_discovery_counts(overall),
        "cells": [
            {
                "condition": condition,
                "snapshot": snapshot,
                **_discovery_counts(cells[(condition, snapshot)]),
            }
            for condition in ("baseline", "candidate")
            for snapshot in ("vulnerable", "fixed")
        ],
    }


def _iso_string(value: datetime) -> str:
    if value.tzinfo is None or value.utcoffset() is None:
        raise SchemaError("M2 assessment timestamp must include a timezone")
    return value.astimezone(UTC).isoformat().replace("+00:00", "Z")
