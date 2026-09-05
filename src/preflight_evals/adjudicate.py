"""Blind mechanism-adjudication packet export and append-only decision import."""

from __future__ import annotations

import hashlib
import json
import re
import unicodedata
from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import TYPE_CHECKING, Any, Literal, cast

from preflight_evals.canonical import JsonValue, canonical_digest, canonical_json_bytes
from preflight_evals.errors import ExecutionError, SchemaError
from preflight_evals.model_types import iso_datetime, object_list, object_mapping, repository_path
from preflight_evals.reviewer_models import Evidence, Finding
from preflight_evals.run_models import ExperimentManifest, PlannedRun, RunRecord
from preflight_evals.schema import validate_contract
from preflight_evals.scorer_models import AdjudicationRecord, GoldRecord

if TYPE_CHECKING:
    from preflight_evals.execution import ExperimentStore

type DecisionClassification = Literal["match", "symptom_only", "incorrect_cause", "uncertain"]
type DecisionRole = Literal["primary", "calibration", "resolution"]

_PACKET_FIELDS = frozenset(
    {
        "schema_version",
        "packet_id",
        "rubric_version",
        "exported_at",
        "calibration_size",
        "items",
        "content_digest",
    }
)
_MAPPING_FIELDS = frozenset(
    {
        "schema_version",
        "packet_id",
        "packet_digest",
        "experiment_id",
        "experiment_digest",
        "rubric_version",
        "rubric_approved_by",
        "rubric_approved_at",
        "primary_adjudicator",
        "calibration_adjudicator",
        "resolution_adjudicator",
        "rubrics",
        "items",
        "content_digest",
    }
)
_MAPPING_ITEM_FIELDS = frozenset(
    {
        "assignment_id",
        "run_id",
        "case_id",
        "finding_id",
        "expected_mechanism_id",
        "finding_digest",
        "rubric_digest",
        "calibration",
    }
)
_RUBRIC_BINDING_FIELDS = frozenset({"case_id", "mechanism_id", "rubric_digest"})
_DECISION_KEY = tuple[str, str]


@dataclass(frozen=True, slots=True)
class BlindedFinding:
    title: str
    explanation: str
    file_path: str
    start_line: int | None
    end_line: int | None
    severity: str
    defect_category: str
    failure_mechanism: str
    confidence: float
    evidence: tuple[Evidence, ...]

    @classmethod
    def from_dict(cls, document: Mapping[str, Any]) -> BlindedFinding:
        model = cls(
            title=cast(str, document["title"]),
            explanation=cast(str, document["explanation"]),
            file_path=repository_path(
                cast(str, document["file_path"]), field="adjudication finding path"
            ).as_posix(),
            start_line=cast(int | None, document.get("start_line")),
            end_line=cast(int | None, document.get("end_line")),
            severity=cast(str, document["severity"]),
            defect_category=cast(str, document["defect_category"]),
            failure_mechanism=cast(str, document["failure_mechanism"]),
            confidence=float(cast(int | float, document["confidence"])),
            evidence=tuple(
                Evidence(
                    source_type=cast(str, object_mapping(item)["source_type"]),
                    reference=cast(str, object_mapping(item)["reference"]),
                )
                for item in object_list(document["evidence"])
            ),
        )
        if model.end_line is not None and model.start_line is None:
            raise SchemaError("blinded finding end_line requires start_line")
        if (
            model.start_line is not None
            and model.end_line is not None
            and model.end_line < model.start_line
        ):
            raise SchemaError("blinded finding end_line cannot precede start_line")
        return model

    @classmethod
    def from_finding(
        cls, finding: Finding, *, redacted_finding_ids: Iterable[str] = ()
    ) -> BlindedFinding:
        finding_ids = tuple(sorted(set(redacted_finding_ids), key=len, reverse=True))

        def redact(value: str) -> str:
            for finding_id in finding_ids:
                value = value.replace(finding_id, "[redacted finding reference]")
            return value

        return cls(
            title=redact(finding.title),
            explanation=redact(finding.explanation),
            file_path=redact(finding.file_path.as_posix()),
            start_line=finding.start_line,
            end_line=finding.end_line,
            severity=finding.severity,
            defect_category=finding.defect_category,
            failure_mechanism=redact(finding.failure_mechanism),
            confidence=finding.confidence,
            evidence=tuple(
                Evidence(source_type=item.source_type, reference=redact(item.reference))
                for item in finding.evidence
            ),
        )

    def to_dict(self) -> dict[str, JsonValue]:
        document: dict[str, JsonValue] = {
            "title": self.title,
            "explanation": self.explanation,
            "file_path": self.file_path,
            "severity": self.severity,
            "defect_category": self.defect_category,
            "failure_mechanism": self.failure_mechanism,
            "confidence": self.confidence,
            "evidence": [item.to_dict() for item in self.evidence],
        }
        if self.start_line is not None:
            document["start_line"] = self.start_line
        if self.end_line is not None:
            document["end_line"] = self.end_line
        return document


@dataclass(frozen=True, slots=True)
class AdjudicationPacketItem:
    assignment_id: str
    calibration: bool
    finding: BlindedFinding
    rubric: str

    def to_dict(self) -> dict[str, JsonValue]:
        return {
            "assignment_id": self.assignment_id,
            "calibration": self.calibration,
            "finding": self.finding.to_dict(),
            "rubric": self.rubric,
        }


@dataclass(frozen=True, slots=True)
class AdjudicationPacket:
    schema_version: str
    packet_id: str
    rubric_version: str
    exported_at: datetime
    calibration_size: int
    items: tuple[AdjudicationPacketItem, ...]
    content_digest: str

    @classmethod
    def from_dict(cls, document: Mapping[str, Any]) -> AdjudicationPacket:
        data = validate_contract("adjudication-packet", dict(document))
        items = tuple(
            AdjudicationPacketItem(
                assignment_id=cast(str, item["assignment_id"]),
                calibration=cast(bool, item["calibration"]),
                finding=BlindedFinding.from_dict(object_mapping(item["finding"])),
                rubric=cast(str, item["rubric"]),
            )
            for item in (object_mapping(value) for value in object_list(data["items"]))
        )
        model = cls(
            schema_version=cast(str, data["schema_version"]),
            packet_id=cast(str, data["packet_id"]),
            rubric_version=cast(str, data["rubric_version"]),
            exported_at=iso_datetime(cast(str, data["exported_at"]), field="exported_at"),
            calibration_size=cast(int, data["calibration_size"]),
            items=items,
            content_digest=cast(str, data["content_digest"]),
        )
        identifiers = [item.assignment_id for item in items]
        if len(identifiers) != len(set(identifiers)):
            raise SchemaError("adjudication packet assignment identifiers must be unique")
        if model.calibration_size != sum(item.calibration for item in items):
            raise SchemaError("adjudication packet calibration count is inconsistent")
        _verify_derived_identity(model.to_dict(), kind="packet")
        return model

    def to_dict(self) -> dict[str, JsonValue]:
        return {
            "schema_version": self.schema_version,
            "packet_id": self.packet_id,
            "rubric_version": self.rubric_version,
            "exported_at": _iso_string(self.exported_at),
            "calibration_size": self.calibration_size,
            "items": [item.to_dict() for item in self.items],
            "content_digest": self.content_digest,
        }

    def canonical_bytes(self) -> bytes:
        return canonical_json_bytes(self.to_dict())


@dataclass(frozen=True, slots=True)
class BlindDecision:
    decision_id: str
    assignment_id: str
    classification: DecisionClassification
    decided_at: datetime
    rationale: str
    supersedes: str | None
    resolves: tuple[str, ...]

    def to_dict(self) -> dict[str, JsonValue]:
        return {
            "decision_id": self.decision_id,
            "assignment_id": self.assignment_id,
            "classification": self.classification,
            "decided_at": _iso_string(self.decided_at),
            "rationale": self.rationale,
            "supersedes": self.supersedes,
            "resolves": list(self.resolves),
        }


@dataclass(frozen=True, slots=True)
class DecisionBatch:
    schema_version: str
    batch_id: str
    packet_id: str
    packet_digest: str
    role: DecisionRole
    adjudicator: str
    submitted_at: datetime
    decisions: tuple[BlindDecision, ...]
    content_digest: str

    @classmethod
    def from_dict(cls, document: Mapping[str, Any]) -> DecisionBatch:
        data = validate_contract("adjudication-decisions", dict(document))
        decisions = tuple(
            BlindDecision(
                decision_id=cast(str, item["decision_id"]),
                assignment_id=cast(str, item["assignment_id"]),
                classification=cast(DecisionClassification, item["classification"]),
                decided_at=iso_datetime(cast(str, item["decided_at"]), field="decided_at"),
                rationale=cast(str, item["rationale"]),
                supersedes=cast(str | None, item["supersedes"]),
                resolves=tuple(cast(str, value) for value in object_list(item["resolves"])),
            )
            for item in (object_mapping(value) for value in object_list(data["decisions"]))
        )
        model = cls(
            schema_version=cast(str, data["schema_version"]),
            batch_id=cast(str, data["batch_id"]),
            packet_id=cast(str, data["packet_id"]),
            packet_digest=cast(str, data["packet_digest"]),
            role=cast(DecisionRole, data["role"]),
            adjudicator=cast(str, data["adjudicator"]),
            submitted_at=iso_datetime(cast(str, data["submitted_at"]), field="submitted_at"),
            decisions=decisions,
            content_digest=cast(str, data["content_digest"]),
        )
        decision_ids = [item.decision_id for item in decisions]
        assignments = [item.assignment_id for item in decisions]
        if len(decision_ids) != len(set(decision_ids)):
            raise SchemaError("adjudication decision identifiers must be unique within a batch")
        if len(assignments) != len(set(assignments)):
            raise SchemaError("adjudication batch contains duplicate active assignments")
        if any(item.decided_at > model.submitted_at for item in decisions):
            raise SchemaError("adjudication decision cannot postdate its submitted batch")
        if any(
            item.supersedes == item.decision_id or item.decision_id in item.resolves
            for item in decisions
        ):
            raise SchemaError("adjudication decision cannot supersede or resolve itself")
        if model.role == "resolution":
            if any(len(item.resolves) != 2 for item in decisions):
                raise SchemaError("resolution decisions must identify exactly two source decisions")
        elif any(item.resolves for item in decisions):
            raise SchemaError("non-resolution decisions cannot resolve other decisions")
        _verify_derived_identity(model.to_dict(), kind="batch")
        return model

    def to_dict(self) -> dict[str, JsonValue]:
        return {
            "schema_version": self.schema_version,
            "batch_id": self.batch_id,
            "packet_id": self.packet_id,
            "packet_digest": self.packet_digest,
            "role": self.role,
            "adjudicator": self.adjudicator,
            "submitted_at": _iso_string(self.submitted_at),
            "decisions": [item.to_dict() for item in self.decisions],
            "content_digest": self.content_digest,
        }

    def canonical_bytes(self) -> bytes:
        return canonical_json_bytes(self.to_dict())


@dataclass(frozen=True, slots=True)
class MappingItem:
    assignment_id: str
    run_id: str
    case_id: str
    finding_id: str
    expected_mechanism_id: str
    finding_digest: str
    rubric_digest: str
    calibration: bool

    def to_dict(self) -> dict[str, JsonValue]:
        return {
            "assignment_id": self.assignment_id,
            "run_id": self.run_id,
            "case_id": self.case_id,
            "finding_id": self.finding_id,
            "expected_mechanism_id": self.expected_mechanism_id,
            "finding_digest": self.finding_digest,
            "rubric_digest": self.rubric_digest,
            "calibration": self.calibration,
        }


@dataclass(frozen=True, slots=True)
class RubricBinding:
    case_id: str
    mechanism_id: str
    rubric_digest: str

    def to_dict(self) -> dict[str, JsonValue]:
        return {
            "case_id": self.case_id,
            "mechanism_id": self.mechanism_id,
            "rubric_digest": self.rubric_digest,
        }


@dataclass(frozen=True, slots=True)
class PacketMapping:
    packet_id: str
    packet_digest: str
    experiment_id: str
    experiment_digest: str
    rubric_version: str
    rubric_approved_by: str
    rubric_approved_at: datetime
    primary_adjudicator: str
    calibration_adjudicator: str
    resolution_adjudicator: str
    rubrics: tuple[RubricBinding, ...]
    items: tuple[MappingItem, ...]
    content_digest: str

    @classmethod
    def from_dict(cls, document: Mapping[str, Any]) -> PacketMapping:
        if set(document) != _MAPPING_FIELDS or document.get("schema_version") != "1.0":
            raise ExecutionError("stored adjudication packet mapping has an unsupported shape")
        try:
            raw_items = object_list(document["items"])
            raw_rubrics = object_list(document["rubrics"])
            if any(set(object_mapping(item)) != _MAPPING_ITEM_FIELDS for item in raw_items):
                raise ValueError
            if any(set(object_mapping(item)) != _RUBRIC_BINDING_FIELDS for item in raw_rubrics):
                raise ValueError
            items = tuple(
                MappingItem(
                    assignment_id=cast(str, item["assignment_id"]),
                    run_id=cast(str, item["run_id"]),
                    case_id=cast(str, item["case_id"]),
                    finding_id=cast(str, item["finding_id"]),
                    expected_mechanism_id=cast(str, item["expected_mechanism_id"]),
                    finding_digest=cast(str, item["finding_digest"]),
                    rubric_digest=cast(str, item["rubric_digest"]),
                    calibration=cast(bool, item["calibration"]),
                )
                for item in (object_mapping(value) for value in raw_items)
            )
            rubrics = tuple(
                RubricBinding(
                    case_id=cast(str, item["case_id"]),
                    mechanism_id=cast(str, item["mechanism_id"]),
                    rubric_digest=cast(str, item["rubric_digest"]),
                )
                for item in (object_mapping(value) for value in raw_rubrics)
            )
            model = cls(
                packet_id=cast(str, document["packet_id"]),
                packet_digest=cast(str, document["packet_digest"]),
                experiment_id=cast(str, document["experiment_id"]),
                experiment_digest=cast(str, document["experiment_digest"]),
                rubric_version=cast(str, document["rubric_version"]),
                rubric_approved_by=cast(str, document["rubric_approved_by"]),
                rubric_approved_at=iso_datetime(
                    cast(str, document["rubric_approved_at"]), field="rubric_approved_at"
                ),
                primary_adjudicator=cast(str, document["primary_adjudicator"]),
                calibration_adjudicator=cast(str, document["calibration_adjudicator"]),
                resolution_adjudicator=cast(str, document["resolution_adjudicator"]),
                rubrics=rubrics,
                items=items,
                content_digest=cast(str, document["content_digest"]),
            )
        except (KeyError, TypeError, ValueError, SchemaError) as exc:
            raise ExecutionError("stored adjudication packet mapping is invalid") from exc
        identifiers = [item.assignment_id for item in model.items]
        rubric_keys = [(item.case_id, item.mechanism_id) for item in model.rubrics]
        if (
            not model.rubrics
            or not _valid_mapping_scalars(model)
            or any(not _valid_mapping_item(item) for item in model.items)
            or any(not _valid_rubric_binding(item) for item in model.rubrics)
            or len(identifiers) != len(set(identifiers))
            or len(rubric_keys) != len(set(rubric_keys))
            or tuple(sorted(model.rubrics, key=_rubric_sort_key)) != model.rubrics
            or _rubric_version(model.rubrics) != model.rubric_version
            or any(
                (item.case_id, item.expected_mechanism_id) not in set(rubric_keys)
                for item in model.items
            )
            or len(
                {
                    model.primary_adjudicator,
                    model.calibration_adjudicator,
                    model.resolution_adjudicator,
                }
            )
            != 3
            or any(not actor or len(actor) > 120 for actor in _actors(model))
            or canonical_digest(_without(document, "content_digest")) != model.content_digest
        ):
            raise ExecutionError("stored adjudication packet mapping is invalid")
        return model

    def to_dict(self) -> dict[str, JsonValue]:
        return {
            "schema_version": "1.0",
            "packet_id": self.packet_id,
            "packet_digest": self.packet_digest,
            "experiment_id": self.experiment_id,
            "experiment_digest": self.experiment_digest,
            "rubric_version": self.rubric_version,
            "rubric_approved_by": self.rubric_approved_by,
            "rubric_approved_at": _iso_string(self.rubric_approved_at),
            "primary_adjudicator": self.primary_adjudicator,
            "calibration_adjudicator": self.calibration_adjudicator,
            "resolution_adjudicator": self.resolution_adjudicator,
            "rubrics": [item.to_dict() for item in self.rubrics],
            "items": [item.to_dict() for item in self.items],
            "content_digest": self.content_digest,
        }


@dataclass(frozen=True, slots=True)
class PacketExport:
    packet: AdjudicationPacket
    mapping: PacketMapping


@dataclass(frozen=True, slots=True)
class DerivedProvenance:
    adjudication_id: str
    assignment_id: str
    source_decision_ids: tuple[str, ...]
    source_batch_id: str
    classification: DecisionClassification

    def to_dict(self) -> dict[str, JsonValue]:
        return {
            "adjudication_id": self.adjudication_id,
            "assignment_id": self.assignment_id,
            "source_decision_ids": list(self.source_decision_ids),
            "source_batch_id": self.source_batch_id,
            "classification": self.classification,
        }


@dataclass(frozen=True, slots=True)
class DerivedArtifact:
    records: tuple[AdjudicationRecord, ...]
    provenance: tuple[DerivedProvenance, ...]
    content_digest: str


@dataclass(frozen=True, slots=True)
class ImportSummary:
    packet_id: str
    imported_decisions: int
    calibration_assignments: int
    completed_calibrations: int
    agreements: int
    disagreements: int
    unresolved_disagreements: int
    agreement_rate: float | None
    derived_records: tuple[AdjudicationRecord, ...]
    provenance: tuple[DerivedProvenance, ...]

    def public_dict(self) -> dict[str, JsonValue]:
        return {
            "schema_version": "1.0",
            "packet_id": self.packet_id,
            "imported_decisions": self.imported_decisions,
            "calibration_assignments": self.calibration_assignments,
            "completed_calibrations": self.completed_calibrations,
            "agreements": self.agreements,
            "disagreements": self.disagreements,
            "unresolved_disagreements": self.unresolved_disagreements,
            "agreement_rate": self.agreement_rate,
            "derived_records": len(self.derived_records),
        }


def build_packet(
    experiment: ExperimentManifest,
    planned_runs: Sequence[PlannedRun],
    records: Sequence[RunRecord],
    gold_records: Sequence[GoldRecord],
    *,
    exported_at: datetime,
    rubric_approved_by: str,
    rubric_approved_at: datetime,
    primary_adjudicator: str,
    calibration_adjudicator: str,
    resolution_adjudicator: str,
    calibration_size: int,
) -> PacketExport:
    """Build one blinded packet plus its private identity mapping."""

    _aware(exported_at, field="packet export time")
    _aware(rubric_approved_at, field="rubric approval time")
    actors = (primary_adjudicator, calibration_adjudicator, resolution_adjudicator)
    if (
        len(set(actors)) != 3
        or any(not actor or len(actor) > 120 for actor in actors)
        or not rubric_approved_by
        or len(rubric_approved_by) > 120
    ):
        raise ExecutionError("adjudication actor identities are invalid or not independent")
    if rubric_approved_at > exported_at:
        raise ExecutionError("adjudication rubric approval cannot postdate packet export")
    planned_by_id = {run.run_id: run for run in planned_runs}
    records_by_id = {record.run_id: record for record in records}
    gold_by_case = {gold.case_id: gold for gold in gold_records}
    if (
        not planned_runs
        or len(planned_by_id) != len(planned_runs)
        or len(records_by_id) != len(records)
        or set(records_by_id) != set(planned_by_id)
        or len(gold_by_case) != len(gold_records)
        or set(gold_by_case) != {planned.case_id for planned in planned_runs}
    ):
        raise ExecutionError("adjudication export inputs are missing or duplicated")
    late_boundaries = [
        record.ended_at for record in records if planned_by_id[record.run_id].snapshot == "fixed"
    ] + [record.started_at for record in records if planned_by_id[record.run_id].repetition > 1]
    if late_boundaries and rubric_approved_at > min(late_boundaries):
        raise ExecutionError(
            "adjudication rubric was not approved before fixed completion and later repetitions"
        )

    redacted_finding_ids = tuple(
        finding.finding_id
        for record in records
        if record.reviewer_output is not None
        for finding in record.reviewer_output.findings
    )
    internal: list[tuple[MappingItem, AdjudicationPacketItem]] = []
    rubric_bindings = _rubric_bindings(gold_records)
    rubric_by_key = {
        (binding.case_id, binding.mechanism_id): binding for binding in rubric_bindings
    }
    for planned in planned_runs:
        record = records_by_id[planned.run_id]
        gold = gold_by_case.get(planned.case_id)
        if record.experiment_id != experiment.experiment_id or gold is None:
            raise ExecutionError("adjudication export requires complete bound runs")
        if record.status != "succeeded":
            if record.reviewer_output is not None:
                raise ExecutionError("failed adjudication inputs cannot contain reviewer findings")
            continue
        if record.reviewer_output is None:
            raise ExecutionError("successful adjudication inputs require reviewer findings")
        for mechanism in gold.expected_mechanisms:
            if mechanism.snapshot_expectations.for_snapshot(planned.snapshot) == "unverified":
                continue
            rubric_digest = rubric_by_key[(gold.case_id, mechanism.mechanism_id)].rubric_digest
            for finding in record.reviewer_output.findings:
                assignment_id = _assignment_id(experiment, planned, finding, mechanism.mechanism_id)
                mapping_item = MappingItem(
                    assignment_id=assignment_id,
                    run_id=planned.run_id,
                    case_id=planned.case_id,
                    finding_id=finding.finding_id,
                    expected_mechanism_id=mechanism.mechanism_id,
                    finding_digest=canonical_digest(finding.to_dict()),
                    rubric_digest=rubric_digest,
                    calibration=False,
                )
                packet_item = AdjudicationPacketItem(
                    assignment_id=assignment_id,
                    calibration=False,
                    finding=BlindedFinding.from_finding(
                        finding, redacted_finding_ids=redacted_finding_ids
                    ),
                    rubric=mechanism.adjudication_rubric,
                )
                internal.append((mapping_item, packet_item))
    if not 0 <= calibration_size <= len(internal):
        raise ExecutionError("adjudication calibration size is outside the packet range")
    internal.sort(
        key=lambda pair: _random_key(
            experiment.randomization_seed, pair[0].assignment_id, "adjudication-packet"
        )
    )
    mapped: list[MappingItem] = []
    exposed: list[AdjudicationPacketItem] = []
    for index, (mapping_item, packet_item) in enumerate(internal):
        calibration = index < calibration_size
        mapped.append(_replace_calibration(mapping_item, calibration))
        exposed.append(_replace_packet_calibration(packet_item, calibration))
    rubric_version = _rubric_version(rubric_bindings)
    packet_base: dict[str, JsonValue] = {
        "schema_version": "1.0",
        "rubric_version": rubric_version,
        "exported_at": _iso_string(exported_at),
        "calibration_size": calibration_size,
        "items": [item.to_dict() for item in exposed],
    }
    packet_digest = canonical_digest(packet_base)
    packet_document = {
        **packet_base,
        "packet_id": _derived_id("packet", packet_digest),
        "content_digest": packet_digest,
    }
    packet = AdjudicationPacket.from_dict(packet_document)
    _reject_packet_disclosures(packet, experiment, records)
    mapping_base: dict[str, JsonValue] = {
        "schema_version": "1.0",
        "packet_id": packet.packet_id,
        "packet_digest": packet.content_digest,
        "experiment_id": experiment.experiment_id,
        "experiment_digest": cast(str, experiment.content_digest),
        "rubric_version": rubric_version,
        "rubric_approved_by": rubric_approved_by,
        "rubric_approved_at": _iso_string(rubric_approved_at),
        "primary_adjudicator": primary_adjudicator,
        "calibration_adjudicator": calibration_adjudicator,
        "resolution_adjudicator": resolution_adjudicator,
        "rubrics": [item.to_dict() for item in rubric_bindings],
        "items": [item.to_dict() for item in mapped],
    }
    mapping_document = {**mapping_base, "content_digest": canonical_digest(mapping_base)}
    mapping = PacketMapping.from_dict(mapping_document)
    return PacketExport(packet=packet, mapping=mapping)


def validate_import(
    experiment: ExperimentManifest,
    mapping: PacketMapping,
    packet: AdjudicationPacket,
    records: Sequence[RunRecord],
    gold_records: Sequence[GoldRecord],
    prior_batches: Sequence[DecisionBatch],
    prior_derived: Sequence[AdjudicationRecord],
    batch: DecisionBatch,
) -> ImportSummary:
    """Validate a complete batch and derive scorer records without mutating history."""

    if (
        mapping.packet_id != packet.packet_id
        or mapping.packet_digest != packet.content_digest
        or mapping.rubric_version != packet.rubric_version
        or mapping.experiment_id != experiment.experiment_id
        or mapping.experiment_digest != experiment.content_digest
        or batch.packet_id != packet.packet_id
        or batch.packet_digest != packet.content_digest
    ):
        raise ExecutionError("adjudication packet, mapping, batch, or experiment is stale")
    if mapping.rubric_approved_at > packet.exported_at:
        raise ExecutionError("adjudication rubric approval provenance is stale")
    validate_current_bindings(experiment, packet, mapping, records, gold_records)
    all_batches = (*prior_batches,)
    _reject_unblinded_batch(batch, mapping, experiment)
    by_id, active = _resolve_decisions(all_batches)
    if batch.batch_id in {item.batch_id for item in all_batches}:
        raise ExecutionError("adjudication decision batch was already imported")
    if any(item.decision_id in by_id for item in batch.decisions):
        raise ExecutionError("adjudication decision identifier was already imported")
    expected_actor = {
        "primary": mapping.primary_adjudicator,
        "calibration": mapping.calibration_adjudicator,
        "resolution": mapping.resolution_adjudicator,
    }[batch.role]
    if batch.adjudicator != expected_actor:
        raise ExecutionError("adjudication batch actor does not match its blinded role")
    mapping_by_assignment = {item.assignment_id: item for item in mapping.items}
    calibration_ids = {item.assignment_id for item in mapping.items if item.calibration}
    actual_assignments = {item.assignment_id for item in batch.decisions}
    if batch.role == "primary":
        expected_assignments = set(mapping_by_assignment)
    elif batch.role == "calibration":
        expected_assignments = calibration_ids
    else:
        raw_disagreements = _raw_disagreements(active, calibration_ids)
        unresolved = {
            assignment
            for assignment in raw_disagreements
            if _current_resolution(active, assignment) is None
        }
        if unresolved:
            expected_assignments = unresolved
        elif actual_assignments and actual_assignments <= raw_disagreements:
            # With no unresolved work, a resolution batch is an explicit amendment of
            # the named current resolutions rather than a replay of every old one.
            expected_assignments = actual_assignments
        else:
            raise ExecutionError("adjudication resolution batch has no active disagreements")
    if actual_assignments != expected_assignments:
        raise ExecutionError("adjudication decision batch has missing or unexpected assignments")
    for decision in batch.decisions:
        current = active.get((batch.role, decision.assignment_id))
        if (current is None) != (decision.supersedes is None) or (
            current is not None and decision.supersedes != current.decision_id
        ):
            raise ExecutionError("adjudication decision does not supersede its current record")
        if current is not None and decision.decided_at <= current.decided_at:
            raise ExecutionError("adjudication amendment does not postdate its current record")
        if decision.supersedes == decision.decision_id:
            raise ExecutionError("adjudication decision cannot supersede itself")
        if batch.role == "resolution":
            primary = active.get(("primary", decision.assignment_id))
            calibration = active.get(("calibration", decision.assignment_id))
            if (
                primary is None
                or calibration is None
                or set(decision.resolves)
                != {
                    primary.decision_id,
                    calibration.decision_id,
                }
            ):
                raise ExecutionError("resolution does not bind the two current blind decisions")
    combined_batches = (*prior_batches, batch)
    _combined_by_id, combined_active = _resolve_decisions(combined_batches)
    metrics = _agreement_metrics(combined_active, calibration_ids)
    derived, provenance = _derive_records(mapping, combined_active, prior_derived, batch=batch)
    return ImportSummary(
        packet_id=packet.packet_id,
        imported_decisions=len(batch.decisions),
        calibration_assignments=len(calibration_ids),
        completed_calibrations=metrics[0],
        agreements=metrics[1],
        disagreements=metrics[2],
        unresolved_disagreements=len(_disagreements(combined_active, calibration_ids)),
        agreement_rate=(metrics[1] / metrics[0] if metrics[0] else None),
        derived_records=derived,
        provenance=provenance,
    )


def make_decision_batch(document: Mapping[str, Any]) -> DecisionBatch:
    """Add deterministic batch identity fields to a strict operator-authored document."""

    if "batch_id" in document or "content_digest" in document:
        return DecisionBatch.from_dict(document)
    base = _normalized_batch_document(document)
    digest = canonical_digest(base)
    return DecisionBatch.from_dict(
        {**base, "batch_id": _derived_id("batch", digest), "content_digest": digest}
    )


def load_packet_bytes(payload: bytes) -> AdjudicationPacket:
    return AdjudicationPacket.from_dict(_canonical_object(payload, kind="adjudication packet"))


def load_batch_bytes(payload: bytes) -> DecisionBatch:
    return make_decision_batch(_canonical_object(payload, kind="adjudication decisions"))


def load_submitted_batch_bytes(payload: bytes) -> DecisionBatch:
    """Load human-authored JSON and canonicalize it before immutable publication."""

    try:
        document = json.loads(payload)
        if not isinstance(document, dict):
            raise ValueError
        return make_decision_batch(cast(dict[str, Any], document))
    except (UnicodeError, json.JSONDecodeError, TypeError, ValueError) as exc:
        raise ExecutionError("could not load adjudication decisions") from exc


def load_mapping_bytes(payload: bytes) -> PacketMapping:
    return PacketMapping.from_dict(_canonical_object(payload, kind="adjudication mapping"))


def load_derived_bytes(payload: bytes) -> DerivedArtifact:
    document = _canonical_object(payload, kind="derived adjudication records")
    if set(document) != {"schema_version", "records", "provenance", "content_digest"}:
        raise ExecutionError("derived adjudication record artifact has an unsupported shape")
    if document.get("schema_version") != "1.0" or canonical_digest(
        _without(document, "content_digest")
    ) != document.get("content_digest"):
        raise ExecutionError("derived adjudication record artifact is invalid")
    try:
        records = tuple(
            AdjudicationRecord.from_dict(object_mapping(item))
            for item in object_list(document["records"])
        )
        provenance = tuple(
            _derived_provenance(object_mapping(item))
            for item in object_list(document["provenance"])
        )
    except (SchemaError, TypeError, ValueError) as exc:
        raise ExecutionError("derived adjudication record artifact is invalid") from exc
    records_by_id = {record.adjudication_id: record for record in records}
    provenance_by_id = {item.adjudication_id: item for item in provenance}
    if (
        len(records_by_id) != len(records)
        or len(provenance_by_id) != len(provenance)
        or set(records_by_id) != set(provenance_by_id)
        or [record.adjudication_id for record in records]
        != [item.adjudication_id for item in provenance]
        or any(
            records_by_id[item.adjudication_id].decision != _scoring_decision(item.classification)
            for item in provenance
        )
    ):
        raise ExecutionError("derived adjudication record provenance is inconsistent")
    return DerivedArtifact(
        records=records,
        provenance=provenance,
        content_digest=cast(str, document["content_digest"]),
    )


def derived_artifact(summary: ImportSummary) -> bytes:
    base: dict[str, JsonValue] = {
        "schema_version": "1.0",
        "records": [record.to_dict() for record in summary.derived_records],
        "provenance": [item.to_dict() for item in summary.provenance],
    }
    return canonical_json_bytes({**base, "content_digest": canonical_digest(base)})


def publish_packet_artifacts(
    store: ExperimentStore, packet: AdjudicationPacket, mapping: PacketMapping
) -> None:
    """Publish a packet and its private identity mapping exactly once."""

    from preflight_evals.execution import _publish_private_directory

    target = store.root / "adjudication" / "packets" / packet.packet_id
    _publish_private_directory(
        store.repository_root,
        target.parent,
        target,
        {
            "packet.json": packet.canonical_bytes(),
            "mapping.json": canonical_json_bytes(mapping.to_dict()),
        },
    )


def load_packet_artifacts(
    store: ExperimentStore, packet_id: str
) -> tuple[AdjudicationPacket, PacketMapping]:
    """Load a previously published packet and private mapping."""

    from preflight_evals.execution import _path_contains_symlink, _read_private

    if re.fullmatch(r"packet-[a-f0-9]{32}", packet_id) is None:
        raise ExecutionError("adjudication packet identifier is invalid")
    root = store.root / "adjudication" / "packets" / packet_id
    if (
        root.is_symlink()
        or _path_contains_symlink(store.repository_root, root)
        or not root.is_dir()
        or {item.name for item in root.iterdir()}
        != {
            "packet.json",
            "mapping.json",
        }
    ):
        raise ExecutionError("stored adjudication packet artifacts are missing or unsafe")
    packet = load_packet_bytes(
        _read_private(root / "packet.json", repository_root=store.repository_root)
    )
    mapping = load_mapping_bytes(
        _read_private(root / "mapping.json", repository_root=store.repository_root)
    )
    if packet.packet_id != packet_id or mapping.packet_id != packet_id:
        raise ExecutionError("stored adjudication packet identity is inconsistent")
    return packet, mapping


def publish_import_artifacts(
    store: ExperimentStore, batch: DecisionBatch, summary: ImportSummary
) -> None:
    """Append one immutable imported decision batch and its derived records."""

    from preflight_evals.execution import _publish_private_directory

    target = store.root / "adjudication" / "imports" / batch.packet_id / batch.batch_id
    _publish_private_directory(
        store.repository_root,
        target.parent,
        target,
        {"decisions.json": batch.canonical_bytes(), "derived.json": derived_artifact(summary)},
    )


def load_import_artifacts(
    store: ExperimentStore,
    packet_id: str,
) -> tuple[tuple[DecisionBatch, ...], tuple[AdjudicationRecord, ...]]:
    """Load the complete append-only decision and derived-record history."""

    from preflight_evals.execution import _path_contains_symlink, _read_private

    if re.fullmatch(r"packet-[a-f0-9]{32}", packet_id) is None:
        raise ExecutionError("adjudication packet identifier is invalid")
    root = store.root / "adjudication" / "imports" / packet_id
    if not root.exists() and not root.is_symlink():
        return (), ()
    if (
        root.is_symlink()
        or _path_contains_symlink(store.repository_root, root)
        or not root.is_dir()
    ):
        raise ExecutionError("stored adjudication import history is unsafe")
    batches: list[DecisionBatch] = []
    derived: list[AdjudicationRecord] = []
    loaded_artifacts: list[tuple[DecisionBatch, DerivedArtifact]] = []
    for child in sorted(root.iterdir(), key=lambda path: path.name):
        if (
            child.is_symlink()
            or _path_contains_symlink(store.repository_root, child)
            or not child.is_dir()
            or re.fullmatch(r"batch-[a-f0-9]{32}", child.name) is None
            or {item.name for item in child.iterdir()} != {"decisions.json", "derived.json"}
        ):
            raise ExecutionError("stored adjudication import history contains unexpected state")
        batch = load_batch_bytes(
            _read_private(child / "decisions.json", repository_root=store.repository_root)
        )
        if batch.batch_id != child.name:
            raise ExecutionError("stored adjudication import identity is inconsistent")
        if batch.packet_id != packet_id:
            raise ExecutionError("stored adjudication import targets a different packet")
        batches.append(batch)
        loaded_artifacts.append(
            (
                batch,
                load_derived_bytes(
                    _read_private(child / "derived.json", repository_root=store.repository_root)
                ),
            )
        )
    _resolve_decisions(batches)
    decision_roles = {
        decision.decision_id: (batch.role, decision)
        for batch in batches
        for decision in batch.decisions
    }
    for batch, artifact in loaded_artifacts:
        batch_decision_ids = {item.decision_id for item in batch.decisions}
        for provenance in artifact.provenance:
            sources = [decision_roles.get(item) for item in provenance.source_decision_ids]
            if (
                provenance.source_batch_id != batch.batch_id
                or not batch_decision_ids.intersection(provenance.source_decision_ids)
                or any(source is None for source in sources)
                or any(
                    source[1].assignment_id != provenance.assignment_id
                    for source in sources
                    if source is not None
                )
                or _provenance_classification(sources) != provenance.classification
            ):
                raise ExecutionError("stored adjudication import provenance is inconsistent")
        derived.extend(artifact.records)
    batches.sort(key=lambda batch: (batch.submitted_at, batch.batch_id))
    return tuple(batches), tuple(derived)


def write_packet_file(repository_root: Path, path: Path, packet: AdjudicationPacket) -> None:
    """Write the adjudicator-facing packet under the protected repository artifact tree."""

    from preflight_evals.execution import _write_once

    _write_once(repository_root, path, packet.canonical_bytes())


def validate_current_bindings(
    experiment: ExperimentManifest,
    packet: AdjudicationPacket,
    mapping: PacketMapping,
    records: Sequence[RunRecord],
    gold_records: Sequence[GoldRecord],
) -> None:
    current_rubrics = _rubric_bindings(gold_records)
    if (
        current_rubrics != mapping.rubrics
        or _rubric_version(current_rubrics) != mapping.rubric_version
    ):
        raise ExecutionError("adjudication rubric set version is stale")
    records_by_id = {record.run_id: record for record in records}
    planned_by_id = {planned.run_id: planned for planned in experiment.execution_order}
    gold_by_case = {gold.case_id: gold for gold in gold_records}
    exposed_by_id = {item.assignment_id: item for item in packet.items}
    if set(exposed_by_id) != {item.assignment_id for item in mapping.items}:
        raise ExecutionError("adjudication packet and private mapping assignments do not agree")
    selected_run_ids = {item.run_id for item in mapping.items}
    redacted_finding_ids = tuple(
        finding.finding_id
        for record in records
        if record.reviewer_output is not None
        for finding in record.reviewer_output.findings
    )
    late_boundaries = [
        record.ended_at
        for run_id, record in records_by_id.items()
        if run_id in selected_run_ids
        and planned_by_id.get(run_id) is not None
        and planned_by_id[run_id].snapshot == "fixed"
    ] + [
        record.started_at
        for run_id, record in records_by_id.items()
        if run_id in selected_run_ids
        and planned_by_id.get(run_id) is not None
        and planned_by_id[run_id].repetition > 1
    ]
    if late_boundaries and mapping.rubric_approved_at > min(late_boundaries):
        raise ExecutionError("adjudication rubric approval provenance is stale")
    for item in mapping.items:
        record = records_by_id.get(item.run_id)
        planned = planned_by_id.get(item.run_id)
        gold = gold_by_case.get(item.case_id)
        if (
            record is None
            or record.reviewer_output is None
            or record.experiment_id != mapping.experiment_id
            or record.status != "succeeded"
            or planned is None
            or planned.case_id != item.case_id
            or gold is None
        ):
            raise ExecutionError("adjudication source finding or rubric is unavailable")
        finding = next(
            (
                value
                for value in record.reviewer_output.findings
                if value.finding_id == item.finding_id
            ),
            None,
        )
        mechanism = next(
            (
                value
                for value in gold.expected_mechanisms
                if value.mechanism_id == item.expected_mechanism_id
            ),
            None,
        )
        exposed = exposed_by_id[item.assignment_id]
        if (
            finding is None
            or mechanism is None
            or canonical_digest(finding.to_dict()) != item.finding_digest
            or canonical_digest(
                {
                    "case_id": gold.case_id,
                    "mechanism_id": mechanism.mechanism_id,
                    "rubric": mechanism.adjudication_rubric,
                }
            )
            != item.rubric_digest
            or exposed.calibration != item.calibration
            or exposed.finding.to_dict()
            != BlindedFinding.from_finding(
                finding, redacted_finding_ids=redacted_finding_ids
            ).to_dict()
            or exposed.rubric != mechanism.adjudication_rubric
            or item.assignment_id
            != _assignment_id(experiment, planned, finding, mechanism.mechanism_id)
        ):
            raise ExecutionError("adjudication source finding or rubric is stale")


def _resolve_decisions(
    batches: Sequence[DecisionBatch],
) -> tuple[dict[str, BlindDecision], dict[tuple[str, str], BlindDecision]]:
    by_id: dict[str, BlindDecision] = {}
    roles: dict[str, DecisionRole] = {}
    superseded: set[str] = set()
    for batch in batches:
        for decision in batch.decisions:
            if decision.decision_id in by_id:
                raise ExecutionError("adjudication history contains duplicate decision identifiers")
            by_id[decision.decision_id] = decision
            roles[decision.decision_id] = batch.role

    for decision_id, decision in by_id.items():
        if decision.supersedes is not None:
            prior = by_id.get(decision.supersedes)
            if (
                prior is None
                or roles[decision.supersedes] != roles[decision_id]
                or prior.assignment_id != decision.assignment_id
                or decision.decided_at <= prior.decided_at
                or decision.supersedes in superseded
            ):
                raise ExecutionError("adjudication history contains a forked supersession chain")
            superseded.add(decision.supersedes)
        if roles[decision_id] == "resolution":
            sources = [by_id.get(source_id) for source_id in decision.resolves]
            if (
                any(source is None for source in sources)
                or {roles.get(source_id) for source_id in decision.resolves}
                != {"primary", "calibration"}
                or any(
                    source.assignment_id != decision.assignment_id for source in sources if source
                )
                or any(decision.decided_at <= source.decided_at for source in sources if source)
            ):
                raise ExecutionError("adjudication resolution history has invalid source decisions")

    grouped: dict[tuple[str, str], list[BlindDecision]] = {}
    for decision_id, decision in by_id.items():
        grouped.setdefault((roles[decision_id], decision.assignment_id), []).append(decision)
    active: dict[tuple[str, str], BlindDecision] = {}
    for key, decisions in grouped.items():
        roots = [decision for decision in decisions if decision.supersedes is None]
        leaves = [decision for decision in decisions if decision.decision_id not in superseded]
        if len(roots) != 1 or len(leaves) != 1:
            raise ExecutionError("adjudication history contains a forked supersession chain")
        visited: set[str] = set()
        current: BlindDecision | None = leaves[0]
        while current is not None:
            if current.decision_id in visited:
                raise ExecutionError("adjudication history contains a cyclic supersession chain")
            visited.add(current.decision_id)
            current = by_id.get(current.supersedes) if current.supersedes is not None else None
        if len(visited) != len(decisions):
            raise ExecutionError("adjudication history contains a disconnected supersession chain")
        active[key] = leaves[0]
    return by_id, active


def _raw_disagreements(
    active: Mapping[tuple[str, str], BlindDecision], calibration_ids: set[str]
) -> set[str]:
    return {
        assignment
        for assignment in calibration_ids
        if (primary := active.get(("primary", assignment))) is not None
        and (calibration := active.get(("calibration", assignment))) is not None
        and primary.classification != calibration.classification
    }


def _disagreements(
    active: Mapping[tuple[str, str], BlindDecision], calibration_ids: set[str]
) -> set[str]:
    return {
        assignment
        for assignment in _raw_disagreements(active, calibration_ids)
        if _current_resolution(active, assignment) is None
    }


def _agreement_metrics(
    active: Mapping[tuple[str, str], BlindDecision], calibration_ids: set[str]
) -> tuple[int, int, int]:
    completed = 0
    agreements = 0
    for assignment in calibration_ids:
        primary = active.get(("primary", assignment))
        calibration = active.get(("calibration", assignment))
        if primary is None or calibration is None:
            continue
        completed += 1
        agreements += primary.classification == calibration.classification
    return completed, agreements, completed - agreements


def _derive_records(
    mapping: PacketMapping,
    active: Mapping[tuple[str, str], BlindDecision],
    prior: Sequence[AdjudicationRecord],
    *,
    batch: DecisionBatch,
) -> tuple[tuple[AdjudicationRecord, ...], tuple[DerivedProvenance, ...]]:
    from preflight_evals.score import _resolve_adjudications

    try:
        current_prior = _resolve_adjudications(tuple(prior))
    except SchemaError as exc:
        raise ExecutionError("derived adjudication history is invalid") from exc
    generated: list[AdjudicationRecord] = []
    provenance: list[DerivedProvenance] = []
    for item in mapping.items:
        primary = active.get(("primary", item.assignment_id))
        calibration = active.get(("calibration", item.assignment_id))
        resolution = _current_resolution(active, item.assignment_id)
        source: tuple[BlindDecision, ...]
        if item.calibration:
            if resolution is not None:
                source = (resolution,)
            elif primary is not None and calibration is not None:
                source = (primary, calibration)
            else:
                continue
        elif primary is not None:
            source = (primary,)
        else:
            continue
        classifications = {decision.classification for decision in source}
        classification: DecisionClassification = (
            next(iter(classifications)) if len(classifications) == 1 else "uncertain"
        )
        decision_ids = tuple(
            sorted(
                {
                    *(decision.decision_id for decision in source),
                    *((resolution.resolves) if resolution is not None else ()),
                }
            )
        )
        key = (item.run_id, item.finding_id, item.expected_mechanism_id)
        previous = current_prior.get(key)
        identity = canonical_digest(
            {
                "assignment_id": item.assignment_id,
                "classification": classification,
                "source_decision_ids": list(decision_ids),
            }
        )
        adjudication_id = f"adjudication-{identity.removeprefix('sha256:')[:32]}"
        if previous is not None and previous.adjudication_id == adjudication_id:
            continue
        latest = max(source, key=lambda decision: decision.decided_at)
        actor = (
            mapping.resolution_adjudicator
            if resolution is not None
            else (
                "blind-calibration-consensus" if item.calibration else mapping.primary_adjudicator
            )
        )
        record = AdjudicationRecord.from_dict(
            {
                "schema_version": "1.0",
                "adjudication_id": adjudication_id,
                "run_id": item.run_id,
                "finding_id": item.finding_id,
                "expected_mechanism_id": item.expected_mechanism_id,
                "decision": _scoring_decision(classification),
                "rubric_version": mapping.rubric_version,
                "adjudicator": actor,
                "timestamp": _iso_string(latest.decided_at),
                "rationale": "Imported from blind adjudication decision provenance.",
                "supersedes": previous.adjudication_id if previous is not None else None,
            }
        )
        generated.append(record)
        provenance.append(
            DerivedProvenance(
                adjudication_id=adjudication_id,
                assignment_id=item.assignment_id,
                source_decision_ids=decision_ids,
                source_batch_id=batch.batch_id,
                classification=classification,
            )
        )
    return tuple(generated), tuple(provenance)


def _reject_packet_disclosures(
    packet: AdjudicationPacket,
    experiment: ExperimentManifest,
    records: Sequence[RunRecord],
) -> None:
    sensitive = {
        experiment.experiment_id,
        cast(str, experiment.content_digest),
        experiment.baseline_profile.digest,
        experiment.candidate_profile.digest,
        *(case.case_id for case in experiment.cases),
        *(case.vulnerable_snapshot for case in experiment.cases),
        *(case.fixed_snapshot for case in experiment.cases),
        *(record.run_id for record in records),
        *(
            finding.finding_id
            for record in records
            if record.reviewer_output is not None
            for finding in record.reviewer_output.findings
        ),
    }
    values = tuple(_string_values(packet.to_dict()))
    if (
        _contains_full_sha(values)
        or any(marker and marker in value for value in values for marker in sensitive)
        or _contains_blind_label(values)
    ):
        raise ExecutionError("adjudication packet contains an unblinded identity")
    forbidden_keys = {
        "case_id",
        "run_id",
        "finding_id",
        "mechanism_id",
        "profile",
        "condition",
        "snapshot",
        "repair_sha",
        "source_commit",
    }
    if set(_all_keys(packet.to_dict())).intersection(forbidden_keys):
        raise ExecutionError("adjudication packet contains an unblinded field")


def _reject_unblinded_batch(
    batch: DecisionBatch, mapping: PacketMapping, experiment: ExperimentManifest
) -> None:
    sensitive = {
        mapping.experiment_id,
        mapping.experiment_digest,
        *(item.run_id for item in mapping.items),
        *(item.case_id for item in mapping.items),
        *(item.finding_id for item in mapping.items),
        *(item.expected_mechanism_id for item in mapping.items),
        experiment.baseline_profile.digest,
        experiment.candidate_profile.digest,
        *(case.vulnerable_snapshot for case in experiment.cases),
        *(case.fixed_snapshot for case in experiment.cases),
    }
    values = tuple(_string_values(batch.to_dict()))
    if (
        _contains_full_sha(values)
        or any(marker and marker in value for value in values for marker in sensitive)
        or _contains_blind_label(values)
    ):
        raise ExecutionError("adjudication decisions contain an unblinded identity")


def _current_resolution(
    active: Mapping[tuple[str, str], BlindDecision], assignment: str
) -> BlindDecision | None:
    resolution = active.get(("resolution", assignment))
    primary = active.get(("primary", assignment))
    calibration = active.get(("calibration", assignment))
    if (
        resolution is None
        or primary is None
        or calibration is None
        or set(resolution.resolves) != {primary.decision_id, calibration.decision_id}
    ):
        return None
    return resolution


def _assignment_id(
    experiment: ExperimentManifest,
    planned: PlannedRun,
    finding: Finding,
    mechanism_id: str,
) -> str:
    digest = canonical_digest(
        {
            "namespace": cast(str, experiment.content_digest),
            "run_id": planned.run_id,
            "finding_id": finding.finding_id,
            "mechanism_id": mechanism_id,
        }
    )
    return _derived_id("assignment", digest)


def _random_key(seed: int, identity: str, domain: str) -> bytes:
    return hashlib.sha256(f"{seed}\0{domain}\0{identity}".encode()).digest()


def _replace_calibration(item: MappingItem, calibration: bool) -> MappingItem:
    return MappingItem(
        assignment_id=item.assignment_id,
        run_id=item.run_id,
        case_id=item.case_id,
        finding_id=item.finding_id,
        expected_mechanism_id=item.expected_mechanism_id,
        finding_digest=item.finding_digest,
        rubric_digest=item.rubric_digest,
        calibration=calibration,
    )


def _replace_packet_calibration(
    item: AdjudicationPacketItem, calibration: bool
) -> AdjudicationPacketItem:
    return AdjudicationPacketItem(
        assignment_id=item.assignment_id,
        calibration=calibration,
        finding=item.finding,
        rubric=item.rubric,
    )


def _rubric_bindings(gold_records: Sequence[GoldRecord]) -> tuple[RubricBinding, ...]:
    bindings = tuple(
        sorted(
            (
                RubricBinding(
                    case_id=gold.case_id,
                    mechanism_id=mechanism.mechanism_id,
                    rubric_digest=canonical_digest(
                        {
                            "case_id": gold.case_id,
                            "mechanism_id": mechanism.mechanism_id,
                            "rubric": mechanism.adjudication_rubric,
                        }
                    ),
                )
                for gold in gold_records
                for mechanism in gold.expected_mechanisms
            ),
            key=_rubric_sort_key,
        )
    )
    keys = [(item.case_id, item.mechanism_id) for item in bindings]
    if not bindings or len(keys) != len(set(keys)):
        raise ExecutionError("adjudication rubric set is missing or duplicated")
    return bindings


def build_rubric_review_manifest(gold_records: Sequence[GoldRecord]) -> dict[str, JsonValue]:
    """Build an unblinded private packet for curator review before execution."""

    bindings = _rubric_bindings(gold_records)
    rubrics_by_key = {
        (gold.case_id, mechanism.mechanism_id): mechanism.adjudication_rubric
        for gold in gold_records
        for mechanism in gold.expected_mechanisms
    }
    base: dict[str, JsonValue] = {
        "schema_version": "1.0",
        "rubric_version": _rubric_version(bindings),
        "rubrics": [
            {
                "case_id": binding.case_id,
                "mechanism_id": binding.mechanism_id,
                "rubric": rubrics_by_key[(binding.case_id, binding.mechanism_id)],
                "rubric_digest": binding.rubric_digest,
            }
            for binding in bindings
        ],
    }
    return {**base, "content_digest": canonical_digest(base)}


def validate_complete_decision_history(
    packet: AdjudicationPacket,
    mapping: PacketMapping,
    batches: Sequence[DecisionBatch],
) -> dict[str, JsonValue]:
    """Require complete primary/calibration decisions and resolved disagreements."""

    if packet.packet_id != mapping.packet_id or packet.content_digest != mapping.packet_digest:
        raise ExecutionError("adjudication packet and mapping do not agree")
    _by_id, active = _resolve_decisions(batches)
    assignment_ids = {item.assignment_id for item in packet.items}
    calibration_ids = {item.assignment_id for item in packet.items if item.calibration}
    primary_ids = {assignment for role, assignment in active if role == "primary"}
    observed_calibration_ids = {assignment for role, assignment in active if role == "calibration"}
    expected_actor = {
        "primary": mapping.primary_adjudicator,
        "calibration": mapping.calibration_adjudicator,
        "resolution": mapping.resolution_adjudicator,
    }
    if (
        primary_ids != assignment_ids
        or observed_calibration_ids != calibration_ids
        or not any(batch.role == "primary" for batch in batches)
        or not any(batch.role == "calibration" for batch in batches)
        or any(batch.adjudicator != expected_actor[batch.role] for batch in batches)
    ):
        raise ExecutionError("blind adjudication decision history is incomplete")
    completed, agreements, disagreements = _agreement_metrics(active, calibration_ids)
    unresolved = _disagreements(active, calibration_ids)
    if completed != len(calibration_ids) or unresolved:
        raise ExecutionError("blind adjudication disagreements remain unresolved")
    return {
        "schema_version": "1.0",
        "assignments": len(assignment_ids),
        "calibration_assignments": len(calibration_ids),
        "agreements": agreements,
        "disagreements": disagreements,
        "unresolved_disagreements": 0,
        "agreement_rate": agreements / completed if completed else None,
    }


def _rubric_sort_key(item: RubricBinding) -> tuple[str, str]:
    return item.case_id, item.mechanism_id


def _rubric_version(bindings: Sequence[RubricBinding]) -> str:
    return canonical_digest(
        {
            "schema_version": "1",
            "rubrics": [item.to_dict() for item in bindings],
        }
    )


def _normalized_batch_document(document: Mapping[str, Any]) -> dict[str, JsonValue]:
    try:
        base = {key: cast(JsonValue, value) for key, value in document.items()}
        base["submitted_at"] = _iso_string(
            iso_datetime(cast(str, base["submitted_at"]), field="submitted_at")
        )
        decisions: list[JsonValue] = []
        for value in object_list(base["decisions"]):
            decision = {key: cast(JsonValue, item) for key, item in object_mapping(value).items()}
            decision["decided_at"] = _iso_string(
                iso_datetime(cast(str, decision["decided_at"]), field="decided_at")
            )
            decisions.append(decision)
        base["decisions"] = decisions
        return base
    except (KeyError, TypeError, AttributeError, SchemaError) as exc:
        raise SchemaError("adjudication decision timestamps are invalid") from exc


def _derived_provenance(document: Mapping[str, Any]) -> DerivedProvenance:
    fields = {
        "adjudication_id",
        "assignment_id",
        "source_decision_ids",
        "source_batch_id",
        "classification",
    }
    try:
        sources = tuple(cast(str, item) for item in object_list(document["source_decision_ids"]))
        model = DerivedProvenance(
            adjudication_id=cast(str, document["adjudication_id"]),
            assignment_id=cast(str, document["assignment_id"]),
            source_decision_ids=sources,
            source_batch_id=cast(str, document["source_batch_id"]),
            classification=cast(DecisionClassification, document["classification"]),
        )
    except (KeyError, TypeError, ValueError) as exc:
        raise SchemaError("derived adjudication provenance is invalid") from exc
    if (
        set(document) != fields
        or re.fullmatch(r"adjudication-[a-z0-9]+(?:-[a-z0-9]+)*", model.adjudication_id) is None
        or re.fullmatch(r"assignment-[a-f0-9]{32}", model.assignment_id) is None
        or not model.source_decision_ids
        or len(model.source_decision_ids) != len(set(model.source_decision_ids))
        or any(
            re.fullmatch(r"decision-[a-z0-9]+(?:-[a-z0-9]+)*", item) is None
            for item in model.source_decision_ids
        )
        or re.fullmatch(r"batch-[a-f0-9]{32}", model.source_batch_id) is None
        or model.classification not in {"match", "symptom_only", "incorrect_cause", "uncertain"}
    ):
        raise SchemaError("derived adjudication provenance is invalid")
    return model


def _provenance_classification(
    sources: Sequence[tuple[DecisionRole, BlindDecision] | None],
) -> DecisionClassification:
    available = [source for source in sources if source is not None]
    resolutions = [decision for role, decision in available if role == "resolution"]
    non_resolutions = [(role, decision) for role, decision in available if role != "resolution"]
    if resolutions:
        resolution = resolutions[0]
        if (
            len(resolutions) != 1
            or {role for role, _decision in non_resolutions} != {"primary", "calibration"}
            or set(resolution.resolves)
            != {decision.decision_id for _role, decision in non_resolutions}
        ):
            raise ExecutionError("stored adjudication import provenance is inconsistent")
        return resolution.classification
    if len(non_resolutions) == 1 and non_resolutions[0][0] == "primary":
        return non_resolutions[0][1].classification
    if len(non_resolutions) == 2 and {role for role, _decision in non_resolutions} == {
        "primary",
        "calibration",
    }:
        classifications = {decision.classification for _role, decision in non_resolutions}
        return next(iter(classifications)) if len(classifications) == 1 else "uncertain"
    raise ExecutionError("stored adjudication import provenance is inconsistent")


def _verify_derived_identity(document: Mapping[str, Any], *, kind: str) -> None:
    identifier_key = f"{kind}_id"
    base = _without(document, identifier_key, "content_digest")
    digest = canonical_digest(base)
    if document.get("content_digest") != digest or document.get(identifier_key) != _derived_id(
        kind, digest
    ):
        raise SchemaError(f"adjudication {kind} identity or content digest is inconsistent")


def _derived_id(kind: str, digest: str) -> str:
    return f"{kind}-{digest.removeprefix('sha256:')[:32]}"


def _scoring_decision(classification: DecisionClassification) -> str:
    if classification == "match":
        return "match"
    if classification == "uncertain":
        return "uncertain"
    return "no_match"


def _canonical_object(payload: bytes, *, kind: str) -> dict[str, Any]:
    try:
        document = json.loads(payload)
        if (
            not isinstance(document, dict)
            or canonical_json_bytes(cast(JsonValue, document)) != payload
        ):
            raise ValueError
        return cast(dict[str, Any], document)
    except (UnicodeError, json.JSONDecodeError, TypeError, ValueError) as exc:
        raise ExecutionError(f"could not load canonical {kind}") from exc


def _without(document: Mapping[str, Any], *names: str) -> dict[str, JsonValue]:
    return {key: cast(JsonValue, value) for key, value in document.items() if key not in set(names)}


def _actors(mapping: PacketMapping) -> tuple[str, str, str]:
    return (
        mapping.primary_adjudicator,
        mapping.calibration_adjudicator,
        mapping.resolution_adjudicator,
    )


def _valid_mapping_scalars(mapping: PacketMapping) -> bool:
    return (
        isinstance(mapping.packet_id, str)
        and re.fullmatch(r"packet-[a-f0-9]{32}", mapping.packet_id) is not None
        and isinstance(mapping.packet_digest, str)
        and _digest_pattern(mapping.packet_digest)
        and isinstance(mapping.experiment_id, str)
        and re.fullmatch(r"experiment-[a-f0-9]{32}", mapping.experiment_id) is not None
        and isinstance(mapping.experiment_digest, str)
        and _digest_pattern(mapping.experiment_digest)
        and isinstance(mapping.rubric_version, str)
        and _digest_pattern(mapping.rubric_version)
        and isinstance(mapping.rubric_approved_by, str)
        and 1 <= len(mapping.rubric_approved_by) <= 120
        and all(isinstance(actor, str) for actor in _actors(mapping))
    )


def _valid_mapping_item(item: MappingItem) -> bool:
    return (
        isinstance(item.assignment_id, str)
        and re.fullmatch(r"assignment-[a-f0-9]{32}", item.assignment_id) is not None
        and isinstance(item.run_id, str)
        and re.fullmatch(r"run-[a-z0-9]+(?:-[a-z0-9]+)*", item.run_id) is not None
        and isinstance(item.case_id, str)
        and re.fullmatch(r"[a-z0-9]+(?:-[a-z0-9]+)*", item.case_id) is not None
        and isinstance(item.finding_id, str)
        and re.fullmatch(r"F[0-9]{3,}", item.finding_id) is not None
        and isinstance(item.expected_mechanism_id, str)
        and re.fullmatch(r"mechanism-[a-z0-9]+(?:-[a-z0-9]+)*", item.expected_mechanism_id)
        is not None
        and isinstance(item.finding_digest, str)
        and _digest_pattern(item.finding_digest)
        and isinstance(item.rubric_digest, str)
        and _digest_pattern(item.rubric_digest)
        and type(item.calibration) is bool
    )


def _valid_rubric_binding(item: RubricBinding) -> bool:
    return (
        isinstance(item.case_id, str)
        and re.fullmatch(r"[a-z0-9]+(?:-[a-z0-9]+)*", item.case_id) is not None
        and isinstance(item.mechanism_id, str)
        and re.fullmatch(r"mechanism-[a-z0-9]+(?:-[a-z0-9]+)*", item.mechanism_id) is not None
        and isinstance(item.rubric_digest, str)
        and _digest_pattern(item.rubric_digest)
    )


def _digest_pattern(value: str) -> bool:
    return re.fullmatch(r"sha256:[a-f0-9]{64}", value) is not None


def _contains_full_sha(values: Iterable[str]) -> bool:
    return any(
        re.search(r"(?<![A-Fa-f0-9])[A-Fa-f0-9]{40}(?![A-Fa-f0-9])", value) is not None
        for value in values
    )


def _contains_blind_label(values: Iterable[str]) -> bool:
    exact_labels = {"baseline", "candidate", "vulnerable", "fixed", "development", "holdout"}
    patterns = (
        r"\b(?:baseline|candidate)\s+(?:profile|condition)\b",
        r"\b(?:profile|condition)\s*(?:(?:is|was)\s+|[:=]\s*)?(?:baseline|candidate)\b",
        r"\b(?:vulnerable|fixed)\s+(?:snapshot|condition|case|control)\b",
        r"\b(?:snapshot|condition|case|control)\s*(?:(?:is|was)\s+|[:=]\s*)?(?:vulnerable|fixed)\b",
        r"\b(?:development|holdout)\s+(?:case|cohort|membership|set|role)\b",
        r"\b(?:case|cohort|membership|set|role)\s*(?:(?:is|was)\s+|[:=]\s*)?(?:development|holdout)\b",
    )
    for value in values:
        normalized = " ".join(unicodedata.normalize("NFKC", value).casefold().split())
        if normalized in exact_labels or any(
            re.search(pattern, normalized) for pattern in patterns
        ):
            return True
    return False


def _string_values(value: JsonValue) -> Iterable[str]:
    if isinstance(value, str):
        yield value
    elif isinstance(value, dict):
        for child in value.values():
            yield from _string_values(child)
    elif isinstance(value, list | tuple):
        for child in value:
            yield from _string_values(child)


def _all_keys(value: JsonValue) -> Iterable[str]:
    if isinstance(value, dict):
        for key, child in value.items():
            yield key
            yield from _all_keys(child)
    elif isinstance(value, list | tuple):
        for child in value:
            yield from _all_keys(child)


def _aware(value: datetime, *, field: str) -> None:
    if value.tzinfo is None or value.utcoffset() is None:
        raise ExecutionError(f"{field} must include a timezone")


def _iso_string(value: datetime) -> str:
    return value.astimezone(UTC).isoformat().replace("+00:00", "Z")
