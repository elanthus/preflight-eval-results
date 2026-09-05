"""Scorer-only contract models forbidden from reviewer-facing modules."""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from datetime import datetime
from pathlib import PurePosixPath
from typing import Any, Literal, cast

from preflight_evals.canonical import JsonValue
from preflight_evals.errors import SchemaError
from preflight_evals.model_types import (
    SEVERITY_ORDER,
    DefectCategory,
    Severity,
    iso_datetime,
    object_list,
    object_mapping,
    repository_path,
)
from preflight_evals.schema import validate_contract


@dataclass(frozen=True, slots=True)
class ExpectedBehavior:
    vulnerable: str
    fixed: str


@dataclass(frozen=True, slots=True)
class AcceptableLocation:
    path: PurePosixPath
    aliases: tuple[PurePosixPath, ...]
    start_line: int | None
    end_line: int | None


@dataclass(frozen=True, slots=True)
class SeverityRange:
    minimum: Severity
    maximum: Severity


@dataclass(frozen=True, slots=True)
class FixedFingerprint:
    digest: str
    source_path: PurePosixPath
    source_record_id: str


@dataclass(frozen=True, slots=True)
class Provenance:
    excerpt: str
    source_record_id: str


type SnapshotExpectation = Literal["present", "absent", "unverified"]
type EvaluationRole = Literal["primary", "supplemental"]


@dataclass(frozen=True, slots=True)
class SnapshotExpectations:
    vulnerable: SnapshotExpectation
    fixed: SnapshotExpectation

    def for_snapshot(self, snapshot: str) -> SnapshotExpectation:
        return self.vulnerable if snapshot == "vulnerable" else self.fixed


@dataclass(frozen=True, slots=True)
class ExpectedMechanism:
    mechanism_id: str
    description: str
    adjudication_rubric: str
    evaluation_role: EvaluationRole
    snapshot_expectations: SnapshotExpectations
    acceptable_locations: tuple[AcceptableLocation, ...]
    accepted_defect_categories: tuple[DefectCategory, ...]
    severity_range: SeverityRange
    provenance: Provenance


@dataclass(frozen=True, slots=True)
class AdjudicationRequirements:
    required: bool
    accepted_alternative_matches: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class GoldRecord:
    """Scorer-only labels, fingerprints, acceptable matches, and provenance."""

    schema_version: str
    case_id: str
    expected_behavior: ExpectedBehavior
    expected_mechanisms: tuple[ExpectedMechanism, ...]
    acceptable_locations: tuple[AcceptableLocation, ...]
    accepted_defect_categories: tuple[DefectCategory, ...]
    severity_range: SeverityRange
    forbidden_expected_phrases: tuple[str, ...]
    fixed_only_fingerprints: tuple[FixedFingerprint, ...]
    provenance: Provenance | None
    curator_notes: str
    adjudication: AdjudicationRequirements

    @classmethod
    def from_dict(cls, document: Mapping[str, Any]) -> GoldRecord:
        data = validate_contract("gold", dict(document))
        behavior = object_mapping(data["expected_behavior"])
        adjudication = object_mapping(data["adjudication"])
        schema_version = cast(str, data["schema_version"])
        if schema_version in {"1.0", "1.1"}:
            acceptable_locations = tuple(
                _acceptable_location(object_mapping(item))
                for item in object_list(data["acceptable_locations"])
            )
            accepted_categories = tuple(
                cast(DefectCategory, item)
                for item in object_list(data["accepted_defect_categories"])
            )
            severity = _severity_range(object_mapping(data["severity_range"]))
            provenance = _provenance(object_mapping(data["provenance"]))
            expected_mechanisms = tuple(
                _legacy_expected_mechanism(
                    object_mapping(item),
                    acceptable_locations=acceptable_locations,
                    accepted_defect_categories=accepted_categories,
                    severity_range=severity,
                    provenance=provenance,
                )
                for item in object_list(data["expected_mechanisms"])
            )
        else:
            acceptable_locations = ()
            accepted_categories = ()
            severity = SeverityRange(minimum="low", maximum="critical")
            provenance = None
            expected_mechanisms = tuple(
                _expected_mechanism(object_mapping(item))
                for item in object_list(data["expected_mechanisms"])
            )
        model = cls(
            schema_version=schema_version,
            case_id=cast(str, data["case_id"]),
            expected_behavior=ExpectedBehavior(
                vulnerable=cast(str, behavior["vulnerable"]),
                fixed=cast(str, behavior["fixed"]),
            ),
            expected_mechanisms=expected_mechanisms,
            acceptable_locations=acceptable_locations,
            accepted_defect_categories=accepted_categories,
            severity_range=severity,
            forbidden_expected_phrases=tuple(
                cast(str, item) for item in object_list(data["forbidden_expected_phrases"])
            ),
            fixed_only_fingerprints=tuple(
                _fixed_fingerprint(object_mapping(item))
                for item in object_list(data["fixed_only_fingerprints"])
            ),
            provenance=provenance,
            curator_notes=cast(str, data["curator_notes"]),
            adjudication=AdjudicationRequirements(
                required=cast(bool, adjudication["required"]),
                accepted_alternative_matches=tuple(
                    cast(str, item)
                    for item in object_list(adjudication["accepted_alternative_matches"])
                ),
            ),
        )
        model._validate_relationships()
        return model

    def to_dict(self) -> dict[str, JsonValue]:
        document: dict[str, JsonValue] = {
            "schema_version": self.schema_version,
            "case_id": self.case_id,
            "expected_behavior": {
                "vulnerable": self.expected_behavior.vulnerable,
                "fixed": self.expected_behavior.fixed,
            },
            "expected_mechanisms": [],
            "forbidden_expected_phrases": list(self.forbidden_expected_phrases),
            "fixed_only_fingerprints": [
                {
                    "digest": fingerprint.digest,
                    "source_path": fingerprint.source_path.as_posix(),
                    "source_record_id": fingerprint.source_record_id,
                }
                for fingerprint in self.fixed_only_fingerprints
            ],
            "curator_notes": self.curator_notes,
            "adjudication": {
                "required": self.adjudication.required,
                "accepted_alternative_matches": list(
                    self.adjudication.accepted_alternative_matches
                ),
            },
        }
        if self.schema_version in {"1.0", "1.1"}:
            if self.provenance is None:
                raise SchemaError("legacy gold requires top-level provenance")
            document["expected_mechanisms"] = [
                {
                    "mechanism_id": mechanism.mechanism_id,
                    "description": mechanism.description,
                    "adjudication_rubric": mechanism.adjudication_rubric,
                }
                for mechanism in self.expected_mechanisms
            ]
            document["acceptable_locations"] = [
                _acceptable_location_dict(location) for location in self.acceptable_locations
            ]
            document["accepted_defect_categories"] = list(self.accepted_defect_categories)
            document["severity_range"] = _severity_range_dict(self.severity_range)
            document["provenance"] = _provenance_dict(self.provenance)
        else:
            document["expected_mechanisms"] = [
                _expected_mechanism_dict(mechanism) for mechanism in self.expected_mechanisms
            ]
        return document

    def _validate_relationships(self) -> None:
        mechanism_ids = [mechanism.mechanism_id for mechanism in self.expected_mechanisms]
        if len(mechanism_ids) != len(set(mechanism_ids)):
            raise SchemaError("gold expected mechanism identifiers must be unique")
        if self.schema_version == "2.0":
            primary = [
                mechanism
                for mechanism in self.expected_mechanisms
                if mechanism.evaluation_role == "primary"
            ]
            if len(primary) != 1:
                raise SchemaError("gold 2.0 requires exactly one primary mechanism")
            if primary[0].snapshot_expectations != SnapshotExpectations(
                vulnerable="present", fixed="absent"
            ):
                raise SchemaError(
                    "gold 2.0 primary mechanism must be present in vulnerable and absent in fixed"
                )
        for mechanism in self.expected_mechanisms:
            if (
                mechanism.snapshot_expectations.vulnerable == "unverified"
                and mechanism.snapshot_expectations.fixed == "unverified"
            ):
                raise SchemaError("gold mechanism must verify at least one snapshot")
            _validate_match_constraints(
                mechanism.acceptable_locations,
                mechanism.severity_range,
            )


def _validate_match_constraints(
    locations: tuple[AcceptableLocation, ...], severity_range: SeverityRange
) -> None:
    if SEVERITY_ORDER[severity_range.minimum] > SEVERITY_ORDER[severity_range.maximum]:
        raise SchemaError("gold severity range minimum cannot exceed maximum")
    canonical_paths = {location.path for location in locations}
    alias_owners: dict[PurePosixPath, PurePosixPath] = {}
    for location in locations:
        if location.path in location.aliases:
            raise SchemaError("gold path alias cannot repeat its canonical path")
        if canonical_paths.intersection(location.aliases):
            raise SchemaError("gold path alias cannot shadow an accepted canonical path")
        if any(
            alias in alias_owners and alias_owners[alias] != location.path
            for alias in location.aliases
        ):
            raise SchemaError("gold path aliases must map to exactly one canonical path")
        alias_owners.update({alias: location.path for alias in location.aliases})
        if location.end_line is not None and location.start_line is None:
            raise SchemaError("gold location end_line requires start_line")
        if (
            location.start_line is not None
            and location.end_line is not None
            and location.end_line < location.start_line
        ):
            raise SchemaError("gold location end_line cannot precede start_line")


@dataclass(frozen=True, slots=True)
class LeakageException:
    exception_id: str
    rule_id: str
    location_class: str
    match_digest: str
    expires_at: datetime
    actor: str
    reason: str


@dataclass(frozen=True, slots=True)
class LeakagePolicy:
    """Scorer-only, case-scoped forbidden additions and narrow exceptions."""

    schema_version: str
    policy_version: str
    case_id: str
    additional_sensitive_shas: tuple[str, ...]
    repair_texts: tuple[str, ...]
    evidence_fragments: tuple[str, ...]
    exceptions: tuple[LeakageException, ...]

    @classmethod
    def from_dict(cls, document: Mapping[str, Any]) -> LeakagePolicy:
        data = validate_contract("leakage-policy", dict(document))
        model = cls(
            schema_version=cast(str, data["schema_version"]),
            policy_version=cast(str, data["policy_version"]),
            case_id=cast(str, data["case_id"]),
            additional_sensitive_shas=tuple(
                cast(str, value) for value in object_list(data["additional_sensitive_shas"])
            ),
            repair_texts=tuple(cast(str, value) for value in object_list(data["repair_texts"])),
            evidence_fragments=tuple(
                cast(str, value) for value in object_list(data["evidence_fragments"])
            ),
            exceptions=tuple(
                _leakage_exception(object_mapping(value))
                for value in object_list(data["exceptions"])
            ),
        )
        identifiers = [exception.exception_id for exception in model.exceptions]
        if len(identifiers) != len(set(identifiers)):
            raise SchemaError("leakage exception identifiers must be unique")
        selectors = [
            (exception.rule_id, exception.location_class, exception.match_digest)
            for exception in model.exceptions
        ]
        if len(selectors) != len(set(selectors)):
            raise SchemaError("leakage exception selectors must be unique")
        return model


@dataclass(frozen=True, slots=True)
class AdjudicationRecord:
    schema_version: str
    adjudication_id: str
    run_id: str
    finding_id: str
    expected_mechanism_id: str
    decision: str
    rubric_version: str
    adjudicator: str
    timestamp: datetime
    rationale: str
    supersedes: str | None

    @classmethod
    def from_dict(cls, document: Mapping[str, Any]) -> AdjudicationRecord:
        data = validate_contract("adjudication", dict(document))
        model = cls(
            schema_version=cast(str, data["schema_version"]),
            adjudication_id=cast(str, data["adjudication_id"]),
            run_id=cast(str, data["run_id"]),
            finding_id=cast(str, data["finding_id"]),
            expected_mechanism_id=cast(str, data["expected_mechanism_id"]),
            decision=cast(str, data["decision"]),
            rubric_version=cast(str, data["rubric_version"]),
            adjudicator=cast(str, data["adjudicator"]),
            timestamp=iso_datetime(cast(str, data["timestamp"]), field="timestamp"),
            rationale=cast(str, data["rationale"]),
            supersedes=cast(str | None, data["supersedes"]),
        )
        if model.supersedes == model.adjudication_id:
            raise SchemaError("adjudication record cannot supersede itself")
        return model

    def to_dict(self) -> dict[str, JsonValue]:
        return {
            "schema_version": self.schema_version,
            "adjudication_id": self.adjudication_id,
            "run_id": self.run_id,
            "finding_id": self.finding_id,
            "expected_mechanism_id": self.expected_mechanism_id,
            "decision": self.decision,
            "rubric_version": self.rubric_version,
            "adjudicator": self.adjudicator,
            "timestamp": self.timestamp.isoformat().replace("+00:00", "Z"),
            "rationale": self.rationale,
            "supersedes": self.supersedes,
        }


def _expected_mechanism(data: Mapping[str, Any]) -> ExpectedMechanism:
    expectations = object_mapping(data["snapshot_expectations"])
    return ExpectedMechanism(
        mechanism_id=cast(str, data["mechanism_id"]),
        description=cast(str, data["description"]),
        adjudication_rubric=cast(str, data["adjudication_rubric"]),
        evaluation_role=cast(EvaluationRole, data["evaluation_role"]),
        snapshot_expectations=SnapshotExpectations(
            vulnerable=cast(SnapshotExpectation, expectations["vulnerable"]),
            fixed=cast(SnapshotExpectation, expectations["fixed"]),
        ),
        acceptable_locations=tuple(
            _acceptable_location(object_mapping(item))
            for item in object_list(data["acceptable_locations"])
        ),
        accepted_defect_categories=tuple(
            cast(DefectCategory, item) for item in object_list(data["accepted_defect_categories"])
        ),
        severity_range=_severity_range(object_mapping(data["severity_range"])),
        provenance=_provenance(object_mapping(data["provenance"])),
    )


def _legacy_expected_mechanism(
    data: Mapping[str, Any],
    *,
    acceptable_locations: tuple[AcceptableLocation, ...],
    accepted_defect_categories: tuple[DefectCategory, ...],
    severity_range: SeverityRange,
    provenance: Provenance,
) -> ExpectedMechanism:
    return ExpectedMechanism(
        mechanism_id=cast(str, data["mechanism_id"]),
        description=cast(str, data["description"]),
        adjudication_rubric=cast(str, data["adjudication_rubric"]),
        evaluation_role="primary",
        snapshot_expectations=SnapshotExpectations(vulnerable="present", fixed="absent"),
        acceptable_locations=acceptable_locations,
        accepted_defect_categories=accepted_defect_categories,
        severity_range=severity_range,
        provenance=provenance,
    )


def _expected_mechanism_dict(mechanism: ExpectedMechanism) -> dict[str, JsonValue]:
    return {
        "mechanism_id": mechanism.mechanism_id,
        "description": mechanism.description,
        "adjudication_rubric": mechanism.adjudication_rubric,
        "evaluation_role": mechanism.evaluation_role,
        "snapshot_expectations": {
            "vulnerable": mechanism.snapshot_expectations.vulnerable,
            "fixed": mechanism.snapshot_expectations.fixed,
        },
        "acceptable_locations": [
            _acceptable_location_dict(location) for location in mechanism.acceptable_locations
        ],
        "accepted_defect_categories": list(mechanism.accepted_defect_categories),
        "severity_range": _severity_range_dict(mechanism.severity_range),
        "provenance": _provenance_dict(mechanism.provenance),
    }


def _severity_range(data: Mapping[str, Any]) -> SeverityRange:
    return SeverityRange(
        minimum=cast(Severity, data["minimum"]),
        maximum=cast(Severity, data["maximum"]),
    )


def _severity_range_dict(severity: SeverityRange) -> dict[str, JsonValue]:
    return {"minimum": severity.minimum, "maximum": severity.maximum}


def _provenance(data: Mapping[str, Any]) -> Provenance:
    return Provenance(
        excerpt=cast(str, data["excerpt"]),
        source_record_id=cast(str, data["source_record_id"]),
    )


def _provenance_dict(provenance: Provenance) -> dict[str, JsonValue]:
    return {
        "excerpt": provenance.excerpt,
        "source_record_id": provenance.source_record_id,
    }


def _acceptable_location(data: Mapping[str, Any]) -> AcceptableLocation:
    return AcceptableLocation(
        path=repository_path(cast(str, data["path"]), field="acceptable_locations.path"),
        aliases=tuple(
            repository_path(cast(str, alias), field="acceptable_locations.aliases")
            for alias in object_list(data.get("aliases", []))
        ),
        start_line=cast(int | None, data.get("start_line")),
        end_line=cast(int | None, data.get("end_line")),
    )


def _acceptable_location_dict(location: AcceptableLocation) -> dict[str, JsonValue]:
    document: dict[str, JsonValue] = {"path": location.path.as_posix()}
    if location.aliases:
        document["aliases"] = [path.as_posix() for path in location.aliases]
    if location.start_line is not None:
        document["start_line"] = location.start_line
    if location.end_line is not None:
        document["end_line"] = location.end_line
    return document


def _fixed_fingerprint(data: Mapping[str, Any]) -> FixedFingerprint:
    return FixedFingerprint(
        digest=cast(str, data["digest"]),
        source_path=repository_path(
            cast(str, data["source_path"]), field="fixed_only_fingerprints.source_path"
        ),
        source_record_id=cast(str, data["source_record_id"]),
    )


def _leakage_exception(data: Mapping[str, Any]) -> LeakageException:
    return LeakageException(
        exception_id=cast(str, data["exception_id"]),
        rule_id=cast(str, data["rule_id"]),
        location_class=cast(str, data["location_class"]),
        match_digest=cast(str, data["match_digest"]),
        expires_at=iso_datetime(cast(str, data["expires_at"]), field="expires_at"),
        actor=cast(str, data["actor"]),
        reason=cast(str, data["reason"]),
    )
