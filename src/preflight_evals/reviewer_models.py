"""Models and serialization safe to expose to the reviewer process."""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from datetime import datetime
from pathlib import PurePosixPath
from typing import Any, cast

from preflight_evals.canonical import JsonValue, canonical_digest
from preflight_evals.errors import SchemaError
from preflight_evals.model_types import (
    Condition,
    DefectCategory,
    Severity,
    SnapshotName,
    iso_datetime,
    object_list,
    object_mapping,
    repository_path,
)
from preflight_evals.schema import validate_contract


@dataclass(frozen=True, slots=True)
class ReviewerContextPolicy:
    includes: tuple[PurePosixPath, ...]
    excludes: tuple[PurePosixPath, ...]
    per_file_byte_limit: int
    per_file_token_limit: int
    total_token_limit: int
    symlink_policy: str
    binary_policy: str
    truncation_policy: str

    def to_dict(self) -> dict[str, JsonValue]:
        return {
            "includes": [path.as_posix() for path in self.includes],
            "excludes": [path.as_posix() for path in self.excludes],
            "per_file_byte_limit": self.per_file_byte_limit,
            "per_file_token_limit": self.per_file_token_limit,
            "total_token_limit": self.total_token_limit,
            "symlink_policy": self.symlink_policy,
            "binary_policy": self.binary_policy,
            "truncation_policy": self.truncation_policy,
        }


@dataclass(frozen=True, slots=True)
class ReviewerCase:
    """The only case representation permitted at the reviewer boundary."""

    schema_version: str
    case_id: str
    display_name: str
    defect_category: DefectCategory
    repository: str
    pull_request: int
    source_commit: str
    context_policy: ReviewerContextPolicy

    def to_dict(self) -> dict[str, JsonValue]:
        return {
            "schema_version": self.schema_version,
            "case_id": self.case_id,
            "display_name": self.display_name,
            "defect_category": self.defect_category,
            "source": {
                "repository": self.repository,
                "pull_request": self.pull_request,
                "commit": self.source_commit,
            },
            "context_policy": self.context_policy.to_dict(),
        }


@dataclass(frozen=True, slots=True)
class Evidence:
    source_type: str
    reference: str

    def to_dict(self) -> dict[str, JsonValue]:
        return {"source_type": self.source_type, "reference": self.reference}


@dataclass(frozen=True, slots=True)
class Finding:
    schema_version: str
    finding_id: str
    title: str
    explanation: str
    file_path: PurePosixPath
    start_line: int | None
    end_line: int | None
    severity: Severity
    defect_category: DefectCategory
    failure_mechanism: str
    confidence: float
    evidence: tuple[Evidence, ...]

    @classmethod
    def from_dict(cls, document: Mapping[str, Any]) -> Finding:
        data = validate_contract("finding", dict(document))
        model = cls(
            schema_version=cast(str, data["schema_version"]),
            finding_id=cast(str, data["finding_id"]),
            title=cast(str, data["title"]),
            explanation=cast(str, data["explanation"]),
            file_path=repository_path(cast(str, data["file_path"]), field="file_path"),
            start_line=cast(int | None, data.get("start_line")),
            end_line=cast(int | None, data.get("end_line")),
            severity=cast(Severity, data["severity"]),
            defect_category=cast(DefectCategory, data["defect_category"]),
            failure_mechanism=cast(str, data["failure_mechanism"]),
            confidence=float(cast(int | float, data["confidence"])),
            evidence=tuple(
                Evidence(
                    source_type=cast(str, object_mapping(item)["source_type"]),
                    reference=cast(str, object_mapping(item)["reference"]),
                )
                for item in object_list(data["evidence"])
            ),
        )
        if model.end_line is not None and model.start_line is None:
            raise SchemaError("finding end_line requires start_line")
        if (
            model.start_line is not None
            and model.end_line is not None
            and model.end_line < model.start_line
        ):
            raise SchemaError("finding end_line cannot precede start_line")
        return model

    def to_dict(self) -> dict[str, JsonValue]:
        document: dict[str, JsonValue] = {
            "schema_version": self.schema_version,
            "finding_id": self.finding_id,
            "title": self.title,
            "explanation": self.explanation,
            "file_path": self.file_path.as_posix(),
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
class ReviewerOutput:
    schema_version: str
    findings: tuple[Finding, ...]

    @classmethod
    def from_dict(cls, document: Mapping[str, Any]) -> ReviewerOutput:
        data = validate_contract("reviewer-output", dict(document))
        findings = tuple(
            Finding.from_dict(object_mapping(item)) for item in object_list(data["findings"])
        )
        identifiers = [finding.finding_id for finding in findings]
        if len(identifiers) != len(set(identifiers)):
            raise SchemaError("reviewer-output finding identifiers must be unique")
        return cls(schema_version=cast(str, data["schema_version"]), findings=findings)

    def to_dict(self) -> dict[str, JsonValue]:
        return {
            "schema_version": self.schema_version,
            "findings": [finding.to_dict() for finding in self.findings],
        }


@dataclass(frozen=True, slots=True)
class BundleEntry:
    path: PurePosixPath
    byte_count: int
    token_count: int
    content_digest: str
    truncated: bool
    selection_reason: str


@dataclass(frozen=True, slots=True)
class BundleTokenizerConfiguration:
    implementation: str
    name: str
    version: str
    method: str


@dataclass(frozen=True, slots=True)
class BundleConfiguration:
    encoding: str
    newline_policy: str
    tokenizer: BundleTokenizerConfiguration
    context_policy: ReviewerContextPolicy


@dataclass(frozen=True, slots=True)
class VersionedTemplate:
    name: str
    version: str
    digest: str


@dataclass(frozen=True, slots=True)
class ReviewerConfiguration:
    model: str
    tool_policy: str
    input_token_limit: int
    output_token_limit: int
    temperature: float
    adapter_version: str


@dataclass(frozen=True, slots=True)
class LeakageMatch:
    rule_id: str
    location_class: str
    match_digest: str
    exception_id: str

    def to_dict(self) -> dict[str, JsonValue]:
        return {
            "rule_id": self.rule_id,
            "location_class": self.location_class,
            "match_digest": self.match_digest,
            "exception_id": self.exception_id,
        }


@dataclass(frozen=True, slots=True)
class LeakageResult:
    policy_version: str
    passed: bool
    rule_ids: tuple[str, ...]
    index_digest: str | None = None
    approved_matches: tuple[LeakageMatch, ...] = ()

    def to_dict(self) -> dict[str, JsonValue]:
        document: dict[str, JsonValue] = {
            "policy_version": self.policy_version,
            "passed": self.passed,
            "rule_ids": list(self.rule_ids),
        }
        if self.index_digest is not None:
            document["index_digest"] = self.index_digest
            document["approved_matches"] = [match.to_dict() for match in self.approved_matches]
        return document


@dataclass(frozen=True, slots=True)
class PromptManifest:
    schema_version: str
    case_id: str
    snapshot: SnapshotName
    request_identity: str | None
    bundle_schema_version: str | None
    condition: Condition
    repetition: int
    seed: int | None
    request_id: str
    run_id: str
    source_commit: str
    worktree_digest: str
    bundle_entries: tuple[BundleEntry, ...]
    bundle_digest: str | None
    bundle_byte_count: int | None
    bundle_token_count: int | None
    context_entry_digest: str | None
    context_byte_count: int | None
    context_token_count: int | None
    bundle_config: BundleConfiguration | None
    prompt_template: VersionedTemplate
    profile_template: VersionedTemplate
    reviewer_config: ReviewerConfiguration
    request_digest: str
    leakage: LeakageResult
    created_at: datetime
    content_digest: str

    @classmethod
    def from_dict(cls, document: Mapping[str, Any]) -> PromptManifest:
        data = validate_contract("prompt-manifest", dict(document))
        prompt = object_mapping(data["prompt_template"])
        profile = object_mapping(data["profile_template"])
        config = object_mapping(data["reviewer_config"])
        leakage = object_mapping(data["leakage"])
        bundle_config = (
            _bundle_configuration(object_mapping(data["bundle_config"]))
            if "bundle_config" in data
            else None
        )
        model = cls(
            schema_version=cast(str, data["schema_version"]),
            case_id=cast(str, data["case_id"]),
            snapshot=cast(SnapshotName, data["snapshot"]),
            request_identity=cast(str | None, data.get("request_identity")),
            bundle_schema_version=cast(str | None, data.get("bundle_schema_version")),
            condition=cast(Condition, data["condition"]),
            repetition=cast(int, data["repetition"]),
            seed=cast(int | None, data.get("seed")),
            request_id=cast(str, data["request_id"]),
            run_id=cast(str, data["run_id"]),
            source_commit=cast(str, data["source_commit"]),
            worktree_digest=cast(str, data["worktree_digest"]),
            bundle_entries=tuple(
                _bundle_entry(object_mapping(item)) for item in object_list(data["bundle_entries"])
            ),
            bundle_digest=cast(str | None, data.get("bundle_digest")),
            bundle_byte_count=cast(int | None, data.get("bundle_byte_count")),
            bundle_token_count=cast(int | None, data.get("bundle_token_count")),
            context_entry_digest=cast(str | None, data.get("context_entry_digest")),
            context_byte_count=cast(int | None, data.get("context_byte_count")),
            context_token_count=cast(int | None, data.get("context_token_count")),
            bundle_config=bundle_config,
            prompt_template=_versioned_template(prompt),
            profile_template=_versioned_template(profile),
            reviewer_config=ReviewerConfiguration(
                model=cast(str, config["model"]),
                tool_policy=cast(str, config["tool_policy"]),
                input_token_limit=cast(int, config["input_token_limit"]),
                output_token_limit=cast(int, config["output_token_limit"]),
                temperature=float(cast(int | float, config["temperature"])),
                adapter_version=cast(str, config["adapter_version"]),
            ),
            request_digest=cast(str, data["request_digest"]),
            leakage=LeakageResult(
                policy_version=cast(str, leakage["policy_version"]),
                passed=cast(bool, leakage["passed"]),
                rule_ids=tuple(cast(str, item) for item in object_list(leakage["rule_ids"])),
                index_digest=cast(str | None, leakage.get("index_digest")),
                approved_matches=tuple(
                    _leakage_match(object_mapping(item))
                    for item in object_list(leakage.get("approved_matches", []))
                ),
            ),
            created_at=iso_datetime(cast(str, data["created_at"]), field="created_at"),
            content_digest=cast(str, data["content_digest"]),
        )
        model._validate_relationships(data)
        return model

    def _validate_relationships(self, data: Mapping[str, Any]) -> None:
        paths = [entry.path.as_posix() for entry in self.bundle_entries]
        if paths != sorted(paths) or len(paths) != len(set(paths)):
            raise SchemaError("prompt-manifest bundle entries must be uniquely path-sorted")
        extended = self.bundle_digest is not None
        optional_values = (
            self.bundle_byte_count,
            self.bundle_token_count,
            self.context_entry_digest,
            self.context_byte_count,
            self.context_token_count,
            self.bundle_config,
        )
        if any(value is not None for value in optional_values) != extended:
            raise SchemaError("prompt-manifest bundle metadata must be complete")
        if extended:
            entry_documents: list[JsonValue] = [
                {
                    "path": entry.path.as_posix(),
                    "byte_count": entry.byte_count,
                    "token_count": entry.token_count,
                    "content_digest": entry.content_digest,
                    "truncated": entry.truncated,
                    "selection_reason": entry.selection_reason,
                }
                for entry in self.bundle_entries
            ]
            if self.context_entry_digest != canonical_digest(entry_documents):
                raise SchemaError("prompt-manifest context-entry digest does not match")
            if self.context_byte_count != sum(entry.byte_count for entry in self.bundle_entries):
                raise SchemaError("prompt-manifest context byte count does not match")
            if self.context_token_count != sum(entry.token_count for entry in self.bundle_entries):
                raise SchemaError("prompt-manifest context token count does not match")
        if self.schema_version in {"1.2", "1.3"}:
            if not self.leakage.passed or self.leakage.index_digest is None:
                raise SchemaError(
                    "prompt-manifest current versions require a passing leakage result"
                )
            match_keys = [
                (
                    match.rule_id,
                    match.location_class,
                    match.match_digest,
                    match.exception_id,
                )
                for match in self.leakage.approved_matches
            ]
            if match_keys != sorted(match_keys) or len(match_keys) != len(set(match_keys)):
                raise SchemaError("prompt-manifest leakage matches must be uniquely sorted")
            expected_rule_ids = tuple(
                sorted({match.rule_id for match in self.leakage.approved_matches})
            )
            if self.leakage.rule_ids != expected_rule_ids:
                raise SchemaError("prompt-manifest leakage rule identifiers do not match")
        if self.schema_version == "1.3":
            if self.request_identity is None or self.bundle_schema_version != "2":
                raise SchemaError("prompt-manifest 1.3 requires opaque bundle identity metadata")
        elif self.request_identity is not None or self.bundle_schema_version is not None:
            raise SchemaError("legacy prompt-manifest cannot claim opaque bundle identity metadata")
        content = dict(data)
        content.pop("content_digest", None)
        content.pop("created_at", None)
        if self.content_digest != canonical_digest(cast(JsonValue, content)):
            raise SchemaError("prompt-manifest content digest does not match")


def _bundle_entry(data: Mapping[str, Any]) -> BundleEntry:
    return BundleEntry(
        path=repository_path(cast(str, data["path"]), field="bundle_entries.path"),
        byte_count=cast(int, data["byte_count"]),
        token_count=cast(int, data["token_count"]),
        content_digest=cast(str, data["content_digest"]),
        truncated=cast(bool, data["truncated"]),
        selection_reason=cast(str, data["selection_reason"]),
    )


def _leakage_match(data: Mapping[str, Any]) -> LeakageMatch:
    return LeakageMatch(
        rule_id=cast(str, data["rule_id"]),
        location_class=cast(str, data["location_class"]),
        match_digest=cast(str, data["match_digest"]),
        exception_id=cast(str, data["exception_id"]),
    )


def _versioned_template(data: Mapping[str, Any]) -> VersionedTemplate:
    return VersionedTemplate(
        name=cast(str, data["name"]),
        version=cast(str, data["version"]),
        digest=cast(str, data["digest"]),
    )


def _bundle_configuration(data: Mapping[str, Any]) -> BundleConfiguration:
    tokenizer = object_mapping(data["tokenizer"])
    policy = object_mapping(data["context_policy"])
    return BundleConfiguration(
        encoding=cast(str, data["encoding"]),
        newline_policy=cast(str, data["newline_policy"]),
        tokenizer=BundleTokenizerConfiguration(
            implementation=cast(str, tokenizer["implementation"]),
            name=cast(str, tokenizer["name"]),
            version=cast(str, tokenizer["version"]),
            method=cast(str, tokenizer["method"]),
        ),
        context_policy=ReviewerContextPolicy(
            includes=tuple(
                repository_path(cast(str, item), field="bundle_config.context_policy.includes")
                for item in object_list(policy["includes"])
            ),
            excludes=tuple(
                repository_path(cast(str, item), field="bundle_config.context_policy.excludes")
                for item in object_list(policy["excludes"])
            ),
            per_file_byte_limit=cast(int, policy["per_file_byte_limit"]),
            per_file_token_limit=cast(int, policy["per_file_token_limit"]),
            total_token_limit=cast(int, policy["total_token_limit"]),
            symlink_policy=cast(str, policy["symlink_policy"]),
            binary_policy=cast(str, policy["binary_policy"]),
            truncation_policy=cast(str, policy["truncation_policy"]),
        ),
    )
