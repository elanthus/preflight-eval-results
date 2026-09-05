"""Curator-capable models that must not cross into reviewer-facing modules."""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from datetime import date, datetime
from pathlib import PurePosixPath
from typing import TYPE_CHECKING, Any, cast

from preflight_evals.errors import SchemaError
from preflight_evals.model_types import (
    CatalogDisposition,
    DefectCategory,
    Eligibility,
    FindingIdSource,
    SnapshotName,
    iso_date,
    iso_datetime,
    object_list,
    object_mapping,
    repository_path,
)
from preflight_evals.schema import SCHEMA_VERSION, validate_contract

if TYPE_CHECKING:
    from preflight_evals.reviewer_models import ReviewerCase


@dataclass(frozen=True, slots=True)
class CatalogPullRequest:
    number: int
    title: str
    url: str


@dataclass(frozen=True, slots=True)
class CatalogCommits:
    base: str
    vulnerable: str
    repairs: tuple[str, ...]
    fixed: str | None


@dataclass(frozen=True, slots=True)
class CatalogRecord:
    case_id: str
    finding_id: str
    finding_id_source: FindingIdSource
    repository: str
    pull_request: CatalogPullRequest
    commits: CatalogCommits
    disposition: CatalogDisposition


@dataclass(frozen=True, slots=True)
class Catalog:
    """Strict curator/scorer provenance catalog excluded from reviewer prompts."""

    schema_version: str
    corpus_id: str
    source_evidence: str
    generated_at: datetime
    visibility: str
    records: tuple[CatalogRecord, ...]
    notes: tuple[str, ...]

    @classmethod
    def from_dict(cls, document: Mapping[str, Any]) -> Catalog:
        data = validate_contract("catalog", dict(document))
        model = cls(
            schema_version=cast(str, data["schema_version"]),
            corpus_id=cast(str, data["corpus_id"]),
            source_evidence=cast(str, data["source_evidence"]),
            generated_at=iso_datetime(cast(str, data["generated_at"]), field="generated_at"),
            visibility=cast(str, data["visibility"]),
            records=tuple(
                _catalog_record(object_mapping(item)) for item in object_list(data["records"])
            ),
            notes=tuple(cast(str, item) for item in object_list(data["notes"])),
        )
        model._validate_relationships()
        return model

    def _validate_relationships(self) -> None:
        if self.schema_version != SCHEMA_VERSION:
            raise SchemaError("catalog uses an unsupported schema version")
        case_ids = [record.case_id for record in self.records]
        if len(case_ids) != len(set(case_ids)):
            raise SchemaError("catalog case identifiers must be unique")
        for record in self.records:
            expected_url = (
                f"https://github.com/{record.repository}/pull/{record.pull_request.number}"
            )
            if record.pull_request.url != expected_url:
                raise SchemaError("catalog pull request URL must match repository and number")
            if record.commits.base == record.commits.vulnerable:
                raise SchemaError("catalog base and vulnerable commits must differ")
            if record.disposition == "paired_draft":
                if not record.commits.repairs or record.commits.fixed is None:
                    raise SchemaError("paired catalog record requires repair and fixed commits")
                if record.commits.fixed != record.commits.repairs[-1]:
                    raise SchemaError("paired catalog fixed commit must be the final repair commit")
                if record.commits.vulnerable in record.commits.repairs:
                    raise SchemaError(
                        "paired catalog repair commits must follow the vulnerable commit"
                    )
            elif record.commits.repairs or record.commits.fixed is not None:
                raise SchemaError("special catalog record cannot claim source repair commits")


@dataclass(frozen=True, slots=True)
class SourceReference:
    repository: str
    pull_request: int


@dataclass(frozen=True, slots=True)
class CommitSet:
    base: str
    vulnerable: str
    repair: str
    fixed: str


@dataclass(frozen=True, slots=True)
class ContextPolicy:
    includes: tuple[PurePosixPath, ...]
    excludes: tuple[PurePosixPath, ...]
    per_file_byte_limit: int
    per_file_token_limit: int
    total_token_limit: int
    symlink_policy: str
    binary_policy: str
    truncation_policy: str


@dataclass(frozen=True, slots=True)
class Verification:
    status: str
    verifier: str
    verified_at: date
    method: str
    notes: str | None


@dataclass(frozen=True, slots=True)
class EstimatedInput:
    tokenizer: str
    vulnerable_tokens: int
    fixed_tokens: int


@dataclass(frozen=True, slots=True)
class CaseRecord:
    """Private case record containing curator provenance and eligibility metadata."""

    schema_version: str
    case_id: str
    display_name: str
    defect_category: DefectCategory
    source: SourceReference
    commits: CommitSet
    vulnerable_snapshot: str
    fixed_snapshot: str
    context_policy: ContextPolicy
    eligibility: Eligibility
    eligibility_reason: str | None
    verification: Verification
    estimated_input: EstimatedInput

    @classmethod
    def from_dict(cls, document: Mapping[str, Any]) -> CaseRecord:
        data = validate_contract("case", dict(document))
        source = object_mapping(data["source"])
        commits = object_mapping(data["commits"])
        snapshots = object_mapping(data["snapshots"])
        vulnerable_snapshot = object_mapping(snapshots["vulnerable"])
        fixed_snapshot = object_mapping(snapshots["fixed"])
        policy = object_mapping(data["context_policy"])
        verification = object_mapping(data["verification"])
        estimated = object_mapping(data["estimated_input"])

        model = cls(
            schema_version=cast(str, data["schema_version"]),
            case_id=cast(str, data["case_id"]),
            display_name=cast(str, data["display_name"]),
            defect_category=cast(DefectCategory, data["defect_category"]),
            source=SourceReference(
                repository=cast(str, source["repository"]),
                pull_request=cast(int, source["pull_request"]),
            ),
            commits=CommitSet(
                base=cast(str, commits["base"]),
                vulnerable=cast(str, commits["vulnerable"]),
                repair=cast(str, commits["repair"]),
                fixed=cast(str, commits["fixed"]),
            ),
            vulnerable_snapshot=cast(str, vulnerable_snapshot["commit"]),
            fixed_snapshot=cast(str, fixed_snapshot["commit"]),
            context_policy=ContextPolicy(
                includes=tuple(
                    repository_path(cast(str, path), field="context_policy.includes")
                    for path in object_list(policy["includes"])
                ),
                excludes=tuple(
                    repository_path(cast(str, path), field="context_policy.excludes")
                    for path in object_list(policy["excludes"])
                ),
                per_file_byte_limit=cast(int, policy["per_file_byte_limit"]),
                per_file_token_limit=cast(int, policy["per_file_token_limit"]),
                total_token_limit=cast(int, policy["total_token_limit"]),
                symlink_policy=cast(str, policy["symlink_policy"]),
                binary_policy=cast(str, policy["binary_policy"]),
                truncation_policy=cast(str, policy["truncation_policy"]),
            ),
            eligibility=cast(Eligibility, data["eligibility"]),
            eligibility_reason=cast(str | None, data.get("eligibility_reason")),
            verification=Verification(
                status=cast(str, verification["status"]),
                verifier=cast(str, verification["verifier"]),
                verified_at=iso_date(
                    cast(str, verification["verified_at"]), field="verification.verified_at"
                ),
                method=cast(str, verification["method"]),
                notes=cast(str | None, verification.get("notes")),
            ),
            estimated_input=EstimatedInput(
                tokenizer=cast(str, estimated["tokenizer"]),
                vulnerable_tokens=cast(int, estimated["vulnerable_tokens"]),
                fixed_tokens=cast(int, estimated["fixed_tokens"]),
            ),
        )
        model._validate_relationships()
        return model

    def _validate_relationships(self) -> None:
        if self.schema_version != SCHEMA_VERSION:
            raise SchemaError("case record uses an unsupported schema version")
        if self.commits.vulnerable == self.commits.fixed:
            raise SchemaError("case record vulnerable and fixed commits must differ")
        if self.vulnerable_snapshot != self.commits.vulnerable:
            raise SchemaError("case record vulnerable snapshot must match its commit")
        if self.fixed_snapshot != self.commits.fixed:
            raise SchemaError("case record fixed snapshot must match its commit")
        if self.context_policy.total_token_limit < self.context_policy.per_file_token_limit:
            raise SchemaError("case record total token limit cannot be smaller than its file limit")

    def to_reviewer_case(self, snapshot: SnapshotName) -> ReviewerCase:
        """Create a capability-limited reviewer view with no scorer/curator metadata."""

        from preflight_evals.reviewer_models import ReviewerCase, ReviewerContextPolicy

        source_commit = (
            self.vulnerable_snapshot if snapshot == "vulnerable" else self.fixed_snapshot
        )
        return ReviewerCase(
            schema_version=self.schema_version,
            case_id=self.case_id,
            display_name=self.display_name,
            defect_category=self.defect_category,
            repository=self.source.repository,
            pull_request=self.source.pull_request,
            source_commit=source_commit,
            context_policy=ReviewerContextPolicy(
                includes=self.context_policy.includes,
                excludes=self.context_policy.excludes,
                per_file_byte_limit=self.context_policy.per_file_byte_limit,
                per_file_token_limit=self.context_policy.per_file_token_limit,
                total_token_limit=self.context_policy.total_token_limit,
                symlink_policy=self.context_policy.symlink_policy,
                binary_policy=self.context_policy.binary_policy,
                truncation_policy=self.context_policy.truncation_policy,
            ),
        )


def _catalog_record(data: Mapping[str, Any]) -> CatalogRecord:
    pull_request = object_mapping(data["pull_request"])
    commits = object_mapping(data["commits"])
    return CatalogRecord(
        case_id=cast(str, data["case_id"]),
        finding_id=cast(str, data["finding_id"]),
        finding_id_source=cast(FindingIdSource, data["finding_id_source"]),
        repository=cast(str, data["repository"]),
        pull_request=CatalogPullRequest(
            number=cast(int, pull_request["number"]),
            title=cast(str, pull_request["title"]),
            url=cast(str, pull_request["url"]),
        ),
        commits=CatalogCommits(
            base=cast(str, commits["base"]),
            vulnerable=cast(str, commits["vulnerable"]),
            repairs=tuple(cast(str, item) for item in object_list(commits["repairs"])),
            fixed=cast(str | None, commits["fixed"]),
        ),
        disposition=cast(CatalogDisposition, data["disposition"]),
    )
