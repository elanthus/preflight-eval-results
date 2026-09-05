"""Deterministic, outcome-independent development/holdout split freezing."""

from __future__ import annotations

import hashlib
import itertools
from collections import Counter
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass
from typing import Any, Literal, cast

from preflight_evals.canonical import JsonValue, canonical_digest, canonical_json_bytes
from preflight_evals.curator_models import CaseRecord
from preflight_evals.errors import SchemaError
from preflight_evals.model_types import object_list, object_mapping
from preflight_evals.schema import SCHEMA_VERSION, validate_contract

type CorpusRole = Literal["development", "holdout"]
type ContextSizeBand = Literal["small", "medium", "large"]

ALGORITHM = "exhaustive-stratified-squared-deviation-v1"


@dataclass(frozen=True, slots=True)
class SplitAssignment:
    """One private case assignment plus its outcome-independent strata."""

    case_id: str
    role: CorpusRole
    repository: str
    defect_category: str
    context_size_band: ContextSizeBand

    def to_dict(self) -> dict[str, JsonValue]:
        return {
            "case_id": self.case_id,
            "role": self.role,
            "repository": self.repository,
            "defect_category": self.defect_category,
            "context_size_band": self.context_size_band,
        }


@dataclass(frozen=True, slots=True)
class BalanceCell:
    """Aggregate balance for one value of a declared stratum."""

    dimension: str
    value: str
    total: int
    development: int
    holdout: int

    def to_dict(self) -> dict[str, JsonValue]:
        return {
            "dimension": self.dimension,
            "value": self.value,
            "total": self.total,
            "development": self.development,
            "holdout": self.holdout,
        }


@dataclass(frozen=True, slots=True)
class CorpusSplit:
    """Private frozen split with a disclosure-safe aggregate projection."""

    schema_version: str
    algorithm: str
    seed: int
    target_holdout_count: int
    locked_development: tuple[str, ...]
    assignments: tuple[SplitAssignment, ...]
    ordered_holdout: tuple[str, ...]
    ordered_holdout_checksum: str
    balance: tuple[BalanceCell, ...]
    objective_score: int
    content_digest: str

    @classmethod
    def from_dict(cls, document: Mapping[str, Any]) -> CorpusSplit:
        return cls._from_dict(document)

    @classmethod
    def _from_dict(
        cls,
        document: Mapping[str, Any],
        *,
        optimum: tuple[tuple[str, ...], int] | None = None,
    ) -> CorpusSplit:
        """Reuse an optimum only for the private freeze builder's own document."""
        raw = dict(document)
        supplied_digest = raw.pop("content_digest", None)
        derived_digest = canonical_digest(cast(dict[str, JsonValue], raw))
        if supplied_digest is not None and supplied_digest != derived_digest:
            raise SchemaError("corpus split content digest does not match its content")
        data = validate_contract("corpus-split", {**raw, "content_digest": derived_digest})
        assignments = tuple(
            SplitAssignment(
                case_id=cast(str, item["case_id"]),
                role=cast(CorpusRole, item["role"]),
                repository=cast(str, item["repository"]),
                defect_category=cast(str, item["defect_category"]),
                context_size_band=cast(ContextSizeBand, item["context_size_band"]),
            )
            for item in (object_mapping(value) for value in object_list(data["assignments"]))
        )
        balance = tuple(
            BalanceCell(
                dimension=cast(str, item["dimension"]),
                value=cast(str, item["value"]),
                total=cast(int, item["total"]),
                development=cast(int, item["development"]),
                holdout=cast(int, item["holdout"]),
            )
            for item in (object_mapping(value) for value in object_list(data["balance"]))
        )
        model = cls(
            schema_version=cast(str, data["schema_version"]),
            algorithm=cast(str, data["algorithm"]),
            seed=cast(int, data["seed"]),
            target_holdout_count=cast(int, data["target_holdout_count"]),
            locked_development=tuple(
                cast(str, value) for value in object_list(data["locked_development"])
            ),
            assignments=assignments,
            ordered_holdout=tuple(
                cast(str, value) for value in object_list(data["ordered_holdout"])
            ),
            ordered_holdout_checksum=cast(str, data["ordered_holdout_checksum"]),
            balance=balance,
            objective_score=cast(int, data["objective_score"]),
            content_digest=cast(str, data["content_digest"]),
        )
        model._validate_relationships(optimum=optimum)
        return model

    def _validate_relationships(
        self, *, optimum: tuple[tuple[str, ...], int] | None = None
    ) -> None:
        if self.schema_version != SCHEMA_VERSION or self.algorithm != ALGORITHM:
            raise SchemaError("corpus split uses an unsupported version or algorithm")
        identifiers = [item.case_id for item in self.assignments]
        if identifiers != sorted(identifiers) or len(identifiers) != len(set(identifiers)):
            raise SchemaError("corpus split assignments must be unique and sorted")
        holdout = {item.case_id for item in self.assignments if item.role == "holdout"}
        if len(holdout) != self.target_holdout_count or set(self.ordered_holdout) != holdout:
            raise SchemaError("ordered holdout membership does not match split assignments")
        if len(self.ordered_holdout) != len(set(self.ordered_holdout)):
            raise SchemaError("ordered holdout membership must be unique")
        if (
            self.locked_development != tuple(sorted(self.locked_development))
            or len(self.locked_development) != len(set(self.locked_development))
            or not set(self.locked_development).issubset(identifiers)
        ):
            raise SchemaError("locked development membership must be unique, sorted, and present")
        roles = {item.case_id: item.role for item in self.assignments}
        if any(roles[case_id] != "development" for case_id in self.locked_development):
            raise SchemaError("locked development membership cannot be assigned to holdout")
        expected_order = tuple(sorted(holdout, key=lambda value: _order_key(self.seed, value)))
        if self.ordered_holdout != expected_order:
            raise SchemaError("ordered holdout membership does not match the seeded order")
        if self.ordered_holdout_checksum != ordered_holdout_checksum(self.ordered_holdout):
            raise SchemaError("ordered holdout checksum does not match membership")
        if self.balance != _balance(self.assignments):
            raise SchemaError("corpus split balance does not match assignments")
        expected_holdout, expected_score = (
            optimum
            if optimum is not None
            else _best_holdout(
                self.assignments,
                seed=self.seed,
                holdout_count=self.target_holdout_count,
                locked_development=frozenset(self.locked_development),
            )
        )
        if holdout != set(expected_holdout) or self.objective_score != expected_score:
            raise SchemaError("corpus split is not the deterministic optimum")

    def to_dict(self) -> dict[str, JsonValue]:
        return {
            "schema_version": self.schema_version,
            "algorithm": self.algorithm,
            "seed": self.seed,
            "target_holdout_count": self.target_holdout_count,
            "locked_development": list(self.locked_development),
            "assignments": [item.to_dict() for item in self.assignments],
            "ordered_holdout": list(self.ordered_holdout),
            "ordered_holdout_checksum": self.ordered_holdout_checksum,
            "balance": [item.to_dict() for item in self.balance],
            "objective_score": self.objective_score,
            "content_digest": self.content_digest,
        }

    def canonical_bytes(self) -> bytes:
        return canonical_json_bytes(self.to_dict())

    def public_proof(self) -> dict[str, JsonValue]:
        """Project only aggregate counts, declared parameters, and commitments."""

        development = sum(item.role == "development" for item in self.assignments)
        base: dict[str, JsonValue] = {
            "schema_version": self.schema_version,
            "algorithm": self.algorithm,
            "seed": self.seed,
            "case_count": len(self.assignments),
            "development_count": development,
            "holdout_count": self.target_holdout_count,
            "locked_development_count": len(self.locked_development),
            "ordered_holdout_checksum": self.ordered_holdout_checksum,
            "split_manifest_digest": self.content_digest,
            "objective_score": self.objective_score,
            "balance": [item.to_dict() for item in self.balance],
        }
        return {**base, "content_digest": canonical_digest(base)}


def context_size_band(case: CaseRecord) -> ContextSizeBand:
    """Classify by the larger selected snapshot token estimate."""

    tokens = max(case.estimated_input.vulnerable_tokens, case.estimated_input.fixed_tokens)
    if tokens <= 2_000:
        return "small"
    if tokens <= 8_000:
        return "medium"
    return "large"


def ordered_holdout_checksum(ordered_case_ids: Sequence[str]) -> str:
    """Commit to ordered private membership without exposing it."""

    return canonical_digest({"schema_version": "1.0", "ordered_holdout": list(ordered_case_ids)})


def validate_case_roles(split: CorpusSplit, cases: Sequence[CaseRecord]) -> None:
    """Require executable case roles to agree with the frozen private assignment."""

    declared = {case.case_id: case.eligibility for case in cases}
    if set(declared) != {assignment.case_id for assignment in split.assignments}:
        raise SchemaError("corpus split and case contracts identify different cases")
    if any(declared[item.case_id] != item.role for item in split.assignments):
        raise SchemaError("case contract eligibility does not match the frozen corpus split")


def freeze_corpus_split(
    cases: Sequence[CaseRecord],
    *,
    seed: int,
    holdout_count: int,
    locked_development: frozenset[str],
) -> CorpusSplit:
    """Choose the deterministic best-stratified split without outcome inputs."""

    ordered_cases = tuple(sorted(cases, key=lambda item: item.case_id))
    identifiers = [item.case_id for item in ordered_cases]
    if len(identifiers) != len(set(identifiers)):
        raise SchemaError("corpus split input contains duplicate case identifiers")
    if any(item.verification.status != "verified" for item in ordered_cases):
        raise SchemaError("corpus split input contains an unverified case")
    if not locked_development.issubset(identifiers):
        raise SchemaError("locked development membership is not present in the corpus")
    candidates = tuple(value for value in identifiers if value not in locked_development)
    if holdout_count < 1 or holdout_count > len(candidates):
        raise SchemaError("holdout count is not feasible after development locks")

    provisional = tuple(
        SplitAssignment(
            case_id=item.case_id,
            role="development",
            repository=item.source.repository,
            defect_category=item.defect_category,
            context_size_band=context_size_band(item),
        )
        for item in ordered_cases
    )
    best, objective_score = _best_holdout(
        provisional,
        seed=seed,
        holdout_count=holdout_count,
        locked_development=locked_development,
    )
    selected = frozenset(best)
    assignments = tuple(
        SplitAssignment(
            case_id=item.case_id,
            role="holdout" if item.case_id in selected else "development",
            repository=item.repository,
            defect_category=item.defect_category,
            context_size_band=item.context_size_band,
        )
        for item in provisional
    )
    ordered_holdout = tuple(sorted(selected, key=lambda value: _order_key(seed, value)))
    raw: dict[str, JsonValue] = {
        "schema_version": SCHEMA_VERSION,
        "algorithm": ALGORITHM,
        "seed": seed,
        "target_holdout_count": holdout_count,
        "locked_development": cast(list[JsonValue], sorted(locked_development)),
        "assignments": [item.to_dict() for item in assignments],
        "ordered_holdout": list(ordered_holdout),
        "ordered_holdout_checksum": ordered_holdout_checksum(ordered_holdout),
        "balance": [item.to_dict() for item in _balance(assignments)],
        "objective_score": objective_score,
    }
    return CorpusSplit._from_dict(
        {**raw, "content_digest": canonical_digest(raw)}, optimum=(best, objective_score)
    )


def _order_key(seed: int, case_id: str) -> str:
    return hashlib.sha256(f"{seed}:{case_id}".encode()).hexdigest()


def _best_holdout(
    assignments: Sequence[SplitAssignment],
    *,
    seed: int,
    holdout_count: int,
    locked_development: frozenset[str],
) -> tuple[tuple[str, ...], int]:
    identifiers = tuple(item.case_id for item in assignments)
    candidates = tuple(value for value in identifiers if value not in locked_development)
    if holdout_count < 1 or holdout_count > len(candidates):
        raise SchemaError("holdout count is not feasible after development locks")
    strata = {
        item.case_id: (item.repository, item.defect_category, item.context_size_band)
        for item in assignments
    }
    totals = tuple(Counter(values[index] for values in strata.values()) for index in range(3))
    total_count = len(assignments)

    def score(selection: tuple[str, ...]) -> int:
        selected = set(selection)
        result = 0
        for dimension, total in enumerate(totals):
            observed = Counter(strata[case_id][dimension] for case_id in selected)
            result += sum(
                (observed[value] * total_count - count * holdout_count) ** 2
                for value, count in total.items()
            )
        return result

    def tie_break(selection: tuple[str, ...]) -> str:
        payload = f"{seed}\n" + "\n".join(selection)
        return hashlib.sha256(payload.encode()).hexdigest()

    best = min(
        itertools.combinations(candidates, holdout_count),
        key=lambda selection: (score(selection), tie_break(selection)),
    )
    return best, score(best)


def _balance(assignments: Sequence[SplitAssignment]) -> tuple[BalanceCell, ...]:
    dimensions: tuple[tuple[str, Callable[[SplitAssignment], str]], ...] = (
        ("repository", lambda item: item.repository),
        ("defect_category", lambda item: item.defect_category),
        ("context_size_band", lambda item: item.context_size_band),
    )
    cells: list[BalanceCell] = []
    for dimension, getter in dimensions:
        values = sorted({getter(item) for item in assignments})
        for value in values:
            selected = [item for item in assignments if getter(item) == value]
            holdout = sum(item.role == "holdout" for item in selected)
            cells.append(
                BalanceCell(
                    dimension=dimension,
                    value=value,
                    total=len(selected),
                    development=len(selected) - holdout,
                    holdout=holdout,
                )
            )
    return tuple(cells)
