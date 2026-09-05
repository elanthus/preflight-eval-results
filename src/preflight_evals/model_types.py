"""Shared non-sensitive types and conversion helpers for contract models."""

from __future__ import annotations

from collections.abc import Mapping
from datetime import date, datetime
from pathlib import PurePosixPath
from typing import Any, Literal, cast

from preflight_evals.errors import SchemaError

type DefectCategory = Literal[
    "correctness", "security", "evaluation_integrity", "operational_contract"
]
type Severity = Literal["low", "medium", "high", "critical"]
type SnapshotName = Literal["vulnerable", "fixed"]
type Condition = Literal["baseline", "candidate"]
type Eligibility = Literal["development", "holdout", "special_manual", "rejected"]
type CatalogDisposition = Literal[
    "paired_draft", "special-unrepaired-followup", "special-external-setting"
]
type FindingIdSource = Literal["source_review", "local_ordinal"]

SEVERITY_ORDER: dict[Severity, int] = {
    "low": 0,
    "medium": 1,
    "high": 2,
    "critical": 3,
}


def object_mapping(value: object) -> Mapping[str, Any]:
    """Cast a mapping already checked by JSON Schema."""

    if not isinstance(value, Mapping):
        raise SchemaError("validated contract contains an invalid object boundary")
    return cast(Mapping[str, Any], value)


def object_list(value: object) -> list[Any]:
    """Cast a list already checked by JSON Schema."""

    if not isinstance(value, list):
        raise SchemaError("validated contract contains an invalid list boundary")
    return value


def repository_path(value: str, *, field: str) -> PurePosixPath:
    """Return one normalized repository-relative path or fail without echoing it."""

    raw_parts = value.split("/")
    if (
        not value
        or value.startswith("/")
        or "\\" in value
        or "\x00" in value
        or any(part in {"", ".", ".."} for part in raw_parts)
    ):
        raise SchemaError(f"contract field {field!r} must be a normalized repository path")
    return PurePosixPath(*raw_parts)


def iso_date(value: str, *, field: str) -> date:
    try:
        return date.fromisoformat(value)
    except ValueError as exc:
        raise SchemaError(f"contract field {field!r} must be an ISO date") from exc


def iso_datetime(value: str, *, field: str) -> datetime:
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise SchemaError(f"contract field {field!r} must be an ISO date-time") from exc
    if parsed.tzinfo is None:
        raise SchemaError(f"contract field {field!r} must include a timezone")
    return parsed
