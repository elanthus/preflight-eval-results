"""Typed loading for non-secret evaluator configuration."""

from __future__ import annotations

import tomllib
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from typing import Any

from preflight_evals.artifact_policy import ArtifactRootClass, configured_root_is_allowed
from preflight_evals.errors import ConfigurationError


@dataclass(frozen=True, slots=True)
class ArtifactRoots:
    """Repository-relative roots for generated artifact classes."""

    ephemeral: PurePosixPath
    resumable: PurePosixPath
    raw_traces: PurePosixPath
    aggregate_reports: PurePosixPath


@dataclass(frozen=True, slots=True)
class AdapterProcessConfiguration:
    """Non-secret executable contract for the configured reviewer CLI."""

    executable: str
    review_arguments: tuple[str, ...]
    version_arguments: tuple[str, ...]
    working_directory: PurePosixPath
    probe_timeout_seconds: float
    maximum_stdout_bytes: int
    maximum_stderr_bytes: int


@dataclass(frozen=True, slots=True)
class ReportingConfiguration:
    """Disclosure thresholds for permanent aggregate reports."""

    minimum_public_cell_size: int


@dataclass(frozen=True, slots=True)
class EvaluationConfig:
    """Validated evaluator configuration safe to display to operators."""

    schema_version: str
    artifacts: ArtifactRoots
    adapter: AdapterProcessConfiguration
    reporting: ReportingConfiguration


_ROOT_KEYS = frozenset({"schema_version", "artifacts", "adapter", "reporting"})
_ARTIFACT_KEYS = frozenset({"ephemeral", "resumable", "raw_traces", "aggregate_reports"})
_ADAPTER_KEYS = frozenset(
    {
        "executable",
        "review_arguments",
        "version_arguments",
        "working_directory",
        "probe_timeout_seconds",
        "maximum_stdout_bytes",
        "maximum_stderr_bytes",
    }
)
_REPORTING_KEYS = frozenset({"minimum_public_cell_size"})
_MODEL_ARGUMENT = "{model}"
_DEFAULT_MINIMUM_PUBLIC_CELL_SIZE = 5


def _safe_artifact_root(
    value: object, *, field: str, root_class: ArtifactRootClass
) -> PurePosixPath:
    if not isinstance(value, str) or not value:
        raise ConfigurationError(f"configuration field {field!r} must be a non-empty path")
    raw_parts = value.split("/")
    if "\\" in value or "\x00" in value or any(part in {"", ".", ".."} for part in raw_parts):
        raise ConfigurationError(f"configuration field {field!r} must be a normalized path")
    path = PurePosixPath(*raw_parts)
    if not configured_root_is_allowed(path, root_class):
        raise ConfigurationError(
            f"configuration field {field!r} must stay within its approved artifact root"
        )
    return path


def _expect_table(value: object, *, field: str) -> dict[str, Any]:
    if not isinstance(value, dict) or not all(isinstance(key, str) for key in value):
        raise ConfigurationError(f"configuration field {field!r} must be a table")
    return value


def _argument_tuple(value: object, *, field: str) -> tuple[str, ...]:
    if (
        not isinstance(value, list)
        or not value
        or len(value) > 20
        or any(
            not isinstance(item, str) or not item or any(ord(character) < 32 for character in item)
            for item in value
        )
    ):
        raise ConfigurationError(f"configuration field {field!r} must be an argument array")
    return tuple(value)


def _positive_number(value: object, *, field: str, maximum: float) -> float:
    if isinstance(value, bool) or not isinstance(value, int | float) or not 0 < value <= maximum:
        raise ConfigurationError(f"configuration field {field!r} is outside its safe range")
    return float(value)


def _positive_integer(value: object, *, field: str, maximum: int) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or not 1 <= value <= maximum:
        raise ConfigurationError(f"configuration field {field!r} is outside its safe range")
    return value


def _reject_unknown(actual: set[str], allowed: frozenset[str], *, field: str) -> None:
    if actual - allowed:
        raise ConfigurationError(f"configuration field {field!r} contains unknown keys")


def load_config(path: Path) -> EvaluationConfig:
    """Load a configuration file without exposing raw values in failures."""

    try:
        with path.open("rb") as stream:
            raw = tomllib.load(stream)
    except (OSError, UnicodeError, tomllib.TOMLDecodeError) as exc:
        raise ConfigurationError(f"could not load configuration from {path.name!r}") from exc

    _reject_unknown(set(raw), _ROOT_KEYS, field="root")
    version = raw.get("schema_version")
    if version != "1":
        raise ConfigurationError("configuration schema_version must be '1'")

    artifacts = _expect_table(raw.get("artifacts"), field="artifacts")
    _reject_unknown(set(artifacts), _ARTIFACT_KEYS, field="artifacts")
    missing = _ARTIFACT_KEYS - artifacts.keys()
    if missing:
        raise ConfigurationError("configuration field 'artifacts' is incomplete")

    adapter = _expect_table(raw.get("adapter"), field="adapter")
    _reject_unknown(set(adapter), _ADAPTER_KEYS, field="adapter")
    if _ADAPTER_KEYS - adapter.keys():
        raise ConfigurationError("configuration field 'adapter' is incomplete")
    executable = adapter["executable"]
    if (
        not isinstance(executable, str)
        or not executable
        or any(ord(character) < 32 for character in executable)
    ):
        raise ConfigurationError("configuration field 'adapter.executable' is invalid")
    review_arguments = _argument_tuple(
        adapter["review_arguments"], field="adapter.review_arguments"
    )
    if review_arguments.count(_MODEL_ARGUMENT) != 1:
        raise ConfigurationError("configuration field 'adapter.review_arguments' must bind model")

    reporting_value = raw.get("reporting")
    reporting = (
        _expect_table(reporting_value, field="reporting") if reporting_value is not None else {}
    )
    _reject_unknown(set(reporting), _REPORTING_KEYS, field="reporting")
    minimum_public_cell_size = reporting.get(
        "minimum_public_cell_size", _DEFAULT_MINIMUM_PUBLIC_CELL_SIZE
    )
    if (
        isinstance(minimum_public_cell_size, bool)
        or not isinstance(minimum_public_cell_size, int)
        or not 2 <= minimum_public_cell_size <= 1_000
    ):
        raise ConfigurationError(
            "configuration field 'reporting.minimum_public_cell_size' is outside its safe range"
        )

    return EvaluationConfig(
        schema_version=version,
        artifacts=ArtifactRoots(
            ephemeral=_safe_artifact_root(
                artifacts["ephemeral"],
                field="artifacts.ephemeral",
                root_class="ephemeral",
            ),
            resumable=_safe_artifact_root(
                artifacts["resumable"],
                field="artifacts.resumable",
                root_class="resumable",
            ),
            raw_traces=_safe_artifact_root(
                artifacts["raw_traces"],
                field="artifacts.raw_traces",
                root_class="raw_traces",
            ),
            aggregate_reports=_safe_artifact_root(
                artifacts["aggregate_reports"],
                field="artifacts.aggregate_reports",
                root_class="aggregate_reports",
            ),
        ),
        adapter=AdapterProcessConfiguration(
            executable=executable,
            review_arguments=review_arguments,
            version_arguments=_argument_tuple(
                adapter["version_arguments"], field="adapter.version_arguments"
            ),
            working_directory=_safe_artifact_root(
                adapter["working_directory"],
                field="adapter.working_directory",
                root_class="ephemeral",
            ),
            probe_timeout_seconds=_positive_number(
                adapter["probe_timeout_seconds"],
                field="adapter.probe_timeout_seconds",
                maximum=300,
            ),
            maximum_stdout_bytes=_positive_integer(
                adapter["maximum_stdout_bytes"],
                field="adapter.maximum_stdout_bytes",
                maximum=16_000_000,
            ),
            maximum_stderr_bytes=_positive_integer(
                adapter["maximum_stderr_bytes"],
                field="adapter.maximum_stderr_bytes",
                maximum=1_000_000,
            ),
        ),
        reporting=ReportingConfiguration(
            minimum_public_cell_size=minimum_public_cell_size,
        ),
    )
