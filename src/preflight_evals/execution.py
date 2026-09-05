"""Content-addressed experiment planning and resumable reviewer execution."""

from __future__ import annotations

import hashlib
import json
import os
import shutil
import tempfile
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path, PurePosixPath
from typing import Any, cast

from preflight_evals.adapter import (
    AdapterCapabilities,
    AdapterConfigurationError,
    AdapterInvocation,
    AdapterOutcome,
    ReviewAdapter,
    ensure_paired_invocations,
)
from preflight_evals.artifact_policy import configured_root_is_allowed
from preflight_evals.attempt_metadata import AttemptMetadata, build_attempt_metadata
from preflight_evals.bundle import BundleBuild, ReviewerSettings, parse_manifest_bytes
from preflight_evals.canonical import (
    JsonValue,
    canonical_digest,
    canonical_json_bytes,
    sha256_digest,
)
from preflight_evals.errors import ExecutionError, LeakageError, SchemaError
from preflight_evals.holdout import development_records_digest, validate_holdout_source
from preflight_evals.model_types import Condition, SnapshotName
from preflight_evals.recovery import (
    RETRY_RECOVERY_MAXIMUM_ATTEMPTS,
    validate_retry_recovery_source,
)
from preflight_evals.recovery import (
    is_output_limit_failure as _is_output_limit_failure,
)
from preflight_evals.recovery import (
    terminal_records_digest as _terminal_records_digest,
)
from preflight_evals.recovery import (
    validate_recovery_source as _validate_recovery_source,
)
from preflight_evals.request_contract import request_binding
from preflight_evals.reviewer_models import PromptManifest
from preflight_evals.run_models import (
    ExperimentManifest,
    FrozenReviewerConfiguration,
    PlannedRun,
    PriceProjection,
    ProfileReference,
    RetryPolicy,
    RunRecord,
)

_DIGEST = "sha256:"
_RUN_ID_PREFIX = "run-"
_SUPPORTED_RETRYABLE = frozenset({"invalid_output", "provider_error", "timeout"})


@dataclass(frozen=True, slots=True)
class CaseFreezeInput:
    case_id: str
    role: str
    vulnerable_input_tokens: int
    fixed_input_tokens: int
    case_contract_digest: str
    vulnerable_snapshot: str
    fixed_snapshot: str

    def estimate(self, snapshot: SnapshotName) -> int:
        return self.vulnerable_input_tokens if snapshot == "vulnerable" else self.fixed_input_tokens


def case_role_checksum(cases: Sequence[CaseFreezeInput]) -> str:
    """Return the canonical checksum of the private development/holdout split."""

    return canonical_digest(
        {
            "schema_version": "1",
            "cases": [
                {"case_id": case.case_id, "role": case.role}
                for case in sorted(cases, key=lambda item: item.case_id)
            ],
        }
    )


@dataclass(frozen=True, slots=True)
class ExperimentFreezeInput:
    cases: tuple[CaseFreezeInput, ...]
    case_manifest_checksum: str
    baseline_profile: ProfileReference
    candidate_profile: ProfileReference
    snapshot_set: tuple[SnapshotName, ...]
    repetitions: int
    randomization_seed: int
    reviewer_config: FrozenReviewerConfiguration
    retry_policy: RetryPolicy
    invalid_output_policy: str
    code_revision: str
    environment_lock_digest: str
    required_bundle_schema_version: str | None = None
    prompt_template: ProfileReference | None = None
    analysis_plan: ProfileReference | None = None
    holdout_access_enabled: bool | None = None
    price_projection: PriceProjection | None = None

    @classmethod
    def from_dict(cls, document: Mapping[str, object]) -> ExperimentFreezeInput:
        """Load the private operator definition through a strict non-disclosing boundary."""

        common = {
            "schema_version",
            "cases",
            "case_manifest_checksum",
            "baseline_profile",
            "candidate_profile",
            "snapshot_set",
            "repetitions",
            "randomization_seed",
            "reviewer_config",
            "retry_policy",
            "invalid_output_policy",
            "code_revision",
            "environment_lock_digest",
        }
        protocol = {
            "prompt_template",
            "analysis_plan",
            "holdout_access_enabled",
            "price_projection",
        }
        version = document.get("schema_version")
        expected = common if version == "1" else common | protocol
        if version == "2" and "required_bundle_schema_version" in document:
            expected = expected | {"required_bundle_schema_version"}
        if version not in {"1", "2"} or set(document) != expected:
            raise ExecutionError("experiment definition has an unsupported shape or version")
        try:
            cases = tuple(_case_input(item) for item in _object_sequence(document["cases"]))
            baseline = _profile_input(_object_mapping(document["baseline_profile"]))
            candidate = _profile_input(_object_mapping(document["candidate_profile"]))
            snapshots = tuple(
                cast(SnapshotName, item) for item in _string_sequence(document["snapshot_set"])
            )
            reviewer = _reviewer_input(_object_mapping(document["reviewer_config"]))
            retry = _retry_input(_object_mapping(document["retry_policy"]))
            prompt = (
                _profile_input(_object_mapping(document["prompt_template"]))
                if version == "2"
                else None
            )
            analysis = (
                _profile_input(_object_mapping(document["analysis_plan"]))
                if version == "2"
                else None
            )
            projection = (
                _price_projection_input(_object_mapping(document["price_projection"]))
                if version == "2"
                else None
            )
            model = cls(
                cases=cases,
                case_manifest_checksum=_string(document["case_manifest_checksum"]),
                baseline_profile=baseline,
                candidate_profile=candidate,
                snapshot_set=snapshots,
                repetitions=_integer(document["repetitions"]),
                randomization_seed=_integer(document["randomization_seed"]),
                reviewer_config=reviewer,
                retry_policy=retry,
                invalid_output_policy=_string(document["invalid_output_policy"]),
                code_revision=_string(document["code_revision"]),
                environment_lock_digest=_string(document["environment_lock_digest"]),
                required_bundle_schema_version=(
                    _string(document["required_bundle_schema_version"])
                    if "required_bundle_schema_version" in document
                    else None
                ),
                prompt_template=prompt,
                analysis_plan=analysis,
                holdout_access_enabled=(
                    _boolean(document["holdout_access_enabled"]) if version == "2" else None
                ),
                price_projection=projection,
            )
        except (KeyError, TypeError, ValueError) as exc:
            raise ExecutionError("experiment definition is invalid") from exc
        _validate_freeze_input(model)
        return model


@dataclass(frozen=True, slots=True)
class ExperimentPlanSummary:
    experiment_id: str
    experiment_digest: str
    planned_calls: int
    maximum_provider_calls: int
    development_cases: int
    holdout_cases: int
    excluded_holdout_cases: int
    estimated_input_tokens: int
    maximum_input_tokens: int
    maximum_output_tokens: int
    projected_cost_currency: str
    projected_cost: float | None
    price_table_version: str | None

    def to_dict(self) -> dict[str, JsonValue]:
        return {
            "schema_version": "1",
            "experiment_id": self.experiment_id,
            "experiment_digest": self.experiment_digest,
            "planned_calls": self.planned_calls,
            "maximum_provider_calls": self.maximum_provider_calls,
            "development_cases": self.development_cases,
            "holdout_cases": self.holdout_cases,
            "excluded_holdout_cases": self.excluded_holdout_cases,
            "estimated_input_tokens": self.estimated_input_tokens,
            "maximum_input_tokens": self.maximum_input_tokens,
            "maximum_output_tokens": self.maximum_output_tokens,
            "projected_cost_currency": self.projected_cost_currency,
            "projected_cost": self.projected_cost,
            "price_table_version": self.price_table_version,
        }


@dataclass(frozen=True, slots=True)
class ExecutionSummary:
    experiment_id: str
    snapshot_filter: SnapshotName | None
    planned_runs: int
    terminal_runs: int
    succeeded_runs: int
    failed_runs: int
    calls_started: int
    complete: bool
    interrupted: bool

    def to_dict(self) -> dict[str, JsonValue]:
        return {
            "schema_version": "1",
            "experiment_id": self.experiment_id,
            "snapshot_filter": self.snapshot_filter,
            "planned_runs": self.planned_runs,
            "terminal_runs": self.terminal_runs,
            "succeeded_runs": self.succeeded_runs,
            "failed_runs": self.failed_runs,
            "calls_started": self.calls_started,
            "complete": self.complete,
            "interrupted": self.interrupted,
        }


@dataclass(frozen=True, slots=True)
class AttemptReconciliation:
    experiment_id: str
    accounted_attempts: int
    terminal_runs: int
    recovered_terminal_runs: int

    def to_dict(self) -> dict[str, JsonValue]:
        return {
            "schema_version": "1",
            "experiment_id": self.experiment_id,
            "accounted_attempts": self.accounted_attempts,
            "terminal_runs": self.terminal_runs,
            "recovered_terminal_runs": self.recovered_terminal_runs,
        }


def freeze_experiment(
    definition: ExperimentFreezeInput,
    capabilities: AdapterCapabilities,
    *,
    created_at: datetime,
    approved_by: str,
    approved_at: datetime,
) -> ExperimentManifest:
    """Create one immutable, reproducibly ordered experiment manifest."""

    _validate_freeze_input(definition)
    if definition.case_manifest_checksum != case_role_checksum(definition.cases):
        raise ExecutionError("experiment case-role checksum does not match its frozen cases")
    if not approved_by or len(approved_by) > 120:
        raise ExecutionError("experiment approval actor is invalid")
    _require_aware(created_at, field="creation time")
    _require_aware(approved_at, field="approval time")
    if approved_at < created_at:
        raise ExecutionError("experiment approval cannot precede creation")
    if definition.reviewer_config.adapter_version != capabilities.adapter_version:
        raise ExecutionError("experiment reviewer and adapter versions do not agree")

    cases = tuple(sorted(definition.cases, key=lambda case: case.case_id))
    snapshots = tuple(
        snapshot for snapshot in ("vulnerable", "fixed") if snapshot in definition.snapshot_set
    )
    manifest_version = "1.2" if definition.prompt_template is not None else "1.1"
    namespace_document: dict[str, JsonValue] = {
        "schema_version": manifest_version,
        "cases": [_case_definition_dict(case) for case in cases],
        "case_manifest_checksum": definition.case_manifest_checksum,
        "baseline_profile": _profile_dict(definition.baseline_profile),
        "candidate_profile": _profile_dict(definition.candidate_profile),
        "snapshot_set": list(snapshots),
        "repetitions": definition.repetitions,
        "randomization_seed": definition.randomization_seed,
        "reviewer_config": _reviewer_dict(definition.reviewer_config),
        "retry_policy": _retry_dict(definition.retry_policy),
        "invalid_output_policy": definition.invalid_output_policy,
        "code_revision": definition.code_revision,
        "environment_lock_digest": definition.environment_lock_digest,
        "adapter_capabilities": capabilities.to_dict(),
    }
    if manifest_version == "1.2":
        namespace_document.update(_protocol_definition_dict(definition))
    namespace = canonical_digest(namespace_document)
    blocks = [
        (case, snapshot, repetition)
        for case in cases
        for snapshot in snapshots
        for repetition in range(1, definition.repetitions + 1)
    ]
    blocks.sort(
        key=lambda block: _stable_bytes(
            definition.randomization_seed,
            "block",
            block[0].case_id,
            block[1],
            block[2],
        )
    )
    runs: list[dict[str, JsonValue]] = []
    used_seeds: set[int] = set()
    for case, snapshot, repetition in blocks:
        block_key = (case.case_id, snapshot, repetition)
        paired_seed = (
            _unique_seed(definition.randomization_seed, block_key, used_seeds=used_seeds)
            if manifest_version == "1.2"
            else None
        )
        conditions: tuple[Condition, Condition] = (
            ("baseline", "candidate")
            if _stable_bytes(
                definition.randomization_seed,
                "orientation",
                case.case_id,
                snapshot,
                repetition,
            )[0]
            % 2
            == 0
            else ("candidate", "baseline")
        )
        for condition in conditions:
            tuple_key = (case.case_id, snapshot, condition, repetition)
            request_seed = (
                paired_seed
                if paired_seed is not None
                else _unique_seed(definition.randomization_seed, tuple_key, used_seeds=used_seeds)
            )
            run_hash = hashlib.sha256(
                "\0".join((namespace, *map(str, tuple_key))).encode("utf-8")
            ).hexdigest()
            runs.append(
                {
                    "run_id": f"{_RUN_ID_PREFIX}{run_hash[:32]}",
                    "case_id": case.case_id,
                    "snapshot": snapshot,
                    "condition": condition,
                    "repetition": repetition,
                    "request_seed": request_seed,
                    "estimated_input_tokens": case.estimate(snapshot),
                }
            )

    document: dict[str, JsonValue] = {
        "schema_version": manifest_version,
        "experiment_id": "experiment-pending",
        "cases": [_manifest_case_dict(case) for case in cases],
        "case_manifest_checksum": definition.case_manifest_checksum,
        "baseline_profile": _profile_dict(definition.baseline_profile),
        "candidate_profile": _profile_dict(definition.candidate_profile),
        "snapshot_set": list(snapshots),
        "repetitions": definition.repetitions,
        "execution_order": cast(list[JsonValue], runs),
        "randomization_seed": definition.randomization_seed,
        "reviewer_config": _reviewer_dict(definition.reviewer_config),
        "retry_policy": _retry_dict(definition.retry_policy),
        "invalid_output_policy": definition.invalid_output_policy,
        "code_revision": definition.code_revision,
        "environment_lock_digest": definition.environment_lock_digest,
        "planned_run_count": len(runs),
        "created_at": _iso_string(created_at),
        "approved_by": approved_by,
        "approved_at": _iso_string(approved_at),
        "frozen": True,
        "adapter_capabilities": capabilities.to_dict(),
    }
    if manifest_version == "1.2":
        document.update(_protocol_definition_dict(definition))
    content = dict(document)
    for field in ("experiment_id", "created_at", "approved_by", "approved_at"):
        content.pop(field)
    digest = canonical_digest(content)
    document["content_digest"] = digest
    document["experiment_id"] = f"experiment-{digest.removeprefix(_DIGEST)[:32]}"
    try:
        return ExperimentManifest.from_dict(cast(dict[str, Any], document))
    except SchemaError as exc:  # pragma: no cover - builder/model parity
        raise ExecutionError("generated experiment manifest is invalid") from exc


def terminal_records_digest(experiment: ExperimentManifest, records: Sequence[RunRecord]) -> str:
    try:
        return _terminal_records_digest(experiment, records)
    except SchemaError as exc:
        raise ExecutionError(str(exc)) from exc


def validate_recovery_source(
    recovery: ExperimentManifest,
    source: ExperimentManifest,
    records: Sequence[RunRecord],
) -> None:
    try:
        _validate_recovery_source(recovery, source, records)
    except SchemaError as exc:
        raise ExecutionError(str(exc)) from exc


def validate_recovery_prepared_artifacts(source_record: RunRecord, build: BundleBuild) -> None:
    """Require a recovery call to reuse the exact source request artifacts."""

    identity = source_record.identity
    if (
        identity is None
        or build.bundle_digest != identity.bundle_digest
        or build.request_digest != identity.request_digest
        or build.manifest_digest != source_record.prompt_manifest_digest
    ):
        raise ExecutionError("recovery artifacts do not match the bound source run record")


def freeze_recovery_experiment(
    source: ExperimentManifest,
    records: Sequence[RunRecord],
    capabilities: AdapterCapabilities,
    *,
    maximum_attempts: int,
    code_revision: str,
    environment_lock_digest: str,
    created_at: datetime,
    approved_by: str,
    approved_at: datetime,
    expected_output_limit_failures: int,
    expected_invalid_output_failures: int,
) -> ExperimentManifest:
    """Freeze a sparse supplemental run for the source experiment's output failures."""

    _require_current_manifest(source)
    if source.schema_version != "1.2" or source.recovery_source is not None:
        raise ExecutionError("recovery requires one primary protocol-1.2 experiment")
    if not 1 <= maximum_attempts <= 10:
        raise ExecutionError("recovery maximum attempts is invalid")
    _require_aware(created_at, field="creation time")
    _require_aware(approved_at, field="approval time")
    if not approved_by or approved_at < created_at:
        raise ExecutionError("recovery approval metadata is invalid")
    if len(code_revision) != 40 or any(char not in "0123456789abcdef" for char in code_revision):
        raise ExecutionError("recovery code revision is invalid")
    if not environment_lock_digest.startswith(_DIGEST):
        raise ExecutionError("recovery environment lock digest is invalid")
    source_capabilities = cast(AdapterCapabilities, source.adapter_capabilities)
    source_capability_document = source_capabilities.to_dict()
    recovery_capability_document = capabilities.to_dict()
    for field in ("maximum_stdout_bytes", "maximum_stderr_bytes", "content_digest"):
        source_capability_document.pop(field)
        recovery_capability_document.pop(field)
    stdout_increased = capabilities.maximum_stdout_bytes > source_capabilities.maximum_stdout_bytes
    stderr_increased = capabilities.maximum_stderr_bytes > source_capabilities.maximum_stderr_bytes
    if (
        source_capability_document != recovery_capability_document
        or capabilities.maximum_stdout_bytes < source_capabilities.maximum_stdout_bytes
        or capabilities.maximum_stderr_bytes < source_capabilities.maximum_stderr_bytes
        or not (stdout_increased or stderr_increased)
    ):
        raise ExecutionError("recovery may increase only adapter output capture limits")
    selection_policy = (
        "terminal-output-failures-v2" if stderr_increased else "terminal-output-failures-v1"
    )

    records_by_id = {record.run_id: record for record in records}
    digest = terminal_records_digest(source, records)
    output_limit: list[PlannedRun] = []
    invalid_output: list[PlannedRun] = []
    for planned in source.execution_order:
        record = records_by_id[planned.run_id]
        if _is_output_limit_failure(record):
            output_limit.append(planned)
        elif (
            record.status == "invalid_output"
            and record.attempt >= source.retry_policy.maximum_attempts
            and record.validation_errors == ("OUTPUT_SCHEMA_INVALID",)
        ):
            invalid_output.append(planned)
    if (
        len(output_limit) != expected_output_limit_failures
        or len(invalid_output) != expected_invalid_output_failures
        or not output_limit + invalid_output
    ):
        raise ExecutionError("source terminal failure counts do not match recovery approval")
    selected_ids = {run.run_id for run in (*output_limit, *invalid_output)}
    selected = tuple(run for run in source.execution_order if run.run_id in selected_ids)
    projection = cast(PriceProjection, source.price_projection)
    maximum_provider_calls = len(selected) * maximum_attempts
    recovery_projection = PriceProjection(
        price_table_version=projection.price_table_version,
        currency=projection.currency,
        input_usd_per_million_tokens=projection.input_usd_per_million_tokens,
        output_usd_per_million_tokens=projection.output_usd_per_million_tokens,
        maximum_input_tokens=maximum_provider_calls * source.reviewer_config.input_token_limit,
        maximum_output_tokens=maximum_provider_calls * source.reviewer_config.output_token_limit,
        contingency_rate=projection.contingency_rate,
        projected_cost_usd=(
            (
                maximum_provider_calls
                * source.reviewer_config.input_token_limit
                * projection.input_usd_per_million_tokens
                + maximum_provider_calls
                * source.reviewer_config.output_token_limit
                * projection.output_usd_per_million_tokens
            )
            / 1_000_000
            * (1 + projection.contingency_rate)
        ),
    )
    document = source.to_dict()
    document.update(
        {
            "schema_version": "1.3",
            "experiment_id": "experiment-pending",
            "execution_order": [
                {
                    "run_id": run.run_id,
                    "case_id": run.case_id,
                    "snapshot": run.snapshot,
                    "condition": run.condition,
                    "repetition": run.repetition,
                    "request_seed": cast(int, run.request_seed),
                    "estimated_input_tokens": cast(int, run.estimated_input_tokens),
                }
                for run in selected
            ],
            "reviewer_config": _reviewer_dict(source.reviewer_config),
            "retry_policy": {
                "maximum_attempts": maximum_attempts,
                "retryable_failures": list(source.retry_policy.retryable_failures),
            },
            "code_revision": code_revision,
            "environment_lock_digest": environment_lock_digest,
            "planned_run_count": len(selected),
            "created_at": _iso_string(created_at),
            "approved_by": approved_by,
            "approved_at": _iso_string(approved_at),
            "adapter_capabilities": capabilities.to_dict(),
            "price_projection": _price_projection_dict(recovery_projection),
            "recovery_source": {
                "experiment_id": source.experiment_id,
                "experiment_digest": cast(str, source.content_digest),
                "terminal_records_digest": digest,
                "selection_policy": selection_policy,
                "output_limit_failures": len(output_limit),
                "invalid_output_failures": len(invalid_output),
            },
        }
    )
    document.pop("content_digest", None)
    content = dict(document)
    for field in ("experiment_id", "created_at", "approved_by", "approved_at"):
        content.pop(field)
    recovery_digest = canonical_digest(cast(JsonValue, content))
    document["content_digest"] = recovery_digest
    document["experiment_id"] = f"experiment-{recovery_digest.removeprefix(_DIGEST)[:32]}"
    try:
        return ExperimentManifest.from_dict(cast(dict[str, Any], document))
    except SchemaError as exc:  # pragma: no cover - builder/model parity
        raise ExecutionError("generated recovery experiment manifest is invalid") from exc


def freeze_holdout_experiment(
    source: ExperimentManifest,
    development_records: Sequence[RunRecord],
    capabilities: AdapterCapabilities,
    *,
    code_revision: str,
    environment_lock_digest: str,
    created_at: datetime,
    approved_by: str,
    approved_at: datetime,
) -> ExperimentManifest:
    """Freeze the exact holdout subset after an authorized development checkpoint."""

    _require_current_manifest(source)
    if (
        source.schema_version != "1.2"
        or source.recovery_source is not None
        or source.holdout_source is not None
        or source.holdout_access_enabled is not False
    ):
        raise ExecutionError("holdout requires one primary protocol-1.2 experiment")
    _require_aware(created_at, field="creation time")
    _require_aware(approved_at, field="approval time")
    if not approved_by or approved_at < created_at:
        raise ExecutionError("holdout approval metadata is invalid")
    if len(code_revision) != 40 or any(char not in "0123456789abcdef" for char in code_revision):
        raise ExecutionError("holdout code revision is invalid")
    if not environment_lock_digest.startswith(_DIGEST):
        raise ExecutionError("holdout environment lock digest is invalid")
    if capabilities != source.adapter_capabilities:
        raise ExecutionError("holdout adapter capabilities must exactly match the source")
    try:
        checkpoint_digest = development_records_digest(source, development_records)
    except SchemaError as exc:
        raise ExecutionError("holdout development checkpoint is invalid") from exc
    roles = {case.case_id: case.role for case in source.cases}
    selected = tuple(run for run in source.execution_order if roles[run.case_id] == "holdout")
    if not selected:
        raise ExecutionError("source experiment has no frozen holdout runs")
    projection = cast(PriceProjection, source.price_projection)
    maximum_provider_calls = len(selected) * source.retry_policy.maximum_attempts
    holdout_projection = PriceProjection(
        price_table_version=projection.price_table_version,
        currency=projection.currency,
        input_usd_per_million_tokens=projection.input_usd_per_million_tokens,
        output_usd_per_million_tokens=projection.output_usd_per_million_tokens,
        maximum_input_tokens=maximum_provider_calls * source.reviewer_config.input_token_limit,
        maximum_output_tokens=maximum_provider_calls * source.reviewer_config.output_token_limit,
        contingency_rate=projection.contingency_rate,
        projected_cost_usd=(
            (
                maximum_provider_calls
                * source.reviewer_config.input_token_limit
                * projection.input_usd_per_million_tokens
                + maximum_provider_calls
                * source.reviewer_config.output_token_limit
                * projection.output_usd_per_million_tokens
            )
            / 1_000_000
            * (1 + projection.contingency_rate)
        ),
    )
    document = source.to_dict()
    document.update(
        {
            "schema_version": "1.4",
            "experiment_id": "experiment-pending",
            "holdout_access_enabled": True,
            "execution_order": [_planned_run_dict(run) for run in selected],
            "code_revision": code_revision,
            "environment_lock_digest": environment_lock_digest,
            "planned_run_count": len(selected),
            "created_at": _iso_string(created_at),
            "approved_by": approved_by,
            "approved_at": _iso_string(approved_at),
            "adapter_capabilities": capabilities.to_dict(),
            "price_projection": _price_projection_dict(holdout_projection),
            "holdout_source": {
                "experiment_id": source.experiment_id,
                "experiment_digest": cast(str, source.content_digest),
                "development_records_digest": checkpoint_digest,
                "selection_policy": "frozen-holdout-v1",
                "development_records": len(development_records),
                "holdout_records": len(selected),
            },
        }
    )
    document.pop("recovery_source", None)
    document.pop("content_digest", None)
    content = dict(document)
    for field in ("experiment_id", "created_at", "approved_by", "approved_at"):
        content.pop(field)
    holdout_digest = canonical_digest(cast(JsonValue, content))
    document["content_digest"] = holdout_digest
    document["experiment_id"] = f"experiment-{holdout_digest.removeprefix(_DIGEST)[:32]}"
    try:
        return ExperimentManifest.from_dict(cast(dict[str, Any], document))
    except SchemaError as exc:  # pragma: no cover - builder/model parity
        raise ExecutionError("generated holdout experiment manifest is invalid") from exc


def freeze_retry_recovery_experiment(
    source: ExperimentManifest,
    records: Sequence[RunRecord],
    capabilities: AdapterCapabilities,
    *,
    maximum_attempts: int,
    code_revision: str,
    environment_lock_digest: str,
    created_at: datetime,
    approved_by: str,
    approved_at: datetime,
    expected_provider_error_failures: int,
) -> ExperimentManifest:
    """Freeze a sparse retry of exhausted provider failures from a holdout stage."""

    _require_current_manifest(source)
    if (
        source.schema_version != "1.4"
        or source.recovery_source is not None
        or source.holdout_source is None
        or source.holdout_access_enabled is not True
    ):
        raise ExecutionError("retry recovery requires one primary protocol-1.4 holdout")
    if maximum_attempts != RETRY_RECOVERY_MAXIMUM_ATTEMPTS:
        raise ExecutionError("retry recovery permits exactly one additional attempt")
    _require_aware(created_at, field="creation time")
    _require_aware(approved_at, field="approval time")
    if not approved_by or created_at < source.created_at or approved_at < created_at:
        raise ExecutionError("retry recovery approval metadata is invalid")
    if len(code_revision) != 40 or any(char not in "0123456789abcdef" for char in code_revision):
        raise ExecutionError("retry recovery code revision is invalid")
    if not environment_lock_digest.startswith(_DIGEST):
        raise ExecutionError("retry recovery environment lock digest is invalid")
    if capabilities != source.adapter_capabilities:
        raise ExecutionError("retry recovery adapter capabilities must exactly match the source")
    records_by_id = {record.run_id: record for record in records}
    digest = _terminal_records_digest(source, records)
    selected = tuple(
        run
        for run in source.execution_order
        if records_by_id[run.run_id].status == "provider_error"
        and records_by_id[run.run_id].attempt >= source.retry_policy.maximum_attempts
        and records_by_id[run.run_id].validation_errors == ("PROCESS_NONZERO",)
    )
    if len(selected) != expected_provider_error_failures or not selected:
        raise ExecutionError("source provider failure count does not match recovery approval")
    projection = cast(PriceProjection, source.price_projection)
    maximum_provider_calls = len(selected) * maximum_attempts
    recovery_projection = PriceProjection(
        price_table_version=projection.price_table_version,
        currency=projection.currency,
        input_usd_per_million_tokens=projection.input_usd_per_million_tokens,
        output_usd_per_million_tokens=projection.output_usd_per_million_tokens,
        maximum_input_tokens=maximum_provider_calls * source.reviewer_config.input_token_limit,
        maximum_output_tokens=maximum_provider_calls * source.reviewer_config.output_token_limit,
        contingency_rate=projection.contingency_rate,
        projected_cost_usd=(
            (
                maximum_provider_calls
                * source.reviewer_config.input_token_limit
                * projection.input_usd_per_million_tokens
                + maximum_provider_calls
                * source.reviewer_config.output_token_limit
                * projection.output_usd_per_million_tokens
            )
            / 1_000_000
            * (1 + projection.contingency_rate)
        ),
    )
    document = source.to_dict()
    document.update(
        {
            "schema_version": "1.5",
            "experiment_id": "experiment-pending",
            "execution_order": [_planned_run_dict(run) for run in selected],
            "retry_policy": {
                "maximum_attempts": maximum_attempts,
                "retryable_failures": list(source.retry_policy.retryable_failures),
            },
            "code_revision": code_revision,
            "environment_lock_digest": environment_lock_digest,
            "planned_run_count": len(selected),
            "created_at": _iso_string(created_at),
            "approved_by": approved_by,
            "approved_at": _iso_string(approved_at),
            "adapter_capabilities": capabilities.to_dict(),
            "price_projection": _price_projection_dict(recovery_projection),
            "recovery_source": {
                "experiment_id": source.experiment_id,
                "experiment_digest": cast(str, source.content_digest),
                "terminal_records_digest": digest,
                "selection_policy": "terminal-provider-failures-v1",
                "output_limit_failures": 0,
                "invalid_output_failures": 0,
                "provider_error_failures": len(selected),
                "implementation_transition": {
                    "source_code_revision": source.code_revision,
                    "source_environment_lock_digest": source.environment_lock_digest,
                    "target_code_revision": code_revision,
                    "target_environment_lock_digest": environment_lock_digest,
                    "approved_by": approved_by,
                    "approved_at": _iso_string(approved_at),
                },
            },
        }
    )
    document.pop("content_digest", None)
    content = dict(document)
    for field in ("experiment_id", "created_at", "approved_by", "approved_at"):
        content.pop(field)
    recovery_digest = canonical_digest(cast(JsonValue, content))
    document["content_digest"] = recovery_digest
    document["experiment_id"] = f"experiment-{recovery_digest.removeprefix(_DIGEST)[:32]}"
    try:
        return ExperimentManifest.from_dict(cast(dict[str, Any], document))
    except SchemaError as exc:  # pragma: no cover - builder/model parity
        raise ExecutionError("generated retry recovery manifest is invalid") from exc


def plan_summary(
    manifest: ExperimentManifest, *, allow_holdout: bool = False
) -> ExperimentPlanSummary:
    """Return a count-only plan summary without exposing case or condition membership."""

    _require_current_manifest(manifest)
    case_roles = {case.case_id: case.role for case in manifest.cases}
    selected_runs = tuple(
        run
        for run in manifest.execution_order
        if allow_holdout or case_roles[run.case_id] == "development"
    )
    selected_case_ids = {run.case_id for run in selected_runs}
    planned_case_ids = {run.case_id for run in manifest.execution_order}
    holdout = sum(
        case.role == "holdout" and case.case_id in planned_case_ids for case in manifest.cases
    )
    projection = manifest.price_projection
    maximum_provider_calls = len(selected_runs) * manifest.retry_policy.maximum_attempts
    selected_cost = None
    if projection is not None:
        selected_cost = (
            (
                maximum_provider_calls
                * manifest.reviewer_config.input_token_limit
                * projection.input_usd_per_million_tokens
                + maximum_provider_calls
                * manifest.reviewer_config.output_token_limit
                * projection.output_usd_per_million_tokens
            )
            / 1_000_000
            * (1 + projection.contingency_rate)
        )
    return ExperimentPlanSummary(
        experiment_id=manifest.experiment_id,
        experiment_digest=cast(str, manifest.content_digest),
        planned_calls=len(selected_runs),
        maximum_provider_calls=maximum_provider_calls,
        development_cases=sum(
            case.role == "development" and case.case_id in selected_case_ids
            for case in manifest.cases
        ),
        holdout_cases=holdout if allow_holdout else 0,
        excluded_holdout_cases=0 if allow_holdout else holdout,
        estimated_input_tokens=sum(cast(int, run.estimated_input_tokens) for run in selected_runs),
        maximum_input_tokens=(maximum_provider_calls * manifest.reviewer_config.input_token_limit),
        maximum_output_tokens=(
            maximum_provider_calls * manifest.reviewer_config.output_token_limit
        ),
        projected_cost_currency=projection.currency if projection is not None else "USD",
        projected_cost=selected_cost,
        price_table_version=(projection.price_table_version if projection is not None else None),
    )


class ExperimentStore:
    """Private, append-only filesystem store for one frozen experiment."""

    def __init__(
        self,
        repository_root: Path,
        resumable_root: PurePosixPath,
        manifest: ExperimentManifest,
    ) -> None:
        _require_current_manifest(manifest)
        if (
            not repository_root.is_absolute()
            or not repository_root.is_dir()
            or repository_root.is_symlink()
            or not configured_root_is_allowed(resumable_root, "resumable")
        ):
            raise ExecutionError("experiment store configuration is unsafe")
        self.repository_root = repository_root
        self.resumable_root = resumable_root
        self.manifest = manifest
        self.root = repository_root.joinpath(*resumable_root.parts) / manifest.experiment_id

    @property
    def manifest_path(self) -> Path:
        return self.root / "experiment.json"

    def publish_manifest(self) -> Path:
        payload = self.manifest.canonical_bytes()
        _ensure_private_directory(self.repository_root, self.root.parent)
        if self.root.exists() or self.root.is_symlink():
            if self.root.is_symlink() or not self.root.is_dir():
                raise ExecutionError("experiment store contains unsafe prior state")
            existing = _read_private(self.manifest_path, repository_root=self.repository_root)
            if existing != payload:
                raise ExecutionError("experiment identifier already has different frozen content")
            return self.manifest_path
        staging: Path | None = None
        try:
            staging = Path(
                tempfile.mkdtemp(
                    prefix=f".{self.manifest.experiment_id}.tmp-", dir=self.root.parent
                )
            )
            staging.chmod(0o700)
            _write_exclusive(staging / "experiment.json", payload)
            _fsync_directory(staging)
            staging.rename(self.root)
            staging = None
            _fsync_directory(self.root.parent)
        except OSError as exc:
            raise ExecutionError("could not publish the frozen experiment safely") from exc
        finally:
            if staging is not None:
                shutil.rmtree(staging, ignore_errors=True)
        return self.manifest_path

    def verify_manifest(self) -> None:
        if (
            _read_private(self.manifest_path, repository_root=self.repository_root)
            != self.manifest.canonical_bytes()
        ):
            raise ExecutionError("stored experiment manifest does not match the requested plan")

    def publish_inputs(self, run: PlannedRun, build: BundleBuild) -> PurePosixPath:
        parent = self.root / "inputs"
        target = parent / run.run_id
        files = {
            "bundle.json": build.bundle_bytes,
            "request.json": build.request_bytes,
            "prompt-manifest.json": build.manifest_bytes,
        }
        _publish_private_directory(self.repository_root, parent, target, files)
        return _relative_path(self.repository_root, target / "request.json")

    def validate_inputs(self, run: PlannedRun, record: RunRecord) -> None:
        root = self.root / "inputs" / run.run_id
        bundle = _read_private(root / "bundle.json", repository_root=self.repository_root)
        request = _read_private(root / "request.json", repository_root=self.repository_root)
        prompt = _read_private(root / "prompt-manifest.json", repository_root=self.repository_root)
        parsed = parse_manifest_bytes(prompt)
        identity = record.identity
        expected_request_path = _relative_path(self.repository_root, root / "request.json")
        if identity is None or (
            sha256_digest(bundle) != identity.bundle_digest
            or sha256_digest(request) != identity.request_digest
            or parsed.content_digest != record.prompt_manifest_digest
            or parsed.request_id != identity.request_id
            or record.raw_artifacts.request_path != expected_request_path
            or record.raw_artifacts.request_digest != identity.request_digest
        ):
            raise ExecutionError("stored run inputs do not match the terminal record")
        if (
            parsed.run_id != run.run_id
            or parsed.case_id != run.case_id
            or parsed.snapshot != run.snapshot
            or parsed.condition != run.condition
            or parsed.repetition != run.repetition
            or parsed.seed != run.request_seed
        ):
            raise ExecutionError("stored prompt manifest does not match the frozen run plan")
        response_path = record.raw_artifacts.response_path
        response_digest = record.raw_artifacts.response_digest
        if response_path is not None:
            response = self.repository_root.joinpath(*response_path.parts)
            try:
                response.resolve(strict=True).relative_to(self.repository_root)
            except (OSError, ValueError) as exc:
                raise ExecutionError("stored raw response path is unavailable or unsafe") from exc
            if (
                _path_contains_symlink(self.repository_root, response)
                or sha256_digest(_read_private(response, repository_root=self.repository_root))
                != response_digest
            ):
                raise ExecutionError("stored raw response digest does not match the run record")

    def load_prompt_manifest(self, run: PlannedRun) -> PromptManifest:
        """Load one already-published prompt through the private-store boundary."""

        prompt = _read_private(
            self.root / "inputs" / run.run_id / "prompt-manifest.json",
            repository_root=self.repository_root,
        )
        return parse_manifest_bytes(prompt)

    def mark_started(
        self, run: PlannedRun, attempt: int, started_at: datetime, request_digest: str
    ) -> None:
        payload = canonical_json_bytes(
            {
                "schema_version": "1",
                "experiment_id": self.manifest.experiment_id,
                "experiment_content_digest": cast(str, self.manifest.content_digest),
                "run_id": run.run_id,
                "attempt": attempt,
                "request_digest": request_digest,
                "started_at": _iso_string(started_at),
            }
        )
        path = self._attempt_root(run) / f"started-{attempt}.json"
        _write_once(self.repository_root, path, payload)

    def write_attempt(self, run: PlannedRun, record: RunRecord) -> None:
        path = self._attempt_root(run) / f"attempt-{record.attempt}.json"
        _write_once(self.repository_root, path, record.canonical_bytes())

    def write_attempt_journal(
        self, run: PlannedRun, record: RunRecord, outcome: AdapterOutcome
    ) -> AttemptMetadata:
        """Atomically publish sanitized accounting metadata with a recoverable record."""

        identity = record.identity
        if identity is None or record.content_digest is None:
            raise ExecutionError("attempt journal requires a current run record")
        metadata = build_attempt_metadata(
            experiment_id=self.manifest.experiment_id,
            experiment_content_digest=cast(str, self.manifest.content_digest),
            run_id=run.run_id,
            attempt=record.attempt,
            request_digest=identity.request_digest,
            provider=outcome.provider or "unreported",
            model=self.manifest.reviewer_config.model,
            provider_request_id=record.provider_request_id,
            started_at=record.started_at,
            ended_at=record.ended_at,
            monotonic_latency_ms=record.monotonic_latency_ms,
            response_digest=outcome.raw_trace.stdout_digest,
            usage=record.usage,
            provider_reported_cost_usd=(
                record.cost.total if record.price_table_version is None else None
            ),
            run_record_digest=record.content_digest,
        )
        parent = self.root / "attempt-metadata" / run.run_id
        target = parent / f"attempt-{record.attempt}"
        _publish_private_directory(
            self.repository_root,
            parent,
            target,
            {
                "metadata.json": metadata.canonical_bytes(),
                "run-record.json": record.canonical_bytes(),
            },
        )
        return metadata

    def publish_terminal(self, run: PlannedRun, record: RunRecord) -> None:
        path = self.root / "records" / f"{run.run_id}.json"
        _write_once(self.repository_root, path, record.canonical_bytes())

    def load_terminal(self, run: PlannedRun) -> RunRecord | None:
        path = self.root / "records" / f"{run.run_id}.json"
        if not path.exists() and not path.is_symlink():
            return None
        return _load_run_record(path, self.repository_root)

    def load_attempts(self, run: PlannedRun) -> tuple[RunRecord, ...]:
        root = self._attempt_root(run)
        if not root.exists() and not root.is_symlink():
            return ()
        if root.is_symlink() or not root.is_dir():
            raise ExecutionError("experiment attempt store contains unsafe prior state")
        records: list[RunRecord] = []
        attempt = 1
        while True:
            started = root / f"started-{attempt}.json"
            terminal = root / f"attempt-{attempt}.json"
            if not started.exists() and not terminal.exists():
                break
            if started.is_symlink() or not started.is_file():
                raise ExecutionError("experiment attempt journal is invalid")
            started_request_digest, started_at = _validate_started(
                _read_private(started, repository_root=self.repository_root),
                self.manifest,
                run,
                attempt,
            )
            journal = self._load_attempt_journal(run, attempt)
            if not terminal.exists():
                if journal is None:
                    raise ExecutionError(
                        "an interrupted reviewer attempt has uncertain provider state; "
                        "create a new experiment or resolve it manually"
                    )
                _, record = journal
            else:
                record = _load_run_record(terminal, self.repository_root)
                if journal is not None and journal[1].canonical_bytes() != record.canonical_bytes():
                    raise ExecutionError("experiment attempt metadata conflicts with its result")
            expected_history = tuple((prior.attempt, prior.status) for prior in records)
            actual_history = tuple(
                (event.attempt, event.classification) for event in record.retry_history
            )
            if (
                record.attempt != attempt
                or record.identity is None
                or record.identity.request_digest != started_request_digest
                or record.started_at != started_at
                or actual_history != expected_history
            ):
                raise ExecutionError("experiment attempt journal chain is invalid")
            records.append(record)
            attempt += 1
        unexpected = [
            entry
            for entry in root.iterdir()
            if entry.name
            not in {
                *(f"started-{index}.json" for index in range(1, attempt)),
                *(f"attempt-{index}.json" for index in range(1, attempt)),
            }
        ]
        if unexpected:
            raise ExecutionError("experiment attempt journal contains unexpected state")
        return tuple(records)

    def load_attempt_metadata(self, run: PlannedRun) -> tuple[AttemptMetadata, ...]:
        """Load one run's contiguous append-only metadata suffix."""

        root = self.root / "attempt-metadata" / run.run_id
        if not root.exists() and not root.is_symlink():
            return ()
        if root.is_symlink() or not root.is_dir():
            raise ExecutionError("experiment attempt metadata store is unsafe")
        names = {entry.name for entry in root.iterdir()}
        attempt_numbers: list[int] = []
        for name in names:
            prefix = "attempt-"
            suffix = name.removeprefix(prefix)
            if (
                not name.startswith(prefix)
                or not suffix.isdigit()
                or suffix.startswith("0")
                or int(suffix) < 1
            ):
                raise ExecutionError(
                    "experiment attempt metadata journal contains unexpected state"
                )
            attempt_numbers.append(int(suffix))
        attempt_numbers.sort()
        if attempt_numbers and attempt_numbers != list(
            range(attempt_numbers[0], attempt_numbers[-1] + 1)
        ):
            raise ExecutionError("experiment attempt metadata journal contains unexpected state")
        records: list[AttemptMetadata] = []
        for attempt in attempt_numbers:
            loaded = self._load_attempt_journal(run, attempt)
            if loaded is None:  # pragma: no cover - existence checked immediately above
                raise ExecutionError("experiment attempt metadata journal is invalid")
            records.append(loaded[0])
        return tuple(records)

    def load_all_attempt_metadata(self) -> tuple[AttemptMetadata, ...]:
        """Load metadata in frozen run and attempt order and reject stale run directories."""

        root = self.root / "attempt-metadata"
        if not root.exists() and not root.is_symlink():
            return ()
        if root.is_symlink() or not root.is_dir():
            raise ExecutionError("experiment attempt metadata store is unsafe")
        planned_ids = {run.run_id for run in self.manifest.execution_order}
        if {entry.name for entry in root.iterdir()} - planned_ids:
            raise ExecutionError("experiment attempt metadata contains a stale run identity")
        return tuple(
            metadata
            for run in self.manifest.execution_order
            for metadata in self.load_attempt_metadata(run)
        )

    def _load_attempt_journal(
        self, run: PlannedRun, attempt: int
    ) -> tuple[AttemptMetadata, RunRecord] | None:
        target = self.root / "attempt-metadata" / run.run_id / f"attempt-{attempt}"
        if not target.exists() and not target.is_symlink():
            return None
        if (
            target.is_symlink()
            or not target.is_dir()
            or {entry.name for entry in target.iterdir()} != {"metadata.json", "run-record.json"}
        ):
            raise ExecutionError("experiment attempt metadata journal is invalid")
        try:
            metadata_payload = _read_private(
                target / "metadata.json", repository_root=self.repository_root
            )
            metadata_document = json.loads(metadata_payload)
            if not isinstance(metadata_document, dict):
                raise ValueError
            if canonical_json_bytes(cast(JsonValue, metadata_document)) != metadata_payload:
                raise ValueError
            metadata = AttemptMetadata.from_dict(cast(dict[str, Any], metadata_document))
        except (UnicodeError, json.JSONDecodeError, SchemaError, ValueError) as exc:
            raise ExecutionError("experiment attempt metadata journal is invalid") from exc
        record = _load_run_record(target / "run-record.json", self.repository_root)
        identity = record.identity
        expected_digest = record.content_digest or record.digest_without_self()
        if (
            metadata.experiment_id != self.manifest.experiment_id
            or metadata.experiment_content_digest != self.manifest.content_digest
            or metadata.run_id != run.run_id
            or metadata.attempt != attempt
            or metadata.model != self.manifest.reviewer_config.model
            or record.experiment_id != self.manifest.experiment_id
            or record.run_id != run.run_id
            or record.attempt != attempt
            or identity is None
            or metadata.request_digest != identity.request_digest
            or metadata.provider_request_id != record.provider_request_id
            or metadata.started_at != record.started_at
            or metadata.ended_at != record.ended_at
            or metadata.monotonic_latency_ms != record.monotonic_latency_ms
            or metadata.usage != record.usage
            or metadata.provider_reported_cost_usd
            != (record.cost.total if record.price_table_version is None else None)
            or metadata.run_record_digest != expected_digest
        ):
            raise ExecutionError("experiment attempt metadata does not match its frozen run")
        if (
            record.raw_artifacts.response_digest is not None
            and metadata.response_digest != record.raw_artifacts.response_digest
        ):
            raise ExecutionError("experiment attempt metadata response digest does not match")
        return metadata, record

    def has_any_execution_state(self) -> bool:
        return any((self.root / name).exists() for name in ("attempts", "records", "inputs"))

    def _attempt_root(self, run: PlannedRun) -> Path:
        return self.root / "attempts" / run.run_id


def _validate_attempt_metadata_suffix(
    attempts: Sequence[RunRecord], metadata: Sequence[AttemptMetadata]
) -> None:
    """Allow an absent legacy prefix while requiring all new metadata to be contiguous."""

    if not metadata:
        return
    expected = tuple(range(metadata[0].attempt, attempts[-1].attempt + 1)) if attempts else ()
    if tuple(record.attempt for record in metadata) != expected:
        raise ExecutionError("experiment attempt metadata coverage is incomplete")


def reconcile_experiment(
    manifest: ExperimentManifest, store: ExperimentStore
) -> AttemptReconciliation:
    """Validate journals and promote recoverable terminal work without provider calls."""

    _require_current_manifest(manifest)
    store.verify_manifest()
    all_metadata = store.load_all_attempt_metadata()
    terminal_runs = 0
    recovered = 0
    for planned in manifest.execution_order:
        terminal = store.load_terminal(planned)
        attempts = store.load_attempts(planned)
        metadata = store.load_attempt_metadata(planned)
        _validate_attempt_metadata_suffix(attempts, metadata)
        for record in attempts:
            _validate_record(manifest, planned, record)
            store.validate_inputs(planned, record)
        if terminal is not None:
            if (
                not attempts
                or attempts[-1].canonical_bytes() != terminal.canonical_bytes()
                or not _is_terminal(manifest, terminal)
            ):
                raise ExecutionError("terminal run record does not match its attempt journal")
            terminal_runs += 1
        elif attempts and _is_terminal(manifest, attempts[-1]):
            store.publish_terminal(planned, attempts[-1])
            terminal_runs += 1
            recovered += 1
    return AttemptReconciliation(
        experiment_id=manifest.experiment_id,
        accounted_attempts=len(all_metadata),
        terminal_runs=terminal_runs,
        recovered_terminal_runs=recovered,
    )


def execute_experiment(
    manifest: ExperimentManifest,
    store: ExperimentStore,
    adapter: ReviewAdapter,
    prepare: Callable[[PlannedRun, int], AdapterInvocation],
    *,
    resume: bool,
    allow_holdout: bool = False,
    snapshot: SnapshotName | None = None,
    stop_after_calls: int | None = None,
    source_experiment: ExperimentManifest | None = None,
    source_records: Sequence[RunRecord] = (),
    now: Callable[[], datetime] | None = None,
    reconcile_only: bool = False,
) -> ExecutionSummary:
    """Execute or resume the frozen order without repeating valid terminal calls."""

    _require_current_manifest(manifest)
    if manifest.schema_version == "1.3":
        if source_experiment is None:
            raise ExecutionError("recovery execution requires its bound source state")
        validate_recovery_source(manifest, source_experiment, source_records)
    elif manifest.schema_version == "1.4":
        if source_experiment is None:
            raise ExecutionError("holdout execution requires its bound source state")
        validate_holdout_source(manifest, source_experiment, source_records)
    elif manifest.schema_version == "1.5":
        if source_experiment is None:
            raise ExecutionError("retry recovery execution requires its bound source state")
        validate_retry_recovery_source(manifest, source_experiment, source_records)
    elif source_experiment is not None or source_records:
        raise ExecutionError("source state is valid only for linked execution")
    store.verify_manifest()
    store.load_all_attempt_metadata()
    if stop_after_calls is not None and stop_after_calls < 1:
        raise ExecutionError("controlled interruption call limit must be positive")
    if reconcile_only and not resume:
        raise ExecutionError("reconciliation-only execution requires resume mode")
    if not resume and store.has_any_execution_state():
        raise ExecutionError("experiment already has execution state; use the resume command")
    if allow_holdout and manifest.holdout_access_enabled is False:
        raise ExecutionError("the frozen experiment forbids holdout execution")
    if snapshot is not None and snapshot not in manifest.snapshot_set:
        raise ExecutionError("snapshot checkpoint is not present in the frozen experiment")
    clock = now or (lambda: datetime.now(UTC))
    calls_started = 0
    interrupted = False
    case_roles = {case.case_id: case.role for case in manifest.cases}
    eligible_runs = tuple(
        run
        for run in manifest.execution_order
        if allow_holdout or case_roles[run.case_id] == "development"
    )
    selected_runs = tuple(
        run for run in eligible_runs if snapshot is None or run.snapshot == snapshot
    )
    if reconcile_only:
        reconcile_experiment(manifest, store)
        return _execution_summary(
            manifest,
            store,
            selected_runs,
            snapshot=snapshot,
            calls_started=0,
            interrupted=False,
        )
    selected_ids = {run.run_id for run in selected_runs}
    terminal_records: dict[str, RunRecord] = {}
    attempt_records: dict[str, tuple[RunRecord, ...]] = {}
    initial_invocations: dict[str, AdapterInvocation] = {}
    pair_prompts: dict[str, PromptManifest] = {}

    # Protocol 1.2 validates every prepared pair before crossing the provider
    # boundary. This makes a later malformed pair fail before any experiment call.
    for planned in eligible_runs:
        terminal = store.load_terminal(planned)
        attempts = store.load_attempts(planned)
        metadata = store.load_attempt_metadata(planned)
        _validate_attempt_metadata_suffix(attempts, metadata)
        if terminal is not None and (
            not attempts
            or attempts[-1].canonical_bytes() != terminal.canonical_bytes()
            or not _is_terminal(manifest, terminal)
        ):
            raise ExecutionError("terminal run record does not match its attempt journal")
        for attempt_record in attempts:
            _validate_record(manifest, planned, attempt_record)
            store.validate_inputs(planned, attempt_record)
        if terminal is None and attempts and _is_terminal(manifest, attempts[-1]):
            terminal = attempts[-1]
            store.publish_terminal(planned, terminal)
        if terminal is not None:
            _validate_record(manifest, planned, terminal)
            store.validate_inputs(planned, terminal)
            if planned.run_id not in selected_ids:
                continue
            terminal_records[planned.run_id] = terminal
            if manifest.schema_version in {"1.2", "1.4"}:
                pair_prompts[planned.run_id] = store.load_prompt_manifest(planned)
            continue
        if planned.run_id not in selected_ids:
            if attempts:
                raise ExecutionError(
                    "an unselected snapshot has incomplete execution state; "
                    "resume that checkpoint before selecting another"
                )
            continue
        attempt_records[planned.run_id] = attempts
        if manifest.schema_version in {"1.2", "1.4"}:
            attempt_number = len(attempts) + 1
            invocation = prepare(planned, attempt_number)
            pair_prompts[planned.run_id] = _validate_prepared_invocation(
                manifest, planned, invocation, attempt_number
            )
            initial_invocations[planned.run_id] = invocation

    pair_partners: dict[str, str] = {}
    if manifest.schema_version in {"1.2", "1.4"}:
        pair_partners = _validate_protocol_pairs(selected_runs, pair_prompts, initial_invocations)

    for planned in selected_runs:
        if planned.run_id in terminal_records:
            continue
        attempts = attempt_records[planned.run_id]
        while True:
            attempt_number = len(attempts) + 1
            invocation = (
                initial_invocations.pop(planned.run_id)
                if planned.run_id in initial_invocations
                else prepare(planned, attempt_number)
            )
            prompt = _validate_prepared_invocation(manifest, planned, invocation, attempt_number)
            if manifest.schema_version in {"1.2", "1.4"}:
                _validate_pair_prompts(prompt, pair_prompts[pair_partners[planned.run_id]])
            request_path = store.publish_inputs(planned, invocation.build)
            started_at = clock()
            _require_aware(started_at, field="attempt start time")
            store.mark_started(planned, attempt_number, started_at, invocation.build.request_digest)
            calls_started += 1
            try:
                outcome = adapter.invoke(invocation)
            except AdapterConfigurationError:
                outcome = _configuration_failure()
            except Exception as exc:
                raise ExecutionError(
                    "reviewer invocation ended without a terminal result; "
                    "provider state is uncertain"
                ) from exc
            ended_at = clock()
            _require_aware(ended_at, field="attempt end time")
            record = _record_from_outcome(
                manifest,
                planned,
                prompt,
                invocation,
                outcome,
                request_path=request_path,
                started_at=started_at,
                ended_at=ended_at,
                prior_attempts=attempts,
            )
            store.write_attempt_journal(planned, record, outcome)
            store.validate_inputs(planned, record)
            store.write_attempt(planned, record)
            attempts = (*attempts, record)
            if _is_terminal(manifest, record):
                store.publish_terminal(planned, record)
                break
            if stop_after_calls is not None and calls_started >= stop_after_calls:
                interrupted = True
                break
        if interrupted or (stop_after_calls is not None and calls_started >= stop_after_calls):
            interrupted = True
            break

    return _execution_summary(
        manifest,
        store,
        selected_runs,
        snapshot=snapshot,
        calls_started=calls_started,
        interrupted=interrupted,
    )


def _execution_summary(
    manifest: ExperimentManifest,
    store: ExperimentStore,
    selected_runs: Sequence[PlannedRun],
    *,
    snapshot: SnapshotName | None,
    calls_started: int,
    interrupted: bool,
) -> ExecutionSummary:
    terminal_pairs: list[tuple[PlannedRun, RunRecord]] = []
    for planned in selected_runs:
        terminal_record = store.load_terminal(planned)
        if terminal_record is not None:
            _validate_record(manifest, planned, terminal_record)
            terminal_pairs.append((planned, terminal_record))
    records = tuple(record for _planned, record in terminal_pairs)
    succeeded = sum(record.status == "succeeded" for record in records)
    failed = len(records) - succeeded
    return ExecutionSummary(
        experiment_id=manifest.experiment_id,
        snapshot_filter=snapshot,
        planned_runs=len(selected_runs),
        terminal_runs=len(records),
        succeeded_runs=succeeded,
        failed_runs=failed,
        calls_started=calls_started,
        complete=len(records) == len(selected_runs) and failed == 0,
        interrupted=interrupted,
    )


def load_experiment(path: Path) -> ExperimentManifest:
    """Load a canonical frozen experiment without exposing private document values."""

    try:
        payload = path.read_bytes()
        document = json.loads(payload)
        if canonical_json_bytes(cast(JsonValue, document)) != payload:
            raise ValueError
        if not isinstance(document, dict):
            raise ValueError
        return ExperimentManifest.from_dict(cast(dict[str, Any], document))
    except (OSError, UnicodeError, json.JSONDecodeError, TypeError, ValueError, SchemaError) as exc:
        raise ExecutionError("could not load a canonical frozen experiment") from exc


def _validate_prepared_invocation(
    experiment: ExperimentManifest,
    planned: PlannedRun,
    invocation: AdapterInvocation,
    attempt: int,
) -> Any:
    prompt = parse_manifest_bytes(invocation.build.manifest_bytes)
    if experiment.required_bundle_schema_version is not None and (
        prompt.schema_version != "1.3"
        or prompt.bundle_schema_version != experiment.required_bundle_schema_version
    ):
        raise ExecutionError("prepared reviewer invocation violates the frozen bundle contract")
    if prompt.schema_version == "1.3":
        try:
            binding = request_binding(invocation.build.request_bytes)
        except LeakageError as exc:
            raise ExecutionError(
                "prepared reviewer invocation has an invalid bundle identity"
            ) from exc
        if (
            prompt.bundle_schema_version != "2"
            or binding.request_identity != prompt.request_identity
            or binding.bundle_digest != prompt.bundle_digest
        ):
            raise ExecutionError("prepared reviewer invocation has an invalid bundle identity")
    expected_profile = (
        experiment.baseline_profile
        if planned.condition == "baseline"
        else experiment.candidate_profile
    )
    settings = experiment.reviewer_config
    if (
        prompt.schema_version not in {"1.2", "1.3"}
        or not prompt.leakage.passed
        or prompt.run_id != planned.run_id
        or prompt.case_id != planned.case_id
        or prompt.snapshot != planned.snapshot
        or prompt.condition != planned.condition
        or prompt.repetition != planned.repetition
        or prompt.seed != planned.request_seed
        or prompt.profile_template.version != expected_profile.version
        or prompt.profile_template.digest != expected_profile.digest
        or (
            experiment.prompt_template is not None
            and (
                prompt.prompt_template.version != experiment.prompt_template.version
                or prompt.prompt_template.digest != experiment.prompt_template.digest
            )
        )
        or invocation.profile.version != expected_profile.version
        or invocation.profile.digest != expected_profile.digest
        or invocation.metadata.run_id != planned.run_id
        or invocation.metadata.experiment_id != experiment.experiment_id
        or invocation.metadata.condition != planned.condition
        or invocation.metadata.repetition != planned.repetition
        or invocation.metadata.attempt != attempt
        or invocation.timeout_seconds != settings.timeout_seconds
        or invocation.output_schema_version != settings.output_schema_version
        or invocation.reviewer_settings != _reviewer_settings(settings)
        or invocation.capabilities != experiment.adapter_capabilities
    ):
        raise ExecutionError("prepared reviewer invocation does not match the frozen plan")
    return prompt


def _validate_protocol_pairs(
    runs: Sequence[PlannedRun],
    prompts: Mapping[str, PromptManifest],
    invocations: Mapping[str, AdapterInvocation],
) -> dict[str, str]:
    grouped: dict[tuple[str, SnapshotName, int], list[PlannedRun]] = {}
    for run in runs:
        grouped.setdefault((run.case_id, run.snapshot, run.repetition), []).append(run)
    partners: dict[str, str] = {}
    for pair in grouped.values():
        if len(pair) != 2 or {run.condition for run in pair} != {"baseline", "candidate"}:
            raise ExecutionError("frozen experiment does not contain complete reviewer pairs")
        baseline = next(run for run in pair if run.condition == "baseline")
        candidate = next(run for run in pair if run.condition == "candidate")
        baseline_prompt = prompts[baseline.run_id]
        candidate_prompt = prompts[candidate.run_id]
        _validate_pair_prompts(baseline_prompt, candidate_prompt)
        if baseline.run_id in invocations and candidate.run_id in invocations:
            try:
                ensure_paired_invocations(
                    invocations[baseline.run_id], invocations[candidate.run_id]
                )
            except AdapterConfigurationError as exc:
                raise ExecutionError(
                    "prepared reviewer pair does not preserve frozen invariants"
                ) from exc
        partners[baseline.run_id] = candidate.run_id
        partners[candidate.run_id] = baseline.run_id
    return partners


def _validate_pair_prompts(left: PromptManifest, right: PromptManifest) -> None:
    if {left.condition, right.condition} != {"baseline", "candidate"} or _pair_prompt_fingerprint(
        left
    ) != _pair_prompt_fingerprint(right):
        raise ExecutionError("prepared reviewer pair does not preserve frozen invariants")


def _pair_prompt_fingerprint(prompt: PromptManifest) -> tuple[object, ...]:
    return (
        prompt.bundle_digest,
        prompt.bundle_config,
        prompt.case_id,
        prompt.request_identity,
        prompt.context_entry_digest,
        prompt.prompt_template.digest,
        prompt.repetition,
        prompt.seed,
        prompt.snapshot,
        prompt.source_commit,
        prompt.worktree_digest,
    )


def _record_from_outcome(
    experiment: ExperimentManifest,
    planned: PlannedRun,
    prompt: Any,
    invocation: AdapterInvocation,
    outcome: AdapterOutcome,
    *,
    request_path: PurePosixPath,
    started_at: datetime,
    ended_at: datetime,
    prior_attempts: Sequence[RunRecord],
) -> RunRecord:
    output = outcome.reviewer_output
    status = "succeeded" if outcome.succeeded else cast(str, outcome.failure)
    response_path = outcome.raw_trace.stdout_path
    response_digest = outcome.raw_trace.stdout_digest if response_path is not None else None
    reviewer_config_digest = canonical_digest(_reviewer_dict(experiment.reviewer_config))
    output_digest = canonical_digest(output.to_dict()) if output is not None else None
    identity: dict[str, JsonValue] = {
        "experiment_content_digest": cast(str, experiment.content_digest),
        "source_commit": prompt.source_commit,
        "worktree_digest": prompt.worktree_digest,
        "bundle_digest": prompt.bundle_digest,
        "context_entry_digest": prompt.context_entry_digest,
        "request_id": prompt.request_id,
        "request_digest": prompt.request_digest,
        "profile_digest": prompt.profile_template.digest,
        "reviewer_config_digest": reviewer_config_digest,
        "adapter_capabilities_digest": invocation.capabilities.content_digest,
        "reviewer_output_digest": output_digest,
    }
    document: dict[str, JsonValue] = {
        "schema_version": "1.1",
        "run_id": planned.run_id,
        "experiment_id": experiment.experiment_id,
        "prompt_manifest_digest": invocation.build.manifest_digest,
        "output_schema_version": experiment.reviewer_config.output_schema_version,
        "attempt": invocation.metadata.attempt,
        "status": status,
        "started_at": _iso_string(started_at),
        "ended_at": _iso_string(ended_at),
        "monotonic_latency_ms": outcome.monotonic_latency_ms,
        "provider_request_id": outcome.provider_request_id,
        "seed": planned.request_seed,
        "reviewer_output": output.to_dict() if output is not None else None,
        "validation_errors": list(outcome.validation_errors),
        "usage": {
            "input_tokens": outcome.input_tokens,
            "cached_input_tokens": outcome.cached_input_tokens,
            "output_tokens": outcome.output_tokens,
            "reasoning_tokens": outcome.reasoning_tokens,
        },
        "price_table_version": None,
        "cost": {
            "currency": "USD",
            "input": None,
            "output": None,
            "total": outcome.total_cost_usd,
        },
        "subprocess": {
            "exit_status": outcome.exit_status,
            "stderr_classification": outcome.stderr_classification,
        },
        "retry_history": [
            {"attempt": record.attempt, "classification": record.status}
            for record in prior_attempts
        ],
        "raw_artifacts": {
            "request_path": request_path.as_posix(),
            "request_digest": invocation.build.request_digest,
            "response_path": response_path.as_posix() if response_path is not None else None,
            "response_digest": response_digest,
        },
        "identity": identity,
    }
    document["content_digest"] = canonical_digest(document)
    try:
        return RunRecord.from_dict(cast(dict[str, Any], document))
    except SchemaError as exc:  # pragma: no cover - builder/model parity
        raise ExecutionError("generated run record is invalid") from exc


def _validate_record(
    experiment: ExperimentManifest, planned: PlannedRun, record: RunRecord
) -> None:
    expected_profile = (
        experiment.baseline_profile
        if planned.condition == "baseline"
        else experiment.candidate_profile
    )
    frozen_case = next(case for case in experiment.cases if case.case_id == planned.case_id)
    expected_source_commit = (
        frozen_case.vulnerable_snapshot
        if planned.snapshot == "vulnerable"
        else frozen_case.fixed_snapshot
    )
    identity = record.identity
    if (
        record.schema_version != "1.1"
        or record.experiment_id != experiment.experiment_id
        or record.run_id != planned.run_id
        or record.seed != planned.request_seed
        or identity is None
        or identity.experiment_content_digest != experiment.content_digest
        or identity.source_commit != expected_source_commit
        or identity.profile_digest != expected_profile.digest
        or identity.reviewer_config_digest
        != canonical_digest(_reviewer_dict(experiment.reviewer_config))
        or identity.adapter_capabilities_digest
        != cast(AdapterCapabilities, experiment.adapter_capabilities).content_digest
    ):
        raise ExecutionError("stored run record does not match the frozen experiment")


def _is_terminal(experiment: ExperimentManifest, record: RunRecord) -> bool:
    if record.status == "succeeded":
        return True
    if record.status in {"configuration_error", "adapter_error"}:
        return True
    if record.attempt >= experiment.retry_policy.maximum_attempts:
        return True
    if record.status == "invalid_output" and experiment.invalid_output_policy == "fail_run":
        return True
    return record.status not in experiment.retry_policy.retryable_failures


def _configuration_failure() -> AdapterOutcome:
    from preflight_evals.adapter import RawTraceRecord

    empty = sha256_digest(b"")
    return AdapterOutcome(
        reviewer_output=None,
        failure="configuration_error",
        retryable=False,
        exit_status=None,
        stderr_classification="configuration",
        validation_errors=("INVOCATION_CONFIGURATION_INVALID",),
        monotonic_latency_ms=0.0,
        raw_trace=RawTraceRecord(None, empty, None, empty, False),
    )


def _require_current_manifest(manifest: ExperimentManifest) -> None:
    if (
        manifest.schema_version not in {"1.1", "1.2", "1.3", "1.4", "1.5"}
        or not manifest.frozen
        or manifest.content_digest is None
        or manifest.adapter_capabilities is None
    ):
        raise ExecutionError("execution requires a current fully frozen experiment")


def _path_contains_symlink(repository_root: Path, path: Path) -> bool:
    try:
        relative = path.relative_to(repository_root)
    except ValueError:
        return True
    current = repository_root
    for part in relative.parts:
        if part in {"", ".", ".."}:
            return True
        current /= part
        if current.is_symlink():
            return True
    return False


def _validate_freeze_input(definition: ExperimentFreezeInput) -> None:
    if definition.required_bundle_schema_version is not None and (
        definition.required_bundle_schema_version != "2" or definition.prompt_template is None
    ):
        raise ExecutionError("required bundle schema version is unsupported")
    if not definition.cases or len({case.case_id for case in definition.cases}) != len(
        definition.cases
    ):
        raise ExecutionError("experiment cases must be nonempty and unique")
    if any(
        not case.case_id
        or case.role not in {"development", "holdout"}
        or case.vulnerable_input_tokens < 0
        or case.fixed_input_tokens < 0
        or not _is_digest(case.case_contract_digest)
        or not _is_full_sha(case.vulnerable_snapshot)
        or not _is_full_sha(case.fixed_snapshot)
        or case.vulnerable_snapshot == case.fixed_snapshot
        for case in definition.cases
    ):
        raise ExecutionError("experiment case definitions are invalid")
    if (
        not definition.snapshot_set
        or set(definition.snapshot_set) - {"vulnerable", "fixed"}
        or len(set(definition.snapshot_set)) != len(definition.snapshot_set)
        or definition.repetitions < 1
        or definition.randomization_seed < 0
        or definition.invalid_output_policy not in {"fail_run", "retry_then_fail"}
        or not 1 <= definition.retry_policy.maximum_attempts <= 10
        or set(definition.retry_policy.retryable_failures) - _SUPPORTED_RETRYABLE
    ):
        raise ExecutionError("experiment execution policy is invalid")
    if (
        definition.invalid_output_policy == "retry_then_fail"
        and "invalid_output" not in definition.retry_policy.retryable_failures
    ):
        raise ExecutionError("invalid-output retry policy is internally inconsistent")
    protocol_values = (
        definition.prompt_template,
        definition.analysis_plan,
        definition.holdout_access_enabled,
        definition.price_projection,
    )
    if any(value is not None for value in protocol_values) and not all(
        value is not None for value in protocol_values
    ):
        raise ExecutionError("experiment protocol definition must be complete")
    if all(value is None for value in protocol_values):
        return
    projection = cast(PriceProjection, definition.price_projection)
    planned_runs = len(definition.cases) * len(definition.snapshot_set) * 2 * definition.repetitions
    maximum_provider_calls = planned_runs * definition.retry_policy.maximum_attempts
    maximum_input_tokens = maximum_provider_calls * definition.reviewer_config.input_token_limit
    maximum_output_tokens = maximum_provider_calls * definition.reviewer_config.output_token_limit
    expected_cost = (
        (
            maximum_input_tokens * projection.input_usd_per_million_tokens
            + maximum_output_tokens * projection.output_usd_per_million_tokens
        )
        / 1_000_000
        * (1 + projection.contingency_rate)
    )
    if (
        definition.holdout_access_enabled is not False
        or projection.currency != "USD"
        or not projection.price_table_version
        or projection.input_usd_per_million_tokens < 0
        or projection.output_usd_per_million_tokens < 0
        or projection.maximum_input_tokens != maximum_input_tokens
        or projection.maximum_output_tokens != maximum_output_tokens
        or not 0 <= projection.contingency_rate <= 1
        or abs(projection.projected_cost_usd - expected_cost) > 1e-9
    ):
        raise ExecutionError("experiment protocol price projection is invalid")


def _case_input(value: object) -> CaseFreezeInput:
    data = _object_mapping(value)
    if set(data) != {
        "case_id",
        "role",
        "case_contract_digest",
        "vulnerable_snapshot",
        "fixed_snapshot",
        "token_estimates",
    }:
        raise ValueError
    estimates = _object_mapping(data["token_estimates"])
    if set(estimates) != {"vulnerable", "fixed"}:
        raise ValueError
    return CaseFreezeInput(
        case_id=_string(data["case_id"]),
        role=_string(data["role"]),
        vulnerable_input_tokens=_integer(estimates["vulnerable"]),
        fixed_input_tokens=_integer(estimates["fixed"]),
        case_contract_digest=_string(data["case_contract_digest"]),
        vulnerable_snapshot=_string(data["vulnerable_snapshot"]),
        fixed_snapshot=_string(data["fixed_snapshot"]),
    )


def _profile_input(data: Mapping[str, object]) -> ProfileReference:
    if set(data) != {"version", "digest"}:
        raise ValueError
    return ProfileReference(version=_string(data["version"]), digest=_string(data["digest"]))


def _price_projection_input(data: Mapping[str, object]) -> PriceProjection:
    if set(data) != {
        "price_table_version",
        "currency",
        "input_usd_per_million_tokens",
        "output_usd_per_million_tokens",
        "maximum_input_tokens",
        "maximum_output_tokens",
        "contingency_rate",
        "projected_cost_usd",
    }:
        raise ValueError
    return PriceProjection(
        price_table_version=_string(data["price_table_version"]),
        currency=_string(data["currency"]),
        input_usd_per_million_tokens=_number(data["input_usd_per_million_tokens"]),
        output_usd_per_million_tokens=_number(data["output_usd_per_million_tokens"]),
        maximum_input_tokens=_integer(data["maximum_input_tokens"]),
        maximum_output_tokens=_integer(data["maximum_output_tokens"]),
        contingency_rate=_number(data["contingency_rate"]),
        projected_cost_usd=_number(data["projected_cost_usd"]),
    )


def _reviewer_input(data: Mapping[str, object]) -> FrozenReviewerConfiguration:
    expected = {
        "model",
        "tool_policy",
        "input_token_limit",
        "output_token_limit",
        "output_schema_version",
        "adapter_version",
        "timeout_seconds",
        "temperature",
    }
    if set(data) != expected:
        raise ValueError
    return FrozenReviewerConfiguration(
        model=_string(data["model"]),
        tool_policy=_string(data["tool_policy"]),
        input_token_limit=_integer(data["input_token_limit"]),
        output_token_limit=_integer(data["output_token_limit"]),
        output_schema_version=_string(data["output_schema_version"]),
        adapter_version=_string(data["adapter_version"]),
        timeout_seconds=_number(data["timeout_seconds"]),
        temperature=_number(data["temperature"]),
    )


def _retry_input(data: Mapping[str, object]) -> RetryPolicy:
    if set(data) != {"maximum_attempts", "retryable_failures"}:
        raise ValueError
    return RetryPolicy(
        maximum_attempts=_integer(data["maximum_attempts"]),
        retryable_failures=_string_sequence(data["retryable_failures"]),
    )


def _object_mapping(value: object) -> Mapping[str, object]:
    if not isinstance(value, dict) or not all(isinstance(key, str) for key in value):
        raise ValueError
    return cast(dict[str, object], value)


def _object_sequence(value: object) -> Sequence[object]:
    if not isinstance(value, list):
        raise ValueError
    return value


def _string_sequence(value: object) -> tuple[str, ...]:
    if not isinstance(value, list) or any(not isinstance(item, str) for item in value):
        raise ValueError
    return tuple(cast(list[str], value))


def _string(value: object) -> str:
    if not isinstance(value, str) or not value:
        raise ValueError
    return value


def _integer(value: object) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise ValueError
    return value


def _number(value: object) -> float:
    if isinstance(value, bool) or not isinstance(value, int | float):
        raise ValueError
    return float(value)


def _boolean(value: object) -> bool:
    if not isinstance(value, bool):
        raise ValueError
    return value


def _case_definition_dict(case: CaseFreezeInput) -> dict[str, JsonValue]:
    return {
        "case_id": case.case_id,
        "role": case.role,
        "case_contract_digest": case.case_contract_digest,
        "vulnerable_snapshot": case.vulnerable_snapshot,
        "fixed_snapshot": case.fixed_snapshot,
        "token_estimates": {
            "vulnerable": case.vulnerable_input_tokens,
            "fixed": case.fixed_input_tokens,
        },
    }


def _manifest_case_dict(case: CaseFreezeInput) -> dict[str, JsonValue]:
    return {
        "case_id": case.case_id,
        "role": case.role,
        "case_contract_digest": case.case_contract_digest,
        "vulnerable_snapshot": case.vulnerable_snapshot,
        "fixed_snapshot": case.fixed_snapshot,
    }


def _planned_run_dict(run: PlannedRun) -> dict[str, JsonValue]:
    return {
        "run_id": run.run_id,
        "case_id": run.case_id,
        "snapshot": run.snapshot,
        "condition": run.condition,
        "repetition": run.repetition,
        "request_seed": cast(int, run.request_seed),
        "estimated_input_tokens": cast(int, run.estimated_input_tokens),
    }


def _is_digest(value: str) -> bool:
    prefix, separator, hexadecimal = value.partition(":")
    return (
        prefix == "sha256"
        and separator == ":"
        and len(hexadecimal) == 64
        and all(character in "0123456789abcdef" for character in hexadecimal)
    )


def _is_full_sha(value: str) -> bool:
    return len(value) == 40 and all(character in "0123456789abcdef" for character in value)


def _profile_dict(profile: ProfileReference) -> dict[str, JsonValue]:
    return {"version": profile.version, "digest": profile.digest}


def _price_projection_dict(projection: PriceProjection) -> dict[str, JsonValue]:
    return {
        "price_table_version": projection.price_table_version,
        "currency": projection.currency,
        "input_usd_per_million_tokens": projection.input_usd_per_million_tokens,
        "output_usd_per_million_tokens": projection.output_usd_per_million_tokens,
        "maximum_input_tokens": projection.maximum_input_tokens,
        "maximum_output_tokens": projection.maximum_output_tokens,
        "contingency_rate": projection.contingency_rate,
        "projected_cost_usd": projection.projected_cost_usd,
    }


def _protocol_definition_dict(definition: ExperimentFreezeInput) -> dict[str, JsonValue]:
    document: dict[str, JsonValue] = {
        "prompt_template": _profile_dict(cast(ProfileReference, definition.prompt_template)),
        "analysis_plan": _profile_dict(cast(ProfileReference, definition.analysis_plan)),
        "holdout_access_enabled": cast(bool, definition.holdout_access_enabled),
        "price_projection": _price_projection_dict(
            cast(PriceProjection, definition.price_projection)
        ),
    }

    if definition.required_bundle_schema_version is not None:
        document["required_bundle_schema_version"] = definition.required_bundle_schema_version
    return document


def _reviewer_dict(config: FrozenReviewerConfiguration) -> dict[str, JsonValue]:
    return {
        "model": config.model,
        "tool_policy": config.tool_policy,
        "input_token_limit": config.input_token_limit,
        "output_token_limit": config.output_token_limit,
        "output_schema_version": config.output_schema_version,
        "adapter_version": config.adapter_version,
        "timeout_seconds": config.timeout_seconds,
        "temperature": config.temperature,
    }


def _reviewer_settings(config: FrozenReviewerConfiguration) -> ReviewerSettings:
    return ReviewerSettings(
        model=config.model,
        tool_policy=config.tool_policy,
        input_token_limit=config.input_token_limit,
        output_token_limit=config.output_token_limit,
        temperature=config.temperature,
        adapter_version=config.adapter_version,
    )


def _retry_dict(policy: RetryPolicy) -> dict[str, JsonValue]:
    return {
        "maximum_attempts": policy.maximum_attempts,
        "retryable_failures": list(policy.retryable_failures),
    }


def _stable_bytes(seed: int, *parts: object) -> bytes:
    return hashlib.sha256("\0".join((str(seed), *map(str, parts))).encode("utf-8")).digest()


def _unique_seed(seed: int, tuple_key: tuple[object, ...], *, used_seeds: set[int]) -> int:
    counter = 0
    while True:
        value = int.from_bytes(_stable_bytes(seed, "request", *tuple_key, counter)[:8], "big")
        if value not in used_seeds:
            used_seeds.add(value)
            return value
        counter += 1  # pragma: no cover - 64-bit synthetic collision fallback


def _require_aware(value: datetime, *, field: str) -> None:
    if value.tzinfo is None or value.utcoffset() is None:
        raise ExecutionError(f"experiment {field} must include a timezone")


def _iso_string(value: datetime) -> str:
    return value.astimezone(UTC).isoformat().replace("+00:00", "Z")


def _ensure_private_directory(repository_root: Path, path: Path) -> None:
    try:
        relative = path.relative_to(repository_root)
    except ValueError as exc:
        raise ExecutionError("experiment artifact path escapes the repository") from exc
    current = repository_root
    for component in relative.parts:
        current = current / component
        if current.is_symlink():
            raise ExecutionError("experiment artifact path contains a symlink")
        if current.exists() and not current.is_dir():
            raise ExecutionError("experiment artifact path contains a non-directory")
        current.mkdir(mode=0o700, exist_ok=True)
        current.chmod(0o700)


def _publish_private_directory(
    repository_root: Path,
    parent: Path,
    target: Path,
    files: Mapping[str, bytes],
) -> None:
    _ensure_private_directory(repository_root, parent)
    if target.exists() or target.is_symlink():
        if target.is_symlink() or not target.is_dir():
            raise ExecutionError("experiment input artifact target is unsafe")
        for name, payload in files.items():
            if _read_private(target / name, repository_root=repository_root) != payload:
                raise ExecutionError("experiment input artifacts changed after first use")
        if {entry.name for entry in target.iterdir()} != set(files):
            raise ExecutionError("experiment input artifacts contain unexpected state")
        return
    staging: Path | None = None
    try:
        staging = Path(tempfile.mkdtemp(prefix=f".{target.name}.tmp-", dir=parent))
        staging.chmod(0o700)
        for name, payload in files.items():
            _write_exclusive(staging / name, payload)
        _fsync_directory(staging)
        staging.rename(target)
        staging = None
        _fsync_directory(parent)
    except OSError as exc:
        raise ExecutionError("could not publish experiment inputs safely") from exc
    finally:
        if staging is not None:
            shutil.rmtree(staging, ignore_errors=True)


def _write_once(repository_root: Path, path: Path, payload: bytes) -> None:
    _ensure_private_directory(repository_root, path.parent)
    if path.exists() or path.is_symlink():
        if path.is_symlink() or _read_private(path, repository_root=repository_root) != payload:
            raise ExecutionError("immutable experiment artifact already has different content")
        return
    temporary_parent = path.parent.parent / ".tmp"
    _ensure_private_directory(repository_root, temporary_parent)
    descriptor = -1
    temporary: Path | None = None
    try:
        descriptor, temporary_name = tempfile.mkstemp(
            prefix=f".{path.name}.tmp-", dir=temporary_parent
        )
        temporary = Path(temporary_name)
        os.fchmod(descriptor, 0o600)
        stream = os.fdopen(descriptor, "wb")
        descriptor = -1
        with stream:
            stream.write(payload)
            stream.flush()
            os.fsync(stream.fileno())
        try:
            os.link(temporary, path, follow_symlinks=False)
        except FileExistsError:
            if path.is_symlink() or _read_private(path, repository_root=repository_root) != payload:
                raise ExecutionError(
                    "immutable experiment artifact already has different content"
                ) from None
        finally:
            temporary.unlink(missing_ok=True)
            temporary = None
        _fsync_directory(path.parent)
    except ExecutionError:
        raise
    except OSError as exc:
        raise ExecutionError("could not write an immutable experiment artifact") from exc
    finally:
        if descriptor >= 0:
            os.close(descriptor)
        if temporary is not None:
            temporary.unlink(missing_ok=True)


def _write_exclusive(path: Path, payload: bytes) -> None:
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_CLOEXEC", 0)
    flags |= getattr(os, "O_NOFOLLOW", 0)
    descriptor = os.open(path, flags, 0o600)
    try:
        with os.fdopen(descriptor, "wb", closefd=False) as stream:
            stream.write(payload)
            stream.flush()
            os.fsync(stream.fileno())
    finally:
        os.close(descriptor)


def _read_private(path: Path, *, repository_root: Path | None = None) -> bytes:
    if (
        path.is_symlink()
        or not path.is_file()
        or (repository_root is not None and _path_contains_symlink(repository_root, path))
    ):
        raise ExecutionError("experiment artifact is missing or unsafe")
    try:
        return path.read_bytes()
    except OSError as exc:
        raise ExecutionError("could not read an immutable experiment artifact") from exc


def _load_run_record(path: Path, repository_root: Path) -> RunRecord:
    try:
        payload = _read_private(path, repository_root=repository_root)
        document = json.loads(payload)
        if canonical_json_bytes(cast(JsonValue, document)) != payload or not isinstance(
            document, dict
        ):
            raise ValueError
        return RunRecord.from_dict(cast(dict[str, Any], document))
    except (UnicodeError, json.JSONDecodeError, TypeError, ValueError, SchemaError) as exc:
        raise ExecutionError("stored run record is invalid or digest-mismatched") from exc


def _validate_started(
    payload: bytes,
    experiment: ExperimentManifest,
    run: PlannedRun,
    attempt: int,
) -> tuple[str, datetime]:
    try:
        document = json.loads(payload)
        if canonical_json_bytes(cast(JsonValue, document)) != payload or not isinstance(
            document, dict
        ):
            raise ValueError
        if (
            set(document)
            != {
                "schema_version",
                "experiment_id",
                "experiment_content_digest",
                "run_id",
                "attempt",
                "request_digest",
                "started_at",
            }
            or document["schema_version"] != "1"
            or document["experiment_id"] != experiment.experiment_id
            or document["experiment_content_digest"] != experiment.content_digest
            or document["run_id"] != run.run_id
            or document["attempt"] != attempt
            or not isinstance(document["request_digest"], str)
            or not isinstance(document["started_at"], str)
        ):
            raise ValueError
        started_at = datetime.fromisoformat(document["started_at"].replace("Z", "+00:00"))
        _require_aware(started_at, field="attempt journal start time")
        return document["request_digest"], started_at
    except (UnicodeError, json.JSONDecodeError, TypeError, ValueError, KeyError) as exc:
        raise ExecutionError("experiment attempt journal is invalid") from exc


def _relative_path(repository_root: Path, path: Path) -> PurePosixPath:
    try:
        return PurePosixPath(path.relative_to(repository_root).as_posix())
    except ValueError as exc:  # pragma: no cover - store construction invariant
        raise ExecutionError("experiment artifact path escapes the repository") from exc


def _fsync_directory(path: Path) -> None:
    descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_CLOEXEC", 0))
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)
