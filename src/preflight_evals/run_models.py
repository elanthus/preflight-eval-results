"""Typed immutable run and experiment contract models."""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from datetime import datetime
from pathlib import PurePosixPath
from typing import Any, cast

from preflight_evals.adapter import AdapterCapabilities, AdapterConfigurationError
from preflight_evals.canonical import JsonValue, canonical_digest, canonical_json_bytes
from preflight_evals.errors import SchemaError
from preflight_evals.model_types import (
    Condition,
    SnapshotName,
    iso_datetime,
    object_list,
    object_mapping,
    repository_path,
)
from preflight_evals.reviewer_models import ReviewerOutput
from preflight_evals.schema import SCHEMA_VERSION, validate_contract


@dataclass(frozen=True, slots=True)
class TokenUsage:
    input_tokens: int | None
    cached_input_tokens: int | None
    output_tokens: int | None
    reasoning_tokens: int | None


@dataclass(frozen=True, slots=True)
class Cost:
    currency: str
    input: float | None
    output: float | None
    total: float | None


@dataclass(frozen=True, slots=True)
class SubprocessResult:
    exit_status: int | None
    stderr_classification: str


@dataclass(frozen=True, slots=True)
class RetryEvent:
    attempt: int
    classification: str


@dataclass(frozen=True, slots=True)
class RawArtifacts:
    request_path: PurePosixPath | None
    request_digest: str | None
    response_path: PurePosixPath | None
    response_digest: str | None


@dataclass(frozen=True, slots=True)
class ExecutionIdentity:
    experiment_content_digest: str
    source_commit: str
    worktree_digest: str
    bundle_digest: str
    context_entry_digest: str
    request_id: str
    request_digest: str
    profile_digest: str
    reviewer_config_digest: str
    adapter_capabilities_digest: str
    reviewer_output_digest: str | None


@dataclass(frozen=True, slots=True)
class RunRecord:
    schema_version: str
    run_id: str
    experiment_id: str
    prompt_manifest_digest: str
    output_schema_version: str
    attempt: int
    status: str
    started_at: datetime
    ended_at: datetime
    monotonic_latency_ms: float
    provider_request_id: str | None
    seed: int | None
    reviewer_output: ReviewerOutput | None
    validation_errors: tuple[str, ...]
    usage: TokenUsage
    price_table_version: str | None
    cost: Cost
    subprocess: SubprocessResult
    retry_history: tuple[RetryEvent, ...]
    raw_artifacts: RawArtifacts
    identity: ExecutionIdentity | None
    content_digest: str | None

    @classmethod
    def from_dict(cls, document: Mapping[str, Any]) -> RunRecord:
        data = validate_contract("run-record", dict(document))
        usage = object_mapping(data["usage"])
        cost = object_mapping(data["cost"])
        subprocess = object_mapping(data["subprocess"])
        artifacts = object_mapping(data["raw_artifacts"])
        raw_output = data["reviewer_output"]
        model = cls(
            schema_version=cast(str, data["schema_version"]),
            run_id=cast(str, data["run_id"]),
            experiment_id=cast(str, data["experiment_id"]),
            prompt_manifest_digest=cast(str, data["prompt_manifest_digest"]),
            output_schema_version=cast(str, data["output_schema_version"]),
            attempt=cast(int, data["attempt"]),
            status=cast(str, data["status"]),
            started_at=iso_datetime(cast(str, data["started_at"]), field="started_at"),
            ended_at=iso_datetime(cast(str, data["ended_at"]), field="ended_at"),
            monotonic_latency_ms=float(cast(int | float, data["monotonic_latency_ms"])),
            provider_request_id=cast(str | None, data["provider_request_id"]),
            seed=cast(int | None, data["seed"]),
            reviewer_output=(
                ReviewerOutput.from_dict(object_mapping(raw_output))
                if raw_output is not None
                else None
            ),
            validation_errors=tuple(
                cast(str, item) for item in object_list(data["validation_errors"])
            ),
            usage=TokenUsage(
                input_tokens=cast(int | None, usage["input_tokens"]),
                cached_input_tokens=cast(int | None, usage["cached_input_tokens"]),
                output_tokens=cast(int | None, usage["output_tokens"]),
                reasoning_tokens=cast(int | None, usage["reasoning_tokens"]),
            ),
            price_table_version=cast(str | None, data["price_table_version"]),
            cost=Cost(
                currency=cast(str, cost["currency"]),
                input=_optional_float(cost["input"]),
                output=_optional_float(cost["output"]),
                total=_optional_float(cost["total"]),
            ),
            subprocess=SubprocessResult(
                exit_status=cast(int | None, subprocess["exit_status"]),
                stderr_classification=cast(str, subprocess["stderr_classification"]),
            ),
            retry_history=tuple(
                _retry_event(object_mapping(item)) for item in object_list(data["retry_history"])
            ),
            raw_artifacts=RawArtifacts(
                request_path=_optional_path(
                    artifacts["request_path"], field="raw_artifacts.request_path"
                ),
                request_digest=cast(str | None, artifacts["request_digest"]),
                response_path=_optional_path(
                    artifacts["response_path"], field="raw_artifacts.response_path"
                ),
                response_digest=cast(str | None, artifacts["response_digest"]),
            ),
            identity=(
                _execution_identity(object_mapping(data["identity"]))
                if data.get("identity") is not None
                else None
            ),
            content_digest=cast(str | None, data.get("content_digest")),
        )
        model._validate_relationships()
        return model

    def to_dict(self) -> dict[str, JsonValue]:
        document: dict[str, JsonValue] = {
            "schema_version": self.schema_version,
            "run_id": self.run_id,
            "experiment_id": self.experiment_id,
            "prompt_manifest_digest": self.prompt_manifest_digest,
            "output_schema_version": self.output_schema_version,
            "attempt": self.attempt,
            "status": self.status,
            "started_at": _iso_string(self.started_at),
            "ended_at": _iso_string(self.ended_at),
            "monotonic_latency_ms": self.monotonic_latency_ms,
            "provider_request_id": self.provider_request_id,
            "seed": self.seed,
            "reviewer_output": (
                self.reviewer_output.to_dict() if self.reviewer_output is not None else None
            ),
            "validation_errors": list(self.validation_errors),
            "usage": {
                "input_tokens": self.usage.input_tokens,
                "cached_input_tokens": self.usage.cached_input_tokens,
                "output_tokens": self.usage.output_tokens,
                "reasoning_tokens": self.usage.reasoning_tokens,
            },
            "price_table_version": self.price_table_version,
            "cost": {
                "currency": self.cost.currency,
                "input": self.cost.input,
                "output": self.cost.output,
                "total": self.cost.total,
            },
            "subprocess": {
                "exit_status": self.subprocess.exit_status,
                "stderr_classification": self.subprocess.stderr_classification,
            },
            "retry_history": [
                {"attempt": event.attempt, "classification": event.classification}
                for event in self.retry_history
            ],
            "raw_artifacts": {
                "request_path": (
                    self.raw_artifacts.request_path.as_posix()
                    if self.raw_artifacts.request_path is not None
                    else None
                ),
                "request_digest": self.raw_artifacts.request_digest,
                "response_path": (
                    self.raw_artifacts.response_path.as_posix()
                    if self.raw_artifacts.response_path is not None
                    else None
                ),
                "response_digest": self.raw_artifacts.response_digest,
            },
        }
        if self.identity is not None:
            document["identity"] = _execution_identity_dict(self.identity)
        if self.content_digest is not None:
            document["content_digest"] = self.content_digest
        return document

    def canonical_bytes(self) -> bytes:
        return canonical_json_bytes(self.to_dict())

    def digest_without_self(self) -> str:
        content = self.to_dict()
        content.pop("content_digest", None)
        return canonical_digest(content)

    def _validate_relationships(self) -> None:
        if self.ended_at < self.started_at:
            raise SchemaError("run record ended_at cannot precede started_at")
        if self.output_schema_version != SCHEMA_VERSION:
            raise SchemaError("run record output schema version is unsupported")
        if (
            self.reviewer_output is not None
            and self.reviewer_output.schema_version != self.output_schema_version
        ):
            raise SchemaError("run record output schema versions must agree")
        if self.status == "succeeded":
            if self.subprocess.exit_status != 0 or self.subprocess.stderr_classification != "none":
                raise SchemaError("successful run record requires a clean subprocess result")
        elif self.reviewer_output is not None:
            raise SchemaError("failed run record cannot contain reviewer output")
        if (
            self.usage.input_tokens is not None
            and self.usage.cached_input_tokens is not None
            and self.usage.cached_input_tokens > self.usage.input_tokens
        ):
            raise SchemaError("run record cached input tokens cannot exceed input tokens")
        if (
            self.cost.input is not None
            and self.cost.output is not None
            and self.cost.total is not None
            and abs((self.cost.input + self.cost.output) - self.cost.total) > 1e-9
        ):
            raise SchemaError("run record total cost must equal input plus output cost")
        attempts = [event.attempt for event in self.retry_history]
        if attempts != list(range(1, self.attempt)):
            raise SchemaError("run record retry history must cover each unique prior attempt")
        artifact_pairs = (
            (self.raw_artifacts.request_path, self.raw_artifacts.request_digest),
            (self.raw_artifacts.response_path, self.raw_artifacts.response_digest),
        )
        if any((path is None) != (digest is None) for path, digest in artifact_pairs):
            raise SchemaError("run record artifact paths and digests must appear together")
        if self.schema_version == "1.0":
            if self.identity is not None or self.content_digest is not None:
                raise SchemaError("legacy run records cannot claim execution identity metadata")
        else:
            if self.identity is None or self.content_digest is None:
                raise SchemaError("current run records require execution identity metadata")
            if self.content_digest != self.digest_without_self():
                raise SchemaError("run record content digest does not match its content")
            output_digest = (
                canonical_digest(self.reviewer_output.to_dict())
                if self.reviewer_output is not None
                else None
            )
            if self.identity.reviewer_output_digest != output_digest:
                raise SchemaError("run record reviewer output digest does not match its output")


@dataclass(frozen=True, slots=True)
class ExperimentCase:
    case_id: str
    role: str
    case_contract_digest: str | None = None
    vulnerable_snapshot: str | None = None
    fixed_snapshot: str | None = None


@dataclass(frozen=True, slots=True)
class ProfileReference:
    version: str
    digest: str


@dataclass(frozen=True, slots=True)
class FrozenReviewerConfiguration:
    model: str
    tool_policy: str
    input_token_limit: int
    output_token_limit: int
    output_schema_version: str
    adapter_version: str
    timeout_seconds: float
    temperature: float


@dataclass(frozen=True, slots=True)
class RetryPolicy:
    maximum_attempts: int
    retryable_failures: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class PriceProjection:
    price_table_version: str
    currency: str
    input_usd_per_million_tokens: float
    output_usd_per_million_tokens: float
    maximum_input_tokens: int
    maximum_output_tokens: int
    contingency_rate: float
    projected_cost_usd: float


@dataclass(frozen=True, slots=True)
class ImplementationTransition:
    """Explicit approval for changing implementation identity during recovery."""

    source_code_revision: str
    source_environment_lock_digest: str
    target_code_revision: str
    target_environment_lock_digest: str
    approved_by: str
    approved_at: datetime


@dataclass(frozen=True, slots=True)
class RecoverySource:
    experiment_id: str
    experiment_digest: str
    terminal_records_digest: str
    selection_policy: str
    output_limit_failures: int
    invalid_output_failures: int
    provider_error_failures: int | None
    implementation_transition: ImplementationTransition | None = None


@dataclass(frozen=True, slots=True)
class HoldoutSource:
    experiment_id: str
    experiment_digest: str
    development_records_digest: str
    selection_policy: str
    development_records: int
    holdout_records: int


@dataclass(frozen=True, slots=True)
class PlannedRun:
    run_id: str
    case_id: str
    snapshot: SnapshotName
    condition: Condition
    repetition: int
    request_seed: int | None = None
    estimated_input_tokens: int | None = None


@dataclass(frozen=True, slots=True)
class ExperimentManifest:
    schema_version: str
    experiment_id: str
    cases: tuple[ExperimentCase, ...]
    case_manifest_checksum: str
    baseline_profile: ProfileReference
    candidate_profile: ProfileReference
    prompt_template: ProfileReference | None
    analysis_plan: ProfileReference | None
    holdout_access_enabled: bool | None
    price_projection: PriceProjection | None
    recovery_source: RecoverySource | None
    holdout_source: HoldoutSource | None
    snapshot_set: tuple[SnapshotName, ...]
    repetitions: int
    execution_order: tuple[PlannedRun, ...]
    randomization_seed: int
    reviewer_config: FrozenReviewerConfiguration
    retry_policy: RetryPolicy
    invalid_output_policy: str
    code_revision: str
    environment_lock_digest: str
    planned_run_count: int
    created_at: datetime
    approved_by: str | None
    approved_at: datetime | None
    frozen: bool
    adapter_capabilities: AdapterCapabilities | None
    content_digest: str | None
    required_bundle_schema_version: str | None = None

    @classmethod
    def from_dict(cls, document: Mapping[str, Any]) -> ExperimentManifest:
        data = validate_contract("experiment", dict(document))
        baseline = object_mapping(data["baseline_profile"])
        candidate = object_mapping(data["candidate_profile"])
        prompt = (
            object_mapping(data["prompt_template"])
            if data.get("prompt_template") is not None
            else None
        )
        analysis = (
            object_mapping(data["analysis_plan"]) if data.get("analysis_plan") is not None else None
        )
        projection = (
            object_mapping(data["price_projection"])
            if data.get("price_projection") is not None
            else None
        )
        recovery = (
            object_mapping(data["recovery_source"])
            if data.get("recovery_source") is not None
            else None
        )
        holdout = (
            object_mapping(data["holdout_source"])
            if data.get("holdout_source") is not None
            else None
        )
        config = object_mapping(data["reviewer_config"])
        retry = object_mapping(data["retry_policy"])
        try:
            capabilities = (
                AdapterCapabilities.from_dict(object_mapping(data["adapter_capabilities"]))
                if data.get("adapter_capabilities") is not None
                else None
            )
        except AdapterConfigurationError as exc:
            raise SchemaError("experiment adapter capability evidence is invalid") from exc
        model = cls(
            schema_version=cast(str, data["schema_version"]),
            experiment_id=cast(str, data["experiment_id"]),
            cases=tuple(
                _experiment_case(object_mapping(item)) for item in object_list(data["cases"])
            ),
            case_manifest_checksum=cast(str, data["case_manifest_checksum"]),
            baseline_profile=_profile_reference(baseline),
            candidate_profile=_profile_reference(candidate),
            prompt_template=_profile_reference(prompt) if prompt is not None else None,
            analysis_plan=_profile_reference(analysis) if analysis is not None else None,
            holdout_access_enabled=cast(bool | None, data.get("holdout_access_enabled")),
            price_projection=(_price_projection(projection) if projection is not None else None),
            recovery_source=(_recovery_source(recovery) if recovery is not None else None),
            holdout_source=(_holdout_source(holdout) if holdout is not None else None),
            snapshot_set=tuple(
                cast(SnapshotName, item) for item in object_list(data["snapshot_set"])
            ),
            repetitions=cast(int, data["repetitions"]),
            execution_order=tuple(
                _planned_run(object_mapping(item)) for item in object_list(data["execution_order"])
            ),
            randomization_seed=cast(int, data["randomization_seed"]),
            reviewer_config=FrozenReviewerConfiguration(
                model=cast(str, config["model"]),
                tool_policy=cast(str, config["tool_policy"]),
                input_token_limit=cast(int, config["input_token_limit"]),
                output_token_limit=cast(int, config["output_token_limit"]),
                output_schema_version=cast(str, config["output_schema_version"]),
                adapter_version=cast(str, config["adapter_version"]),
                timeout_seconds=float(cast(int | float, config["timeout_seconds"])),
                temperature=float(cast(int | float, config["temperature"])),
            ),
            retry_policy=RetryPolicy(
                maximum_attempts=cast(int, retry["maximum_attempts"]),
                retryable_failures=tuple(
                    cast(str, item) for item in object_list(retry["retryable_failures"])
                ),
            ),
            invalid_output_policy=cast(str, data["invalid_output_policy"]),
            code_revision=cast(str, data["code_revision"]),
            environment_lock_digest=cast(str, data["environment_lock_digest"]),
            planned_run_count=cast(int, data["planned_run_count"]),
            created_at=iso_datetime(cast(str, data["created_at"]), field="created_at"),
            approved_by=cast(str | None, data["approved_by"]),
            approved_at=(
                iso_datetime(cast(str, data["approved_at"]), field="approved_at")
                if data["approved_at"] is not None
                else None
            ),
            frozen=cast(bool, data["frozen"]),
            adapter_capabilities=capabilities,
            content_digest=cast(str | None, data.get("content_digest")),
            required_bundle_schema_version=cast(
                str | None, data.get("required_bundle_schema_version")
            ),
        )
        model._validate_relationships()
        return model

    def to_dict(self) -> dict[str, JsonValue]:
        document: dict[str, JsonValue] = {
            "schema_version": self.schema_version,
            "experiment_id": self.experiment_id,
            "cases": [_experiment_case_dict(case) for case in self.cases],
            "case_manifest_checksum": self.case_manifest_checksum,
            "baseline_profile": _profile_reference_dict(self.baseline_profile),
            "candidate_profile": _profile_reference_dict(self.candidate_profile),
            "snapshot_set": list(self.snapshot_set),
            "repetitions": self.repetitions,
            "execution_order": [_planned_run_dict(run) for run in self.execution_order],
            "randomization_seed": self.randomization_seed,
            "reviewer_config": _reviewer_configuration_dict(self.reviewer_config),
            "retry_policy": {
                "maximum_attempts": self.retry_policy.maximum_attempts,
                "retryable_failures": list(self.retry_policy.retryable_failures),
            },
            "invalid_output_policy": self.invalid_output_policy,
            "code_revision": self.code_revision,
            "environment_lock_digest": self.environment_lock_digest,
            "planned_run_count": self.planned_run_count,
            "created_at": _iso_string(self.created_at),
            "approved_by": self.approved_by,
            "approved_at": _iso_string(self.approved_at) if self.approved_at is not None else None,
            "frozen": self.frozen,
        }
        if self.required_bundle_schema_version is not None:
            document["required_bundle_schema_version"] = self.required_bundle_schema_version
        if self.prompt_template is not None:
            document["prompt_template"] = _profile_reference_dict(self.prompt_template)
        if self.analysis_plan is not None:
            document["analysis_plan"] = _profile_reference_dict(self.analysis_plan)
        if self.holdout_access_enabled is not None:
            document["holdout_access_enabled"] = self.holdout_access_enabled
        if self.price_projection is not None:
            document["price_projection"] = _price_projection_dict(self.price_projection)
        if self.recovery_source is not None:
            document["recovery_source"] = _recovery_source_dict(self.recovery_source)
        if self.holdout_source is not None:
            document["holdout_source"] = _holdout_source_dict(self.holdout_source)
        if self.adapter_capabilities is not None:
            document["adapter_capabilities"] = self.adapter_capabilities.to_dict()
        if self.content_digest is not None:
            document["content_digest"] = self.content_digest
        return document

    def deterministic_content(self) -> dict[str, JsonValue]:
        content = self.to_dict()
        for field in (
            "experiment_id",
            "content_digest",
            "created_at",
            "approved_by",
            "approved_at",
        ):
            content.pop(field, None)
        return content

    def canonical_bytes(self) -> bytes:
        return canonical_json_bytes(self.to_dict())

    def _validate_relationships(self) -> None:
        case_ids = [case.case_id for case in self.cases]
        if len(case_ids) != len(set(case_ids)):
            raise SchemaError("experiment case identifiers must be unique")
        expected_plan = {
            (case_id, snapshot, condition, repetition)
            for case_id in case_ids
            for snapshot in self.snapshot_set
            for condition in ("baseline", "candidate")
            for repetition in range(1, self.repetitions + 1)
        }
        actual_plan = {
            (run.case_id, run.snapshot, run.condition, run.repetition)
            for run in self.execution_order
        }
        if self.schema_version not in {"1.3", "1.4", "1.5"} and self.planned_run_count != len(
            expected_plan
        ):
            raise SchemaError("experiment planned run count does not match frozen dimensions")
        if len(self.execution_order) != self.planned_run_count:
            raise SchemaError("experiment execution order does not cover every planned run")
        run_ids = [run.run_id for run in self.execution_order]
        if len(run_ids) != len(set(run_ids)):
            raise SchemaError("experiment planned run identifiers must be unique")
        if self.schema_version not in {"1.3", "1.4", "1.5"} and actual_plan != expected_plan:
            raise SchemaError("experiment execution order must cover the exact frozen run plan")
        if self.schema_version == "1.3" and (
            not actual_plan
            or len(actual_plan) != len(self.execution_order)
            or not actual_plan.issubset(expected_plan)
        ):
            raise SchemaError("recovery experiment must contain a unique subset of source runs")
        if self.schema_version == "1.4" and (
            not actual_plan
            or len(actual_plan) != len(self.execution_order)
            or not actual_plan.issubset(expected_plan)
        ):
            raise SchemaError("holdout experiment must contain a unique subset of source runs")
        if self.schema_version == "1.5" and (
            not actual_plan
            or len(actual_plan) != len(self.execution_order)
            or not actual_plan.issubset(expected_plan)
        ):
            raise SchemaError("retry recovery must contain a unique subset of source runs")
        if self.reviewer_config.output_schema_version != SCHEMA_VERSION:
            raise SchemaError("experiment output schema version is unsupported")
        if self.frozen and (self.approved_by is None or self.approved_at is None):
            raise SchemaError("frozen experiment requires approval metadata")
        if self.schema_version == "1.0":
            if any(
                case.case_contract_digest is not None
                or case.vulnerable_snapshot is not None
                or case.fixed_snapshot is not None
                for case in self.cases
            ):
                raise SchemaError("legacy experiments cannot claim frozen case contracts")
            if self.adapter_capabilities is not None or self.content_digest is not None:
                raise SchemaError("legacy experiments cannot claim current freeze metadata")
            if any(
                run.request_seed is not None or run.estimated_input_tokens is not None
                for run in self.execution_order
            ):
                raise SchemaError("legacy experiments cannot claim current planned-run metadata")
            if any(
                value is not None
                for value in (
                    self.prompt_template,
                    self.analysis_plan,
                    self.holdout_access_enabled,
                    self.price_projection,
                    self.recovery_source,
                    self.holdout_source,
                )
            ):
                raise SchemaError("legacy experiments cannot claim protocol metadata")
        else:
            if any(
                case.case_contract_digest is None
                or case.vulnerable_snapshot is None
                or case.fixed_snapshot is None
                or case.vulnerable_snapshot == case.fixed_snapshot
                for case in self.cases
            ):
                raise SchemaError("current experiments must bind exact case contracts")
            if not self.frozen or self.adapter_capabilities is None or self.content_digest is None:
                raise SchemaError("current experiment manifests must be completely frozen")
            if any(
                run.request_seed is None or run.estimated_input_tokens is None
                for run in self.execution_order
            ):
                raise SchemaError("current experiment runs require seeds and token estimates")
            if self.reviewer_config.adapter_version != self.adapter_capabilities.adapter_version:
                raise SchemaError("experiment adapter versions do not agree")
            if self.content_digest != canonical_digest(self.deterministic_content()):
                raise SchemaError("experiment content digest does not match frozen content")
            expected_id = f"experiment-{self.content_digest.removeprefix('sha256:')[:32]}"
            if self.experiment_id != expected_id:
                raise SchemaError("experiment identifier does not match frozen content")
            expected_case_checksum = canonical_digest(
                {
                    "schema_version": "1",
                    "cases": [
                        {"case_id": case.case_id, "role": case.role}
                        for case in sorted(self.cases, key=lambda item: item.case_id)
                    ],
                }
            )
            if self.case_manifest_checksum != expected_case_checksum:
                raise SchemaError("experiment case-role checksum does not match frozen cases")
            supported_retryable = {"invalid_output", "provider_error", "timeout"}
            if set(self.retry_policy.retryable_failures) - supported_retryable:
                raise SchemaError("current experiment retry policy includes a permanent failure")
            if (
                self.invalid_output_policy == "retry_then_fail"
                and "invalid_output" not in self.retry_policy.retryable_failures
            ):
                raise SchemaError("current experiment invalid-output policy is inconsistent")
            if self.schema_version == "1.1":
                seeds = [cast(int, run.request_seed) for run in self.execution_order]
                if len(seeds) != len(set(seeds)):
                    raise SchemaError("experiment 1.1 request seeds must be unique")
                if any(
                    value is not None
                    for value in (
                        self.prompt_template,
                        self.analysis_plan,
                        self.holdout_access_enabled,
                        self.price_projection,
                        self.recovery_source,
                        self.holdout_source,
                    )
                ):
                    raise SchemaError("experiment 1.1 cannot claim protocol metadata")
            elif self.schema_version == "1.2":
                block_seeds: dict[tuple[str, SnapshotName, int], set[int]] = {}
                for run in self.execution_order:
                    block = (run.case_id, run.snapshot, run.repetition)
                    block_seeds.setdefault(block, set()).add(cast(int, run.request_seed))
                if any(len(seeds) != 1 for seeds in block_seeds.values()) or len(
                    {next(iter(seeds)) for seeds in block_seeds.values()}
                ) != len(block_seeds):
                    raise SchemaError(
                        "experiment 1.2 request seeds must match within pairs "
                        "and differ across pairs"
                    )
                if (
                    self.prompt_template is None
                    or self.analysis_plan is None
                    or self.holdout_access_enabled is not False
                    or self.price_projection is None
                ):
                    raise SchemaError("experiment 1.2 requires a complete frozen protocol")
                projection = self.price_projection
                maximum_provider_calls = self.planned_run_count * self.retry_policy.maximum_attempts
                if (
                    projection.currency != "USD"
                    or not projection.price_table_version
                    or projection.input_usd_per_million_tokens < 0
                    or projection.output_usd_per_million_tokens < 0
                    or projection.maximum_input_tokens
                    != maximum_provider_calls * self.reviewer_config.input_token_limit
                    or projection.maximum_output_tokens
                    != maximum_provider_calls * self.reviewer_config.output_token_limit
                    or not 0 <= projection.contingency_rate <= 1
                ):
                    raise SchemaError("experiment price projection does not match frozen limits")
                expected_cost = (
                    (
                        projection.maximum_input_tokens * projection.input_usd_per_million_tokens
                        + projection.maximum_output_tokens
                        * projection.output_usd_per_million_tokens
                    )
                    / 1_000_000
                    * (1 + projection.contingency_rate)
                )
                if abs(projection.projected_cost_usd - expected_cost) > 1e-9:
                    raise SchemaError("experiment projected cost does not match frozen prices")
            elif self.schema_version == "1.3":
                source = self.recovery_source
                if (
                    self.prompt_template is None
                    or self.analysis_plan is None
                    or self.holdout_access_enabled is not False
                    or self.price_projection is None
                    or source is None
                    or source.selection_policy
                    not in {"terminal-output-failures-v1", "terminal-output-failures-v2"}
                    or source.output_limit_failures < 0
                    or source.invalid_output_failures < 0
                    or source.provider_error_failures is not None
                    or source.output_limit_failures + source.invalid_output_failures
                    != self.planned_run_count
                ):
                    raise SchemaError("experiment 1.3 requires a complete recovery protocol")
                projection = self.price_projection
                maximum_provider_calls = self.planned_run_count * self.retry_policy.maximum_attempts
                if (
                    projection.maximum_input_tokens
                    != maximum_provider_calls * self.reviewer_config.input_token_limit
                    or projection.maximum_output_tokens
                    != maximum_provider_calls * self.reviewer_config.output_token_limit
                ):
                    raise SchemaError("experiment price projection does not match frozen limits")
                expected_cost = (
                    (
                        projection.maximum_input_tokens * projection.input_usd_per_million_tokens
                        + projection.maximum_output_tokens
                        * projection.output_usd_per_million_tokens
                    )
                    / 1_000_000
                    * (1 + projection.contingency_rate)
                )
                if abs(projection.projected_cost_usd - expected_cost) > 1e-9:
                    raise SchemaError("experiment projected cost does not match frozen prices")
            elif self.schema_version == "1.4":
                holdout_reference = self.holdout_source
                if (
                    self.prompt_template is None
                    or self.analysis_plan is None
                    or self.holdout_access_enabled is not True
                    or self.price_projection is None
                    or holdout_reference is None
                    or holdout_reference.selection_policy != "frozen-holdout-v1"
                    or holdout_reference.development_records < 1
                    or holdout_reference.holdout_records != self.planned_run_count
                    or self.recovery_source is not None
                ):
                    raise SchemaError("experiment 1.4 requires a complete holdout protocol")
                projection = self.price_projection
                maximum_provider_calls = self.planned_run_count * self.retry_policy.maximum_attempts
                if (
                    projection.maximum_input_tokens
                    != maximum_provider_calls * self.reviewer_config.input_token_limit
                    or projection.maximum_output_tokens
                    != maximum_provider_calls * self.reviewer_config.output_token_limit
                ):
                    raise SchemaError("experiment price projection does not match frozen limits")
                expected_cost = (
                    (
                        projection.maximum_input_tokens * projection.input_usd_per_million_tokens
                        + projection.maximum_output_tokens
                        * projection.output_usd_per_million_tokens
                    )
                    / 1_000_000
                    * (1 + projection.contingency_rate)
                )
                if abs(projection.projected_cost_usd - expected_cost) > 1e-9:
                    raise SchemaError("experiment projected cost does not match frozen prices")
            elif self.schema_version == "1.5":
                recovery_reference = self.recovery_source
                if (
                    self.prompt_template is None
                    or self.analysis_plan is None
                    or self.holdout_access_enabled is not True
                    or self.price_projection is None
                    or self.holdout_source is None
                    or recovery_reference is None
                    or recovery_reference.selection_policy != "terminal-provider-failures-v1"
                    or recovery_reference.output_limit_failures != 0
                    or recovery_reference.invalid_output_failures != 0
                    or recovery_reference.provider_error_failures != self.planned_run_count
                ):
                    raise SchemaError("experiment 1.5 requires a complete retry recovery protocol")
                projection = self.price_projection
                maximum_provider_calls = self.planned_run_count * self.retry_policy.maximum_attempts
                if (
                    projection.maximum_input_tokens
                    != maximum_provider_calls * self.reviewer_config.input_token_limit
                    or projection.maximum_output_tokens
                    != maximum_provider_calls * self.reviewer_config.output_token_limit
                ):
                    raise SchemaError("experiment price projection does not match frozen limits")
                expected_cost = (
                    (
                        projection.maximum_input_tokens * projection.input_usd_per_million_tokens
                        + projection.maximum_output_tokens
                        * projection.output_usd_per_million_tokens
                    )
                    / 1_000_000
                    * (1 + projection.contingency_rate)
                )
                if abs(projection.projected_cost_usd - expected_cost) > 1e-9:
                    raise SchemaError("experiment projected cost does not match frozen prices")
            else:  # pragma: no cover - rejected by the JSON schema
                raise SchemaError("experiment schema version is unsupported")


def _optional_float(value: object) -> float | None:
    if value is None:
        return None
    return float(cast(int | float, value))


def _optional_path(value: object, *, field: str) -> PurePosixPath | None:
    if value is None:
        return None
    return repository_path(cast(str, value), field=field)


def _retry_event(data: Mapping[str, Any]) -> RetryEvent:
    return RetryEvent(
        attempt=cast(int, data["attempt"]), classification=cast(str, data["classification"])
    )


def _experiment_case(data: Mapping[str, Any]) -> ExperimentCase:
    return ExperimentCase(
        case_id=cast(str, data["case_id"]),
        role=cast(str, data["role"]),
        case_contract_digest=cast(str | None, data.get("case_contract_digest")),
        vulnerable_snapshot=cast(str | None, data.get("vulnerable_snapshot")),
        fixed_snapshot=cast(str | None, data.get("fixed_snapshot")),
    )


def _experiment_case_dict(case: ExperimentCase) -> dict[str, JsonValue]:
    document: dict[str, JsonValue] = {"case_id": case.case_id, "role": case.role}
    if case.case_contract_digest is None:
        return document
    document.update(
        {
            "case_contract_digest": case.case_contract_digest,
            "vulnerable_snapshot": cast(str, case.vulnerable_snapshot),
            "fixed_snapshot": cast(str, case.fixed_snapshot),
        }
    )
    return document


def _profile_reference(data: Mapping[str, Any]) -> ProfileReference:
    return ProfileReference(version=cast(str, data["version"]), digest=cast(str, data["digest"]))


def _price_projection(data: Mapping[str, Any]) -> PriceProjection:
    return PriceProjection(
        price_table_version=cast(str, data["price_table_version"]),
        currency=cast(str, data["currency"]),
        input_usd_per_million_tokens=float(cast(int | float, data["input_usd_per_million_tokens"])),
        output_usd_per_million_tokens=float(
            cast(int | float, data["output_usd_per_million_tokens"])
        ),
        maximum_input_tokens=cast(int, data["maximum_input_tokens"]),
        maximum_output_tokens=cast(int, data["maximum_output_tokens"]),
        contingency_rate=float(cast(int | float, data["contingency_rate"])),
        projected_cost_usd=float(cast(int | float, data["projected_cost_usd"])),
    )


def _recovery_source(data: Mapping[str, Any]) -> RecoverySource:
    transition_data = data.get("implementation_transition")
    transition = (
        _implementation_transition(object_mapping(transition_data))
        if transition_data is not None
        else None
    )
    return RecoverySource(
        experiment_id=cast(str, data["experiment_id"]),
        experiment_digest=cast(str, data["experiment_digest"]),
        terminal_records_digest=cast(str, data["terminal_records_digest"]),
        selection_policy=cast(str, data["selection_policy"]),
        output_limit_failures=cast(int, data["output_limit_failures"]),
        invalid_output_failures=cast(int, data["invalid_output_failures"]),
        provider_error_failures=cast(int | None, data.get("provider_error_failures")),
        implementation_transition=transition,
    )


def _implementation_transition(data: Mapping[str, Any]) -> ImplementationTransition:
    return ImplementationTransition(
        source_code_revision=cast(str, data["source_code_revision"]),
        source_environment_lock_digest=cast(str, data["source_environment_lock_digest"]),
        target_code_revision=cast(str, data["target_code_revision"]),
        target_environment_lock_digest=cast(str, data["target_environment_lock_digest"]),
        approved_by=cast(str, data["approved_by"]),
        approved_at=iso_datetime(cast(str, data["approved_at"]), field="approved_at"),
    )


def _holdout_source(data: Mapping[str, Any]) -> HoldoutSource:
    return HoldoutSource(
        experiment_id=cast(str, data["experiment_id"]),
        experiment_digest=cast(str, data["experiment_digest"]),
        development_records_digest=cast(str, data["development_records_digest"]),
        selection_policy=cast(str, data["selection_policy"]),
        development_records=cast(int, data["development_records"]),
        holdout_records=cast(int, data["holdout_records"]),
    )


def _planned_run(data: Mapping[str, Any]) -> PlannedRun:
    return PlannedRun(
        run_id=cast(str, data["run_id"]),
        case_id=cast(str, data["case_id"]),
        snapshot=cast(SnapshotName, data["snapshot"]),
        condition=cast(Condition, data["condition"]),
        repetition=cast(int, data["repetition"]),
        request_seed=cast(int | None, data.get("request_seed")),
        estimated_input_tokens=cast(int | None, data.get("estimated_input_tokens")),
    )


def _execution_identity(data: Mapping[str, Any]) -> ExecutionIdentity:
    return ExecutionIdentity(
        experiment_content_digest=cast(str, data["experiment_content_digest"]),
        source_commit=cast(str, data["source_commit"]),
        worktree_digest=cast(str, data["worktree_digest"]),
        bundle_digest=cast(str, data["bundle_digest"]),
        context_entry_digest=cast(str, data["context_entry_digest"]),
        request_id=cast(str, data["request_id"]),
        request_digest=cast(str, data["request_digest"]),
        profile_digest=cast(str, data["profile_digest"]),
        reviewer_config_digest=cast(str, data["reviewer_config_digest"]),
        adapter_capabilities_digest=cast(str, data["adapter_capabilities_digest"]),
        reviewer_output_digest=cast(str | None, data["reviewer_output_digest"]),
    )


def _execution_identity_dict(identity: ExecutionIdentity) -> dict[str, JsonValue]:
    return {
        "experiment_content_digest": identity.experiment_content_digest,
        "source_commit": identity.source_commit,
        "worktree_digest": identity.worktree_digest,
        "bundle_digest": identity.bundle_digest,
        "context_entry_digest": identity.context_entry_digest,
        "request_id": identity.request_id,
        "request_digest": identity.request_digest,
        "profile_digest": identity.profile_digest,
        "reviewer_config_digest": identity.reviewer_config_digest,
        "adapter_capabilities_digest": identity.adapter_capabilities_digest,
        "reviewer_output_digest": identity.reviewer_output_digest,
    }


def _profile_reference_dict(profile: ProfileReference) -> dict[str, JsonValue]:
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


def _recovery_source_dict(source: RecoverySource) -> dict[str, JsonValue]:
    result: dict[str, JsonValue] = {
        "experiment_id": source.experiment_id,
        "experiment_digest": source.experiment_digest,
        "terminal_records_digest": source.terminal_records_digest,
        "selection_policy": source.selection_policy,
        "output_limit_failures": source.output_limit_failures,
        "invalid_output_failures": source.invalid_output_failures,
    }
    if source.provider_error_failures is not None:
        result["provider_error_failures"] = source.provider_error_failures
    if source.implementation_transition is not None:
        transition = source.implementation_transition
        result["implementation_transition"] = {
            "source_code_revision": transition.source_code_revision,
            "source_environment_lock_digest": transition.source_environment_lock_digest,
            "target_code_revision": transition.target_code_revision,
            "target_environment_lock_digest": transition.target_environment_lock_digest,
            "approved_by": transition.approved_by,
            "approved_at": _iso_string(transition.approved_at),
        }
    return result


def _holdout_source_dict(source: HoldoutSource) -> dict[str, JsonValue]:
    return {
        "experiment_id": source.experiment_id,
        "experiment_digest": source.experiment_digest,
        "development_records_digest": source.development_records_digest,
        "selection_policy": source.selection_policy,
        "development_records": source.development_records,
        "holdout_records": source.holdout_records,
    }


def _reviewer_configuration_dict(config: FrozenReviewerConfiguration) -> dict[str, JsonValue]:
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


def _planned_run_dict(run: PlannedRun) -> dict[str, JsonValue]:
    result: dict[str, JsonValue] = {
        "run_id": run.run_id,
        "case_id": run.case_id,
        "snapshot": run.snapshot,
        "condition": run.condition,
        "repetition": run.repetition,
    }
    if run.request_seed is not None:
        result["request_seed"] = run.request_seed
    if run.estimated_input_tokens is not None:
        result["estimated_input_tokens"] = run.estimated_input_tokens
    return result


def _iso_string(value: datetime) -> str:
    return value.isoformat().replace("+00:00", "Z")
