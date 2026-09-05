"""Pure validation for sparse supplemental recovery experiments."""

from __future__ import annotations

from collections.abc import Sequence

from preflight_evals.canonical import JsonValue, canonical_digest
from preflight_evals.errors import SchemaError
from preflight_evals.run_models import ExperimentManifest, PlannedRun, RunRecord

_OUTPUT_LIMIT_ERRORS = {
    ("OUTPUT_LIMIT_EXCEEDED",),
    ("OUTPUT_LIMIT_EXCEEDED", "STDOUT_LIMIT_EXCEEDED"),
    ("OUTPUT_LIMIT_EXCEEDED", "STDERR_LIMIT_EXCEEDED"),
    ("OUTPUT_LIMIT_EXCEEDED", "STDOUT_LIMIT_EXCEEDED", "STDERR_LIMIT_EXCEEDED"),
}
RETRY_RECOVERY_MAXIMUM_ATTEMPTS = 1
FROZEN_M31_LEGACY_RETRY_IDENTITY = (
    "experiment-fc52ffb6945c3266b58e5cb87c8c373c",
    "sha256:fc52ffb6945c3266b58e5cb87c8c373c1e1e4c3cb00cc24fbb06716ecf4ece76",
)


def is_output_limit_failure(record: RunRecord) -> bool:
    """Recognize legacy and stream-specific terminal output-limit records."""

    return record.status == "adapter_error" and record.validation_errors in _OUTPUT_LIMIT_ERRORS


def is_terminal_record(experiment: ExperimentManifest, record: RunRecord) -> bool:
    if record.status == "succeeded":
        return True
    if record.status in {"configuration_error", "adapter_error"}:
        return True
    if record.attempt >= experiment.retry_policy.maximum_attempts:
        return True
    if record.status == "invalid_output" and experiment.invalid_output_policy == "fail_run":
        return True
    return record.status not in experiment.retry_policy.retryable_failures


def validate_run_record(
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
    capabilities = experiment.adapter_capabilities
    if (
        record.schema_version != "1.1"
        or record.experiment_id != experiment.experiment_id
        or record.run_id != planned.run_id
        or record.seed != planned.request_seed
        or record.content_digest is None
        or record.content_digest != record.digest_without_self()
        or identity is None
        or identity.experiment_content_digest != experiment.content_digest
        or identity.source_commit != expected_source_commit
        or identity.profile_digest != expected_profile.digest
        or identity.reviewer_config_digest != canonical_digest(_reviewer_configuration(experiment))
        or capabilities is None
        or identity.adapter_capabilities_digest != capabilities.content_digest
    ):
        raise SchemaError("run record does not match the frozen experiment")


def terminal_records_digest(experiment: ExperimentManifest, records: Sequence[RunRecord]) -> str:
    """Bind the complete ordered terminal state without exposing tuple identities."""

    by_id = {record.run_id: record for record in records}
    if len(by_id) != len(records) or set(by_id) != {
        run.run_id for run in experiment.execution_order
    }:
        raise SchemaError("source experiment terminal records are incomplete")
    content: list[JsonValue] = []
    for planned in experiment.execution_order:
        record = by_id[planned.run_id]
        validate_run_record(experiment, planned, record)
        if not is_terminal_record(experiment, record):
            raise SchemaError("source experiment contains a nonterminal record")
        content.append({"run_id": record.run_id, "content_digest": record.content_digest})
    return canonical_digest(content)


def validate_recovery_source(
    recovery: ExperimentManifest,
    source: ExperimentManifest,
    records: Sequence[RunRecord],
) -> None:
    """Fail closed unless a recovery manifest still matches the full source terminal state."""

    reference = recovery.recovery_source
    if recovery.schema_version != "1.3" or reference is None:
        raise SchemaError("experiment is not a linked recovery plan")
    if source.schema_version != "1.2" or source.recovery_source is not None:
        raise SchemaError("recovery source is not a primary protocol-1.2 experiment")
    source_capabilities = source.adapter_capabilities
    recovery_capabilities = recovery.adapter_capabilities
    if source_capabilities is None or recovery_capabilities is None:
        raise SchemaError("recovery adapter capability evidence is incomplete")
    source_controls = source_capabilities.to_dict()
    recovery_controls = recovery_capabilities.to_dict()
    policy = reference.selection_policy
    mutable_limits = (
        ("maximum_stdout_bytes",)
        if policy == "terminal-output-failures-v1"
        else ("maximum_stdout_bytes", "maximum_stderr_bytes")
    )
    for field in (*mutable_limits, "content_digest"):
        source_controls.pop(field)
        recovery_controls.pop(field)
    stdout_increased = (
        recovery_capabilities.maximum_stdout_bytes > source_capabilities.maximum_stdout_bytes
    )
    stderr_increased = (
        recovery_capabilities.maximum_stderr_bytes > source_capabilities.maximum_stderr_bytes
    )
    valid_capture_limits = (
        policy in {"terminal-output-failures-v1", "terminal-output-failures-v2"}
        and recovery_capabilities.maximum_stdout_bytes >= source_capabilities.maximum_stdout_bytes
        and recovery_capabilities.maximum_stderr_bytes >= source_capabilities.maximum_stderr_bytes
        and (stdout_increased or stderr_increased)
        and (policy == "terminal-output-failures-v2" or stdout_increased)
    )
    if (
        source_controls != recovery_controls
        or not valid_capture_limits
        or _source_protocol_identity(recovery) != _source_protocol_identity(source)
    ):
        raise SchemaError("recovery protocol does not preserve source invariants")
    if (
        reference.experiment_id != source.experiment_id
        or reference.experiment_digest != source.content_digest
        or reference.terminal_records_digest != terminal_records_digest(source, records)
    ):
        raise SchemaError("recovery source experiment binding does not match")
    source_runs = {run.run_id: run for run in source.execution_order}
    source_records = {record.run_id: record for record in records}
    selected_ids = set()
    output_limit = 0
    invalid_output = 0
    for run_id, record in source_records.items():
        if is_output_limit_failure(record):
            selected_ids.add(run_id)
            output_limit += 1
        elif (
            record.status == "invalid_output"
            and record.attempt >= source.retry_policy.maximum_attempts
            and record.validation_errors == ("OUTPUT_SCHEMA_INVALID",)
        ):
            selected_ids.add(run_id)
            invalid_output += 1
    if (
        selected_ids != {run.run_id for run in recovery.execution_order}
        or output_limit != reference.output_limit_failures
        or invalid_output != reference.invalid_output_failures
        or any(source_runs[run.run_id] != run for run in recovery.execution_order)
    ):
        raise SchemaError("recovery plan no longer matches the selected source failures")


def validate_retry_recovery_source(
    recovery: ExperimentManifest,
    source: ExperimentManifest,
    records: Sequence[RunRecord],
    *,
    allow_frozen_m31_legacy: bool = False,
) -> None:
    """Validate a sparse retry of provider failures from an authorized holdout stage."""

    reference = recovery.recovery_source
    if recovery.schema_version != "1.5" or reference is None:
        raise SchemaError("experiment is not a linked retry recovery plan")
    if (
        source.schema_version != "1.4"
        or source.recovery_source is not None
        or source.holdout_source is None
        or source.holdout_access_enabled is not True
    ):
        raise SchemaError("retry recovery source is not a primary protocol-1.4 holdout")
    is_legacy = (
        allow_frozen_m31_legacy
        and (recovery.experiment_id, recovery.content_digest) == FROZEN_M31_LEGACY_RETRY_IDENTITY
        and reference.implementation_transition is None
    )
    if recovery.retry_policy.maximum_attempts != RETRY_RECOVERY_MAXIMUM_ATTEMPTS and not is_legacy:
        raise SchemaError("retry recovery must permit exactly one additional attempt")
    transition = reference.implementation_transition
    if not is_legacy and (
        transition is None
        or recovery.approved_by is None
        or recovery.approved_at is None
        or transition.source_code_revision != source.code_revision
        or transition.source_environment_lock_digest != source.environment_lock_digest
        or transition.target_code_revision != recovery.code_revision
        or transition.target_environment_lock_digest != recovery.environment_lock_digest
        or transition.approved_by != recovery.approved_by
        or transition.approved_at != recovery.approved_at
        or transition.approved_at < recovery.created_at
        or (source.approved_at is not None and transition.approved_at < source.approved_at)
    ):
        raise SchemaError("retry recovery implementation transition is not explicitly bound")
    if (
        recovery.adapter_capabilities != source.adapter_capabilities
        or recovery.holdout_source != source.holdout_source
        or _source_protocol_identity(recovery) != _source_protocol_identity(source)
    ):
        raise SchemaError("retry recovery protocol does not preserve source invariants")
    if (
        reference.experiment_id != source.experiment_id
        or reference.experiment_digest != source.content_digest
        or reference.terminal_records_digest != terminal_records_digest(source, records)
        or reference.selection_policy != "terminal-provider-failures-v1"
        or reference.output_limit_failures != 0
        or reference.invalid_output_failures != 0
    ):
        raise SchemaError("retry recovery source experiment binding does not match")
    source_runs = {run.run_id: run for run in source.execution_order}
    selected_ids = {
        record.run_id
        for record in records
        if record.status == "provider_error"
        and record.attempt >= source.retry_policy.maximum_attempts
        and record.validation_errors == ("PROCESS_NONZERO",)
    }
    if (
        not selected_ids
        or reference.provider_error_failures != len(selected_ids)
        or selected_ids != {run.run_id for run in recovery.execution_order}
        or any(source_runs[run.run_id] != run for run in recovery.execution_order)
    ):
        raise SchemaError("retry recovery plan no longer matches the source provider failures")


def overlay_recovery_records(
    source: ExperimentManifest,
    source_records: Sequence[RunRecord],
    recovery: ExperimentManifest,
    recovery_records: Sequence[RunRecord],
    *,
    allow_frozen_m31_legacy: bool = False,
) -> dict[str, RunRecord]:
    """Return source records with successful, fully validated recovery records overlaid."""

    reference = recovery.recovery_source
    legacy_overlay = (
        allow_frozen_m31_legacy
        and (recovery.experiment_id, recovery.content_digest) == FROZEN_M31_LEGACY_RETRY_IDENTITY
        and reference is not None
        and reference.implementation_transition is None
    )
    if recovery.schema_version == "1.5":
        validate_retry_recovery_source(
            recovery,
            source,
            source_records,
            allow_frozen_m31_legacy=allow_frozen_m31_legacy,
        )
    else:
        validate_recovery_source(recovery, source, source_records)
    recovered_by_id = {record.run_id: record for record in recovery_records}
    recovery_plan = {run.run_id: run for run in recovery.execution_order}
    if len(recovered_by_id) != len(recovery_records) or set(recovered_by_id) != set(recovery_plan):
        raise SchemaError("recovery requires one recovery record per selected source run")
    for run_id, record in recovered_by_id.items():
        validate_run_record(recovery, recovery_plan[run_id], record)
        if not is_terminal_record(recovery, record):
            raise SchemaError("recovery records must be terminal")
        if legacy_overlay and (
            record.attempt != RETRY_RECOVERY_MAXIMUM_ATTEMPTS or record.retry_history
        ):
            raise SchemaError("legacy retry overlay exceeded the authorized one-attempt ceiling")

    effective = {record.run_id: record for record in source_records}
    for run_id, record in recovered_by_id.items():
        if record.status == "succeeded":
            effective[run_id] = record
    return effective


def overlaid_run_record_digest(source_record: RunRecord, recovery_record: RunRecord | None) -> str:
    """Bind provenance to the source and every supplied terminal recovery record."""

    source_digest = source_record.content_digest or source_record.digest_without_self()
    if recovery_record is None:
        return source_digest
    recovery_digest = recovery_record.content_digest or recovery_record.digest_without_self()
    return canonical_digest(
        {
            "schema_version": "1",
            "source_run_record": source_digest,
            "recovery_run_record": recovery_digest,
        }
    )


def _source_protocol_identity(experiment: ExperimentManifest) -> tuple[object, ...]:
    projection = experiment.price_projection
    price_identity = (
        None
        if projection is None
        else (
            projection.price_table_version,
            projection.currency,
            projection.input_usd_per_million_tokens,
            projection.output_usd_per_million_tokens,
            projection.contingency_rate,
        )
    )
    return (
        experiment.cases,
        experiment.case_manifest_checksum,
        experiment.baseline_profile,
        experiment.candidate_profile,
        experiment.prompt_template,
        experiment.required_bundle_schema_version,
        experiment.analysis_plan,
        experiment.holdout_access_enabled,
        experiment.snapshot_set,
        experiment.repetitions,
        experiment.randomization_seed,
        experiment.reviewer_config,
        experiment.retry_policy.retryable_failures,
        experiment.invalid_output_policy,
        price_identity,
    )


def _reviewer_configuration(experiment: ExperimentManifest) -> dict[str, JsonValue]:
    config = experiment.reviewer_config
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
