"""Validation for an authorized holdout stage linked to a frozen primary experiment."""

from __future__ import annotations

from collections.abc import Sequence

from preflight_evals.canonical import JsonValue, canonical_digest
from preflight_evals.errors import SchemaError
from preflight_evals.recovery import is_terminal_record, validate_run_record
from preflight_evals.run_models import ExperimentManifest, RunRecord


def development_records_digest(experiment: ExperimentManifest, records: Sequence[RunRecord]) -> str:
    """Bind the complete ordered development checkpoint while keeping holdout unopened."""

    roles = {case.case_id: case.role for case in experiment.cases}
    planned = tuple(
        run for run in experiment.execution_order if roles[run.case_id] == "development"
    )
    by_id = {record.run_id: record for record in records}
    if len(by_id) != len(records) or set(by_id) != {run.run_id for run in planned}:
        raise SchemaError("source experiment development records are incomplete")
    content: list[JsonValue] = []
    for run in planned:
        record = by_id[run.run_id]
        validate_run_record(experiment, run, record)
        if not is_terminal_record(experiment, record):
            raise SchemaError("source experiment contains a nonterminal development record")
        content.append({"run_id": record.run_id, "content_digest": record.content_digest})
    return canonical_digest(content)


def validate_holdout_source(
    holdout: ExperimentManifest,
    source: ExperimentManifest,
    development_records: Sequence[RunRecord],
) -> None:
    """Fail closed unless the holdout stage matches its source and development checkpoint."""

    reference = holdout.holdout_source
    if holdout.schema_version != "1.4" or reference is None:
        raise SchemaError("experiment is not a linked holdout plan")
    if (
        source.schema_version != "1.2"
        or source.recovery_source is not None
        or source.holdout_source is not None
        or source.holdout_access_enabled is not False
    ):
        raise SchemaError("holdout source is not a primary protocol-1.2 experiment")
    if holdout.adapter_capabilities != source.adapter_capabilities or _protocol_identity(
        holdout
    ) != _protocol_identity(source):
        raise SchemaError("holdout protocol does not preserve source invariants")
    digest = development_records_digest(source, development_records)
    if (
        reference.experiment_id != source.experiment_id
        or reference.experiment_digest != source.content_digest
        or reference.development_records_digest != digest
        or reference.selection_policy != "frozen-holdout-v1"
        or reference.development_records != len(development_records)
        or reference.holdout_records != len(holdout.execution_order)
    ):
        raise SchemaError("holdout source experiment binding does not match")
    roles = {case.case_id: case.role for case in source.cases}
    selected = tuple(run for run in source.execution_order if roles[run.case_id] == "holdout")
    if holdout.execution_order != selected:
        raise SchemaError("holdout plan no longer matches the frozen source selection")


def _protocol_identity(experiment: ExperimentManifest) -> tuple[object, ...]:
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
        experiment.snapshot_set,
        experiment.repetitions,
        experiment.randomization_seed,
        experiment.reviewer_config,
        experiment.retry_policy,
        experiment.invalid_output_policy,
        price_identity,
    )
