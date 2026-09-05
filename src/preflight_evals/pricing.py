"""Dated model-price loading and fail-closed token-cost accounting."""

from __future__ import annotations

import math
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from datetime import date
from decimal import Decimal
from pathlib import Path
from typing import Any, Literal, cast

import yaml

from preflight_evals.attempt_metadata import AttemptMetadata
from preflight_evals.canonical import JsonValue
from preflight_evals.errors import SchemaError
from preflight_evals.recovery import overlay_recovery_records
from preflight_evals.run_models import ExperimentManifest, PlannedRun, RunRecord, TokenUsage

type ReasoningBilling = Literal["included_in_output"]

_TABLE_FIELDS = {
    "schema_version",
    "version",
    "effective_date",
    "currency",
    "source",
    "entries",
}
_ENTRY_FIELDS = {
    "provider",
    "model",
    "input_usd_per_million_tokens",
    "cached_input_usd_per_million_tokens",
    "output_usd_per_million_tokens",
    "reasoning_billing",
    "long_context",
}
_LONG_CONTEXT_FIELDS = {
    "threshold_input_tokens",
    "input_multiplier",
    "output_multiplier",
}


@dataclass(frozen=True, slots=True)
class LongContextPrice:
    threshold_input_tokens: int
    input_multiplier: float
    output_multiplier: float


@dataclass(frozen=True, slots=True)
class ModelPrice:
    provider: str
    model: str
    input_usd_per_million_tokens: float
    cached_input_usd_per_million_tokens: float
    output_usd_per_million_tokens: float
    reasoning_billing: ReasoningBilling
    long_context: LongContextPrice | None


@dataclass(frozen=True, slots=True)
class PriceTable:
    schema_version: str
    version: str
    effective_date: date
    currency: str
    source: str
    entries: tuple[ModelPrice, ...]

    @classmethod
    def from_dict(cls, document: Mapping[str, Any]) -> PriceTable:
        try:
            entries = tuple(_model_price(_mapping(item)) for item in _list(document["entries"]))
            effective = document["effective_date"]
            model = cls(
                schema_version=_string(document["schema_version"]),
                version=_string(document["version"]),
                effective_date=(
                    effective if type(effective) is date else date.fromisoformat(_string(effective))
                ),
                currency=_string(document["currency"]),
                source=_string(document["source"]),
                entries=entries,
            )
        except (KeyError, TypeError, ValueError) as exc:
            raise SchemaError("price table is invalid") from exc
        keys = [(entry.provider, entry.model) for entry in model.entries]
        if (
            set(document) != _TABLE_FIELDS
            or model.schema_version != "1.0"
            or not model.version
            or len(model.version) > 100
            or model.currency != "USD"
            or not model.source.startswith("https://")
            or not model.entries
            or len(keys) != len(set(keys))
            or tuple(sorted(model.entries, key=lambda item: (item.provider, item.model)))
            != model.entries
        ):
            raise SchemaError("price table is invalid")
        return model

    def lookup(self, provider: str, model: str) -> ModelPrice | None:
        return next(
            (
                entry
                for entry in self.entries
                if entry.provider == provider and entry.model == model
            ),
            None,
        )

    def to_dict(self) -> dict[str, JsonValue]:
        return {
            "schema_version": self.schema_version,
            "version": self.version,
            "effective_date": self.effective_date.isoformat(),
            "currency": self.currency,
            "source": self.source,
            "entries": [_model_price_dict(entry) for entry in self.entries],
        }


@dataclass(frozen=True, slots=True)
class UsageCost:
    input_usd: float
    cached_input_usd: float
    output_usd: float
    total_usd: float
    long_context_pricing: bool

    def to_dict(self) -> dict[str, JsonValue]:
        return {
            "input_usd": self.input_usd,
            "cached_input_usd": self.cached_input_usd,
            "output_usd": self.output_usd,
            "total_usd": self.total_usd,
            "long_context_pricing": self.long_context_pricing,
        }


@dataclass(frozen=True, slots=True)
class CostAccounting:
    price_table_version: str
    price_effective_date: date
    price_source: str
    provider: str
    model: str
    completed_runs: int
    unfinished_runs: int
    provider_usage_runs: int
    unknown_usage_or_price_runs: int
    unaccounted_retry_attempts: int
    known_terminal_cost_usd: float | None
    actual_cost_usd: float | None
    projected_remaining_cost_usd: float | None
    projected_total_cost_usd: float | None
    frozen_worst_case_cost_usd: float | None
    projection_method: str

    def to_dict(self) -> dict[str, JsonValue]:
        return {
            "price_table_version": self.price_table_version,
            "price_effective_date": self.price_effective_date.isoformat(),
            "price_source": self.price_source,
            "provider": self.provider,
            "model": self.model,
            "completed_runs": self.completed_runs,
            "unfinished_runs": self.unfinished_runs,
            "provider_usage_runs": self.provider_usage_runs,
            "unknown_usage_or_price_runs": self.unknown_usage_or_price_runs,
            "unaccounted_retry_attempts": self.unaccounted_retry_attempts,
            "known_terminal_cost_usd": self.known_terminal_cost_usd,
            "actual_cost_usd": self.actual_cost_usd,
            "projected_remaining_cost_usd": self.projected_remaining_cost_usd,
            "projected_total_cost_usd": self.projected_total_cost_usd,
            "frozen_worst_case_cost_usd": self.frozen_worst_case_cost_usd,
            "projection_method": self.projection_method,
        }


def load_price_table(path: Path) -> PriceTable:
    """Load one strict, dated YAML price table without implicit defaults."""

    try:
        document = yaml.safe_load(path.read_bytes())
    except (OSError, UnicodeError, yaml.YAMLError) as exc:
        raise SchemaError("could not load price table") from exc
    if not isinstance(document, Mapping):
        raise SchemaError("price table is invalid")
    return PriceTable.from_dict(cast(Mapping[str, Any], document))


def price_usage(usage: TokenUsage, price: ModelPrice) -> UsageCost | None:
    """Price complete provider-reported token usage; preserve partial usage as unknown."""

    supplied = (
        usage.input_tokens,
        usage.cached_input_tokens,
        usage.output_tokens,
        usage.reasoning_tokens,
    )
    if any(value is not None and (type(value) is not int or value < 0) for value in supplied):
        raise SchemaError("provider token usage is invalid")
    if (
        usage.input_tokens is None
        or usage.cached_input_tokens is None
        or usage.output_tokens is None
        or usage.cached_input_tokens > usage.input_tokens
    ):
        return None
    long_price = price.long_context
    long_context = long_price is not None and usage.input_tokens > long_price.threshold_input_tokens
    input_multiplier = long_price.input_multiplier if long_context and long_price else 1.0
    output_multiplier = long_price.output_multiplier if long_context and long_price else 1.0
    uncached = usage.input_tokens - usage.cached_input_tokens
    input_cost = _token_cost(uncached, price.input_usd_per_million_tokens * input_multiplier)
    cached_cost = _token_cost(
        usage.cached_input_tokens,
        price.cached_input_usd_per_million_tokens * input_multiplier,
    )
    # Provider output usage already includes reasoning-token details for this price table.
    output_cost = _token_cost(
        usage.output_tokens, price.output_usd_per_million_tokens * output_multiplier
    )
    total = input_cost + cached_cost + output_cost
    return UsageCost(
        input_usd=float(input_cost),
        cached_input_usd=float(cached_cost),
        output_usd=float(output_cost),
        total_usd=float(total),
        long_context_pricing=long_context,
    )


def account_costs(
    experiment: ExperimentManifest,
    run_records: Sequence[RunRecord],
    price_table: PriceTable,
    *,
    provider: str,
    recovery_experiment: ExperimentManifest | None = None,
    recovery_records: Sequence[RunRecord] = (),
    attempt_metadata: Sequence[AttemptMetadata] | None = None,
    recovery_attempt_metadata: Sequence[AttemptMetadata] | None = None,
    allow_frozen_m31_legacy: bool = False,
) -> CostAccounting:
    """Calculate actual terminal cost and a conservative unfinished-run projection."""

    experiment = ExperimentManifest.from_dict(experiment.to_dict())
    run_records = tuple(RunRecord.from_dict(record.to_dict()) for record in run_records)
    price_table = PriceTable.from_dict(price_table.to_dict())
    recovery_experiment = (
        ExperimentManifest.from_dict(recovery_experiment.to_dict())
        if recovery_experiment is not None
        else None
    )
    recovery_records = tuple(RunRecord.from_dict(record.to_dict()) for record in recovery_records)
    attempt_metadata = (
        tuple(AttemptMetadata.from_dict(record.to_dict()) for record in attempt_metadata)
        if attempt_metadata is not None
        else None
    )
    recovery_attempt_metadata = (
        tuple(AttemptMetadata.from_dict(record.to_dict()) for record in recovery_attempt_metadata)
        if recovery_attempt_metadata is not None
        else None
    )
    planned_by_id = {run.run_id: run for run in experiment.execution_order}
    records_by_id = {record.run_id: record for record in run_records}
    if (
        len(records_by_id) != len(run_records)
        or set(records_by_id) - set(planned_by_id)
        or any(record.experiment_id != experiment.experiment_id for record in run_records)
        or any(not _is_terminal_record(experiment, record) for record in run_records)
    ):
        raise SchemaError("cost accounting records do not match the frozen experiment")
    effective_by_id = records_by_id
    if recovery_experiment is None:
        if recovery_records or recovery_attempt_metadata:
            raise SchemaError("recovery cost records require a linked recovery experiment")
    else:
        effective_by_id = overlay_recovery_records(
            experiment,
            run_records,
            recovery_experiment,
            recovery_records,
            allow_frozen_m31_legacy=allow_frozen_m31_legacy,
        )
    price = price_table.lookup(provider, experiment.reviewer_config.model)
    if not _matches_frozen_projection(experiment, price_table, price):
        price = None
    known_costs: list[float] = []
    provider_usage_runs = 0
    unknown_runs = 0
    retry_attempts = 0
    attempts_started_by_run: dict[str, int] = {}
    if attempt_metadata is None and recovery_attempt_metadata is None:
        accounting_records = {run_id: [record] for run_id, record in records_by_id.items()}
        for recovery_record in recovery_records:
            accounting_records[recovery_record.run_id].append(recovery_record)
        for records in accounting_records.values():
            if all(_has_complete_provider_usage(record.usage) for record in records):
                provider_usage_runs += 1
            run_has_unknown = False
            for record in records:
                provider_total = record.cost.total if record.price_table_version is None else None
                priced = None
                if provider_total is None:
                    priced = (
                        price_usage(record.usage, price)
                        if price is not None and record.price_table_version == price_table.version
                        else None
                    )
                if provider_total is not None:
                    known_costs.append(provider_total)
                elif priced is None:
                    run_has_unknown = True
                else:
                    known_costs.append(priced.total_usd)
            unknown_runs += run_has_unknown
        retry_attempts = sum(
            len(record.retry_history)
            for records in accounting_records.values()
            for record in records
        )
    else:
        source_attempts, source_missing, source_missing_retries = _reconcile_attempt_metadata(
            experiment,
            run_records,
            attempt_metadata or (),
            provider=provider,
        )
        recovery_attempts: dict[str, tuple[AttemptMetadata, ...]] = {}
        recovery_missing: dict[str, int] = {}
        recovery_missing_retries = 0
        if recovery_experiment is not None:
            (
                recovery_attempts,
                recovery_missing,
                recovery_missing_retries,
            ) = _reconcile_attempt_metadata(
                recovery_experiment,
                recovery_records,
                recovery_attempt_metadata or (),
                provider=provider,
            )
        for run_id in planned_by_id:
            attempts_for_run = (
                *source_attempts.get(run_id, ()),
                *recovery_attempts.get(run_id, ()),
            )
            if attempts_for_run:
                attempts_started_by_run[run_id] = max(
                    attempt_record.attempt for attempt_record in attempts_for_run
                )
            missing = source_missing.get(run_id, 0) + recovery_missing.get(run_id, 0)
            if (
                attempts_for_run
                and missing == 0
                and all(
                    _has_complete_provider_usage(attempt_record.usage)
                    for attempt_record in attempts_for_run
                )
            ):
                provider_usage_runs += 1
            run_has_unknown = missing > 0
            for attempt_record in attempts_for_run:
                provider_total = attempt_record.provider_reported_cost_usd
                priced = price_usage(attempt_record.usage, price) if price is not None else None
                if provider_total is not None:
                    known_costs.append(provider_total)
                elif priced is None:
                    run_has_unknown = True
                else:
                    known_costs.append(priced.total_usd)
            unknown_runs += run_has_unknown
        retry_attempts = source_missing_retries + recovery_missing_retries
    all_terminal_known = unknown_runs == 0 and retry_attempts == 0
    known_total = (
        _stable_sum(known_costs) if known_costs else (0.0 if not effective_by_id else None)
    )
    actual = known_total if all_terminal_known else None
    unfinished = [
        planned for planned in experiment.execution_order if planned.run_id not in records_by_id
    ]
    remaining = _remaining_projection(
        experiment,
        unfinished,
        price_table,
        price,
        attempts_started_by_run=attempts_started_by_run,
    )
    projected_total = (
        _stable_sum([actual, remaining]) if actual is not None and remaining is not None else None
    )
    return CostAccounting(
        price_table_version=price_table.version,
        price_effective_date=price_table.effective_date,
        price_source=price_table.source,
        provider=provider,
        model=experiment.reviewer_config.model,
        completed_runs=len(records_by_id),
        unfinished_runs=len(unfinished),
        provider_usage_runs=provider_usage_runs,
        unknown_usage_or_price_runs=unknown_runs,
        unaccounted_retry_attempts=retry_attempts,
        known_terminal_cost_usd=known_total,
        actual_cost_usd=actual,
        projected_remaining_cost_usd=remaining,
        projected_total_cost_usd=projected_total,
        frozen_worst_case_cost_usd=_frozen_worst_case_cost(
            experiment,
            recovery_experiment,
        ),
        projection_method=(
            "linked-recovery-effective-terminal-plus-unaccounted-prior-attempts"
            if recovery_experiment is not None
            else "planned-input-plus-output-limit-retry-ceiling-with-frozen-contingency"
        ),
    )


def _reconcile_attempt_metadata(
    experiment: ExperimentManifest,
    run_records: Sequence[RunRecord],
    metadata_records: Sequence[AttemptMetadata],
    *,
    provider: str,
) -> tuple[dict[str, tuple[AttemptMetadata, ...]], dict[str, int], int]:
    """Bind every supplied attempt to one frozen run and expose missing coverage."""

    planned_by_id = {run.run_id: run for run in experiment.execution_order}
    terminal_by_id = {record.run_id: record for record in run_records}
    by_key: dict[tuple[str, int], AttemptMetadata] = {}
    for metadata in metadata_records:
        key = (metadata.run_id, metadata.attempt)
        if key in by_key:
            raise SchemaError("attempt metadata identities must be unique")
        if (
            metadata.experiment_id != experiment.experiment_id
            or metadata.experiment_content_digest != experiment.content_digest
            or metadata.run_id not in planned_by_id
            or metadata.model != experiment.reviewer_config.model
            or metadata.provider not in {provider, "unreported"}
        ):
            raise SchemaError("attempt metadata does not match the frozen experiment")
        terminal = terminal_by_id.get(metadata.run_id)
        maximum = (
            terminal.attempt if terminal is not None else experiment.retry_policy.maximum_attempts
        )
        if metadata.attempt > maximum:
            raise SchemaError("attempt metadata is stale relative to terminal state")
        by_key[key] = metadata

    grouped: dict[str, tuple[AttemptMetadata, ...]] = {}
    missing: dict[str, int] = {}
    missing_retries = 0
    for run_id in planned_by_id:
        terminal = terminal_by_id.get(run_id)
        available = sorted(attempt for candidate, attempt in by_key if candidate == run_id)
        if terminal is None:
            if available and available != list(range(available[0], available[-1] + 1)):
                raise SchemaError("attempt metadata for unfinished work is not contiguous")
            expected_attempts = list(range(1, available[-1] + 1)) if available else []
            missing_retries += sum(
                (run_id, attempt) not in by_key for attempt in expected_attempts[:-1]
            )
        else:
            expected_attempts = list(range(1, terminal.attempt + 1))
            terminal_metadata = by_key.get((run_id, terminal.attempt))
            identity = terminal.identity
            if terminal_metadata is not None and (
                identity is None
                or terminal_metadata.request_digest != identity.request_digest
                or terminal_metadata.provider_request_id != terminal.provider_request_id
                or terminal_metadata.started_at != terminal.started_at
                or terminal_metadata.ended_at != terminal.ended_at
                or terminal_metadata.monotonic_latency_ms != terminal.monotonic_latency_ms
                or terminal_metadata.usage != terminal.usage
                or terminal_metadata.provider_reported_cost_usd
                != (terminal.cost.total if terminal.price_table_version is None else None)
                or terminal_metadata.run_record_digest
                != (terminal.content_digest or terminal.digest_without_self())
                or (
                    terminal.raw_artifacts.response_digest is not None
                    and terminal_metadata.response_digest != terminal.raw_artifacts.response_digest
                )
            ):
                raise SchemaError("attempt metadata conflicts with its terminal run record")
            missing_retries += sum(
                (run_id, attempt) not in by_key for attempt in range(1, terminal.attempt)
            )
        selected = tuple(
            by_key[(run_id, attempt)]
            for attempt in expected_attempts
            if (run_id, attempt) in by_key
        )
        if selected:
            grouped[run_id] = selected
        missing[run_id] = len(expected_attempts) - len(selected)
    return grouped, missing, missing_retries


def _frozen_worst_case_cost(
    experiment: ExperimentManifest,
    recovery_experiment: ExperimentManifest | None,
) -> float | None:
    projection = experiment.price_projection
    if projection is None:
        return None
    if recovery_experiment is None:
        return projection.projected_cost_usd
    recovery_projection = recovery_experiment.price_projection
    if recovery_projection is None:
        return None
    return _stable_sum([projection.projected_cost_usd, recovery_projection.projected_cost_usd])


def _remaining_projection(
    experiment: ExperimentManifest,
    unfinished: Sequence[PlannedRun],
    table: PriceTable,
    price: ModelPrice | None,
    *,
    attempts_started_by_run: Mapping[str, int],
) -> float | None:
    projection = experiment.price_projection
    if (
        price is None
        or projection is None
        or projection.price_table_version != table.version
        or price.input_usd_per_million_tokens != projection.input_usd_per_million_tokens
        or price.output_usd_per_million_tokens != projection.output_usd_per_million_tokens
        or any(planned.estimated_input_tokens is None for planned in unfinished)
    ):
        return None
    costs: list[float] = []
    for planned in unfinished:
        usage = TokenUsage(
            input_tokens=cast(int, planned.estimated_input_tokens),
            cached_input_tokens=0,
            output_tokens=experiment.reviewer_config.output_token_limit,
            reasoning_tokens=None,
        )
        priced = price_usage(usage, price)
        if priced is None:
            return None
        remaining_attempts = experiment.retry_policy.maximum_attempts - attempts_started_by_run.get(
            planned.run_id, 0
        )
        costs.extend([priced.total_usd] * remaining_attempts)
    return _stable_sum(costs) * (1 + projection.contingency_rate)


def _matches_frozen_projection(
    experiment: ExperimentManifest, table: PriceTable, price: ModelPrice | None
) -> bool:
    projection = experiment.price_projection
    return (
        price is not None
        and projection is not None
        and projection.price_table_version == table.version
        and price.input_usd_per_million_tokens == projection.input_usd_per_million_tokens
        and price.output_usd_per_million_tokens == projection.output_usd_per_million_tokens
    )


def _has_complete_provider_usage(usage: TokenUsage) -> bool:
    return all(
        value is not None
        for value in (usage.input_tokens, usage.cached_input_tokens, usage.output_tokens)
    )


def _is_terminal_record(experiment: ExperimentManifest, record: RunRecord) -> bool:
    if record.status == "succeeded" or record.status in {"configuration_error", "adapter_error"}:
        return True
    if record.attempt >= experiment.retry_policy.maximum_attempts:
        return True
    if record.status == "invalid_output" and experiment.invalid_output_policy == "fail_run":
        return True
    return record.status not in experiment.retry_policy.retryable_failures


def _model_price(document: Mapping[str, Any]) -> ModelPrice:
    if set(document) != _ENTRY_FIELDS:
        raise SchemaError("price entry is invalid")
    long_document = document["long_context"]
    long_context = _long_context(_mapping(long_document)) if long_document is not None else None
    try:
        model = ModelPrice(
            provider=_string(document["provider"]),
            model=_string(document["model"]),
            input_usd_per_million_tokens=_rate(document["input_usd_per_million_tokens"]),
            cached_input_usd_per_million_tokens=_rate(
                document["cached_input_usd_per_million_tokens"]
            ),
            output_usd_per_million_tokens=_rate(document["output_usd_per_million_tokens"]),
            reasoning_billing=cast(ReasoningBilling, _string(document["reasoning_billing"])),
            long_context=long_context,
        )
    except (TypeError, ValueError) as exc:
        raise SchemaError("price entry is invalid") from exc
    if (
        not model.provider
        or not model.model
        or model.reasoning_billing != "included_in_output"
        or model.cached_input_usd_per_million_tokens > model.input_usd_per_million_tokens
    ):
        raise SchemaError("price entry is invalid")
    return model


def _long_context(document: Mapping[str, Any]) -> LongContextPrice:
    try:
        model = LongContextPrice(
            threshold_input_tokens=_integer(document["threshold_input_tokens"]),
            input_multiplier=_multiplier(document["input_multiplier"]),
            output_multiplier=_multiplier(document["output_multiplier"]),
        )
    except (KeyError, TypeError, ValueError) as exc:
        raise SchemaError("long-context price entry is invalid") from exc
    if (
        set(document) != _LONG_CONTEXT_FIELDS
        or model.threshold_input_tokens < 1
        or model.input_multiplier < 1
        or model.output_multiplier < 1
    ):
        raise SchemaError("long-context price entry is invalid")
    return model


def _model_price_dict(price: ModelPrice) -> dict[str, JsonValue]:
    return {
        "provider": price.provider,
        "model": price.model,
        "input_usd_per_million_tokens": price.input_usd_per_million_tokens,
        "cached_input_usd_per_million_tokens": price.cached_input_usd_per_million_tokens,
        "output_usd_per_million_tokens": price.output_usd_per_million_tokens,
        "reasoning_billing": price.reasoning_billing,
        "long_context": (
            {
                "threshold_input_tokens": price.long_context.threshold_input_tokens,
                "input_multiplier": price.long_context.input_multiplier,
                "output_multiplier": price.long_context.output_multiplier,
            }
            if price.long_context is not None
            else None
        ),
    }


def _token_cost(tokens: int, rate: float) -> Decimal:
    return Decimal(tokens) * Decimal(str(rate)) / Decimal(1_000_000)


def _stable_sum(values: Sequence[float]) -> float:
    return float(sum((Decimal(str(value)) for value in values), start=Decimal(0)))


def _mapping(value: object) -> Mapping[str, Any]:
    if not isinstance(value, Mapping):
        raise SchemaError("price table contains an invalid object")
    return cast(Mapping[str, Any], value)


def _list(value: object) -> list[Any]:
    if not isinstance(value, list):
        raise SchemaError("price table contains an invalid list")
    return value


def _string(value: object) -> str:
    if not isinstance(value, str):
        raise TypeError("expected string")
    return value


def _integer(value: object) -> int:
    if type(value) is not int:
        raise TypeError("expected integer")
    return value


def _rate(value: object) -> float:
    if type(value) not in {int, float}:
        raise TypeError("expected numeric price")
    number = float(cast(int | float, value))
    if not math.isfinite(number) or number < 0:
        raise ValueError("invalid price")
    return number


def _multiplier(value: object) -> float:
    number = _rate(value)
    if number < 1:
        raise ValueError("invalid multiplier")
    return number
