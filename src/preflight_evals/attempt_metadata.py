"""Privacy-bounded, content-addressed provider-attempt metadata."""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any, cast

from preflight_evals.canonical import JsonValue, canonical_digest, canonical_json_bytes
from preflight_evals.errors import SchemaError
from preflight_evals.run_models import TokenUsage
from preflight_evals.schema import validate_contract


@dataclass(frozen=True, slots=True)
class AttemptMetadata:
    """One append-only accounting record with no prompt or response content."""

    schema_version: str
    experiment_id: str
    experiment_content_digest: str
    run_id: str
    attempt: int
    request_digest: str
    provider: str
    model: str
    provider_request_id: str | None
    started_at: datetime
    ended_at: datetime
    monotonic_latency_ms: float
    response_digest: str
    usage: TokenUsage
    currency: str
    provider_reported_cost_usd: float | None
    run_record_digest: str
    content_digest: str

    @classmethod
    def from_dict(cls, document: Mapping[str, Any]) -> AttemptMetadata:
        data = validate_contract("attempt-metadata", document)
        usage = cast(dict[str, object], data["usage"])
        cost = cast(dict[str, object], data["provider_reported_cost"])
        try:
            model = cls(
                schema_version=cast(str, data["schema_version"]),
                experiment_id=cast(str, data["experiment_id"]),
                experiment_content_digest=cast(str, data["experiment_content_digest"]),
                run_id=cast(str, data["run_id"]),
                attempt=cast(int, data["attempt"]),
                request_digest=cast(str, data["request_digest"]),
                provider=cast(str, data["provider"]),
                model=cast(str, data["model"]),
                provider_request_id=cast(str | None, data["provider_request_id"]),
                started_at=_parse_timestamp(cast(str, data["started_at"])),
                ended_at=_parse_timestamp(cast(str, data["ended_at"])),
                # Preserve the validated JSON representation because 1 and 1.0
                # have different canonical bytes and therefore different digests.
                monotonic_latency_ms=cast(float, data["monotonic_latency_ms"]),
                response_digest=cast(str, data["response_digest"]),
                usage=TokenUsage(
                    input_tokens=cast(int | None, usage["input_tokens"]),
                    cached_input_tokens=cast(int | None, usage["cached_input_tokens"]),
                    output_tokens=cast(int | None, usage["output_tokens"]),
                    reasoning_tokens=cast(int | None, usage["reasoning_tokens"]),
                ),
                currency=cast(str, cost["currency"]),
                provider_reported_cost_usd=_optional_float(cost["total_usd"]),
                run_record_digest=cast(str, data["run_record_digest"]),
                content_digest=cast(str, data["content_digest"]),
            )
        except (KeyError, TypeError, ValueError) as exc:  # pragma: no cover - schema parity
            raise SchemaError("attempt metadata is invalid") from exc
        model._validate_relationships()
        return model

    def to_dict(self) -> dict[str, JsonValue]:
        return {
            "schema_version": self.schema_version,
            "experiment_id": self.experiment_id,
            "experiment_content_digest": self.experiment_content_digest,
            "run_id": self.run_id,
            "attempt": self.attempt,
            "request_digest": self.request_digest,
            "provider": self.provider,
            "model": self.model,
            "provider_request_id": self.provider_request_id,
            "started_at": _iso_string(self.started_at),
            "ended_at": _iso_string(self.ended_at),
            "monotonic_latency_ms": self.monotonic_latency_ms,
            "response_digest": self.response_digest,
            "usage": {
                "input_tokens": self.usage.input_tokens,
                "cached_input_tokens": self.usage.cached_input_tokens,
                "output_tokens": self.usage.output_tokens,
                "reasoning_tokens": self.usage.reasoning_tokens,
            },
            "provider_reported_cost": {
                "currency": self.currency,
                "total_usd": self.provider_reported_cost_usd,
            },
            "run_record_digest": self.run_record_digest,
            "content_digest": self.content_digest,
        }

    def canonical_bytes(self) -> bytes:
        return canonical_json_bytes(self.to_dict())

    def _validate_relationships(self) -> None:
        if self.ended_at < self.started_at:
            raise SchemaError("attempt metadata end time cannot precede its start time")
        if (
            self.usage.input_tokens is not None
            and self.usage.cached_input_tokens is not None
            and self.usage.cached_input_tokens > self.usage.input_tokens
        ):
            raise SchemaError("attempt metadata cached input exceeds total input")
        content = self.to_dict()
        content.pop("content_digest")
        if self.content_digest != canonical_digest(content):
            raise SchemaError("attempt metadata content digest does not match")


def build_attempt_metadata(
    *,
    experiment_id: str,
    experiment_content_digest: str,
    run_id: str,
    attempt: int,
    request_digest: str,
    provider: str,
    model: str,
    provider_request_id: str | None,
    started_at: datetime,
    ended_at: datetime,
    monotonic_latency_ms: float,
    response_digest: str,
    usage: TokenUsage,
    provider_reported_cost_usd: float | None,
    run_record_digest: str,
) -> AttemptMetadata:
    """Build and reparse a canonical record through the public trust boundary."""

    document: dict[str, JsonValue] = {
        "schema_version": "1.0",
        "experiment_id": experiment_id,
        "experiment_content_digest": experiment_content_digest,
        "run_id": run_id,
        "attempt": attempt,
        "request_digest": request_digest,
        "provider": provider,
        "model": model,
        "provider_request_id": provider_request_id,
        "started_at": _iso_string(started_at),
        "ended_at": _iso_string(ended_at),
        "monotonic_latency_ms": monotonic_latency_ms,
        "response_digest": response_digest,
        "usage": {
            "input_tokens": usage.input_tokens,
            "cached_input_tokens": usage.cached_input_tokens,
            "output_tokens": usage.output_tokens,
            "reasoning_tokens": usage.reasoning_tokens,
        },
        "provider_reported_cost": {
            "currency": "USD",
            "total_usd": provider_reported_cost_usd,
        },
        "run_record_digest": run_record_digest,
    }
    document["content_digest"] = canonical_digest(document)
    return AttemptMetadata.from_dict(cast(dict[str, Any], document))


def _parse_timestamp(value: str) -> datetime:
    if not value.endswith("Z"):
        raise SchemaError("attempt metadata timestamp must be canonical UTC")
    try:
        parsed = datetime.fromisoformat(value.removesuffix("Z") + "+00:00")
    except ValueError as exc:
        raise SchemaError("attempt metadata timestamp is invalid") from exc
    if _iso_string(parsed) != value:
        raise SchemaError("attempt metadata timestamp must be canonical UTC")
    return parsed


def _iso_string(value: datetime) -> str:
    if value.tzinfo is None or value.utcoffset() is None:
        raise SchemaError("attempt metadata timestamp must include a timezone")
    return value.astimezone(UTC).isoformat().replace("+00:00", "Z")


def _optional_float(value: object) -> float | None:
    if value is None:
        return None
    if isinstance(value, bool) or not isinstance(value, int | float):
        raise ValueError
    # Keep integral JSON numbers integral so a parsed record remains byte-stable.
    return cast(float, value)
