"""Canonical JSON serialization and content digests."""

from __future__ import annotations

import hashlib
import json

type JsonScalar = bool | int | float | str | None
type JsonValue = JsonScalar | list[JsonValue] | tuple[JsonValue, ...] | dict[str, JsonValue]


def canonical_json_bytes(value: JsonValue) -> bytes:
    """Serialize JSON deterministically as UTF-8 with no insignificant whitespace."""

    return json.dumps(
        value,
        ensure_ascii=False,
        allow_nan=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")


def sha256_digest(value: bytes) -> str:
    """Return a lowercase, algorithm-prefixed SHA-256 digest."""

    return f"sha256:{hashlib.sha256(value).hexdigest()}"


def canonical_digest(value: JsonValue) -> str:
    """Hash the canonical JSON representation of *value*."""

    return sha256_digest(canonical_json_bytes(value))
