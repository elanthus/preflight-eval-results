from __future__ import annotations

import math

import pytest

from preflight_evals.canonical import JsonValue, canonical_digest, canonical_json_bytes


def test_canonical_json_is_byte_stable() -> None:
    left: JsonValue = {"z": ["snowman ☃", 2], "a": {"enabled": True}}
    right: JsonValue = {"a": {"enabled": True}, "z": ["snowman ☃", 2]}

    expected = b'{"a":{"enabled":true},"z":["snowman \xe2\x98\x83",2]}'
    assert canonical_json_bytes(left) == expected
    assert canonical_json_bytes(right) == expected
    assert canonical_digest(left) == canonical_digest(right)
    assert canonical_digest(left) == canonical_digest(left)


def test_non_finite_numbers_fail_closed() -> None:
    with pytest.raises(ValueError, match="Out of range float values"):
        canonical_json_bytes({"unsafe": math.nan})


def test_supported_sequence_type_is_explicit() -> None:
    value: JsonValue = ("alpha", 2, None)

    assert canonical_json_bytes(value) == b'["alpha",2,null]'
