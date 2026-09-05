"""Reviewer-safe parsing of serialized request identity and envelope contracts."""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from typing import cast

from preflight_evals.canonical import JsonValue, canonical_json_bytes, sha256_digest
from preflight_evals.errors import LeakageError

_REQUEST_IDENTITY = re.compile(r"hmac-sha256:[0-9a-f]{64}")


@dataclass(frozen=True, slots=True)
class RequestBinding:
    request_identity: str | None
    case_id: str | None
    snapshot: str | None
    bundle_digest: str


def request_binding(request_bytes: bytes) -> RequestBinding:
    """Return the versioned reviewer bundle identity and digest."""

    document = _request_document(request_bytes)
    bundle = document.get("repository_context")
    if not isinstance(bundle, dict):
        raise LeakageError("serialized reviewer request has an unsupported shape")
    version = bundle.get("schema_version")
    request_identity = bundle.get("request_identity")
    case_id = bundle.get("case_id")
    snapshot = bundle.get("snapshot")
    if version == "2":
        if (
            not isinstance(request_identity, str)
            or _REQUEST_IDENTITY.fullmatch(request_identity) is None
            or case_id is not None
            or snapshot is not None
        ):
            raise LeakageError("serialized reviewer request has an unsupported context identity")
        return RequestBinding(
            request_identity=request_identity,
            case_id=None,
            snapshot=None,
            bundle_digest=sha256_digest(canonical_json_bytes(cast(JsonValue, bundle))),
        )
    if (
        version != "1"
        or not isinstance(case_id, str)
        or snapshot
        not in {
            "vulnerable",
            "fixed",
        }
    ):
        raise LeakageError("serialized reviewer request has an unsupported context identity")
    return RequestBinding(
        request_identity=None,
        case_id=case_id,
        snapshot=cast(str, snapshot),
        bundle_digest=sha256_digest(canonical_json_bytes(cast(JsonValue, bundle))),
    )


def _request_document(request_bytes: bytes) -> dict[str, object]:
    try:
        document = json.loads(request_bytes)
    except (UnicodeError, json.JSONDecodeError) as exc:
        raise LeakageError("serialized reviewer request is not valid JSON") from exc
    if not isinstance(document, dict):
        raise LeakageError("serialized reviewer request is not canonical")
    try:
        canonical = canonical_json_bytes(cast(JsonValue, document))
    except (TypeError, ValueError) as exc:
        raise LeakageError("serialized reviewer request is not canonical") from exc
    if canonical != request_bytes:
        raise LeakageError("serialized reviewer request is not canonical")
    if set(document) != {
        "schema_version",
        "prompt_template",
        "profile_template",
        "repository_context",
        "reviewer_config",
    }:
        raise LeakageError("serialized reviewer request has an unsupported shape")
    return cast(dict[str, object], document)
