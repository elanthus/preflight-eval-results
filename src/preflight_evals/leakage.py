"""Scorer-capable, fail-closed reviewer-request leakage validation."""

from __future__ import annotations

import hashlib
import hmac
import json
import re
import unicodedata
from collections.abc import Iterable
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Literal, cast

from preflight_evals.bundle import (
    BundleBuild,
    BundleDraft,
    RequestComponent,
)
from preflight_evals.canonical import (
    JsonValue,
    canonical_digest,
    canonical_json_bytes,
    sha256_digest,
)
from preflight_evals.curator_models import CaseRecord
from preflight_evals.errors import BundleError, LeakageError, SchemaError
from preflight_evals.model_types import SnapshotName
from preflight_evals.request_contract import _request_document
from preflight_evals.request_contract import request_binding as request_binding
from preflight_evals.reviewer_models import LeakageMatch, LeakageResult, PromptManifest
from preflight_evals.scorer_models import GoldRecord, LeakageException, LeakagePolicy

type LeakageLocation = Literal[
    "serialized_request",
    "profile",
    "filename",
    "tool_configuration",
    "context_bundle",
]
type MatchMode = Literal["sha", "fingerprint", "phrase", "token", "pull_request_token"]

SENSITIVE_SHA = "LEAKAGE_SENSITIVE_SHA"
EXPECTED_PHRASE = "LEAKAGE_EXPECTED_PHRASE"
REPAIR_TEXT = "LEAKAGE_REPAIR_TEXT"
FIXED_FINGERPRINT = "LEAKAGE_FIXED_FINGERPRINT"
EVIDENCE_FRAGMENT = "LEAKAGE_EVIDENCE_FRAGMENT"
SNAPSHOT_LABEL = "LEAKAGE_SNAPSHOT_LABEL"

_HEX_TOKEN = re.compile(r"(?<![0-9a-f])([0-9a-f]{7,40})(?![0-9a-f])", re.IGNORECASE)
_FINGERPRINT_TOKEN = re.compile(
    r"(?<![0-9a-f])(?:sha256:)?([0-9a-f]{64})(?![0-9a-f])", re.IGNORECASE
)
_PULL_REQUEST_TOKEN = re.compile(r"(?<![a-z0-9_])pr[0-9]+(?![a-z0-9_])", re.IGNORECASE)
_REQUEST_IDENTITY = re.compile(r"hmac-sha256:[0-9a-f]{64}")


@dataclass(frozen=True, slots=True)
class _ForbiddenValue:
    rule_id: str
    mode: MatchMode
    value: str
    value_digest: str


@dataclass(frozen=True, slots=True)
class ForbiddenContentIndex:
    """Case-scoped raw forbidden material retained only inside the leakage process."""

    case_id: str
    policy_version: str
    entries: tuple[_ForbiddenValue, ...]
    index_digest: str
    match_key: bytes


@dataclass(frozen=True, slots=True)
class AuditMatch:
    rule_id: str
    location_class: LeakageLocation
    match_digest: str
    exception_id: str | None

    def to_dict(self) -> dict[str, JsonValue]:
        document: dict[str, JsonValue] = {
            "rule_id": self.rule_id,
            "location_class": self.location_class,
            "match_digest": self.match_digest,
        }
        if self.exception_id is not None:
            document["exception_id"] = self.exception_id
        return document


@dataclass(frozen=True, slots=True)
class LeakageAudit:
    schema_version: str
    case_id: str
    policy_version: str
    passed: bool
    index_digest: str
    matches: tuple[AuditMatch, ...]

    @property
    def rule_ids(self) -> tuple[str, ...]:
        return tuple(sorted({match.rule_id for match in self.matches}))

    def to_dict(self) -> dict[str, JsonValue]:
        return {
            "schema_version": self.schema_version,
            "policy_version": self.policy_version,
            "passed": self.passed,
            "index_digest": self.index_digest,
            "rule_ids": list(self.rule_ids),
            "matches": [match.to_dict() for match in self.matches],
        }

    def canonical_bytes(self) -> bytes:
        return canonical_json_bytes(self.to_dict())


def derive_request_identity(case: CaseRecord, gold: GoldRecord, snapshot: SnapshotName) -> str:
    """Derive one opaque reviewer identity from scorer-only case and gold material."""

    if case.case_id != gold.case_id:
        raise LeakageError("request identity inputs do not identify the same case")
    if snapshot not in {"vulnerable", "fixed"}:
        raise LeakageError("request identity snapshot is unsupported")
    selected_commit = case.vulnerable_snapshot if snapshot == "vulnerable" else case.fixed_snapshot
    private_commits: dict[str, JsonValue] = {
        name: value
        for name, value in (
            ("base", case.commits.base),
            ("vulnerable", case.commits.vulnerable),
            ("repair", case.commits.repair),
            ("fixed", case.commits.fixed),
        )
        if value != selected_commit
    }
    private_key_material = canonical_json_bytes(
        {
            "unselected_curator_commits": private_commits,
            "gold_content_digest": canonical_digest(gold.to_dict()),
        }
    )
    key = hmac.new(
        b"preflight-evals-request-identity-key-v1\0",
        private_key_material,
        hashlib.sha256,
    ).digest()
    message = f"preflight-evals-request-identity-v1\0{case.case_id}\0{snapshot}".encode()
    return f"hmac-sha256:{hmac.new(key, message, hashlib.sha256).hexdigest()}"


def resolve_request_identity(
    identity: str,
    candidates: Iterable[tuple[CaseRecord, GoldRecord]],
) -> tuple[str, SnapshotName]:
    """Resolve an opaque identity against explicit scorer-supplied private candidates."""

    if _REQUEST_IDENTITY.fullmatch(identity) is None:
        raise LeakageError("request identity does not uniquely match the supplied candidates")
    matches: list[tuple[str, SnapshotName]] = []
    for case, gold in candidates:
        for snapshot in ("vulnerable", "fixed"):
            if hmac.compare_digest(derive_request_identity(case, gold, snapshot), identity):
                matches.append((case.case_id, snapshot))
    if len(matches) != 1:
        raise LeakageError("request identity does not uniquely match the supplied candidates")
    return matches[0]


@dataclass(frozen=True, slots=True)
class _ApprovedBundleBuild(BundleBuild):
    """Private capability produced only by this module's complete approval path."""


def default_policy(case_id: str) -> LeakagePolicy:
    """Return the versioned no-exception policy for a case."""

    return LeakagePolicy(
        schema_version="1.0",
        policy_version="leakage-v1",
        case_id=case_id,
        additional_sensitive_shas=(),
        repair_texts=(),
        evidence_fragments=(),
        exceptions=(),
    )


def build_forbidden_index(
    case: CaseRecord,
    gold: GoldRecord,
    policy: LeakagePolicy,
    *,
    reviewer_source_commit: str,
) -> ForbiddenContentIndex:
    """Build a deterministic index without serializing its raw values."""

    if case.case_id != gold.case_id or case.case_id != policy.case_id:
        raise LeakageError("leakage inputs do not identify the same case")
    if reviewer_source_commit not in {case.vulnerable_snapshot, case.fixed_snapshot}:
        raise LeakageError("leakage source commit is not a declared case snapshot")
    values: list[tuple[str, MatchMode, str]] = []
    sensitive_shas = {
        case.commits.base,
        case.commits.vulnerable,
        case.commits.repair,
        case.commits.fixed,
    }
    sensitive_shas.discard(reviewer_source_commit)
    sensitive_shas.update(policy.additional_sensitive_shas)
    values.extend((SENSITIVE_SHA, "sha", value.lower()) for value in sensitive_shas)
    values.extend(
        (EXPECTED_PHRASE, "phrase", _normalize_phrase(value))
        for value in gold.forbidden_expected_phrases
    )
    values.extend(
        (REPAIR_TEXT, "phrase", _normalize_phrase(value)) for value in policy.repair_texts
    )
    values.extend(
        (FIXED_FINGERPRINT, "fingerprint", fingerprint.digest.lower())
        for fingerprint in gold.fixed_only_fingerprints
    )
    evidence_values = (
        *(mechanism.provenance.excerpt for mechanism in gold.expected_mechanisms),
        *policy.evidence_fragments,
    )
    values.extend(
        (EVIDENCE_FRAGMENT, "phrase", _normalize_phrase(value)) for value in evidence_values
    )
    values.extend((SNAPSHOT_LABEL, "phrase", value) for value in ("vulnerable", "fixed"))
    values.append((SNAPSHOT_LABEL, "token", case.case_id.casefold()))
    values.append((SNAPSHOT_LABEL, "pull_request_token", "pr<digits>"))

    entries: list[_ForbiddenValue] = []
    seen: set[tuple[str, MatchMode, str]] = set()
    for rule_id, mode, value in values:
        if not value:
            raise LeakageError("leakage source normalizes to an empty value")
        key = (rule_id, mode, value)
        if key in seen:
            continue
        seen.add(key)
        entries.append(
            _ForbiddenValue(
                rule_id=rule_id,
                mode=mode,
                value=value,
                value_digest=_value_digest(rule_id, value),
            )
        )
    return _assemble_index(case.case_id, policy.policy_version, tuple(entries))


# Frozen manifest 1.2 uses exactly these rule/mode pairs, independent of future rules.
_LEGACY_RULE_SET = frozenset(
    {
        (SENSITIVE_SHA, "sha"),
        (EXPECTED_PHRASE, "phrase"),
        (REPAIR_TEXT, "phrase"),
        (FIXED_FINGERPRINT, "fingerprint"),
        (EVIDENCE_FRAGMENT, "phrase"),
    }
)


def legacy_forbidden_index(index: ForbiddenContentIndex) -> ForbiddenContentIndex:
    """Assemble the declared historical rule set for immutable manifest 1.2 artifacts."""
    entries = tuple(
        entry for entry in index.entries if (entry.rule_id, entry.mode) in _LEGACY_RULE_SET
    )
    return _assemble_index(index.case_id, index.policy_version, entries)


def _assemble_index(
    case_id: str, policy_version: str, entries: tuple[_ForbiddenValue, ...]
) -> ForbiddenContentIndex:
    entries = tuple(
        sorted(entries, key=lambda entry: (entry.rule_id, entry.mode, entry.value_digest))
    )
    safe_entries: list[JsonValue] = [
        {"rule_id": entry.rule_id, "mode": entry.mode, "value_digest": entry.value_digest}
        for entry in entries
    ]
    private_entries: list[JsonValue] = [
        {"rule_id": entry.rule_id, "mode": entry.mode, "value": entry.value} for entry in entries
    ]
    match_key = hashlib.sha256(
        b"leakage-audit-key-v1\0"
        + case_id.encode()
        + b"\0"
        + policy_version.encode()
        + b"\0"
        + canonical_json_bytes(private_entries)
    ).digest()
    return ForbiddenContentIndex(
        case_id=case_id,
        policy_version=policy_version,
        entries=entries,
        index_digest=canonical_digest(
            {
                "case_id": case_id,
                "policy_version": policy_version,
                "entries": safe_entries,
            }
        ),
        match_key=match_key,
    )


def scan_components(
    components: tuple[RequestComponent, ...],
    index: ForbiddenContentIndex,
    policy: LeakagePolicy,
    *,
    checked_at: datetime,
) -> LeakageAudit:
    """Scan every component and apply only exact, unexpired exception selectors."""

    if checked_at.utcoffset() is None:
        raise LeakageError("leakage check time must include a timezone")
    if index.case_id != policy.case_id or index.policy_version != policy.policy_version:
        raise LeakageError("leakage policy does not match the forbidden index")
    exceptions = _active_exceptions(policy.exceptions, checked_at)
    observed: dict[tuple[str, str, str], AuditMatch] = {}
    for component in components:
        location = _location(component.location_class)
        try:
            text = component.payload.decode("utf-8")
        except UnicodeDecodeError as exc:
            raise LeakageError("reviewer request component is not valid UTF-8") from exc
        normalized = _normalize_phrase(text)
        label_text = _snapshot_label_surface(location, text)
        for entry in index.entries:
            if entry.rule_id == SNAPSHOT_LABEL and entry.mode == "phrase":
                if label_text is None:
                    continue
                matches_for_entry = _find_matches(entry, label_text, _normalize_phrase(label_text))
            else:
                matches_for_entry = _find_matches(entry, text, normalized)
            for matched_value in matches_for_entry:
                digest = _match_digest(index, entry.rule_id, matched_value)
                selector = (entry.rule_id, location, digest)
                exception = exceptions.get(selector)
                observed[selector] = AuditMatch(
                    rule_id=entry.rule_id,
                    location_class=location,
                    match_digest=digest,
                    exception_id=exception.exception_id if exception is not None else None,
                )
    matches = tuple(
        sorted(
            observed.values(),
            key=lambda match: (
                match.rule_id,
                match.location_class,
                match.match_digest,
                match.exception_id or "",
            ),
        )
    )
    return LeakageAudit(
        schema_version="1",
        case_id=index.case_id,
        policy_version=index.policy_version,
        passed=all(match.exception_id is not None for match in matches),
        index_digest=index.index_digest,
        matches=matches,
    )


def scan_serialized_request(
    request_bytes: bytes,
    index: ForbiddenContentIndex,
    policy: LeakagePolicy,
    *,
    checked_at: datetime,
) -> LeakageAudit:
    """Parse canonical request bytes and scan the same surfaces used during bundling."""

    return scan_components(request_components(request_bytes), index, policy, checked_at=checked_at)


def approve_bundle(
    draft: BundleDraft,
    index: ForbiddenContentIndex,
    policy: LeakagePolicy,
) -> BundleBuild:
    """Scan at trusted current UTC and return the reviewer adapter boundary type."""

    return _approve_bundle_at(draft, index, policy, checked_at=datetime.now(UTC))


def reapprove_bundle_artifacts(
    bundle_bytes: bytes,
    request_bytes: bytes,
    manifest_bytes: bytes,
    index: ForbiddenContentIndex,
    policy: LeakagePolicy,
) -> BundleBuild:
    """Re-scan persisted canonical artifacts and recover the approved adapter capability."""

    try:
        raw_manifest = json.loads(manifest_bytes)
        raw_bundle = json.loads(bundle_bytes)
        if (
            not isinstance(raw_manifest, dict)
            or not isinstance(raw_bundle, dict)
            or canonical_json_bytes(cast(JsonValue, raw_manifest)) != manifest_bytes
            or canonical_json_bytes(cast(JsonValue, raw_bundle)) != bundle_bytes
        ):
            raise ValueError
        manifest = PromptManifest.from_dict(cast(dict[str, object], raw_manifest))
    except (UnicodeError, json.JSONDecodeError, TypeError, ValueError, SchemaError) as exc:
        raise LeakageError("persisted reviewer artifacts are invalid") from exc
    try:
        binding = request_binding(request_bytes)
    except LeakageError as exc:
        raise LeakageError(
            "persisted reviewer artifacts do not match their prompt manifest"
        ) from exc
    if (
        manifest.schema_version not in {"1.2", "1.3"}
        or not manifest.leakage.passed
        or manifest.bundle_digest != sha256_digest(bundle_bytes)
        or manifest.request_digest != sha256_digest(request_bytes)
        or binding.bundle_digest != manifest.bundle_digest
        or (
            manifest.schema_version == "1.2"
            and (binding.case_id, binding.snapshot) != (manifest.case_id, manifest.snapshot)
        )
        or (
            manifest.schema_version == "1.3"
            and binding.request_identity != manifest.request_identity
        )
    ):
        raise LeakageError("persisted reviewer artifacts do not match their prompt manifest")
    seed_document = cast(dict[str, JsonValue], dict(raw_manifest))
    for field in ("created_at", "content_digest", "leakage"):
        seed_document.pop(field, None)
    draft = BundleDraft(
        bundle_bytes=bundle_bytes,
        request_bytes=request_bytes,
        manifest_seed_bytes=canonical_json_bytes(seed_document),
        created_at=manifest.created_at.isoformat().replace("+00:00", "Z"),
        bundle_digest=manifest.bundle_digest,
        request_digest=manifest.request_digest,
        context_entry_digest=cast(str, manifest.context_entry_digest),
        entry_count=len(manifest.bundle_entries),
        context_byte_count=cast(int, manifest.context_byte_count),
        context_token_count=cast(int, manifest.context_token_count),
        bundle_token_count=cast(int, manifest.bundle_token_count),
        scan_components=request_components(request_bytes),
    )
    approval_index = legacy_forbidden_index(index) if manifest.schema_version == "1.2" else index
    approved = approve_bundle(draft, approval_index, policy)
    if approved.manifest_bytes != manifest_bytes:
        raise LeakageError("persisted reviewer leakage approval is stale or inconsistent")
    return approved


def _approve_bundle_at(
    draft: BundleDraft,
    index: ForbiddenContentIndex,
    policy: LeakagePolicy,
    *,
    checked_at: datetime,
) -> BundleBuild:
    """Approve at an injected time for deterministic tests; production owns its clock."""

    audit = scan_components(draft.scan_components, index, policy, checked_at=checked_at)
    if not audit.passed:
        raise LeakageError(
            "reviewer request failed leakage validation", audit_bytes=audit.canonical_bytes()
        )
    approved_matches = tuple(
        LeakageMatch(
            rule_id=match.rule_id,
            location_class=match.location_class,
            match_digest=match.match_digest,
            exception_id=cast(str, match.exception_id),
        )
        for match in audit.matches
    )
    result = LeakageResult(
        policy_version=audit.policy_version,
        passed=True,
        rule_ids=tuple(sorted({match.rule_id for match in approved_matches})),
        index_digest=audit.index_digest,
        approved_matches=approved_matches,
    )
    return _finalize_approved_bundle(draft, result)


def _finalize_approved_bundle(draft: BundleDraft, leakage: LeakageResult) -> BundleBuild:
    """Construct the private approved capability after this module's successful scan."""

    if not leakage.passed or leakage.index_digest is None:  # pragma: no cover - invariant
        raise BundleError("prompt manifest requires a passing leakage validation")
    try:
        loaded = json.loads(draft.manifest_seed_bytes)
    except (UnicodeError, json.JSONDecodeError) as exc:  # pragma: no cover - internal bytes
        raise BundleError("prompt manifest seed is invalid") from exc
    if not isinstance(loaded, dict):  # pragma: no cover - internal canonical object
        raise BundleError("prompt manifest seed is invalid")
    manifest_content = cast(dict[str, JsonValue], loaded)
    manifest_content["leakage"] = leakage.to_dict()
    manifest_digest = canonical_digest(manifest_content)
    manifest_document: dict[str, JsonValue] = {
        **manifest_content,
        "created_at": draft.created_at,
        "content_digest": manifest_digest,
    }
    PromptManifest.from_dict(cast(dict[str, object], manifest_document))
    return _ApprovedBundleBuild(
        draft=draft,
        manifest_bytes=canonical_json_bytes(manifest_document),
        manifest_digest=manifest_digest,
        leakage=leakage,
    )


def request_components(request_bytes: bytes) -> tuple[RequestComponent, ...]:
    """Validate and label a fully serialized request without exposing its values."""

    document = _request_document(request_bytes)
    profile = document.get("profile_template")
    prompt = document.get("prompt_template")
    bundle = document.get("repository_context")
    reviewer_config = document.get("reviewer_config")
    if (
        not isinstance(prompt, str)
        or not isinstance(profile, str)
        or not isinstance(bundle, dict)
        or not isinstance(reviewer_config, dict)
    ):
        raise LeakageError("serialized reviewer request has an unsupported shape")
    entries = bundle.get("entries")
    if not isinstance(entries, list):
        raise LeakageError("serialized reviewer request has an unsupported context shape")
    filenames: list[RequestComponent] = []
    context_contents: list[RequestComponent] = []
    for item in entries:
        if (
            not isinstance(item, dict)
            or not isinstance(item.get("path"), str)
            or not isinstance(item.get("content"), str)
        ):
            raise LeakageError("serialized reviewer request has an unsupported context shape")
        filenames.append(RequestComponent("filename", cast(str, item["path"]).encode("utf-8")))
        context_contents.append(
            RequestComponent("context_bundle", cast(str, item["content"]).encode("utf-8"))
        )
    tool_values = tuple(
        RequestComponent("tool_configuration", value.encode("utf-8"))
        for value in reviewer_config.values()
        if isinstance(value, str)
    )
    return (
        RequestComponent("serialized_request", request_bytes),
        RequestComponent("serialized_request", prompt.encode("utf-8")),
        RequestComponent("profile", profile.encode("utf-8")),
        *filenames,
        RequestComponent(
            "tool_configuration", canonical_json_bytes(cast(JsonValue, reviewer_config))
        ),
        *tool_values,
        RequestComponent("context_bundle", canonical_json_bytes(cast(JsonValue, bundle))),
        *context_contents,
    )


def _snapshot_label_surface(location: LeakageLocation, text: str) -> str | None:
    """Exclude only repository-owned paths and contents, including their JSON copies."""
    if location in {"context_bundle", "filename"}:
        return None
    if location != "serialized_request":
        return text
    try:
        document = json.loads(text)
    except json.JSONDecodeError:
        return text
    if not isinstance(document, dict) or not isinstance(document.get("repository_context"), dict):
        return text
    bundle = document["repository_context"]
    entries = bundle.get("entries")
    if isinstance(entries, list):
        bundle["entries"] = [
            {key: value for key, value in item.items() if key not in {"path", "content"}}
            if isinstance(item, dict)
            else item
            for item in entries
        ]
    return canonical_json_bytes(cast(JsonValue, document)).decode("utf-8")


def _find_matches(entry: _ForbiddenValue, text: str, normalized: str) -> tuple[str, ...]:
    if entry.mode == "phrase":
        padded_haystack = f" {normalized} "
        return (entry.value,) if f" {entry.value} " in padded_haystack else ()
    if entry.mode == "sha":
        candidates = {
            match.group(1).lower()
            for match in _HEX_TOKEN.finditer(text)
            if entry.value.startswith(match.group(1).lower())
        }
        return tuple(sorted(candidates))
    if entry.mode == "token":
        token = re.compile(rf"(?<![a-z0-9-]){re.escape(entry.value)}(?![a-z0-9-])", re.IGNORECASE)
        return (entry.value,) if token.search(unicodedata.normalize("NFKC", text)) else ()
    if entry.mode == "pull_request_token":
        return tuple(
            sorted({match.group(0).casefold() for match in _PULL_REQUEST_TOKEN.finditer(text)})
        )
    expected = entry.value.removeprefix("sha256:")
    candidates = {
        match.group(1).lower()
        for match in _FINGERPRINT_TOKEN.finditer(text)
        if match.group(1).lower() == expected
    }
    return tuple(sorted(candidates))


def _active_exceptions(
    exceptions: tuple[LeakageException, ...], checked_at: datetime
) -> dict[tuple[str, str, str], LeakageException]:
    active: dict[tuple[str, str, str], LeakageException] = {}
    for exception in exceptions:
        if exception.expires_at <= checked_at:
            continue
        key = (exception.rule_id, exception.location_class, exception.match_digest)
        active[key] = exception
    return active


def _normalize_phrase(value: str) -> str:
    normalized = unicodedata.normalize("NFKC", value).casefold()
    tokens: list[str] = []
    current: list[str] = []
    for character in normalized:
        if character.isalnum():
            current.append(character)
        elif current:
            tokens.append("".join(current))
            current = []
    if current:
        tokens.append("".join(current))
    return " ".join(tokens)


def _value_digest(rule_id: str, normalized_value: str) -> str:
    return sha256_digest(f"leakage-index-v1\0{rule_id}\0{normalized_value}".encode())


def _match_digest(index: ForbiddenContentIndex, rule_id: str, normalized_value: str) -> str:
    payload = f"leakage-match-v1\0{rule_id}\0{normalized_value}".encode()
    return f"sha256:{hmac.new(index.match_key, payload, hashlib.sha256).hexdigest()}"


def _location(value: str) -> LeakageLocation:
    if value not in {
        "serialized_request",
        "profile",
        "filename",
        "tool_configuration",
        "context_bundle",
    }:
        raise LeakageError("reviewer request component has an unsupported location class")
    return cast(LeakageLocation, value)
