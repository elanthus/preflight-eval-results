from __future__ import annotations

import json
from dataclasses import replace
from datetime import UTC, datetime, timedelta, tzinfo
from importlib import metadata
from pathlib import Path
from typing import Any, Self, cast

import pytest

import preflight_evals.bundle as bundle_module
import preflight_evals.leakage as leakage_module
from preflight_evals.bundle import (
    BundleBuild,
    BundleDraft,
    RequestComponent,
    ReviewerSettings,
    TemplateInput,
    build_bundle,
)
from preflight_evals.canonical import canonical_json_bytes, sha256_digest
from preflight_evals.curator_models import CaseRecord
from preflight_evals.errors import BundleError, LeakageError, SchemaError
from preflight_evals.leakage import (
    EVIDENCE_FRAGMENT,
    EXPECTED_PHRASE,
    FIXED_FINGERPRINT,
    REPAIR_TEXT,
    SENSITIVE_SHA,
    SNAPSHOT_LABEL,
    ForbiddenContentIndex,
    _approve_bundle_at,
    approve_bundle,
    build_forbidden_index,
    derive_request_identity,
    legacy_forbidden_index,
    reapprove_bundle_artifacts,
    request_binding,
    request_components,
    resolve_request_identity,
    scan_components,
)
from preflight_evals.reviewer_models import PromptManifest
from preflight_evals.scorer_models import GoldRecord, LeakageException, LeakagePolicy

TOKENIZER = f"tiktoken/o200k_base@{metadata.version('tiktoken')}/per_file_utf8_sum_v1"
CHECKED_AT = datetime(2026, 8, 18, 12, 30, tzinfo=UTC)


def _case_document() -> dict[str, object]:
    return {
        "schema_version": "1.0",
        "case_id": "synthetic-leakage-case",
        "display_name": "Synthetic leakage case",
        "defect_category": "security",
        "source": {"repository": "synthetic/example", "pull_request": 9},
        "commits": {
            "base": "0" * 40,
            "vulnerable": "a" * 40,
            "repair": "b" * 40,
            "fixed": "c" * 40,
        },
        "snapshots": {
            "vulnerable": {"commit": "a" * 40},
            "fixed": {"commit": "c" * 40},
        },
        "context_policy": {
            "includes": ["src"],
            "excludes": [],
            "per_file_byte_limit": 100_000,
            "per_file_token_limit": 16_000,
            "total_token_limit": 24_000,
            "symlink_policy": "reject",
            "binary_policy": "omit",
            "truncation_policy": "reject",
        },
        "eligibility": "development",
        "verification": {
            "status": "verified",
            "verifier": "synthetic-verifier",
            "verified_at": "2026-08-18",
            "method": "synthetic fixture",
        },
        "estimated_input": {
            "tokenizer": TOKENIZER,
            "vulnerable_tokens": 10,
            "fixed_tokens": 10,
        },
    }


def _gold_document() -> dict[str, object]:
    return {
        "schema_version": "1.0",
        "case_id": "synthetic-leakage-case",
        "expected_behavior": {"vulnerable": "Synthetic bad", "fixed": "Synthetic good"},
        "expected_mechanisms": [
            {
                "mechanism_id": "mechanism-synthetic",
                "description": "Synthetic expected mechanism",
                "adjudication_rubric": "Match only the synthetic mechanism",
            }
        ],
        "acceptable_locations": [{"path": "src/example.py"}],
        "accepted_defect_categories": ["security"],
        "severity_range": {"minimum": "medium", "maximum": "critical"},
        "forbidden_expected_phrases": ["Resume state already closed"],
        "fixed_only_fingerprints": [
            {
                "digest": f"sha256:{'d' * 64}",
                "source_path": "src/example.py",
                "source_record_id": "synthetic-record",
            }
        ],
        "provenance": {
            "excerpt": "Evidence ledger fragment alpha",
            "source_record_id": "synthetic-record",
        },
        "curator_notes": "Synthetic only",
        "adjudication": {"required": True, "accepted_alternative_matches": []},
    }


def _case() -> CaseRecord:
    return CaseRecord.from_dict(_case_document())


def _gold() -> GoldRecord:
    return GoldRecord.from_dict(_gold_document())


def _gold_v2() -> GoldRecord:
    fixture = Path(__file__).parent / "fixtures" / "gold-v2.json"
    document = json.loads(fixture.read_text(encoding="utf-8"))
    document["case_id"] = "synthetic-leakage-case"
    return GoldRecord.from_dict(document)


def _policy(*, exceptions: tuple[LeakageException, ...] = ()) -> LeakagePolicy:
    return LeakagePolicy(
        schema_version="1.0",
        policy_version="leakage-v1",
        case_id="synthetic-leakage-case",
        additional_sensitive_shas=("e" * 40,),
        repair_texts=("Repair skips reopened finding",),
        evidence_fragments=("Known evidence fragment beta",),
        exceptions=exceptions,
    )


def _index(
    policy: LeakagePolicy | None = None,
) -> tuple[ForbiddenContentIndex, LeakagePolicy]:
    selected = policy or _policy()
    return (
        build_forbidden_index(_case(), _gold(), selected, reviewer_source_commit="a" * 40),
        selected,
    )


def test_gold_2_leakage_index_includes_every_mechanism_provenance() -> None:
    policy = _policy()
    index = build_forbidden_index(_case(), _gold_v2(), policy, reviewer_source_commit="a" * 40)

    for excerpt in (b"Synthetic primary provenance", b"Synthetic supplemental provenance"):
        audit = scan_components(
            (RequestComponent("profile", excerpt),),
            index,
            policy,
            checked_at=CHECKED_AT,
        )
        assert not audit.passed
        assert audit.rule_ids == (EVIDENCE_FRAGMENT,)


def _draft(
    tmp_path: Path,
    *,
    profile: str = "Use a careful review profile.",
    prompt: str = "Review the repository.\n",
    context: str = "safe_context = True\n",
) -> BundleDraft:
    source = tmp_path / "src"
    source.mkdir(parents=True)
    (source / "example.py").write_text(context, encoding="utf-8")
    case = _case()
    return build_bundle(
        case.to_reviewer_case("vulnerable"),
        "vulnerable",
        "baseline",
        request_identity=derive_request_identity(case, _gold(), "vulnerable"),
        worktree=tmp_path,
        worktree_digest=bundle_module._compute_worktree_digest(tmp_path.resolve()),
        tokenizer_spec=TOKENIZER,
        prompt_template=TemplateInput("review", "1", prompt),
        profile_template=TemplateInput("baseline", "1", profile),
        reviewer_settings=ReviewerSettings(
            model="synthetic-model",
            tool_policy="read-only",
            input_token_limit=100_000,
            output_token_limit=4_000,
            temperature=0.0,
            adapter_version="synthetic-1",
        ),
        repetition=1,
        seed=42,
        request_id="request-synthetic-one",
        run_id="run-synthetic-one",
        created_at=CHECKED_AT,
    )


def test_persisted_bundle_is_reapproved_only_after_a_fresh_complete_scan(
    tmp_path: Path,
) -> None:
    draft = _draft(tmp_path)
    index, policy = _index()
    approved = approve_bundle(draft, index, policy)

    recovered = reapprove_bundle_artifacts(
        approved.bundle_bytes,
        approved.request_bytes,
        approved.manifest_bytes,
        index,
        policy,
    )

    assert recovered.manifest_bytes == approved.manifest_bytes
    with pytest.raises(LeakageError, match="do not match"):
        reapprove_bundle_artifacts(
            approved.bundle_bytes,
            approved.request_bytes + b" ",
            approved.manifest_bytes,
            index,
            policy,
        )


def test_legacy_1_2_artifacts_reapprove_with_their_historical_rule_set(
    tmp_path: Path,
) -> None:
    draft = _draft(tmp_path)
    index, policy = _index()
    bundle_document = json.loads(draft.bundle_bytes)
    bundle_document.pop("request_identity")
    bundle_document.update(
        {"schema_version": "1", "case_id": policy.case_id, "snapshot": "vulnerable"}
    )
    bundle_bytes = canonical_json_bytes(cast(Any, bundle_document))
    request_document = json.loads(draft.request_bytes)
    request_document["repository_context"] = bundle_document
    request_bytes = canonical_json_bytes(cast(Any, request_document))
    manifest_seed = json.loads(draft.manifest_seed_bytes)
    manifest_seed.pop("request_identity")
    manifest_seed.pop("bundle_schema_version")
    manifest_seed.update(
        {
            "schema_version": "1.2",
            "bundle_digest": sha256_digest(bundle_bytes),
            "bundle_byte_count": len(bundle_bytes),
            "bundle_token_count": bundle_module._load_tokenizer(TOKENIZER).count(
                bundle_bytes.decode()
            ),
            "request_digest": sha256_digest(request_bytes),
        }
    )
    legacy_draft = replace(
        draft,
        bundle_bytes=bundle_bytes,
        request_bytes=request_bytes,
        manifest_seed_bytes=canonical_json_bytes(cast(Any, manifest_seed)),
        bundle_digest=sha256_digest(bundle_bytes),
        request_digest=sha256_digest(request_bytes),
        bundle_token_count=cast(int, manifest_seed["bundle_token_count"]),
        scan_components=request_components(request_bytes),
    )
    legacy = approve_bundle(legacy_draft, legacy_forbidden_index(index), policy)

    assert not scan_components(
        legacy_draft.scan_components, index, policy, checked_at=CHECKED_AT
    ).passed
    recovered = reapprove_bundle_artifacts(
        legacy.bundle_bytes,
        legacy.request_bytes,
        legacy.manifest_bytes,
        index,
        policy,
    )
    assert recovered.manifest_bytes == legacy.manifest_bytes


INJECTIONS = (
    (SENSITIVE_SHA, "b" * 40, ("B" * 12)),
    (EXPECTED_PHRASE, "Resume state already closed", "RESUME--state\nalready CLOSED"),
    (REPAIR_TEXT, "Repair skips reopened finding", "repair...SKIPS reopened\tfinding"),
    (FIXED_FINGERPRINT, f"sha256:{'d' * 64}", "D" * 64),
    (EVIDENCE_FRAGMENT, "Evidence ledger fragment alpha", "evidence/LEDGER fragment ALPHA"),
    (SNAPSHOT_LABEL, "fixed", "FiXeD"),
)
LOCATIONS = (
    "serialized_request",
    "profile",
    "filename",
    "tool_configuration",
    "context_bundle",
)


@pytest.mark.parametrize(("rule_id", "literal", "mutation"), INJECTIONS)
@pytest.mark.parametrize("location", LOCATIONS)
def test_every_forbidden_class_and_request_component_fails_closed(
    rule_id: str, literal: str, mutation: str, location: str
) -> None:
    index, policy = _index()
    for value in (literal, mutation):
        audit = scan_components(
            (RequestComponent(location, f"prefix {value} suffix".encode()),),
            index,
            policy,
            checked_at=CHECKED_AT,
        )
        if rule_id == SNAPSHOT_LABEL and location in {"filename", "context_bundle"}:
            assert audit.passed
            continue
        assert not audit.passed
        assert rule_id in audit.rule_ids
        rendered = audit.canonical_bytes()
        assert value.encode() not in rendered
        assert literal.encode() not in rendered
        assert mutation.encode() not in rendered


@pytest.mark.parametrize(("rule_id", "_literal", "_mutation"), INJECTIONS)
def test_every_forbidden_class_has_a_negative_control(
    rule_id: str, _literal: str, _mutation: str
) -> None:
    index, policy = _index()
    audit = scan_components(
        (RequestComponent("serialized_request", b"unrelated safe content"),),
        index,
        policy,
        checked_at=CHECKED_AT,
    )
    assert audit.passed
    assert audit.matches == ()


@pytest.mark.parametrize("location", LOCATIONS)
@pytest.mark.parametrize("value", ["VULNERABLE", "synthetic-leakage-case", "PR204"])
def test_snapshot_identity_rule_covers_each_token_class(value: str, location: str) -> None:
    index, policy = _index()

    audit = scan_components(
        (RequestComponent(location, f"prefix {value} suffix".encode()),),
        index,
        policy,
        checked_at=CHECKED_AT,
    )

    if value == "VULNERABLE" and location in {"filename", "context_bundle"}:
        assert audit.passed
        return
    assert not audit.passed
    assert audit.rule_ids == (SNAPSHOT_LABEL,)
    assert value.encode() not in audit.canonical_bytes()


def test_snapshot_identity_rule_respects_token_boundaries() -> None:
    index, policy = _index()

    for value in ("invulnerable", "synthetic-leakage-case-extra", "xpr204", "pr204x"):
        audit = scan_components(
            (RequestComponent("serialized_request", value.encode()),),
            index,
            policy,
            checked_at=CHECKED_AT,
        )
        assert audit.passed


def test_request_identity_round_trip_is_private_unique_and_fail_closed() -> None:
    case = _case()
    gold = _gold()
    other_case = replace(case, case_id="demo-alpha")
    other_gold = replace(gold, case_id="demo-alpha")
    candidates = ((case, gold), (other_case, other_gold))
    vulnerable = derive_request_identity(case, gold, "vulnerable")
    fixed = derive_request_identity(case, gold, "fixed")
    other = derive_request_identity(other_case, other_gold, "vulnerable")

    assert resolve_request_identity(vulnerable, candidates) == (
        "synthetic-leakage-case",
        "vulnerable",
    )
    assert resolve_request_identity(fixed, candidates) == (
        "synthetic-leakage-case",
        "fixed",
    )
    assert len({vulnerable, fixed, other}) == 3
    with pytest.raises(LeakageError, match="does not uniquely match"):
        resolve_request_identity(f"hmac-sha256:{'9' * 64}", candidates)
    with pytest.raises(LeakageError, match="does not uniquely match"):
        resolve_request_identity("not-an-identity", candidates)


def test_request_identity_derivation_rejects_mismatched_private_inputs() -> None:
    with pytest.raises(LeakageError, match="same case"):
        derive_request_identity(_case(), replace(_gold(), case_id="demo-alpha"), "fixed")
    with pytest.raises(LeakageError, match="snapshot is unsupported"):
        derive_request_identity(_case(), _gold(), cast(Any, "unknown"))


def test_short_sha_and_exact_fingerprint_boundaries_are_conservative() -> None:
    index, policy = _index()
    short_sha = scan_components(
        (RequestComponent("profile", b"commit=BBBBBBB"),),
        index,
        policy,
        checked_at=CHECKED_AT,
    )
    assert not short_sha.passed
    assert short_sha.rule_ids == (SENSITIVE_SHA,)

    selected_snapshot = scan_components(
        (RequestComponent("serialized_request", ("a" * 40).encode()),),
        index,
        policy,
        checked_at=CHECKED_AT,
    )
    assert selected_snapshot.passed

    controls = (
        b"hex=bbbbbb",
        ("inside=" + "f" + "b" * 40 + "f").encode(),
        ("digest=" + "f" + "d" * 64 + "f").encode(),
    )
    for payload in controls:
        assert scan_components(
            (RequestComponent("profile", payload),), index, policy, checked_at=CHECKED_AT
        ).passed


def test_exception_is_exact_case_scoped_versioned_and_expiring() -> None:
    index, policy = _index()
    component = RequestComponent("profile", b"Resume state already closed")
    failed = scan_components((component,), index, policy, checked_at=CHECKED_AT)
    assert not failed.passed
    match = failed.matches[0]
    exception = LeakageException(
        exception_id="exception-synthetic-profile",
        rule_id=match.rule_id,
        location_class=match.location_class,
        match_digest=match.match_digest,
        expires_at=CHECKED_AT + timedelta(days=1),
        actor="synthetic-operator",
        reason="Narrow synthetic false positive",
    )
    approved_policy = replace(policy, exceptions=(exception,))
    approved_index = build_forbidden_index(
        _case(), _gold(), approved_policy, reviewer_source_commit="a" * 40
    )
    approved = scan_components((component,), approved_index, approved_policy, checked_at=CHECKED_AT)
    assert approved.passed
    assert approved.matches[0].exception_id == exception.exception_id

    wrong_location = replace(exception, location_class="filename")
    wrong_policy = replace(policy, exceptions=(wrong_location,))
    assert not scan_components(
        (component,),
        build_forbidden_index(_case(), _gold(), wrong_policy, reviewer_source_commit="a" * 40),
        wrong_policy,
        checked_at=CHECKED_AT,
    ).passed

    expired = replace(exception, expires_at=CHECKED_AT)
    expired_policy = replace(policy, exceptions=(expired,))
    assert not scan_components(
        (component,),
        build_forbidden_index(_case(), _gold(), expired_policy, reviewer_source_commit="a" * 40),
        expired_policy,
        checked_at=CHECKED_AT,
    ).passed

    other_case = replace(policy, case_id="other-case")
    with pytest.raises(LeakageError, match="same case"):
        build_forbidden_index(_case(), _gold(), other_case, reviewer_source_commit="a" * 40)


def test_match_digests_are_bound_to_case_and_policy_version() -> None:
    index, policy = _index()
    component = RequestComponent("profile", b"Resume state already closed")
    original = scan_components((component,), index, policy, checked_at=CHECKED_AT)

    other_case = replace(_case(), case_id="other-case")
    other_gold = replace(_gold(), case_id="other-case")
    other_policy = replace(policy, case_id="other-case")
    other_index = build_forbidden_index(
        other_case,
        other_gold,
        other_policy,
        reviewer_source_commit="a" * 40,
    )
    other = scan_components((component,), other_index, other_policy, checked_at=CHECKED_AT)

    revised_policy = replace(policy, policy_version="leakage-v2")
    revised_index = build_forbidden_index(
        _case(), _gold(), revised_policy, reviewer_source_commit="a" * 40
    )
    revised = scan_components((component,), revised_index, revised_policy, checked_at=CHECKED_AT)
    assert index.index_digest != other_index.index_digest
    assert index.index_digest != revised_index.index_digest
    assert original.matches[0].match_digest != other.matches[0].match_digest
    assert original.matches[0].match_digest != revised.matches[0].match_digest


def test_failed_scan_creates_no_approved_request_and_makes_zero_calls(tmp_path: Path) -> None:
    draft = _draft(tmp_path, profile="Resume state already closed")
    index, policy = _index()
    calls = 0

    def synthetic_reviewer(_request: bytes) -> None:
        nonlocal calls
        calls += 1

    with pytest.raises(LeakageError) as captured:
        approved = _approve_bundle_at(draft, index, policy, checked_at=CHECKED_AT)
        synthetic_reviewer(approved.request_bytes)
    assert calls == 0
    assert not hasattr(draft, "manifest_bytes")
    audit = json.loads(captured.value.audit_bytes)
    assert audit["passed"] is False
    assert "Resume state already closed" not in captured.value.audit_bytes.decode()


def test_passing_scan_finalizes_manifest_with_only_sanitized_metadata(tmp_path: Path) -> None:
    draft = _draft(tmp_path)
    index, policy = _index()
    approved = _approve_bundle_at(draft, index, policy, checked_at=CHECKED_AT)
    manifest = PromptManifest.from_dict(cast(dict[str, Any], json.loads(approved.manifest_bytes)))

    assert manifest.schema_version == "1.3"
    assert manifest.request_identity == derive_request_identity(_case(), _gold(), "vulnerable")
    assert manifest.leakage.passed
    assert manifest.leakage.index_digest == index.index_digest
    assert manifest.leakage.rule_ids == ()
    assert manifest.leakage.approved_matches == ()
    assert manifest.content_digest == approved.manifest_digest
    private_values = (
        "Resume state already closed",
        "Repair skips reopened finding",
        "Evidence ledger fragment alpha",
        "Known evidence fragment beta",
        "b" * 40,
        "d" * 64,
    )
    assert all(value.encode() not in approved.manifest_bytes for value in private_values)


def test_approved_exception_is_auditable_without_matched_content(tmp_path: Path) -> None:
    draft = _draft(tmp_path, profile="Resume state already closed")
    index, policy = _index()
    failed = scan_components(draft.scan_components, index, policy, checked_at=CHECKED_AT)
    exceptions = tuple(
        LeakageException(
            exception_id=f"exception-synthetic-{number}",
            rule_id=match.rule_id,
            location_class=match.location_class,
            match_digest=match.match_digest,
            expires_at=CHECKED_AT + timedelta(days=1),
            actor="synthetic-operator",
            reason="Narrow synthetic false positive",
        )
        for number, match in enumerate(failed.matches, 1)
    )
    approved_policy = replace(policy, exceptions=exceptions)
    approved_index = build_forbidden_index(
        _case(), _gold(), approved_policy, reviewer_source_commit="a" * 40
    )
    approved = _approve_bundle_at(draft, approved_index, approved_policy, checked_at=CHECKED_AT)

    assert approved.leakage.rule_ids == (EXPECTED_PHRASE,)
    assert len(approved.leakage.approved_matches) == len(failed.matches)
    assert b"Resume state already closed" not in approved.manifest_bytes
    assert all(
        match.exception_id.startswith("exception-synthetic-")
        for match in approved.leakage.approved_matches
    )


def test_production_approval_owns_current_utc_for_exception_expiry(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    draft = _draft(tmp_path, profile="Resume state already closed")
    index, policy = _index()
    failed = scan_components(draft.scan_components, index, policy, checked_at=CHECKED_AT)
    approved_policy = replace(
        policy,
        exceptions=tuple(
            LeakageException(
                exception_id=f"exception-clock-{number}",
                rule_id=match.rule_id,
                location_class=match.location_class,
                match_digest=match.match_digest,
                expires_at=CHECKED_AT + timedelta(days=1),
                actor="synthetic-operator",
                reason="Narrow synthetic false positive",
            )
            for number, match in enumerate(failed.matches, 1)
        ),
    )
    approved_index = build_forbidden_index(
        _case(), _gold(), approved_policy, reviewer_source_commit="a" * 40
    )

    class _TrustedNow(datetime):
        @classmethod
        def now(cls, tz: tzinfo | None = None) -> Self:
            assert tz is UTC
            trusted = CHECKED_AT + timedelta(days=2)
            return cls.fromtimestamp(trusted.timestamp(), tz=tz)

    monkeypatch.setattr(leakage_module, "datetime", _TrustedNow)
    with pytest.raises(LeakageError, match="failed leakage validation"):
        approve_bundle(draft, approved_index, approved_policy)
    with pytest.raises(TypeError, match="checked_at"):
        cast(Any, approve_bundle)(draft, approved_index, approved_policy, checked_at=CHECKED_AT)


def test_bundle_build_cannot_be_constructed_without_private_approval(tmp_path: Path) -> None:
    draft = _draft(tmp_path)
    with pytest.raises(BundleError, match="only be created by leakage approval"):
        BundleBuild(
            draft=draft,
            manifest_bytes=b"{}",
            manifest_digest=f"sha256:{'0' * 64}",
            leakage=object(),
        )

    index, policy = _index()
    approved = _approve_bundle_at(draft, index, policy, checked_at=CHECKED_AT)
    assert isinstance(approved, BundleBuild)
    assert type(approved).__name__ == "_ApprovedBundleBuild"


def test_request_component_parser_rejects_noncanonical_or_unknown_shapes(tmp_path: Path) -> None:
    draft = _draft(tmp_path)
    locations = [component.location_class for component in request_components(draft.request_bytes)]
    assert set(locations) == {
        "serialized_request",
        "profile",
        "filename",
        "tool_configuration",
        "context_bundle",
    }
    assert locations.count("serialized_request") == 2
    assert locations.count("context_bundle") == 2
    with pytest.raises(LeakageError, match="canonical"):
        request_components(b'{"schema_version": "1"}')
    with pytest.raises(LeakageError, match="unsupported shape"):
        request_components(b'{"schema_version":"1"}')
    with pytest.raises(LeakageError, match="canonical"):
        request_components(b'{"schema_version":NaN}')


def test_request_binding_rejects_invalid_new_and_legacy_identities(tmp_path: Path) -> None:
    document = json.loads(_draft(tmp_path).request_bytes)
    document["repository_context"]["request_identity"] = "not-opaque"
    with pytest.raises(LeakageError, match="unsupported context identity"):
        request_binding(canonical_json_bytes(cast(Any, document)))

    document["repository_context"] = {
        "schema_version": "1",
        "entries": document["repository_context"]["entries"],
    }
    with pytest.raises(LeakageError, match="unsupported context identity"):
        request_binding(canonical_json_bytes(cast(Any, document)))


def test_decoded_prompt_and_context_are_scanned_despite_json_escaping(tmp_path: Path) -> None:
    index, policy = _index()
    prompt_draft = _draft(
        tmp_path / "prompt",
        prompt="RESUME--state\nalready CLOSED",
    )
    prompt_audit = scan_components(
        prompt_draft.scan_components, index, policy, checked_at=CHECKED_AT
    )
    assert not prompt_audit.passed
    assert any(
        match.rule_id == EXPECTED_PHRASE and match.location_class == "serialized_request"
        for match in prompt_audit.matches
    )

    context_draft = _draft(
        tmp_path / "context",
        context="repair...SKIPS reopened\nfinding",
    )
    context_audit = scan_components(
        context_draft.scan_components, index, policy, checked_at=CHECKED_AT
    )
    assert not context_audit.passed
    assert any(
        match.rule_id == REPAIR_TEXT and match.location_class == "context_bundle"
        for match in context_audit.matches
    )


def test_leakage_policy_rejects_global_or_duplicate_exception_selectors() -> None:
    with pytest.raises(SchemaError):
        LeakagePolicy.from_dict(
            {
                "schema_version": "1.0",
                "policy_version": "leakage-v1",
                "case_id": "synthetic-leakage-case",
                "additional_sensitive_shas": [],
                "repair_texts": [],
                "evidence_fragments": [],
                "exceptions": [
                    {
                        "exception_id": "exception-global",
                        "rule_id": "*",
                        "location_class": "*",
                        "match_digest": "*",
                        "expires_at": "2099-01-01T00:00:00Z",
                        "actor": "operator",
                        "reason": "invalid",
                    }
                ],
            }
        )


@pytest.mark.parametrize("context", ["fixed_size = 3", "# fixed in v2", "# vulnerable parser"])
def test_repository_labels_pass_build_and_reapproval(tmp_path: Path, context: str) -> None:
    draft = _draft(tmp_path, context=context)
    index, policy = _index()
    approved = approve_bundle(draft, index, policy)
    assert (
        reapprove_bundle_artifacts(
            approved.bundle_bytes, approved.request_bytes, approved.manifest_bytes, index, policy
        ).manifest_bytes
        == approved.manifest_bytes
    )


@pytest.mark.parametrize(
    "surface",
    ["prompt_template", "profile_template", "reviewer_config", "envelope", "bundle_metadata"],
)
def test_serialized_request_labels_still_reject_harness_surfaces(
    tmp_path: Path, surface: str
) -> None:
    document = json.loads(_draft(tmp_path).request_bytes)
    if surface == "reviewer_config":
        document[surface]["model"] = "fixed"
    elif surface == "envelope":
        document["snapshot"] = "fixed"
    elif surface == "bundle_metadata":
        document["repository_context"]["snapshot"] = "fixed"
    else:
        document[surface] = "fixed"
    index, policy = _index()
    audit = scan_components(
        (RequestComponent("serialized_request", canonical_json_bytes(document)),),
        index,
        policy,
        checked_at=CHECKED_AT,
    )
    assert SNAPSHOT_LABEL in audit.rule_ids


def test_legacy_index_excludes_future_rules_and_preserves_historical_hashes() -> None:
    index, _ = _index()
    legacy = legacy_forbidden_index(index)
    future = leakage_module._ForbiddenValue(
        "LEAKAGE_FUTURE", "phrase", "future", "sha256:" + "e" * 64
    )
    assert legacy_forbidden_index(replace(index, entries=(*index.entries, future))) == legacy
    assert (
        legacy.index_digest
        == "sha256:80449b734578fb8b8b966f57242389a9c955d3e9a2265b7f5add7921943b6b28"
    )
    assert (
        f"sha256:{legacy.match_key.hex()}"
        == "sha256:80a619970139f527cdde37aae16df22896482d4119ce603a2c37e75a645db49a"
    )


@pytest.mark.parametrize("filename", ["fixed_size.py", "vulnerable.md"])
def test_repository_label_filenames_are_exempt_in_serialized_copies(
    tmp_path: Path, filename: str
) -> None:
    document = json.loads(_draft(tmp_path).request_bytes)
    document["repository_context"]["entries"][0]["path"] = filename
    index, policy = _index()
    assert scan_components(
        request_components(canonical_json_bytes(document)),
        index,
        policy,
        checked_at=CHECKED_AT,
    ).passed
