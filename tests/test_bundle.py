from __future__ import annotations

import hashlib
import json
import os
import re
from dataclasses import replace
from datetime import UTC, datetime
from importlib import metadata
from pathlib import Path, PurePosixPath
from typing import Any, cast

import pytest
import tiktoken

import preflight_evals.bundle as bundle_module
from preflight_evals.bundle import (
    ReviewerSettings,
    TemplateInput,
    build_bundle,
    canonical_summary,
    load_template,
    parse_manifest_bytes,
    write_bundle,
)
from preflight_evals.canonical import (
    JsonValue,
    canonical_digest,
    canonical_json_bytes,
    sha256_digest,
)
from preflight_evals.errors import BundleError, SchemaError
from preflight_evals.leakage import ForbiddenContentIndex, approve_bundle, default_policy
from preflight_evals.model_types import Condition
from preflight_evals.reviewer_models import ReviewerCase, ReviewerContextPolicy

TOKENIZER = f"tiktoken/o200k_base@{metadata.version('tiktoken')}/per_file_utf8_sum_v1"
WORKTREE_DIGEST = f"sha256:{'b' * 64}"
CREATED_AT = datetime(2026, 8, 18, 12, 30, tzinfo=UTC)
REQUEST_IDENTITY = f"hmac-sha256:{'1' * 64}"


def _case(**policy_changes: object) -> ReviewerCase:
    policy: dict[str, object] = {
        "includes": (PurePosixPath("src"),),
        "excludes": (),
        "per_file_byte_limit": 100_000,
        "per_file_token_limit": 16_000,
        "total_token_limit": 24_000,
        "symlink_policy": "reject",
        "binary_policy": "omit",
        "truncation_policy": "reject",
    }
    policy.update(policy_changes)
    return ReviewerCase(
        schema_version="1.0",
        case_id="synthetic-case",
        display_name="Synthetic case",
        defect_category="correctness",
        repository="synthetic/example",
        pull_request=1,
        source_commit="a" * 40,
        context_policy=ReviewerContextPolicy(**cast(Any, policy)),
    )


def _settings(**changes: object) -> ReviewerSettings:
    values: dict[str, object] = {
        "model": "synthetic-model",
        "tool_policy": "read-only",
        "input_token_limit": 100_000,
        "output_token_limit": 4_000,
        "temperature": 0.0,
        "adapter_version": "synthetic-1",
    }
    values.update(changes)
    return ReviewerSettings(**cast(Any, values))


def _build(
    worktree: Path,
    *,
    case: ReviewerCase | None = None,
    condition: str = "baseline",
    profile: str = "",
    run_id: str = "run-synthetic-one",
    created_at: datetime = CREATED_AT,
    settings: ReviewerSettings | None = None,
) -> bundle_module.BundleBuild:
    worktree_digest = WORKTREE_DIGEST
    if worktree.is_dir() and not worktree.is_symlink():
        worktree_digest = bundle_module._compute_worktree_digest(worktree.resolve())
    draft = build_bundle(
        case or _case(),
        "vulnerable",
        cast(Condition, condition),
        request_identity=REQUEST_IDENTITY,
        worktree=worktree,
        worktree_digest=worktree_digest,
        tokenizer_spec=TOKENIZER,
        prompt_template=TemplateInput("review", "1", "Review the repository.\r\n"),
        profile_template=TemplateInput("profile", "1", profile),
        reviewer_settings=settings or _settings(),
        repetition=1,
        seed=42,
        request_id=f"request-{condition}",
        run_id=run_id,
        created_at=created_at,
    )
    policy = default_policy("synthetic-case")
    return approve_bundle(
        draft,
        ForbiddenContentIndex(
            case_id="synthetic-case",
            policy_version="leakage-v1",
            index_digest=f"sha256:{'c' * 64}",
            entries=(),
            match_key=b"synthetic-empty-index",
        ),
        policy,
    )


def _bundle_document(build: bundle_module.BundleBuild) -> dict[str, Any]:
    document = json.loads(build.bundle_bytes)
    assert isinstance(document, dict)
    return document


def test_repeated_builds_are_byte_stable_and_conditions_share_context(tmp_path: Path) -> None:
    source = tmp_path / "src"
    source.mkdir()
    (source / "z.py").write_bytes(b"print('z')\r\n")
    (source / "á.py").write_text("snowman = '☃'\r", encoding="utf-8")

    baseline = _build(tmp_path)
    repeated = _build(tmp_path)
    candidate = _build(tmp_path, condition="candidate", profile="Apply the profile.\n")

    assert repeated.bundle_bytes == baseline.bundle_bytes
    assert repeated.manifest_bytes == baseline.manifest_bytes
    assert repeated.manifest_digest == baseline.manifest_digest
    assert candidate.bundle_bytes == baseline.bundle_bytes
    assert candidate.bundle_digest == baseline.bundle_digest
    assert candidate.context_entry_digest == baseline.context_entry_digest
    assert candidate.manifest_bytes != baseline.manifest_bytes
    assert candidate.request_digest != baseline.request_digest

    document = _bundle_document(baseline)
    assert document["schema_version"] == "2"
    assert document["request_identity"] == REQUEST_IDENTITY
    assert "case_id" not in document
    assert "snapshot" not in document
    assert [entry["path"] for entry in document["entries"]] == ["src/z.py", "src/á.py"]
    assert document["entries"][0]["content"] == "print('z')\n"
    assert document["entries"][1]["content"] == "snowman = '☃'\n"
    assert "condition" not in document
    assert "profile" not in baseline.bundle_bytes.decode()
    manifest = parse_manifest_bytes(baseline.manifest_bytes)
    assert manifest.bundle_digest == baseline.bundle_digest
    assert manifest.schema_version == "1.3"
    assert manifest.bundle_schema_version == "2"
    assert manifest.request_identity == REQUEST_IDENTITY
    assert manifest.context_entry_digest == baseline.context_entry_digest
    assert manifest.context_byte_count == baseline.context_byte_count
    assert manifest.context_token_count == baseline.context_token_count
    assert manifest.content_digest == baseline.manifest_digest

    later = _build(tmp_path, created_at=datetime(2026, 8, 19, 12, 30, tzinfo=UTC))
    assert later.manifest_bytes != baseline.manifest_bytes
    assert later.manifest_digest == baseline.manifest_digest


def test_reviewer_request_omits_case_snapshot_and_pull_request_tokens(tmp_path: Path) -> None:
    source = tmp_path / "src"
    source.mkdir()
    (source / "example.py").write_text("safe = True\n", encoding="utf-8")

    build = _build(tmp_path)
    request = build.request_bytes.decode().casefold()
    bundle = _bundle_document(build)

    assert "synthetic-case" not in request
    assert "vulnerable" not in request
    assert "fixed" not in request
    assert re.search(r"(?<![a-z0-9_])pr[0-9]+(?![a-z0-9_])", request) is None
    assert "case_id" not in bundle
    assert "snapshot" not in bundle


def test_worktree_digest_is_recomputed_before_bundling(tmp_path: Path) -> None:
    source = tmp_path / "src"
    source.mkdir()
    (source / "a.py").write_text("content", encoding="utf-8")
    with pytest.raises(BundleError, match="worktree digest does not match"):
        build_bundle(
            _case(),
            "vulnerable",
            "baseline",
            request_identity=REQUEST_IDENTITY,
            worktree=tmp_path,
            worktree_digest=WORKTREE_DIGEST,
            tokenizer_spec=TOKENIZER,
            prompt_template=TemplateInput("review", "1", "review"),
            profile_template=TemplateInput("profile", "1", ""),
            reviewer_settings=_settings(),
            repetition=1,
            seed=None,
            request_id="request-one",
            run_id="run-synthetic-one",
            created_at=CREATED_AT,
        )


def test_worktree_digest_matches_materializer_manifest_algorithm(tmp_path: Path) -> None:
    source = tmp_path / "src"
    source.mkdir()
    plain = b"plain\n"
    executable = b"#!/bin/sh\n"
    (source / "plain.txt").write_bytes(plain)
    script = source / "run.sh"
    script.write_bytes(executable)
    script.chmod(0o755)
    (source / "plain-link").symlink_to("plain.txt")

    def entry(path: str, mode: str, payload: bytes) -> dict[str, JsonValue]:
        digest = hashlib.sha1(f"blob {len(payload)}\0".encode("ascii"), usedforsecurity=False)
        digest.update(payload)
        return {
            "content_digest": sha256_digest(payload),
            "git_object_id": digest.hexdigest(),
            "mode": mode,
            "path": path,
            "size": len(payload),
        }

    expected = canonical_digest(
        [
            entry("src/plain-link", "120000", b"plain.txt"),
            entry("src/plain.txt", "100644", plain),
            entry("src/run.sh", "100755", executable),
        ]
    )
    assert bundle_module._compute_worktree_digest(tmp_path.resolve()) == expected


def test_order_does_not_depend_on_filesystem_iteration(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    source = tmp_path / "src"
    source.mkdir()
    for name in ("c.py", "a.py", "b.py"):
        (source / name).write_text(name, encoding="utf-8")
    expected = _build(tmp_path)
    original_walk = bundle_module._walk_files

    def reverse_walk(root: Path) -> tuple[Path, ...]:
        return tuple(reversed(original_walk(root)))

    monkeypatch.setattr(bundle_module, "_walk_files", reverse_walk)
    actual = _build(tmp_path)
    assert actual.bundle_bytes == expected.bundle_bytes
    assert actual.manifest_bytes == expected.manifest_bytes


def test_include_precedence_and_excludes_are_recorded_deterministically(tmp_path: Path) -> None:
    source = tmp_path / "src"
    source.mkdir()
    (source / "a.py").write_text("a", encoding="utf-8")
    private = source / "private"
    private.mkdir()
    (private / "gold.py").write_text("must not appear", encoding="utf-8")
    case = _case(
        includes=(PurePosixPath("src/a.py"), PurePosixPath("src")),
        excludes=(PurePosixPath("src/private"),),
    )

    document = _bundle_document(_build(tmp_path, case=case))
    assert len(document["entries"]) == 1
    assert document["entries"][0]["path"] == "src/a.py"
    assert document["entries"][0]["selection_reason"] == "include[0]"
    assert "must not appear" not in json.dumps(document)


@pytest.mark.parametrize("payload", [b"text\0binary", b"\xffnot-utf8"])
def test_binary_policy_omits_or_rejects(payload: bytes, tmp_path: Path) -> None:
    source = tmp_path / "src"
    source.mkdir()
    (source / "good.py").write_text("good", encoding="utf-8")
    (source / "binary.bin").write_bytes(payload)

    omitted = _bundle_document(_build(tmp_path))
    assert [entry["path"] for entry in omitted["entries"]] == ["src/good.py"]
    with pytest.raises(BundleError, match=r"binary|non-UTF-8"):
        _build(tmp_path, case=_case(binary_policy="reject"))


def test_symlink_policy_rejects_escape_and_can_follow_regular_file_within_root(
    tmp_path: Path,
) -> None:
    source = tmp_path / "src"
    source.mkdir()
    target = source / "target.py"
    target.write_text("safe", encoding="utf-8")
    link = source / "link.py"
    link.symlink_to(target.name)
    case = _case(includes=(PurePosixPath("src/link.py"),))

    with pytest.raises(BundleError, match="disallowed symlink"):
        _build(tmp_path, case=case)
    followed = _bundle_document(
        _build(
            tmp_path,
            case=replace(
                case,
                context_policy=replace(case.context_policy, symlink_policy="follow_within_root"),
            ),
        )
    )
    assert followed["entries"][0]["content"] == "safe"

    outside = tmp_path.parent / f"{tmp_path.name}-outside.py"
    outside.write_text("outside", encoding="utf-8")
    link.unlink()
    link.symlink_to(outside)
    with pytest.raises(BundleError, match="does not stay within"):
        _build(
            tmp_path,
            case=replace(
                case,
                context_policy=replace(case.context_policy, symlink_policy="follow_within_root"),
            ),
        )


@pytest.mark.parametrize(
    "include",
    [PurePosixPath("../escape.py"), PurePosixPath("/absolute.py"), PurePosixPath("src\\x")],
)
def test_unsafe_context_paths_fail_before_reading(include: PurePosixPath, tmp_path: Path) -> None:
    (tmp_path / "src").mkdir()
    with pytest.raises(BundleError, match="unsafe repository path"):
        _build(tmp_path, case=_case(includes=(include,)))


def test_missing_or_empty_selection_fails_closed(tmp_path: Path) -> None:
    (tmp_path / "src").mkdir()
    with pytest.raises(BundleError, match="selected no files"):
        _build(tmp_path)
    with pytest.raises(BundleError, match="unavailable"):
        _build(tmp_path, case=_case(includes=(PurePosixPath("missing.py"),)))


@pytest.mark.parametrize("policy", ["head", "head_tail"])
def test_exact_limits_and_deterministic_truncation(policy: str, tmp_path: Path) -> None:
    source = tmp_path / "src"
    source.mkdir()
    content = "αβγδεζηθ" * 20
    payload = content.encode("utf-8")
    path = source / "unicode.py"
    path.write_bytes(payload)
    exact = _case(
        per_file_byte_limit=len(payload),
        per_file_token_limit=10_000,
        total_token_limit=10_000,
        truncation_policy=policy,
    )
    exact_entry = _bundle_document(_build(tmp_path, case=exact))["entries"][0]
    assert exact_entry["content"] == content
    assert exact_entry["truncated"] is False

    limited = replace(
        exact,
        context_policy=replace(exact.context_policy, per_file_byte_limit=80),
    )
    first = _build(tmp_path, case=limited)
    second = _build(tmp_path, case=limited)
    entry = _bundle_document(first)["entries"][0]
    assert first.bundle_bytes == second.bundle_bytes
    assert entry["truncated"] is True
    assert "<preflight-evals:truncated>" in entry["content"]
    assert entry["byte_count"] <= 80
    if policy == "head_tail":
        assert entry["content"].endswith(content[-1])


def test_exact_token_and_total_boundaries_are_inclusive(tmp_path: Path) -> None:
    source = tmp_path / "src"
    source.mkdir()
    content = "token boundary example " * 40
    for name in ("a.py", "b.py"):
        (source / name).write_text(content, encoding="utf-8")
    encoder = tiktoken.get_encoding("o200k_base")
    token_count = len(encoder.encode(content, disallowed_special=()))
    exact = _case(
        per_file_token_limit=token_count,
        total_token_limit=token_count * 2,
        truncation_policy="head",
    )
    exact_entries = _bundle_document(_build(tmp_path, case=exact))["entries"]
    assert all(not entry["truncated"] for entry in exact_entries)
    assert sum(entry["token_count"] for entry in exact_entries) == token_count * 2

    one_below = replace(
        exact,
        context_policy=replace(exact.context_policy, total_token_limit=token_count * 2 - 1),
    )
    limited_entries = _bundle_document(_build(tmp_path, case=one_below))["entries"]
    assert any(entry["truncated"] for entry in limited_entries)
    assert sum(entry["token_count"] for entry in limited_entries) <= token_count * 2 - 1


def test_truncation_keeps_longest_fitting_prefix_for_non_monotonic_bpe() -> None:
    text = ",WXcGogG,.c:wbFrKm.:\ni1VfZ-/xn.,u"
    rendered, truncated = bundle_module._limit_text(
        text,
        bundle_module._load_tokenizer(TOKENIZER),
        byte_limit=1_000,
        token_limit=22,
        policy="head",
    )
    assert truncated is True
    assert rendered == text[:21] + "\n<preflight-evals:truncated>\n"


def test_reject_and_total_token_limits_fail_or_truncate_deterministically(tmp_path: Path) -> None:
    source = tmp_path / "src"
    source.mkdir()
    for name in ("a.py", "b.py"):
        (source / name).write_text("word " * 200, encoding="utf-8")
    with pytest.raises(BundleError, match="configured limit"):
        _build(
            tmp_path,
            case=_case(per_file_token_limit=20, total_token_limit=40, truncation_policy="reject"),
        )
    build = _build(
        tmp_path,
        case=_case(per_file_token_limit=100, total_token_limit=60, truncation_policy="head_tail"),
    )
    assert build.context_token_count <= 60
    assert all(entry["truncated"] for entry in _bundle_document(build)["entries"])


def test_gold_file_is_never_inferred_into_context(tmp_path: Path) -> None:
    source = tmp_path / "src"
    source.mkdir()
    (source / "visible.py").write_text("visible", encoding="utf-8")
    private_value = "synthetic-expected-finding-phrase"
    (tmp_path / "gold.yaml").write_text(private_value, encoding="utf-8")

    build = _build(tmp_path)
    assert private_value.encode() not in build.bundle_bytes
    assert private_value.encode() not in build.manifest_bytes


def test_request_limit_and_tokenizer_version_fail_closed(tmp_path: Path) -> None:
    source = tmp_path / "src"
    source.mkdir()
    (source / "a.py").write_text("small", encoding="utf-8")
    with pytest.raises(BundleError, match="input token limit"):
        _build(tmp_path, settings=_settings(input_token_limit=1))
    with pytest.raises(BundleError, match="version does not match"):
        build_bundle(
            _case(),
            "vulnerable",
            "baseline",
            request_identity=REQUEST_IDENTITY,
            worktree=tmp_path,
            worktree_digest=WORKTREE_DIGEST,
            tokenizer_spec="tiktoken/o200k_base@0.0.0/per_file_utf8_sum_v1",
            prompt_template=TemplateInput("review", "1", "review"),
            profile_template=TemplateInput("profile", "1", ""),
            reviewer_settings=_settings(),
            repetition=1,
            seed=None,
            request_id="request-one",
            run_id="run-synthetic-one",
            created_at=CREATED_AT,
        )


@pytest.mark.parametrize(
    ("changes", "message"),
    [
        ({"run_id": "unsafe"}, "run identifier"),
        ({"request_id": ""}, "request identifier"),
        ({"request_id": "request\nprivate"}, "request identifier"),
        ({"repetition": 0}, "repetition must be positive"),
        ({"created_at": datetime(2026, 8, 18)}, "include a timezone"),
        ({"worktree_digest": "sha256:invalid"}, "worktree digest"),
        ({"request_identity": "not-opaque"}, "opaque request identity"),
        ({"prompt_template": TemplateInput("", "1", "")}, "template name"),
        ({"profile_template": TemplateInput("profile", "", "")}, "template version"),
        ({"reviewer_settings": _settings(model="")}, "reviewer configuration"),
        ({"reviewer_settings": _settings(model="m" * 201)}, "reviewer configuration"),
        (
            {"reviewer_settings": _settings(tool_policy="t" * 201)},
            "reviewer configuration",
        ),
        (
            {"reviewer_settings": _settings(adapter_version="a" * 101)},
            "reviewer configuration",
        ),
    ],
)
def test_bundle_input_validation_is_fail_closed(changes: dict[str, object], message: str) -> None:
    arguments: dict[str, object] = {
        "worktree_digest": WORKTREE_DIGEST,
        "request_identity": REQUEST_IDENTITY,
        "repetition": 1,
        "request_id": "request-one",
        "run_id": "run-synthetic-one",
        "created_at": CREATED_AT,
        "prompt_template": TemplateInput("review", "1", "review"),
        "profile_template": TemplateInput("profile", "1", ""),
        "reviewer_settings": _settings(),
    }
    arguments.update(changes)
    with pytest.raises(BundleError, match=message):
        bundle_module._validate_inputs(_case(), **cast(Any, arguments))


@pytest.mark.parametrize(
    "identity_arguments",
    [pytest.param({}, id="omitted"), pytest.param({"request_identity": None}, id="explicit-none")],
)
def test_bundle_requires_an_explicit_opaque_request_identity(
    tmp_path: Path, identity_arguments: dict[str, object]
) -> None:
    with pytest.raises(BundleError, match=r"^opaque request identity is required$"):
        build_bundle(
            _case(),
            "vulnerable",
            "baseline",
            **cast(Any, identity_arguments),
            worktree=tmp_path,
            worktree_digest=WORKTREE_DIGEST,
            tokenizer_spec=TOKENIZER,
            prompt_template=TemplateInput("review", "1", "review"),
            profile_template=TemplateInput("profile", "1", ""),
            reviewer_settings=_settings(),
            repetition=1,
            seed=None,
            request_id="request-one",
            run_id="run-synthetic-one",
            created_at=CREATED_AT,
        )


def test_invalid_source_commit_and_tokenizer_specifications_fail_closed(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    with pytest.raises(BundleError, match="source commit"):
        bundle_module._validate_inputs(
            replace(_case(), source_commit="A" * 40),
            worktree_digest=WORKTREE_DIGEST,
            repetition=1,
            request_id="request-one",
            run_id="run-synthetic-one",
            created_at=CREATED_AT,
            prompt_template=TemplateInput("review", "1", "review"),
            profile_template=TemplateInput("profile", "1", ""),
            reviewer_settings=_settings(),
            request_identity=REQUEST_IDENTITY,
        )
    with pytest.raises(BundleError, match="unsupported"):
        bundle_module._load_tokenizer("synthetic")
    monkeypatch.setattr(tiktoken, "get_encoding", lambda _: (_ for _ in ()).throw(KeyError()))
    with pytest.raises(BundleError, match="encoding is unavailable"):
        bundle_module._load_tokenizer(TOKENIZER)


def test_worktree_root_and_unsupported_entries_fail_closed(tmp_path: Path) -> None:
    missing = tmp_path / "missing"
    with pytest.raises(BundleError, match="root is unavailable"):
        _build(missing)
    file_root = tmp_path / "file-root"
    file_root.write_text("not a directory", encoding="utf-8")
    with pytest.raises(BundleError, match="root is unavailable"):
        _build(file_root)
    actual = tmp_path / "actual"
    (actual / "src").mkdir(parents=True)
    (actual / "src" / "a.py").write_text("content", encoding="utf-8")
    linked = tmp_path / "linked"
    linked.symlink_to(actual, target_is_directory=True)
    with pytest.raises(BundleError, match="root must not be a symlink"):
        _build(linked)

    fifo = actual / "src" / "pipe"
    os.mkfifo(fifo)
    with pytest.raises(BundleError, match="unsupported entry"):
        _build(actual)


def test_omitting_every_binary_file_fails_closed(tmp_path: Path) -> None:
    source = tmp_path / "src"
    source.mkdir()
    (source / "binary.bin").write_bytes(b"\0binary")
    with pytest.raises(BundleError, match="no reviewer-visible text"):
        _build(tmp_path)


def test_symlinked_parent_and_directory_target_fail_closed(tmp_path: Path) -> None:
    real = tmp_path / "real"
    real.mkdir()
    (real / "a.py").write_text("content", encoding="utf-8")
    source = tmp_path / "src"
    source.symlink_to(real, target_is_directory=True)
    case = _case(includes=(PurePosixPath("src/a.py"),), symlink_policy="follow_within_root")
    with pytest.raises(BundleError, match="unavailable or unsafe"):
        _build(tmp_path, case=case)

    source.unlink()
    source.mkdir()
    directory = source / "directory"
    directory.mkdir()
    link = source / "directory-link"
    link.symlink_to(directory, target_is_directory=True)
    case = _case(
        includes=(PurePosixPath("src/directory-link"),), symlink_policy="follow_within_root"
    )
    with pytest.raises(BundleError, match="does not resolve to a regular file"):
        _build(tmp_path, case=case)


def test_bundle_writer_is_atomic_private_and_refuses_replacement(tmp_path: Path) -> None:
    source = tmp_path / "worktree" / "src"
    source.mkdir(parents=True)
    (source / "a.py").write_text("content", encoding="utf-8")
    build = _build(source.parent)
    output = tmp_path / "bundles"

    bundle_path, request_path, manifest_path = write_bundle(
        build, output_root=output, run_id="run-one"
    )
    assert bundle_path.read_bytes() == build.bundle_bytes
    assert request_path.read_bytes() == build.request_bytes
    assert manifest_path.read_bytes() == build.manifest_bytes
    assert os.stat(bundle_path).st_mode & 0o777 == 0o600
    assert os.stat(request_path).st_mode & 0o777 == 0o600
    assert os.stat(manifest_path).st_mode & 0o777 == 0o600
    assert not any(path.name.startswith(".run-one.tmp-") for path in output.iterdir())
    with pytest.raises(BundleError, match="already exists"):
        write_bundle(build, output_root=output, run_id="run-one")


def test_bundle_writer_rejects_unsafe_run_and_output_root(tmp_path: Path) -> None:
    source = tmp_path / "worktree" / "src"
    source.mkdir(parents=True)
    (source / "a.py").write_text("content", encoding="utf-8")
    build = _build(source.parent)
    with pytest.raises(BundleError, match="run identifier"):
        write_bundle(build, output_root=tmp_path / "bundles", run_id="unsafe")
    actual = tmp_path / "actual-output"
    actual.mkdir()
    linked = tmp_path / "linked-output"
    linked.symlink_to(actual, target_is_directory=True)
    with pytest.raises(BundleError, match="unsafe prior state"):
        write_bundle(build, output_root=linked, run_id="run-one")
    file_root = tmp_path / "file-output"
    file_root.write_text("unsafe", encoding="utf-8")
    with pytest.raises(BundleError, match="unsafe prior state"):
        write_bundle(build, output_root=file_root, run_id="run-one")
    parent = tmp_path / "parent"
    outside = tmp_path / "outside"
    parent.mkdir()
    outside.mkdir()
    (parent / "link").symlink_to(outside, target_is_directory=True)
    escaped_root = parent / "link" / "bundles"
    with pytest.raises(BundleError, match="unsafe prior state"):
        write_bundle(build, output_root=escaped_root, run_id="run-one")
    assert not (outside / "bundles").exists()


def test_failed_bundle_write_publishes_no_run_directory(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    source = tmp_path / "worktree" / "src"
    source.mkdir(parents=True)
    (source / "a.py").write_text("content", encoding="utf-8")
    build = _build(source.parent)
    output = tmp_path / "bundles"
    calls = 0
    original = bundle_module._write_exclusive

    def fail_second(path: Path, payload: bytes) -> None:
        nonlocal calls
        calls += 1
        if calls == 2:
            raise OSError("synthetic private failure")
        original(path, payload)

    monkeypatch.setattr(bundle_module, "_write_exclusive", fail_second)
    with pytest.raises(BundleError, match="write private bundle artifacts"):
        write_bundle(build, output_root=output, run_id="run-failed")
    assert not (output / "run-failed").exists()
    assert not any(output.iterdir())


def test_manifest_tampering_and_invalid_templates_fail_safely(tmp_path: Path) -> None:
    source = tmp_path / "src"
    source.mkdir()
    (source / "a.py").write_text("content", encoding="utf-8")
    build = _build(tmp_path)
    manifest = json.loads(build.manifest_bytes)
    manifest["context_byte_count"] += 1
    with pytest.raises(SchemaError, match="context byte count"):
        parse_manifest_bytes(canonical_json_bytes(manifest))

    template = tmp_path / "template.txt"
    template.write_bytes(b"\xffprivate")
    with pytest.raises(BundleError, match="load a reviewer template"):
        load_template(template, name="review", version="1")
    template.write_bytes(b"private\0value")
    with pytest.raises(BundleError, match="unsupported content"):
        load_template(template, name="review", version="1")
    with pytest.raises(BundleError, match="not valid JSON"):
        parse_manifest_bytes(b"{invalid")
    with pytest.raises(BundleError, match="must contain an object"):
        parse_manifest_bytes(b"[]")


def _case_document() -> dict[str, object]:
    return {
        "schema_version": "1.0",
        "case_id": "synthetic-case",
        "display_name": "Synthetic bundle case",
        "defect_category": "correctness",
        "source": {"repository": "synthetic/example", "pull_request": 1},
        "commits": {
            "base": "0" * 40,
            "vulnerable": "a" * 40,
            "repair": "b" * 40,
            "fixed": "b" * 40,
        },
        "snapshots": {
            "vulnerable": {"commit": "a" * 40},
            "fixed": {"commit": "b" * 40},
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
            "vulnerable_tokens": 1,
            "fixed_tokens": 1,
        },
    }


def _gold_document() -> dict[str, object]:
    return {
        "schema_version": "1.0",
        "case_id": "synthetic-case",
        "expected_behavior": {"vulnerable": "bad", "fixed": "good"},
        "expected_mechanisms": [
            {
                "mechanism_id": "mechanism-synthetic",
                "description": "Synthetic mechanism",
                "adjudication_rubric": "Match the synthetic mechanism",
            }
        ],
        "acceptable_locations": [{"path": "src/a.py"}],
        "accepted_defect_categories": ["correctness"],
        "severity_range": {"minimum": "low", "maximum": "critical"},
        "forbidden_expected_phrases": ["forbidden synthetic phrase"],
        "fixed_only_fingerprints": [
            {
                "digest": f"sha256:{'d' * 64}",
                "source_path": "src/a.py",
                "source_record_id": "synthetic-record",
            }
        ],
        "provenance": {
            "excerpt": "private synthetic provenance",
            "source_record_id": "synthetic-record",
        },
        "curator_notes": "",
        "adjudication": {"required": False, "accepted_alternative_matches": []},
    }


def test_canonical_summary_contains_no_artifact_paths(tmp_path: Path) -> None:
    source = tmp_path / "src"
    source.mkdir()
    (source / "private-name.py").write_text("private-content", encoding="utf-8")
    summary = canonical_summary(_build(tmp_path))
    assert b"private-name" not in summary
    assert b"private-content" not in summary
    assert json.loads(summary)["entry_count"] == 1
