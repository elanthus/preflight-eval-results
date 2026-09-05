"""Deterministic, reviewer-safe context bundling and prompt manifests."""

from __future__ import annotations

import hashlib
import json
import os
import re
import shutil
import stat
import tempfile
import unicodedata
from collections.abc import Iterable, Sequence
from dataclasses import dataclass
from datetime import datetime
from importlib import metadata
from pathlib import Path, PurePosixPath
from typing import Literal, cast

import tiktoken

from preflight_evals.canonical import (
    JsonValue,
    canonical_digest,
    canonical_json_bytes,
    sha256_digest,
)
from preflight_evals.errors import BundleError
from preflight_evals.model_types import Condition, SnapshotName
from preflight_evals.reviewer_models import LeakageResult, PromptManifest, ReviewerCase

_RUN_ID = re.compile(r"run-[a-z0-9]+(?:-[a-z0-9]+)*")
_REQUEST_IDENTITY = re.compile(r"hmac-sha256:[0-9a-f]{64}")
_TOKENIZER_SPEC = re.compile(
    r"tiktoken/(?P<name>[A-Za-z0-9_]+)@(?P<version>[0-9A-Za-z_.+-]+)/"
    r"(?P<method>per_file_utf8_sum_v1)"
)
_TRUNCATION_MARKER = "\n<preflight-evals:truncated>\n"

type TruncationPolicy = Literal["reject", "head", "head_tail"]


@dataclass(frozen=True, slots=True)
class TemplateInput:
    """One normalized prompt/profile component supplied by the run plan."""

    name: str
    version: str
    content: str


@dataclass(frozen=True, slots=True)
class ReviewerSettings:
    """Execution-affecting reviewer configuration captured by the manifest."""

    model: str
    tool_policy: str
    input_token_limit: int
    output_token_limit: int
    temperature: float
    adapter_version: str


@dataclass(frozen=True, slots=True)
class BundleEntryRecord:
    path: PurePosixPath
    content: str
    byte_count: int
    token_count: int
    content_digest: str
    truncated: bool
    selection_reason: str

    def manifest_dict(self) -> dict[str, JsonValue]:
        return {
            "path": self.path.as_posix(),
            "byte_count": self.byte_count,
            "token_count": self.token_count,
            "content_digest": self.content_digest,
            "truncated": self.truncated,
            "selection_reason": self.selection_reason,
        }

    def bundle_dict(self) -> dict[str, JsonValue]:
        return {**self.manifest_dict(), "content": self.content}


@dataclass(frozen=True, slots=True)
class RequestComponent:
    """One private request surface labeled only by its safe location class."""

    location_class: str
    payload: bytes


@dataclass(frozen=True, slots=True)
class BundleDraft:
    """A complete private request whose manifest is intentionally not finalized."""

    bundle_bytes: bytes
    request_bytes: bytes
    manifest_seed_bytes: bytes
    created_at: str
    bundle_digest: str
    request_digest: str
    context_entry_digest: str
    entry_count: int
    context_byte_count: int
    context_token_count: int
    bundle_token_count: int
    scan_components: tuple[RequestComponent, ...]


@dataclass(frozen=True, slots=True, init=False)
class BundleBuild:
    """A leakage-approved request and its finalized prompt manifest."""

    draft: BundleDraft
    manifest_bytes: bytes
    manifest_digest: str
    leakage: LeakageResult

    def __init__(self, *_args: object, **_kwargs: object) -> None:
        """Reject direct construction outside the private leakage approval capability."""

        raise BundleError("bundle builds can only be created by leakage approval")

    @property
    def bundle_bytes(self) -> bytes:
        return self.draft.bundle_bytes

    @property
    def request_bytes(self) -> bytes:
        return self.draft.request_bytes

    @property
    def bundle_digest(self) -> str:
        return self.draft.bundle_digest

    @property
    def request_digest(self) -> str:
        return self.draft.request_digest

    @property
    def context_entry_digest(self) -> str:
        return self.draft.context_entry_digest

    @property
    def entry_count(self) -> int:
        return self.draft.entry_count

    @property
    def context_byte_count(self) -> int:
        return self.draft.context_byte_count

    @property
    def context_token_count(self) -> int:
        return self.draft.context_token_count

    @property
    def bundle_token_count(self) -> int:
        return self.draft.bundle_token_count

    def summary(self) -> dict[str, JsonValue]:
        return {
            "bundle_byte_count": len(self.bundle_bytes),
            "bundle_digest": self.bundle_digest,
            "bundle_token_count": self.bundle_token_count,
            "context_byte_count": self.context_byte_count,
            "context_entry_digest": self.context_entry_digest,
            "context_token_count": self.context_token_count,
            "entry_count": self.entry_count,
            "manifest_digest": self.manifest_digest,
            "request_digest": self.request_digest,
            "schema_version": "1",
        }


@dataclass(frozen=True, slots=True)
class _Tokenizer:
    name: str
    version: str
    method: str
    encoder: tiktoken.Encoding

    def count(self, text: str) -> int:
        return len(self.encoder.encode(text, disallowed_special=()))


@dataclass(frozen=True, slots=True)
class _SelectedSource:
    path: PurePosixPath
    content: str
    selection_reason: str


def build_bundle(
    case: ReviewerCase,
    snapshot: SnapshotName,
    condition: Condition,
    *,
    request_identity: str | None = None,
    worktree: Path,
    worktree_digest: str,
    tokenizer_spec: str,
    prompt_template: TemplateInput,
    profile_template: TemplateInput,
    reviewer_settings: ReviewerSettings,
    repetition: int,
    seed: int | None,
    request_id: str,
    run_id: str,
    created_at: datetime,
) -> BundleDraft:
    """Build one byte-stable request without finalizing a prompt manifest."""

    if request_identity is None:
        raise BundleError("opaque request identity is required")
    _validate_inputs(
        case,
        worktree_digest=worktree_digest,
        repetition=repetition,
        request_id=request_id,
        run_id=run_id,
        created_at=created_at,
        prompt_template=prompt_template,
        profile_template=profile_template,
        reviewer_settings=reviewer_settings,
        request_identity=request_identity,
    )
    tokenizer = _load_tokenizer(tokenizer_spec)
    root = _resolve_worktree_root(worktree)
    actual_worktree_digest = _compute_worktree_digest(root)
    if actual_worktree_digest != worktree_digest:
        raise BundleError("materialized worktree digest does not match the supplied record")
    sources = _select_sources(case, root)
    if _compute_worktree_digest(root) != worktree_digest:
        raise BundleError("materialized worktree changed while the bundle was being built")
    entries = _render_entries(case, sources, tokenizer)
    if not entries:
        raise BundleError("context policy selected no reviewer-visible text files")

    bundle_document: dict[str, JsonValue] = {
        "schema_version": "2",
        "request_identity": request_identity,
        "entries": [entry.bundle_dict() for entry in entries],
    }
    bundle_bytes = canonical_json_bytes(bundle_document)
    try:
        bundle_text = bundle_bytes.decode("utf-8")
    except UnicodeDecodeError as exc:  # pragma: no cover - canonical JSON is UTF-8
        raise BundleError("canonical reviewer bundle is not valid UTF-8") from exc
    bundle_token_count = tokenizer.count(bundle_text)

    prompt_content = _normalize_template(prompt_template.content)
    profile_content = _normalize_template(profile_template.content)
    prompt_digest = sha256_digest(prompt_content.encode("utf-8"))
    profile_digest = sha256_digest(profile_content.encode("utf-8"))
    reviewer_config = _reviewer_config_dict(reviewer_settings)
    request_document: dict[str, JsonValue] = {
        "schema_version": "1",
        "prompt_template": prompt_content,
        "profile_template": profile_content,
        "repository_context": bundle_document,
        "reviewer_config": reviewer_config,
    }
    request_bytes = canonical_json_bytes(request_document)
    if tokenizer.count(request_bytes.decode("utf-8")) > reviewer_settings.input_token_limit:
        raise BundleError("serialized reviewer request exceeds its configured input token limit")
    request_digest = sha256_digest(request_bytes)

    bundle_manifest_entries: list[JsonValue] = [entry.manifest_dict() for entry in entries]
    context_entry_digest = canonical_digest(bundle_manifest_entries)
    bundle_digest = sha256_digest(bundle_bytes)
    manifest_content: dict[str, JsonValue] = {
        "schema_version": "1.3",
        "case_id": case.case_id,
        "snapshot": snapshot,
        "request_identity": request_identity,
        "bundle_schema_version": "2",
        "condition": condition,
        "repetition": repetition,
        "request_id": request_id,
        "run_id": run_id,
        "source_commit": case.source_commit,
        "worktree_digest": worktree_digest,
        "bundle_entries": bundle_manifest_entries,
        "bundle_digest": bundle_digest,
        "bundle_byte_count": len(bundle_bytes),
        "bundle_token_count": bundle_token_count,
        "context_entry_digest": context_entry_digest,
        "context_byte_count": sum(entry.byte_count for entry in entries),
        "context_token_count": sum(entry.token_count for entry in entries),
        "bundle_config": _bundle_config_dict(case, tokenizer),
        "prompt_template": {
            "name": prompt_template.name,
            "version": prompt_template.version,
            "digest": prompt_digest,
        },
        "profile_template": {
            "name": profile_template.name,
            "version": profile_template.version,
            "digest": profile_digest,
        },
        "reviewer_config": reviewer_config,
        "request_digest": request_digest,
    }
    if seed is not None:
        manifest_content["seed"] = seed
    filename_components = tuple(
        RequestComponent("filename", entry.path.as_posix().encode("utf-8")) for entry in entries
    )
    return BundleDraft(
        bundle_bytes=bundle_bytes,
        request_bytes=request_bytes,
        manifest_seed_bytes=canonical_json_bytes(manifest_content),
        created_at=created_at.isoformat().replace("+00:00", "Z"),
        bundle_digest=bundle_digest,
        request_digest=request_digest,
        context_entry_digest=context_entry_digest,
        entry_count=len(entries),
        context_byte_count=sum(entry.byte_count for entry in entries),
        context_token_count=sum(entry.token_count for entry in entries),
        bundle_token_count=bundle_token_count,
        scan_components=(
            RequestComponent("serialized_request", request_bytes),
            RequestComponent("serialized_request", prompt_content.encode("utf-8")),
            RequestComponent("profile", profile_content.encode("utf-8")),
            *filename_components,
            RequestComponent("tool_configuration", canonical_json_bytes(reviewer_config)),
            *(
                RequestComponent("tool_configuration", value.encode("utf-8"))
                for value in (
                    reviewer_settings.model,
                    reviewer_settings.tool_policy,
                    reviewer_settings.adapter_version,
                )
            ),
            RequestComponent("context_bundle", bundle_bytes),
            *(
                RequestComponent("context_bundle", entry.content.encode("utf-8"))
                for entry in entries
            ),
        ),
    )


def write_bundle(build: BundleBuild, *, output_root: Path, run_id: str) -> tuple[Path, Path, Path]:
    """Write one build atomically without replacing any previous private artifact."""

    if _RUN_ID.fullmatch(run_id) is None:
        raise BundleError("run identifier must be normalized and path-safe")
    _reject_symlinked_output_components(output_root)
    if output_root.is_symlink() or (output_root.exists() and not output_root.is_dir()):
        raise BundleError("bundle output root contains unsafe prior state")
    target = output_root / run_id
    staging: Path | None = None
    try:
        output_root.mkdir(parents=True, mode=0o700, exist_ok=True)
        _reject_symlinked_output_components(output_root)
        if output_root.is_symlink() or not output_root.is_dir():
            raise BundleError("bundle output root contains unsafe prior state")
        if target.exists() or target.is_symlink():
            raise BundleError("bundle output target already exists")
        staging = Path(tempfile.mkdtemp(prefix=f".{run_id}.tmp-", dir=output_root))
        staging.chmod(0o700)
        _write_exclusive(staging / "bundle.json", build.bundle_bytes)
        _write_exclusive(staging / "request.json", build.request_bytes)
        _write_exclusive(staging / "prompt-manifest.json", build.manifest_bytes)
        _fsync_directory(staging)
        if target.exists() or target.is_symlink():
            raise BundleError("bundle output target already exists")
        staging.rename(target)
        staging = None
        _fsync_directory(output_root)
    except BundleError:
        raise
    except OSError as exc:
        raise BundleError("could not write private bundle artifacts safely") from exc
    finally:
        if staging is not None:
            shutil.rmtree(staging, ignore_errors=True)
    return (
        target / "bundle.json",
        target / "request.json",
        target / "prompt-manifest.json",
    )


def _validate_inputs(
    case: ReviewerCase,
    *,
    worktree_digest: str,
    repetition: int,
    request_id: str,
    run_id: str,
    created_at: datetime,
    prompt_template: TemplateInput,
    profile_template: TemplateInput,
    reviewer_settings: ReviewerSettings,
    request_identity: str,
) -> None:
    if _RUN_ID.fullmatch(run_id) is None:
        raise BundleError("run identifier must be normalized and path-safe")
    if (
        not request_id
        or len(request_id) > 200
        or any(character in request_id for character in "\r\n")
    ):
        raise BundleError("request identifier is invalid")
    if repetition < 1:
        raise BundleError("repetition must be positive")
    if created_at.tzinfo is None:
        raise BundleError("manifest creation time must include a timezone")
    if not re.fullmatch(r"sha256:[0-9a-f]{64}", worktree_digest):
        raise BundleError("worktree digest is invalid")
    if not re.fullmatch(r"[0-9a-f]{40}", case.source_commit):
        raise BundleError("reviewer case source commit is invalid")
    if _REQUEST_IDENTITY.fullmatch(request_identity) is None:
        raise BundleError("opaque request identity is invalid")
    for template in (prompt_template, profile_template):
        if not template.name or len(template.name) > 200:
            raise BundleError("template name is invalid")
        if not template.version or len(template.version) > 100:
            raise BundleError("template version is invalid")
    if (
        not reviewer_settings.model
        or len(reviewer_settings.model) > 200
        or not reviewer_settings.tool_policy
        or len(reviewer_settings.tool_policy) > 200
        or reviewer_settings.input_token_limit < 1
        or reviewer_settings.output_token_limit < 1
        or not 0 <= reviewer_settings.temperature <= 2
        or not reviewer_settings.adapter_version
        or len(reviewer_settings.adapter_version) > 100
    ):
        raise BundleError("reviewer configuration is invalid")


def _load_tokenizer(specification: str) -> _Tokenizer:
    matched = _TOKENIZER_SPEC.fullmatch(specification)
    if matched is None:
        raise BundleError("case tokenizer specification is unsupported")
    runtime_version = metadata.version("tiktoken")
    if matched.group("version") != runtime_version:
        raise BundleError("case tokenizer version does not match the runtime")
    try:
        encoder = tiktoken.get_encoding(matched.group("name"))
    except Exception as exc:
        raise BundleError("case tokenizer encoding is unavailable") from exc
    return _Tokenizer(
        name=matched.group("name"),
        version=runtime_version,
        method=matched.group("method"),
        encoder=encoder,
    )


def _resolve_worktree_root(worktree: Path) -> Path:
    try:
        if worktree.is_symlink():
            raise BundleError("materialized worktree root must not be a symlink")
        root = worktree.resolve(strict=True)
        if not root.is_dir():
            raise BundleError("materialized worktree root is unavailable")
    except OSError as exc:
        raise BundleError("materialized worktree root is unavailable") from exc
    return root


def _compute_worktree_digest(root: Path) -> str:
    manifest: list[JsonValue] = []
    for candidate in sorted(_walk_files(root), key=lambda path: path.relative_to(root).as_posix()):
        relative = PurePosixPath(*candidate.relative_to(root).parts)
        _validate_policy_path(relative)
        try:
            metadata_value = candidate.lstat()
        except OSError as exc:
            raise BundleError("materialized worktree changed during digest verification") from exc
        if stat.S_ISLNK(metadata_value.st_mode):
            payload = _read_relative_symlink(root, relative)
            mode = "120000"
        elif stat.S_ISREG(metadata_value.st_mode):
            payload = _read_relative_regular_file(root, relative)
            mode = "100755" if metadata_value.st_mode & stat.S_IXUSR else "100644"
        else:
            raise BundleError("materialized worktree contains an unsupported entry")
        git_digest = hashlib.sha1(f"blob {len(payload)}\0".encode("ascii"), usedforsecurity=False)
        git_digest.update(payload)
        manifest.append(
            {
                "content_digest": sha256_digest(payload),
                "git_object_id": git_digest.hexdigest(),
                "mode": mode,
                "path": relative.as_posix(),
                "size": len(payload),
            }
        )
    return canonical_digest(manifest)


def _select_sources(case: ReviewerCase, worktree: Path) -> tuple[_SelectedSource, ...]:
    root = _resolve_worktree_root(worktree)

    selected: dict[str, tuple[PurePosixPath, str]] = {}
    for include_index, include in enumerate(case.context_policy.includes):
        _validate_policy_path(include)
        candidate = root.joinpath(*include.parts)
        try:
            metadata_value = candidate.lstat()
        except OSError as exc:
            raise BundleError(f"context include at index {include_index} is unavailable") from exc
        candidates: Iterable[Path]
        if stat.S_ISDIR(metadata_value.st_mode):
            candidates = _walk_files(candidate)
        else:
            candidates = (candidate,)
        found = False
        for selected_path in candidates:
            found = True
            relative = PurePosixPath(*selected_path.relative_to(root).parts)
            _validate_policy_path(relative)
            if _is_excluded(relative, case.context_policy.excludes):
                continue
            key = relative.as_posix()
            selected.setdefault(key, (relative, f"include[{include_index}]"))
        if not found and not _is_excluded(include, case.context_policy.excludes):
            raise BundleError(f"context include at index {include_index} selected no files")

    sources: list[_SelectedSource] = []
    for key in sorted(selected):
        path, reason = selected[key]
        content = _read_source(root, path, case)
        if content is not None:
            sources.append(_SelectedSource(path=path, content=content, selection_reason=reason))
    return tuple(sources)


def _walk_files(root: Path) -> tuple[Path, ...]:
    files: list[Path] = []
    for current, directories, filenames in os.walk(root, followlinks=False):
        current_path = Path(current)
        for directory in directories:
            child = current_path / directory
            if child.is_symlink():
                files.append(child)
        files.extend(current_path / filename for filename in filenames)
    return tuple(files)


def _read_source(root: Path, relative: PurePosixPath, case: ReviewerCase) -> str | None:
    candidate = root.joinpath(*relative.parts)
    try:
        metadata_value = candidate.lstat()
    except OSError as exc:
        raise BundleError("selected context file is unavailable") from exc
    if stat.S_ISLNK(metadata_value.st_mode):
        if case.context_policy.symlink_policy == "reject":
            raise BundleError("selected context contains a disallowed symlink")
        try:
            resolved = candidate.resolve(strict=True)
            resolved.relative_to(root)
        except (OSError, ValueError) as exc:
            raise BundleError("selected context symlink does not stay within the worktree") from exc
        if not resolved.is_file():
            raise BundleError("selected context symlink does not resolve to a regular file")
        resolved_relative = PurePosixPath(*resolved.relative_to(root).parts)
        payload = _read_relative_regular_file(root, resolved_relative)
    elif stat.S_ISREG(metadata_value.st_mode):
        payload = _read_relative_regular_file(root, relative)
    else:
        raise BundleError("selected context contains an unsupported filesystem entry")

    if b"\0" in payload:
        if case.context_policy.binary_policy == "omit":
            return None
        raise BundleError("selected context contains a binary file")
    try:
        text = payload.decode("utf-8")
    except UnicodeDecodeError as exc:
        if case.context_policy.binary_policy == "omit":
            return None
        raise BundleError("selected context contains non-UTF-8 content") from exc
    return _normalize_newlines(text)


def _read_relative_regular_file(root: Path, relative: PurePosixPath) -> bytes:
    directory_flags = (
        os.O_RDONLY
        | getattr(os, "O_CLOEXEC", 0)
        | getattr(os, "O_DIRECTORY", 0)
        | getattr(os, "O_NOFOLLOW", 0)
    )
    file_flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    current_descriptor: int | None = None
    file_descriptor: int | None = None
    try:
        current_descriptor = os.open(root, directory_flags)
        for part in relative.parent.parts:
            next_descriptor = os.open(part, directory_flags, dir_fd=current_descriptor)
            os.close(current_descriptor)
            current_descriptor = next_descriptor
        file_descriptor = os.open(relative.name, file_flags, dir_fd=current_descriptor)
        metadata_value = os.fstat(file_descriptor)
        if not stat.S_ISREG(metadata_value.st_mode):
            raise BundleError("selected context file is not regular")
        chunks: list[bytes] = []
        while True:
            chunk = os.read(file_descriptor, 1024 * 1024)
            if not chunk:
                break
            chunks.append(chunk)
        return b"".join(chunks)
    except BundleError:
        raise
    except OSError as exc:
        raise BundleError("selected context path is unavailable or unsafe") from exc
    finally:
        if file_descriptor is not None:
            os.close(file_descriptor)
        if current_descriptor is not None:
            os.close(current_descriptor)


def _read_relative_symlink(root: Path, relative: PurePosixPath) -> bytes:
    directory_flags = (
        os.O_RDONLY
        | getattr(os, "O_CLOEXEC", 0)
        | getattr(os, "O_DIRECTORY", 0)
        | getattr(os, "O_NOFOLLOW", 0)
    )
    current_descriptor: int | None = None
    try:
        current_descriptor = os.open(root, directory_flags)
        for part in relative.parent.parts:
            next_descriptor = os.open(part, directory_flags, dir_fd=current_descriptor)
            os.close(current_descriptor)
            current_descriptor = next_descriptor
        target = os.readlink(relative.name, dir_fd=current_descriptor)
        return target.encode("utf-8")
    except (OSError, UnicodeError) as exc:
        raise BundleError("materialized worktree symlink is unavailable or unsafe") from exc
    finally:
        if current_descriptor is not None:
            os.close(current_descriptor)


def _validate_policy_path(path: PurePosixPath) -> None:
    value = path.as_posix()
    if (
        not value
        or value.startswith("/")
        or "\\" in value
        or "\0" in value
        or unicodedata.normalize("NFC", value) != value
        or any(part in {"", ".", ".."} for part in value.split("/"))
    ):
        raise BundleError("context policy contains an unsafe repository path")


def _is_excluded(path: PurePosixPath, excludes: Sequence[PurePosixPath]) -> bool:
    for exclude in excludes:
        _validate_policy_path(exclude)
        if path == exclude or exclude in path.parents:
            return True
    return False


def _render_entries(
    case: ReviewerCase, sources: Sequence[_SelectedSource], tokenizer: _Tokenizer
) -> tuple[BundleEntryRecord, ...]:
    policy = cast(TruncationPolicy, case.context_policy.truncation_policy)
    preliminary = [
        _render_entry(
            source,
            tokenizer,
            byte_limit=case.context_policy.per_file_byte_limit,
            token_limit=case.context_policy.per_file_token_limit,
            policy=policy,
        )
        for source in sources
    ]
    if sum(entry.token_count for entry in preliminary) <= case.context_policy.total_token_limit:
        return tuple(preliminary)
    if policy == "reject":
        raise BundleError("selected context exceeds the configured total token limit")

    rendered: list[BundleEntryRecord] = []
    remaining_tokens = case.context_policy.total_token_limit
    for index, source in enumerate(sources):
        remaining_files = len(sources) - index
        token_share = remaining_tokens // remaining_files
        entry = _render_entry(
            source,
            tokenizer,
            byte_limit=case.context_policy.per_file_byte_limit,
            token_limit=min(case.context_policy.per_file_token_limit, token_share),
            policy=policy,
        )
        rendered.append(entry)
        remaining_tokens -= entry.token_count
    if remaining_tokens < 0:
        raise BundleError("selected context cannot fit its configured total token limit")
    return tuple(rendered)


def _render_entry(
    source: _SelectedSource,
    tokenizer: _Tokenizer,
    *,
    byte_limit: int,
    token_limit: int,
    policy: TruncationPolicy,
) -> BundleEntryRecord:
    content, truncated = _limit_text(
        source.content,
        tokenizer,
        byte_limit=byte_limit,
        token_limit=token_limit,
        policy=policy,
    )
    payload = content.encode("utf-8")
    return BundleEntryRecord(
        path=source.path,
        content=content,
        byte_count=len(payload),
        token_count=tokenizer.count(content),
        content_digest=sha256_digest(payload),
        truncated=truncated,
        selection_reason=source.selection_reason,
    )


def _limit_text(
    text: str,
    tokenizer: _Tokenizer,
    *,
    byte_limit: int,
    token_limit: int,
    policy: TruncationPolicy,
) -> tuple[str, bool]:
    if _fits(text, tokenizer, byte_limit=byte_limit, token_limit=token_limit):
        return text, False
    if policy == "reject":
        raise BundleError("selected context file exceeds a configured limit")
    if token_limit < 1 or not _fits(
        _TRUNCATION_MARKER,
        tokenizer,
        byte_limit=byte_limit,
        token_limit=token_limit,
    ):
        raise BundleError("configured limits cannot contain a truncation marker")

    def candidate(kept: int) -> str:
        if policy == "head":
            return text[:kept] + _TRUNCATION_MARKER
        head_count = (kept + 1) // 2
        tail_count = kept // 2
        tail = text[len(text) - tail_count :] if tail_count else ""
        return text[:head_count] + _TRUNCATION_MARKER + tail

    low = 0
    high = len(text)
    byte_ceiling = 0
    while low <= high:
        midpoint = (low + high) // 2
        rendered = candidate(midpoint)
        if len(rendered.encode("utf-8")) <= byte_limit:
            byte_ceiling = midpoint
            low = midpoint + 1
        else:
            high = midpoint - 1
    # A stable prefix survives every completion, including our marker and tail.
    # If that prefix alone exceeds the budget, every longer candidate is impossible.
    # Binary search only narrows this conservative ceiling: token fit itself is
    # non-monotonic, so examine every remaining candidate in descending order.
    low, high = 0, byte_ceiling
    token_ceiling = byte_ceiling
    while low <= high:
        midpoint = (low + high) // 2
        head_count = midpoint if policy == "head" else (midpoint + 1) // 2
        stable, _ = tokenizer.encoder.encode_with_unstable(text[:head_count], disallowed_special=())
        if len(stable) > token_limit:
            token_ceiling = midpoint - 1
            high = midpoint - 1
        else:
            low = midpoint + 1
    for kept in range(token_ceiling, -1, -1):
        rendered = candidate(kept)
        if _fits(rendered, tokenizer, byte_limit=byte_limit, token_limit=token_limit):
            return rendered, True
    raise BundleError("selected context cannot be truncated within configured limits")


def _fits(text: str, tokenizer: _Tokenizer, *, byte_limit: int, token_limit: int) -> bool:
    return len(text.encode("utf-8")) <= byte_limit and tokenizer.count(text) <= token_limit


def _normalize_newlines(value: str) -> str:
    return value.replace("\r\n", "\n").replace("\r", "\n")


def _normalize_template(value: str) -> str:
    if "\0" in value:
        raise BundleError("template contains unsupported content")
    return _normalize_newlines(value)


def _reviewer_config_dict(settings: ReviewerSettings) -> dict[str, JsonValue]:
    return {
        "model": settings.model,
        "tool_policy": settings.tool_policy,
        "input_token_limit": settings.input_token_limit,
        "output_token_limit": settings.output_token_limit,
        "temperature": settings.temperature,
        "adapter_version": settings.adapter_version,
    }


def _bundle_config_dict(case: ReviewerCase, tokenizer: _Tokenizer) -> dict[str, JsonValue]:
    return {
        "encoding": "utf-8",
        "newline_policy": "normalize_lf_v1",
        "tokenizer": {
            "implementation": "tiktoken",
            "name": tokenizer.name,
            "version": tokenizer.version,
            "method": tokenizer.method,
        },
        "context_policy": case.context_policy.to_dict(),
    }


def _write_exclusive(path: Path, payload: bytes) -> None:
    flags = (
        os.O_WRONLY
        | os.O_CREAT
        | os.O_EXCL
        | getattr(os, "O_CLOEXEC", 0)
        | getattr(os, "O_NOFOLLOW", 0)
    )
    descriptor = os.open(path, flags, 0o600)
    try:
        with os.fdopen(descriptor, "wb", closefd=False) as stream:
            stream.write(payload)
            stream.flush()
            os.fsync(descriptor)
    finally:
        os.close(descriptor)


def _fsync_directory(path: Path) -> None:
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0)
    descriptor = os.open(path, flags)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def _reject_symlinked_output_components(path: Path) -> None:
    if ".." in path.parts:
        raise BundleError("bundle output root contains unsafe prior state")
    absolute = path.absolute()
    current = Path(absolute.anchor)
    for part in absolute.parts[1:]:
        current /= part
        try:
            metadata_value = current.lstat()
        except FileNotFoundError:
            break
        except OSError as exc:
            raise BundleError("bundle output root contains unsafe prior state") from exc
        if stat.S_ISLNK(metadata_value.st_mode):
            raise BundleError("bundle output root contains unsafe prior state")


def load_template(path: Path, *, name: str, version: str) -> TemplateInput:
    """Load a UTF-8 template without exposing its contents in failures."""

    try:
        payload = path.read_bytes()
        content = payload.decode("utf-8")
    except (OSError, UnicodeError) as exc:
        raise BundleError("could not load a reviewer template safely") from exc
    return TemplateInput(name=name, version=version, content=_normalize_template(content))


def canonical_summary(build: BundleBuild) -> bytes:
    """Return the non-content CLI summary as canonical JSON."""

    return canonical_json_bytes(build.summary())


def parse_manifest_bytes(payload: bytes) -> PromptManifest:
    """Validate one generated manifest without accepting non-object JSON."""

    try:
        document = json.loads(payload)
    except (UnicodeError, json.JSONDecodeError) as exc:
        raise BundleError("prompt manifest is not valid JSON") from exc
    if not isinstance(document, dict):
        raise BundleError("prompt manifest must contain an object")
    return PromptManifest.from_dict(cast(dict[str, object], document))
