"""Bounded, shell-free reviewer subprocess adapter."""

from __future__ import annotations

import hashlib
import json
import os
import re
import shutil
import signal
import subprocess
import tempfile
import threading
import time
from collections.abc import Mapping
from contextlib import suppress
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from typing import BinaryIO, Literal, Protocol, cast

from preflight_evals.artifact_policy import configured_root_is_allowed
from preflight_evals.bundle import BundleBuild, ReviewerSettings, parse_manifest_bytes
from preflight_evals.canonical import JsonValue, canonical_digest, sha256_digest
from preflight_evals.config import EvaluationConfig
from preflight_evals.errors import BundleError, ConfigurationError, SchemaError
from preflight_evals.reviewer_models import PromptManifest, ReviewerOutput

type FailureClassification = Literal[
    "invalid_output",
    "provider_error",
    "configuration_error",
    "timeout",
    "adapter_error",
]
type StderrClassification = Literal[
    "none",
    "usage",
    "configuration",
    "provider",
    "timeout",
    "internal",
    "redacted_unknown",
]

ADAPTER_VERSION = "direct-cli-subprocess-v1"
_RUN_ID = re.compile(r"run-[a-z0-9]+(?:-[a-z0-9]+)*")
_EXPERIMENT_ID = re.compile(r"experiment-[a-z0-9]+(?:-[a-z0-9]+)*")
_VERSION = re.compile(r"[^\x00-\x1f\x7f]{1,200}")
_DIGEST = re.compile(r"sha256:[0-9a-f]{64}")
_ADAPTER_CAPABILITIES = (
    "stdin-request-v1",
    "structured-reviewer-output-v1",
)
_MODEL_ARGUMENT = "{model}"
_ENVIRONMENT_ALLOWLIST = (
    "HOME",
    "LANG",
    "LC_ALL",
    "LOGNAME",
    "PATH",
    "SHELL",
    "SSL_CERT_DIR",
    "SSL_CERT_FILE",
    "TMPDIR",
    "USER",
    "XDG_CONFIG_HOME",
)
_READ_CHUNK = 16 * 1024
_TERMINATION_GRACE_SECONDS = 0.5
_CAPTURE_SHUTDOWN_SECONDS = 1.0
_WORKING_DIRECTORY_POLICY = "explicit-empty-directory-v1"
_ENVIRONMENT_POLICY = "minimal-allowlist-v1"
_TERMINATION_POLICY = "new-session-term-kill-v1"


@dataclass(frozen=True, slots=True)
class AdapterConfiguration:
    """Local process controls that never contain reviewer content."""

    executable: str
    review_arguments: tuple[str, ...]
    working_directory: Path
    version_arguments: tuple[str, ...] = ("--version",)
    probe_timeout_seconds: float = 10.0
    maximum_stdout_bytes: int = 1_000_000
    maximum_stderr_bytes: int = 64_000

    def validate(self) -> None:
        if not self.executable or any(ord(character) < 32 for character in self.executable):
            raise AdapterConfigurationError("adapter executable configuration is invalid")
        _ensure_working_directory(self.working_directory)
        for arguments in (
            self.review_arguments,
            self.version_arguments,
        ):
            if (
                not arguments
                or len(arguments) > 20
                or any(
                    not argument or any(ord(character) < 32 for character in argument)
                    for argument in arguments
                )
            ):
                raise AdapterConfigurationError("adapter argument configuration is invalid")
        if self.review_arguments.count(_MODEL_ARGUMENT) != 1:
            raise AdapterConfigurationError("adapter review arguments must bind the model")
        if not 0 < self.probe_timeout_seconds <= 300:
            raise AdapterConfigurationError("adapter probe timeout is invalid")
        if not 1 <= self.maximum_stdout_bytes <= 16_000_000:
            raise AdapterConfigurationError("adapter stdout limit is invalid")
        if not 1 <= self.maximum_stderr_bytes <= 1_000_000:
            raise AdapterConfigurationError("adapter stderr limit is invalid")


@dataclass(frozen=True, slots=True)
class TracePolicy:
    """Raw-output retention rooted in the repository's configured trace class."""

    repository_root: Path
    raw_trace_root: PurePosixPath
    retain_raw_output: bool

    def validate(self) -> None:
        if (
            not self.repository_root.is_absolute()
            or not self.repository_root.is_dir()
            or self.repository_root.is_symlink()
        ):
            raise AdapterConfigurationError("adapter trace repository root is invalid")
        if (
            self.raw_trace_root.is_absolute()
            or ".." in self.raw_trace_root.parts
            or "\\" in self.raw_trace_root.as_posix()
        ):
            raise AdapterConfigurationError("adapter trace root violates artifact policy")
        if not configured_root_is_allowed(self.raw_trace_root, "raw_traces"):
            raise AdapterConfigurationError("adapter trace root violates artifact policy")


@dataclass(frozen=True, slots=True)
class ProfileIdentity:
    name: str
    version: str
    digest: str


@dataclass(frozen=True, slots=True)
class AdapterRunMetadata:
    run_id: str
    experiment_id: str
    request_id: str
    condition: str
    repetition: int
    attempt: int


@dataclass(frozen=True, slots=True)
class AdapterCapabilities:
    """Canonical executable evidence suitable for freezing into an experiment."""

    adapter_version: str
    executable_version: str
    executable_digest: str
    review_arguments: tuple[str, ...]
    version_arguments: tuple[str, ...]
    probe_timeout_seconds: float
    maximum_stdout_bytes: int
    maximum_stderr_bytes: int
    working_directory_policy: str
    environment_policy: str
    termination_policy: str
    capabilities: tuple[str, ...]
    content_digest: str

    @classmethod
    def from_dict(cls, document: Mapping[str, object]) -> AdapterCapabilities:
        """Load frozen capability evidence without trusting caller-created fields."""

        expected = {
            "adapter_version",
            "executable_version",
            "executable_digest",
            "review_arguments",
            "version_arguments",
            "probe_timeout_seconds",
            "maximum_stdout_bytes",
            "maximum_stderr_bytes",
            "working_directory_policy",
            "environment_policy",
            "termination_policy",
            "capabilities",
            "content_digest",
        }
        if set(document) != expected:
            raise AdapterConfigurationError("adapter capability evidence is invalid")
        try:
            review_arguments = _frozen_string_tuple(document["review_arguments"])
            version_arguments = _frozen_string_tuple(document["version_arguments"])
            capabilities = _frozen_string_tuple(document["capabilities"])
            probe_timeout = _strict_number(document["probe_timeout_seconds"])
            maximum_stdout = _strict_integer(document["maximum_stdout_bytes"])
            maximum_stderr = _strict_integer(document["maximum_stderr_bytes"])
            model = cls(
                adapter_version=_strict_string(document["adapter_version"]),
                executable_version=_strict_string(document["executable_version"]),
                executable_digest=_strict_string(document["executable_digest"]),
                review_arguments=review_arguments,
                version_arguments=version_arguments,
                probe_timeout_seconds=probe_timeout,
                maximum_stdout_bytes=maximum_stdout,
                maximum_stderr_bytes=maximum_stderr,
                working_directory_policy=_strict_string(document["working_directory_policy"]),
                environment_policy=_strict_string(document["environment_policy"]),
                termination_policy=_strict_string(document["termination_policy"]),
                capabilities=capabilities,
                content_digest=_strict_string(document["content_digest"]),
            )
        except (KeyError, TypeError, ValueError) as exc:
            raise AdapterConfigurationError("adapter capability evidence is invalid") from exc
        if (
            model.adapter_version != ADAPTER_VERSION
            or _DIGEST.fullmatch(model.executable_digest) is None
            or _DIGEST.fullmatch(model.content_digest) is None
            or not 0 < model.probe_timeout_seconds <= 300
            or not 1 <= model.maximum_stdout_bytes <= 16_000_000
            or not 1 <= model.maximum_stderr_bytes <= 1_000_000
            or model.working_directory_policy != _WORKING_DIRECTORY_POLICY
            or model.environment_policy != _ENVIRONMENT_POLICY
            or model.termination_policy != _TERMINATION_POLICY
            or model.capabilities != _ADAPTER_CAPABILITIES
            or model.content_digest != _capabilities_digest(model)
        ):
            raise AdapterConfigurationError("adapter capability evidence is invalid")
        return model

    def to_dict(self) -> dict[str, JsonValue]:
        return {
            "adapter_version": self.adapter_version,
            "executable_version": self.executable_version,
            "executable_digest": self.executable_digest,
            "review_arguments": list(self.review_arguments),
            "version_arguments": list(self.version_arguments),
            "probe_timeout_seconds": self.probe_timeout_seconds,
            "maximum_stdout_bytes": self.maximum_stdout_bytes,
            "maximum_stderr_bytes": self.maximum_stderr_bytes,
            "working_directory_policy": self.working_directory_policy,
            "environment_policy": self.environment_policy,
            "termination_policy": self.termination_policy,
            "capabilities": list(self.capabilities),
            "content_digest": self.content_digest,
        }


@dataclass(frozen=True, slots=True)
class AdapterInvocation:
    """One immutable, leakage-approved reviewer invocation."""

    build: BundleBuild
    profile: ProfileIdentity
    reviewer_settings: ReviewerSettings
    output_schema_version: str
    timeout_seconds: float
    metadata: AdapterRunMetadata
    capabilities: AdapterCapabilities
    trace_policy: TracePolicy


@dataclass(frozen=True, slots=True)
class RawTraceRecord:
    stdout_path: PurePosixPath | None
    stdout_digest: str
    stderr_path: PurePosixPath | None
    stderr_digest: str
    truncated: bool

    def to_dict(self) -> dict[str, JsonValue]:
        return {
            "stdout_path": self.stdout_path.as_posix() if self.stdout_path is not None else None,
            "stdout_digest": self.stdout_digest,
            "stderr_path": self.stderr_path.as_posix() if self.stderr_path is not None else None,
            "stderr_digest": self.stderr_digest,
            "truncated": self.truncated,
        }


@dataclass(frozen=True, slots=True)
class AdapterOutcome:
    """Disclosure-safe machine result; raw process content is never stored here."""

    reviewer_output: ReviewerOutput | None
    failure: FailureClassification | None
    retryable: bool
    exit_status: int | None
    stderr_classification: StderrClassification
    validation_errors: tuple[str, ...]
    monotonic_latency_ms: float
    raw_trace: RawTraceRecord
    provider: str | None = None
    provider_request_id: str | None = None
    input_tokens: int | None = None
    cached_input_tokens: int | None = None
    output_tokens: int | None = None
    reasoning_tokens: int | None = None
    total_cost_usd: float | None = None

    @property
    def succeeded(self) -> bool:
        return self.failure is None

    def to_dict(self) -> dict[str, JsonValue]:
        return {
            "succeeded": self.succeeded,
            "reviewer_output": (
                self.reviewer_output.to_dict() if self.reviewer_output is not None else None
            ),
            "failure": self.failure,
            "retryable": self.retryable,
            "exit_status": self.exit_status,
            "stderr_classification": self.stderr_classification,
            "validation_errors": list(self.validation_errors),
            "monotonic_latency_ms": self.monotonic_latency_ms,
            "raw_trace": self.raw_trace.to_dict(),
            "provider": self.provider,
            "provider_request_id": self.provider_request_id,
            "usage": {
                "input_tokens": self.input_tokens,
                "cached_input_tokens": self.cached_input_tokens,
                "output_tokens": self.output_tokens,
                "reasoning_tokens": self.reasoning_tokens,
            },
            "total_cost_usd": self.total_cost_usd,
        }


class ReviewAdapter(Protocol):
    def probe(self) -> AdapterCapabilities: ...

    def invoke(self, invocation: AdapterInvocation) -> AdapterOutcome: ...


class AdapterConfigurationError(ConfigurationError):
    """A disclosure-safe invalid adapter configuration or invocation."""


@dataclass(frozen=True, slots=True)
class _ProcessCapture:
    stdout: bytes
    stderr: bytes
    exit_status: int | None
    timed_out: bool
    stdout_oversized: bool
    stderr_oversized: bool
    read_error: bool
    latency_ms: float


class ReviewerSubprocessAdapter:
    """Invoke a reviewer executable with fixed arguments and canonical stdin content."""

    def __init__(self, configuration: AdapterConfiguration) -> None:
        configuration.validate()
        self._configuration = configuration

    def probe(self) -> AdapterCapabilities:
        _ensure_working_directory(self._configuration.working_directory)
        executable = _resolve_executable(self._configuration.executable)
        version_capture = self._capture(
            (str(executable), *self._configuration.version_arguments),
            b"",
            self._configuration.probe_timeout_seconds,
        )
        if not _probe_capture_succeeded(version_capture):
            raise AdapterConfigurationError("adapter executable version probe failed")
        version_text = _decode_probe(version_capture.stdout)
        executable_version = version_text.strip()
        if _VERSION.fullmatch(executable_version) is None:
            raise AdapterConfigurationError("adapter executable version response is invalid")

        capabilities = _ADAPTER_CAPABILITIES
        content: dict[str, JsonValue] = {
            "adapter_version": ADAPTER_VERSION,
            "executable_version": executable_version,
            "executable_digest": _file_digest(executable),
            "review_arguments": list(self._configuration.review_arguments),
            "version_arguments": list(self._configuration.version_arguments),
            "probe_timeout_seconds": self._configuration.probe_timeout_seconds,
            "maximum_stdout_bytes": self._configuration.maximum_stdout_bytes,
            "maximum_stderr_bytes": self._configuration.maximum_stderr_bytes,
            "working_directory_policy": _WORKING_DIRECTORY_POLICY,
            "environment_policy": _ENVIRONMENT_POLICY,
            "termination_policy": _TERMINATION_POLICY,
            "capabilities": list(capabilities),
        }
        return AdapterCapabilities(
            adapter_version=ADAPTER_VERSION,
            executable_version=executable_version,
            executable_digest=cast(str, content["executable_digest"]),
            review_arguments=self._configuration.review_arguments,
            version_arguments=self._configuration.version_arguments,
            probe_timeout_seconds=self._configuration.probe_timeout_seconds,
            maximum_stdout_bytes=self._configuration.maximum_stdout_bytes,
            maximum_stderr_bytes=self._configuration.maximum_stderr_bytes,
            working_directory_policy=_WORKING_DIRECTORY_POLICY,
            environment_policy=_ENVIRONMENT_POLICY,
            termination_policy=_TERMINATION_POLICY,
            capabilities=capabilities,
            content_digest=canonical_digest(content),
        )

    def invoke(self, invocation: AdapterInvocation) -> AdapterOutcome:
        manifest = _validate_invocation(invocation)
        try:
            _ensure_working_directory(self._configuration.working_directory)
        except AdapterConfigurationError:
            return _failure_without_process("configuration_error", "WORKING_DIRECTORY_UNSAFE")
        try:
            executable = _resolve_executable(self._configuration.executable)
            executable_digest = _file_digest(executable)
        except AdapterConfigurationError:
            return _failure_without_process("configuration_error", "EXECUTABLE_UNAVAILABLE")
        if executable_digest != invocation.capabilities.executable_digest:
            return _failure_without_process("configuration_error", "EXECUTABLE_CHANGED")
        if not _configuration_matches_capabilities(self._configuration, invocation.capabilities):
            return _failure_without_process("configuration_error", "PROCESS_CONTROLS_CHANGED")
        started = time.monotonic()
        try:
            capture = self._capture(
                (
                    str(executable),
                    *_review_arguments(
                        self._configuration.review_arguments,
                        invocation.reviewer_settings.model,
                    ),
                ),
                invocation.build.request_bytes,
                invocation.timeout_seconds,
            )
        except AdapterConfigurationError:
            return _failure_without_process("configuration_error", "PROCESS_START_FAILED")
        metadata = _provider_metadata_from_nonzero(capture.stdout)
        try:
            trace = _retain_raw_trace(invocation, capture)
        except AdapterConfigurationError:
            return AdapterOutcome(
                reviewer_output=None,
                failure="adapter_error",
                retryable=False,
                exit_status=capture.exit_status,
                stderr_classification="internal",
                validation_errors=("TRACE_RETENTION_FAILED",),
                monotonic_latency_ms=(time.monotonic() - started) * 1000,
                raw_trace=_trace_digests(capture),
                provider=metadata.provider,
                provider_request_id=metadata.provider_request_id,
                input_tokens=metadata.input_tokens,
                cached_input_tokens=metadata.cached_input_tokens,
                output_tokens=metadata.output_tokens,
                reasoning_tokens=metadata.reasoning_tokens,
                total_cost_usd=metadata.total_cost_usd,
            )
        return _classify_capture(capture, trace, manifest)

    def _capture(
        self, arguments: tuple[str, ...], input_bytes: bytes, timeout_seconds: float
    ) -> _ProcessCapture:
        return _run_bounded(
            arguments,
            input_bytes,
            working_directory=self._configuration.working_directory,
            timeout_seconds=timeout_seconds,
            maximum_stdout_bytes=self._configuration.maximum_stdout_bytes,
            maximum_stderr_bytes=self._configuration.maximum_stderr_bytes,
        )


def configuration_from_evaluation(
    config: EvaluationConfig, repository_root: Path
) -> AdapterConfiguration:
    """Resolve the validated non-secret process configuration against one repository."""

    process = config.adapter
    return AdapterConfiguration(
        executable=process.executable,
        review_arguments=process.review_arguments,
        working_directory=repository_root.joinpath(*process.working_directory.parts),
        version_arguments=process.version_arguments,
        probe_timeout_seconds=process.probe_timeout_seconds,
        maximum_stdout_bytes=process.maximum_stdout_bytes,
        maximum_stderr_bytes=process.maximum_stderr_bytes,
    )


def trace_policy_from_evaluation(
    config: EvaluationConfig,
    repository_root: Path,
    *,
    retain_raw_output: bool,
) -> TracePolicy:
    """Resolve the configured raw-trace class without exposing its contents."""

    return TracePolicy(
        repository_root=repository_root,
        raw_trace_root=config.artifacts.raw_traces,
        retain_raw_output=retain_raw_output,
    )


def ensure_paired_invocations(baseline: AdapterInvocation, candidate: AdapterInvocation) -> None:
    """Require paired calls to differ only in approved profile/identity fields."""

    baseline_manifest = _validate_invocation(baseline)
    candidate_manifest = _validate_invocation(candidate)
    if baseline.metadata.condition != "baseline" or candidate.metadata.condition != "candidate":
        raise AdapterConfigurationError("paired adapter conditions are invalid")
    baseline_fingerprint = _pair_fingerprint(baseline, baseline_manifest)
    candidate_fingerprint = _pair_fingerprint(candidate, candidate_manifest)
    if baseline_fingerprint != candidate_fingerprint:
        raise AdapterConfigurationError("paired adapter settings are not invariant")


def _validate_invocation(invocation: AdapterInvocation) -> PromptManifest:
    invocation.trace_policy.validate()
    metadata = invocation.metadata
    if (
        _RUN_ID.fullmatch(metadata.run_id) is None
        or _EXPERIMENT_ID.fullmatch(metadata.experiment_id) is None
    ):
        raise AdapterConfigurationError("adapter run metadata is invalid")
    if (
        not metadata.request_id
        or len(metadata.request_id) > 200
        or metadata.condition not in {"baseline", "candidate"}
        or metadata.repetition < 1
        or metadata.attempt < 1
    ):
        raise AdapterConfigurationError("adapter run metadata is invalid")
    if invocation.output_schema_version != "1.0":
        raise AdapterConfigurationError("adapter output schema version is unsupported")
    if not 0 < invocation.timeout_seconds <= 3600:
        raise AdapterConfigurationError("adapter invocation timeout is invalid")
    capabilities = invocation.capabilities
    if (
        capabilities.adapter_version != ADAPTER_VERSION
        or _DIGEST.fullmatch(capabilities.executable_digest) is None
        or _DIGEST.fullmatch(capabilities.content_digest) is None
        or not capabilities.review_arguments
        or not capabilities.version_arguments
        or not 0 < capabilities.probe_timeout_seconds <= 300
        or not 1 <= capabilities.maximum_stdout_bytes <= 16_000_000
        or not 1 <= capabilities.maximum_stderr_bytes <= 1_000_000
        or capabilities.working_directory_policy != _WORKING_DIRECTORY_POLICY
        or capabilities.environment_policy != _ENVIRONMENT_POLICY
        or capabilities.termination_policy != _TERMINATION_POLICY
        or _VERSION.fullmatch(capabilities.executable_version) is None
        or capabilities.capabilities != _ADAPTER_CAPABILITIES
        or capabilities.content_digest != _capabilities_digest(capabilities)
    ):
        raise AdapterConfigurationError("adapter capability evidence is invalid")
    try:
        manifest = parse_manifest_bytes(invocation.build.manifest_bytes)
    except (BundleError, SchemaError) as exc:  # pragma: no cover - approved-build invariant
        raise AdapterConfigurationError("approved bundle manifest is invalid") from exc
    settings = invocation.reviewer_settings
    config = manifest.reviewer_config
    if (
        settings.model != config.model
        or settings.tool_policy != config.tool_policy
        or settings.input_token_limit != config.input_token_limit
        or settings.output_token_limit != config.output_token_limit
        or settings.temperature != config.temperature
        or settings.adapter_version != config.adapter_version
    ):
        raise AdapterConfigurationError("adapter reviewer settings do not match the manifest")
    profile = manifest.profile_template
    if (
        invocation.profile.name != profile.name
        or invocation.profile.version != profile.version
        or invocation.profile.digest != profile.digest
    ):
        raise AdapterConfigurationError("adapter profile identity does not match the manifest")
    if (
        metadata.run_id != manifest.run_id
        or metadata.request_id != manifest.request_id
        or metadata.condition != manifest.condition
        or metadata.repetition != manifest.repetition
    ):
        raise AdapterConfigurationError("adapter run metadata does not match the manifest")
    return manifest


def _pair_fingerprint(
    invocation: AdapterInvocation, manifest: PromptManifest
) -> dict[str, JsonValue]:
    return {
        "adapter_capabilities": invocation.capabilities.to_dict(),
        "bundle_digest": manifest.bundle_digest,
        "bundle_config": _bundle_configuration_dict(manifest),
        "case_id": manifest.case_id,
        "context_entry_digest": manifest.context_entry_digest,
        "output_schema_version": invocation.output_schema_version,
        "prompt_digest": manifest.prompt_template.digest,
        "repetition": manifest.repetition,
        "seed": manifest.seed,
        "reviewer_config": {
            "adapter_version": invocation.reviewer_settings.adapter_version,
            "input_token_limit": invocation.reviewer_settings.input_token_limit,
            "model": invocation.reviewer_settings.model,
            "output_token_limit": invocation.reviewer_settings.output_token_limit,
            "temperature": invocation.reviewer_settings.temperature,
            "tool_policy": invocation.reviewer_settings.tool_policy,
        },
        "snapshot": manifest.snapshot,
        "source_commit": manifest.source_commit,
        "timeout_seconds": invocation.timeout_seconds,
        "worktree_digest": manifest.worktree_digest,
    }


def _bundle_configuration_dict(manifest: PromptManifest) -> JsonValue:
    config = manifest.bundle_config
    if config is None:  # pragma: no cover - approved manifest 1.2 requires this group
        return None
    return {
        "encoding": config.encoding,
        "newline_policy": config.newline_policy,
        "tokenizer": {
            "implementation": config.tokenizer.implementation,
            "name": config.tokenizer.name,
            "version": config.tokenizer.version,
            "method": config.tokenizer.method,
        },
        "context_policy": config.context_policy.to_dict(),
    }


def _capabilities_digest(capabilities: AdapterCapabilities) -> str:
    content: dict[str, JsonValue] = {
        "adapter_version": capabilities.adapter_version,
        "executable_version": capabilities.executable_version,
        "executable_digest": capabilities.executable_digest,
        "review_arguments": list(capabilities.review_arguments),
        "version_arguments": list(capabilities.version_arguments),
        "probe_timeout_seconds": capabilities.probe_timeout_seconds,
        "maximum_stdout_bytes": capabilities.maximum_stdout_bytes,
        "maximum_stderr_bytes": capabilities.maximum_stderr_bytes,
        "working_directory_policy": capabilities.working_directory_policy,
        "environment_policy": capabilities.environment_policy,
        "termination_policy": capabilities.termination_policy,
        "capabilities": list(capabilities.capabilities),
    }
    return canonical_digest(content)


def _configuration_matches_capabilities(
    configuration: AdapterConfiguration, capabilities: AdapterCapabilities
) -> bool:
    return (
        configuration.review_arguments == capabilities.review_arguments
        and configuration.version_arguments == capabilities.version_arguments
        and configuration.probe_timeout_seconds == capabilities.probe_timeout_seconds
        and configuration.maximum_stdout_bytes == capabilities.maximum_stdout_bytes
        and configuration.maximum_stderr_bytes == capabilities.maximum_stderr_bytes
        and capabilities.working_directory_policy == _WORKING_DIRECTORY_POLICY
        and capabilities.environment_policy == _ENVIRONMENT_POLICY
        and capabilities.termination_policy == _TERMINATION_POLICY
    )


def _review_arguments(arguments: tuple[str, ...], model: str) -> tuple[str, ...]:
    return tuple(model if argument == _MODEL_ARGUMENT else argument for argument in arguments)


def _strict_string(value: object) -> str:
    if not isinstance(value, str) or not value:
        raise ValueError
    return value


def _strict_integer(value: object) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise ValueError
    return value


def _strict_number(value: object) -> float:
    if isinstance(value, bool) or not isinstance(value, int | float):
        raise ValueError
    return float(value)


def _frozen_string_tuple(value: object) -> tuple[str, ...]:
    if (
        not isinstance(value, list)
        or not value
        or len(value) > 20
        or any(
            not isinstance(item, str) or not item or any(ord(character) < 32 for character in item)
            for item in value
        )
    ):
        raise ValueError
    return tuple(value)


def _classify_capture(
    capture: _ProcessCapture, trace: RawTraceRecord, _manifest: PromptManifest
) -> AdapterOutcome:
    stderr_classification = _classify_stderr(capture.stderr)
    if capture.timed_out:
        return _failed(capture, trace, "timeout", True, "PROCESS_TIMEOUT", "timeout")
    if capture.stdout_oversized or capture.stderr_oversized:
        validation_errors = (
            "OUTPUT_LIMIT_EXCEEDED",
            *(("STDOUT_LIMIT_EXCEEDED",) if capture.stdout_oversized else ()),
            *(("STDERR_LIMIT_EXCEEDED",) if capture.stderr_oversized else ()),
        )
        return _failed(
            capture,
            trace,
            "adapter_error",
            False,
            validation_errors,
            stderr_classification,
        )
    if capture.read_error:
        return _failed(capture, trace, "adapter_error", False, "OUTPUT_CAPTURE_FAILED", "internal")
    if capture.exit_status != 0:
        failure, retryable = _nonzero_failure(stderr_classification)
        metadata = _provider_metadata_from_nonzero(capture.stdout)
        return _failed(
            capture,
            trace,
            failure,
            retryable,
            "PROCESS_NONZERO",
            stderr_classification,
            metadata,
        )
    metadata = _ProviderMetadata()
    try:
        payload, metadata = _provider_payload(capture.stdout)
        document = _structured_document(payload)
        reviewer_output = ReviewerOutput.from_dict(document)
    except UnicodeError:
        return _failed(
            capture,
            trace,
            "invalid_output",
            True,
            "OUTPUT_ENCODING_INVALID",
            "none",
            metadata,
        )
    except (json.JSONDecodeError, RecursionError):
        return _failed(
            capture, trace, "invalid_output", True, "OUTPUT_JSON_INVALID", "none", metadata
        )
    except SchemaError:
        return _failed(
            capture, trace, "invalid_output", True, "OUTPUT_SCHEMA_INVALID", "none", metadata
        )
    return AdapterOutcome(
        reviewer_output=reviewer_output,
        failure=None,
        retryable=False,
        exit_status=capture.exit_status,
        stderr_classification="none",
        validation_errors=(),
        monotonic_latency_ms=capture.latency_ms,
        raw_trace=trace,
        provider=metadata.provider,
        provider_request_id=metadata.provider_request_id,
        input_tokens=metadata.input_tokens,
        cached_input_tokens=metadata.cached_input_tokens,
        output_tokens=metadata.output_tokens,
        reasoning_tokens=metadata.reasoning_tokens,
        total_cost_usd=metadata.total_cost_usd,
    )


def _failed(
    capture: _ProcessCapture,
    trace: RawTraceRecord,
    failure: FailureClassification,
    retryable: bool,
    error: str | tuple[str, ...],
    stderr_classification: StderrClassification,
    metadata: _ProviderMetadata | None = None,
) -> AdapterOutcome:
    metadata = metadata or _ProviderMetadata()
    return AdapterOutcome(
        reviewer_output=None,
        failure=failure,
        retryable=retryable,
        exit_status=capture.exit_status,
        stderr_classification=stderr_classification,
        validation_errors=(error,) if isinstance(error, str) else error,
        monotonic_latency_ms=capture.latency_ms,
        raw_trace=trace,
        provider=metadata.provider,
        provider_request_id=metadata.provider_request_id,
        input_tokens=metadata.input_tokens,
        cached_input_tokens=metadata.cached_input_tokens,
        output_tokens=metadata.output_tokens,
        reasoning_tokens=metadata.reasoning_tokens,
        total_cost_usd=metadata.total_cost_usd,
    )


def _failure_without_process(failure: FailureClassification, error: str) -> AdapterOutcome:
    empty_digest = sha256_digest(b"")
    return AdapterOutcome(
        reviewer_output=None,
        failure=failure,
        retryable=False,
        exit_status=None,
        stderr_classification="configuration",
        validation_errors=(error,),
        monotonic_latency_ms=0.0,
        raw_trace=RawTraceRecord(None, empty_digest, None, empty_digest, False),
    )


def _structured_document(output: bytes) -> dict[str, object]:
    text = output.decode("utf-8")
    decoder = json.JSONDecoder(
        object_pairs_hook=_unique_json_object,
        parse_constant=_reject_json_constant,
    )
    stripped = text.strip()
    try:
        loaded = json.loads(
            stripped,
            object_pairs_hook=_unique_json_object,
            parse_constant=_reject_json_constant,
        )
    except (json.JSONDecodeError, RecursionError):
        pass
    else:
        if isinstance(loaded, dict):
            return cast(dict[str, object], loaded)
        raise json.JSONDecodeError("structured output must be a top-level object", text, 0)

    start = text.find("{")
    if start < 0:
        raise json.JSONDecodeError("structured output is missing or ambiguous", text, 0)
    value, end = decoder.raw_decode(text, start)
    if not isinstance(value, dict):
        raise json.JSONDecodeError("structured output is missing or ambiguous", text, start)
    offset = end
    for _attempt in range(1024):
        next_start = text.find("{", offset)
        if next_start < 0:
            return cast(dict[str, object], value)
        offset = next_start + 1
        try:
            next_value, next_end = decoder.raw_decode(text, next_start)
        except json.JSONDecodeError:
            continue
        if isinstance(next_value, dict):
            raise json.JSONDecodeError("structured output is ambiguous", text, next_start)
        offset = next_end
    raise json.JSONDecodeError("structured output is ambiguous", text, offset)


@dataclass(frozen=True, slots=True)
class _ProviderMetadata:
    provider: str | None = None
    provider_request_id: str | None = None
    input_tokens: int | None = None
    cached_input_tokens: int | None = None
    output_tokens: int | None = None
    reasoning_tokens: int | None = None
    total_cost_usd: float | None = None


def _provider_payload(output: bytes) -> tuple[bytes, _ProviderMetadata]:
    """Unwrap Claude Code's JSON result envelope while retaining billing metadata."""

    outer = _structured_document(output)
    if outer.get("type") != "result":
        return output, _ProviderMetadata()
    metadata = _provider_metadata(outer)
    if outer.get("subtype") != "success" or outer.get("is_error") is not False:
        raise SchemaError("provider result envelope is not successful")
    structured_output = outer.get("structured_output")
    result = outer.get("result")
    if structured_output is not None:
        if not isinstance(structured_output, Mapping):
            raise SchemaError("provider result envelope is invalid")
        payload = json.dumps(
            structured_output,
            ensure_ascii=False,
            allow_nan=False,
            separators=(",", ":"),
        ).encode("utf-8")
    elif isinstance(result, str):
        payload = result.encode("utf-8")
    else:
        raise SchemaError("provider result envelope is invalid")
    return payload, metadata


def _provider_metadata(document: Mapping[str, object]) -> _ProviderMetadata:
    provider_request_id = document.get("uuid")
    if provider_request_id is None:
        provider_request_id = document.get("session_id")
    if provider_request_id is not None and (
        not isinstance(provider_request_id, str) or len(provider_request_id) > 200
    ):
        raise SchemaError("provider result envelope is invalid")
    total_cost = document.get("total_cost_usd")
    if isinstance(total_cost, bool) or not isinstance(total_cost, int | float) or total_cost < 0:
        raise SchemaError("provider result envelope cost is invalid")
    input_tokens, cached_input_tokens, output_tokens = _claude_usage(document)
    return _ProviderMetadata(
        provider="anthropic",
        provider_request_id=provider_request_id,
        input_tokens=input_tokens,
        cached_input_tokens=cached_input_tokens,
        output_tokens=output_tokens,
        total_cost_usd=float(total_cost),
    )


def _provider_metadata_from_nonzero(output: bytes) -> _ProviderMetadata:
    """Retain safe Claude billing metadata without changing nonzero classification."""

    try:
        document = _structured_document(output)
        if document.get("type") != "result":
            return _ProviderMetadata()
        return _provider_metadata(document)
    except (UnicodeError, json.JSONDecodeError, RecursionError, SchemaError):
        return _ProviderMetadata()


def _claude_usage(document: Mapping[str, object]) -> tuple[int, int, int]:
    model_usage = document.get("modelUsage")
    if isinstance(model_usage, Mapping) and model_usage:
        values = tuple(model_usage.values())
        if all(isinstance(value, Mapping) for value in values):
            input_tokens = sum(
                _usage_integer(cast(Mapping[str, object], value), "inputTokens")
                + _usage_integer(cast(Mapping[str, object], value), "cacheCreationInputTokens")
                + _usage_integer(cast(Mapping[str, object], value), "cacheReadInputTokens")
                for value in values
            )
            cached_input_tokens = sum(
                _usage_integer(cast(Mapping[str, object], value), "cacheReadInputTokens")
                for value in values
            )
            output_tokens = sum(
                _usage_integer(cast(Mapping[str, object], value), "outputTokens")
                for value in values
            )
            return input_tokens, cached_input_tokens, output_tokens
    usage = document.get("usage")
    if not isinstance(usage, Mapping):
        raise SchemaError("provider result envelope usage is invalid")
    input_tokens = (
        _usage_integer(usage, "input_tokens")
        + _usage_integer(usage, "cache_creation_input_tokens")
        + _usage_integer(usage, "cache_read_input_tokens")
    )
    return (
        input_tokens,
        _usage_integer(usage, "cache_read_input_tokens"),
        _usage_integer(usage, "output_tokens"),
    )


def _usage_integer(usage: Mapping[str, object], field: str) -> int:
    value = usage.get(field, 0)
    if type(value) is not int or value < 0:
        raise SchemaError("provider result envelope usage is invalid")
    return value


def _unique_json_object(pairs: list[tuple[str, object]]) -> dict[str, object]:
    document: dict[str, object] = {}
    for key, value in pairs:
        if key in document:
            raise json.JSONDecodeError("structured output contains a duplicate key", key, 0)
        document[key] = value
    return document


def _reject_json_constant(value: str) -> object:
    raise json.JSONDecodeError("structured output contains a non-standard number", value, 0)


def _classify_stderr(stderr: bytes) -> StderrClassification:
    if not stderr:
        return "none"
    text = stderr.decode("utf-8", errors="replace").casefold()
    if any(token in text for token in ("timed out", "timeout")):
        return "timeout"
    if any(
        token in text
        for token in (
            "rate limit",
            "provider",
            "transport",
            "network",
            "connection reset",
            "connection refused",
        )
    ):
        return "provider"
    if any(token in text for token in ("usage:", "unknown option", "unrecognized argument")):
        return "usage"
    if any(
        token in text
        for token in ("configuration", "config file", "missing setting", "not configured")
    ):
        return "configuration"
    if any(token in text for token in ("traceback", "internal error", "assertionerror")):
        return "internal"
    return "redacted_unknown"


def _nonzero_failure(
    stderr: StderrClassification,
) -> tuple[FailureClassification, bool]:
    if stderr in {"usage", "configuration"}:
        return "configuration_error", False
    if stderr == "provider":
        return "provider_error", True
    if stderr == "timeout":
        return "timeout", True
    return "adapter_error", False


def _run_bounded(
    arguments: tuple[str, ...],
    input_bytes: bytes,
    *,
    working_directory: Path,
    timeout_seconds: float,
    maximum_stdout_bytes: int,
    maximum_stderr_bytes: int,
) -> _ProcessCapture:
    if timeout_seconds <= 0:
        raise AdapterConfigurationError("adapter invocation timeout is invalid")
    started = time.monotonic()
    environment = {
        key: value for key in _ENVIRONMENT_ALLOWLIST if (value := os.environ.get(key)) is not None
    }
    environment.update({"NO_COLOR": "1", "PYTHONUNBUFFERED": "1"})
    with tempfile.TemporaryFile() as request_stream:
        request_stream.write(input_bytes)
        request_stream.seek(0)
        try:
            process = subprocess.Popen(
                list(arguments),
                stdin=request_stream,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                env=environment,
                cwd=working_directory,
                shell=False,
                close_fds=True,
                start_new_session=os.name != "nt",
            )
        except OSError as exc:
            raise AdapterConfigurationError("adapter executable could not be started") from exc
        assert process.stdout is not None
        assert process.stderr is not None
        overflow = threading.Event()
        read_error = threading.Event()
        stdout = bytearray()
        stderr = bytearray()
        readers = (
            threading.Thread(
                target=_bounded_reader,
                args=(process.stdout, stdout, maximum_stdout_bytes, overflow, read_error),
                daemon=True,
            ),
            threading.Thread(
                target=_bounded_reader,
                args=(process.stderr, stderr, maximum_stderr_bytes, overflow, read_error),
                daemon=True,
            ),
        )
        for reader in readers:
            reader.start()
        deadline = started + timeout_seconds
        timed_out = False
        while True:
            if overflow.is_set():
                _terminate_process(process)
                break
            readers_alive = any(reader.is_alive() for reader in readers)
            if process.poll() is not None and not readers_alive:
                break
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                timed_out = True
                _terminate_process(process)
                break
            overflow.wait(min(0.05, remaining))
        capture_deadline = time.monotonic() + _CAPTURE_SHUTDOWN_SECONDS
        for reader in readers:
            reader.join(timeout=max(0.0, capture_deadline - time.monotonic()))
        for reader, stream in zip(readers, (process.stdout, process.stderr), strict=True):
            if reader.is_alive():  # pragma: no cover - OS pipe failure
                read_error.set()
            else:
                stream.close()
        return _ProcessCapture(
            stdout=bytes(stdout[: maximum_stdout_bytes + 1]),
            stderr=bytes(stderr[: maximum_stderr_bytes + 1]),
            exit_status=process.poll(),
            timed_out=timed_out,
            stdout_oversized=len(stdout) > maximum_stdout_bytes,
            stderr_oversized=len(stderr) > maximum_stderr_bytes,
            read_error=read_error.is_set(),
            latency_ms=(time.monotonic() - started) * 1000,
        )


def _bounded_reader(
    stream: BinaryIO,
    destination: bytearray,
    limit: int,
    overflow: threading.Event,
    read_error: threading.Event,
) -> None:
    try:
        while True:
            chunk = stream.read(_READ_CHUNK)
            if not chunk:
                return
            remaining = limit + 1 - len(destination)
            if remaining > 0:
                destination.extend(chunk[:remaining])
            if len(chunk) > remaining or len(destination) > limit:
                overflow.set()
    except OSError:
        read_error.set()


def _terminate_process(process: subprocess.Popen[bytes]) -> None:
    if os.name == "nt":  # pragma: no cover - Windows compatibility
        if process.poll() is not None:
            return
        try:
            process.terminate()
            process.wait(timeout=_TERMINATION_GRACE_SECONDS)
        except (OSError, subprocess.TimeoutExpired):
            try:
                process.kill()
                process.wait(timeout=_TERMINATION_GRACE_SECONDS)
            except (OSError, subprocess.TimeoutExpired):
                pass
        return
    try:
        os.killpg(process.pid, signal.SIGTERM)
    except OSError:
        return
    termination_deadline = time.monotonic() + _TERMINATION_GRACE_SECONDS
    while time.monotonic() < termination_deadline:
        process.poll()
        try:
            os.killpg(process.pid, 0)
        except OSError:
            return
        time.sleep(max(0.0, min(0.01, termination_deadline - time.monotonic())))
    with suppress(OSError):  # pragma: no cover - OS process failure
        os.killpg(process.pid, signal.SIGKILL)
    if process.poll() is None:
        with suppress(subprocess.TimeoutExpired):  # pragma: no cover - OS process failure
            process.wait(timeout=_TERMINATION_GRACE_SECONDS)


def _resolve_executable(executable: str) -> Path:
    candidate = shutil.which(executable)
    if candidate is None:
        raise AdapterConfigurationError("adapter executable is unavailable")
    path = Path(candidate).resolve()
    if not path.is_file() or not os.access(path, os.X_OK):
        raise AdapterConfigurationError("adapter executable is unavailable")
    return path


def _file_digest(path: Path) -> str:
    digest = hashlib.sha256()
    try:
        with path.open("rb") as stream:
            while chunk := stream.read(_READ_CHUNK):
                digest.update(chunk)
    except OSError as exc:
        raise AdapterConfigurationError("adapter executable could not be inspected") from exc
    return f"sha256:{digest.hexdigest()}"


def _probe_capture_succeeded(capture: _ProcessCapture) -> bool:
    return (
        capture.exit_status == 0
        and not capture.timed_out
        and not capture.stdout_oversized
        and not capture.stderr_oversized
        and not capture.read_error
        and not capture.stderr
    )


def _decode_probe(output: bytes) -> str:
    try:
        return output.decode("utf-8")
    except UnicodeError as exc:
        raise AdapterConfigurationError("adapter probe response is not UTF-8") from exc


def _trace_digests(capture: _ProcessCapture) -> RawTraceRecord:
    return RawTraceRecord(
        stdout_path=None,
        stdout_digest=sha256_digest(capture.stdout),
        stderr_path=None,
        stderr_digest=sha256_digest(capture.stderr),
        truncated=capture.stdout_oversized or capture.stderr_oversized,
    )


def _retain_raw_trace(invocation: AdapterInvocation, capture: _ProcessCapture) -> RawTraceRecord:
    policy = invocation.trace_policy
    base = _trace_digests(capture)
    if not policy.retain_raw_output:
        return base
    policy.validate()
    root = policy.repository_root.resolve(strict=True)
    relative_parent = policy.raw_trace_root / invocation.metadata.run_id
    parent = root.joinpath(*relative_parent.parts)
    _reject_symlinked_components(root, relative_parent)
    try:
        parent.mkdir(parents=True, mode=0o700, exist_ok=True)
    except OSError as exc:
        raise AdapterConfigurationError("adapter raw trace could not be retained") from exc
    _reject_symlinked_components(root, relative_parent)
    attempt = f"attempt-{invocation.metadata.attempt}"
    target = parent / attempt
    if target.exists() or target.is_symlink():
        raise AdapterConfigurationError("adapter raw trace target already exists")
    staging: Path | None = None
    try:
        staging = Path(tempfile.mkdtemp(prefix=f".{attempt}.", dir=parent))
        _write_private(staging / "stdout.bin", capture.stdout)
        _write_private(staging / "stderr.bin", capture.stderr)
        os.rename(staging, target)
        staging = None
        _fsync_directory(parent)
    except OSError as exc:
        raise AdapterConfigurationError("adapter raw trace could not be retained") from exc
    finally:
        if staging is not None:
            shutil.rmtree(staging, ignore_errors=True)
    stdout_path = relative_parent / attempt / "stdout.bin"
    stderr_path = relative_parent / attempt / "stderr.bin"
    return RawTraceRecord(
        stdout_path=stdout_path,
        stdout_digest=base.stdout_digest,
        stderr_path=stderr_path,
        stderr_digest=base.stderr_digest,
        truncated=base.truncated,
    )


def _reject_symlinked_components(root: Path, relative: PurePosixPath) -> None:
    current = root
    for part in relative.parts:
        current /= part
        if current.is_symlink():
            raise AdapterConfigurationError("adapter raw trace path contains a symlink")


def _ensure_working_directory(path: Path) -> None:
    if not path.is_absolute() or not path.is_dir() or path.is_symlink():
        raise AdapterConfigurationError("adapter working directory is invalid")
    try:
        if any(path.iterdir()):
            raise AdapterConfigurationError("adapter working directory must be empty")
    except OSError as exc:
        raise AdapterConfigurationError("adapter working directory is invalid") from exc


def _write_private(path: Path, content: bytes) -> None:
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        with os.fdopen(descriptor, "wb", closefd=False) as stream:
            stream.write(content)
            stream.flush()
            os.fsync(stream.fileno())
    finally:
        os.close(descriptor)


def _fsync_directory(path: Path) -> None:
    descriptor = os.open(path, os.O_RDONLY)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)
