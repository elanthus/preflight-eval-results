from __future__ import annotations

import os
import signal
import stat
import subprocess
import textwrap
import time
from dataclasses import replace
from datetime import UTC, datetime
from importlib import metadata
from pathlib import Path, PurePosixPath
from typing import Any, cast
from unittest.mock import Mock

import pytest

import preflight_evals.adapter as adapter_module
import preflight_evals.bundle as bundle_module
from preflight_evals.adapter import (
    ADAPTER_VERSION,
    AdapterConfiguration,
    AdapterConfigurationError,
    AdapterInvocation,
    AdapterRunMetadata,
    ProfileIdentity,
    ReviewerSubprocessAdapter,
    TracePolicy,
    configuration_from_evaluation,
    ensure_paired_invocations,
    trace_policy_from_evaluation,
)
from preflight_evals.bundle import (
    ReviewerSettings,
    TemplateInput,
    build_bundle,
    parse_manifest_bytes,
)
from preflight_evals.canonical import canonical_digest, sha256_digest
from preflight_evals.config import load_config
from preflight_evals.leakage import ForbiddenContentIndex, approve_bundle, default_policy
from preflight_evals.reviewer_models import ReviewerCase, ReviewerContextPolicy

TOKENIZER = f"tiktoken/o200k_base@{metadata.version('tiktoken')}/per_file_utf8_sum_v1"
CREATED_AT = datetime(2026, 8, 18, 12, 30, tzinfo=UTC)
SENSITIVE_MARKER = "profile; touch adapter-shell-injection"
SENSITIVE_STDERR = "provider transport failed token=synthetic-secret-value"
REPOSITORY = Path(__file__).resolve().parents[1]


def _case(*, total_token_limit: int = 24_000) -> ReviewerCase:
    return ReviewerCase(
        schema_version="1.0",
        case_id="synthetic-adapter-case",
        display_name="Synthetic adapter case",
        defect_category="correctness",
        repository="synthetic/example",
        pull_request=10,
        source_commit="a" * 40,
        context_policy=ReviewerContextPolicy(
            includes=(PurePosixPath("src"),),
            excludes=(),
            per_file_byte_limit=100_000,
            per_file_token_limit=16_000,
            total_token_limit=total_token_limit,
            symlink_policy="reject",
            binary_policy="omit",
            truncation_policy="reject",
        ),
    )


def _settings(**changes: object) -> ReviewerSettings:
    values: dict[str, object] = {
        "model": "synthetic-model",
        "tool_policy": "read-only",
        "input_token_limit": 100_000,
        "output_token_limit": 4_000,
        "temperature": 0.0,
        "adapter_version": "synthetic-adapter-1",
    }
    values.update(changes)
    return ReviewerSettings(**cast(Any, values))


def _build(
    root: Path,
    *,
    condition: str = "baseline",
    profile_name: str = "baseline",
    profile_content: str = SENSITIVE_MARKER,
    settings: ReviewerSettings | None = None,
    seed: int = 42,
    total_token_limit: int = 24_000,
) -> bundle_module.BundleBuild:
    worktree = root / "worktree"
    source = worktree / "src"
    source.mkdir(parents=True, exist_ok=True)
    (source / "unsafe;$(touch adapter-pwned).py").write_text("safe = True\n", encoding="utf-8")
    reviewer_settings = settings or _settings()
    run_id = f"run-adapter-{condition}"
    draft = build_bundle(
        _case(total_token_limit=total_token_limit),
        "vulnerable",
        cast(Any, condition),
        request_identity=f"hmac-sha256:{'1' * 64}",
        worktree=worktree,
        worktree_digest=bundle_module._compute_worktree_digest(worktree.resolve()),
        tokenizer_spec=TOKENIZER,
        prompt_template=TemplateInput("review", "1", "Review the repository.\n"),
        profile_template=TemplateInput(profile_name, "1", profile_content),
        reviewer_settings=reviewer_settings,
        repetition=1,
        seed=seed,
        request_id=f"request-adapter-{condition}",
        run_id=run_id,
        created_at=CREATED_AT,
    )
    policy = default_policy("synthetic-adapter-case")
    return approve_bundle(
        draft,
        ForbiddenContentIndex(
            case_id="synthetic-adapter-case",
            policy_version=policy.policy_version,
            entries=(),
            index_digest=f"sha256:{'b' * 64}",
            match_key=b"synthetic-empty-index",
        ),
        policy,
    )


def _fake_executable(
    root: Path,
    mode: str,
    *,
    expected_marker: str = SENSITIVE_MARKER,
    child_pid_path: Path | None = None,
) -> Path:
    executable = root / f"fake-reviewer-{mode}"
    finding = {
        "schema_version": "1.0",
        "finding_id": "F001",
        "title": "Synthetic defect",
        "explanation": "Synthetic explanation",
        "file_path": "src/example.py",
        "severity": "medium",
        "defect_category": "correctness",
        "failure_mechanism": "Synthetic failure mechanism",
        "confidence": 0.75,
        "evidence": [{"source_type": "file", "reference": "src/example.py"}],
    }
    source = f"""\
#!/usr/bin/env python3
import json
import os
import subprocess
import sys
import time

MODE = {mode!r}
EXPECTED_MARKER = {expected_marker!r}
CHILD_PID_PATH = {str(child_pid_path) if child_pid_path is not None else ""!r}
FINDING = {finding!r}

if sys.argv[1:] == ["--version"]:
    if MODE == "bad-version":
        print("bad")
        print("version")
    elif MODE == "claude-version":
        print("2.1.224 (Claude Code)")
    else:
        print("codex-cli 0.147.0")
    raise SystemExit(0)
if sys.argv[1:] != ["run", "synthetic-model"]:
    print("usage: unexpected arguments", file=sys.stderr)
    raise SystemExit(2)

request = sys.stdin.buffer.read()
if EXPECTED_MARKER.encode() not in request:
    print("configuration missing expected stdin request", file=sys.stderr)
    raise SystemExit(2)
if "SYNTHETIC_PROVIDER_SECRET" in os.environ:
    print("environment allowlist failure", file=sys.stderr)
    raise SystemExit(2)
if os.environ.get("NO_COLOR") != "1":
    print("configuration missing fixed environment", file=sys.stderr)
    raise SystemExit(2)
if MODE == "required-user-env" and (
    os.environ.get("USER"), os.environ.get("LOGNAME"), os.environ.get("SHELL")
) != ("adapter-user", "adapter-login", "/bin/adapter-shell"):
    print("configuration missing user environment", file=sys.stderr)
    raise SystemExit(2)
if os.path.basename(os.getcwd()) != "adapter-cwd" or os.listdir("."):
    print("configuration unsafe working directory", file=sys.stderr)
    raise SystemExit(2)

if MODE == "success":
    print("Reviewer preamble")
    print(json.dumps({{"schema_version": "1.0", "findings": [FINDING]}}))
    print("Reviewer epilogue")
elif MODE == "success-stderr":
    print("provider: openai; timeout_seconds: 600", file=sys.stderr)
    print(json.dumps({{"schema_version": "1.0", "findings": []}}))
elif MODE == "empty":
    print(json.dumps({{"schema_version": "1.0", "findings": []}}))
elif MODE == "required-user-env":
    print(json.dumps({{"schema_version": "1.0", "findings": []}}))
elif MODE == "claude-json":
    print(json.dumps({{
        "type": "result",
        "subtype": "success",
        "is_error": False,
        "uuid": "provider-request-123",
        "total_cost_usd": 0.03125,
        "usage": {{
            "input_tokens": 5,
            "cache_creation_input_tokens": 100,
            "cache_read_input_tokens": 200,
            "output_tokens": 20,
        }},
        "modelUsage": {{
            "claude-haiku": {{
                "inputTokens": 10,
                "cacheCreationInputTokens": 0,
                "cacheReadInputTokens": 0,
                "outputTokens": 2,
            }},
            "claude-sonnet-5": {{
                "inputTokens": 5,
                "cacheCreationInputTokens": 100,
                "cacheReadInputTokens": 200,
                "outputTokens": 20,
            }},
        }},
        "result": "Structured output was produced.",
        "structured_output": {{"schema_version": "1.0", "findings": []}},
    }}))
elif MODE == "claude-json-invalid-result":
    print(json.dumps({{
        "type": "result",
        "subtype": "success",
        "is_error": False,
        "uuid": "provider-request-invalid",
        "total_cost_usd": 0.0425,
        "usage": {{"input_tokens": 10, "output_tokens": 3}},
        "result": "not reviewer json",
    }}))
elif MODE == "claude-json-provider-error":
    print(json.dumps({{
        "type": "result",
        "subtype": "success",
        "is_error": True,
        "uuid": "provider-request-rate-limit",
        "total_cost_usd": 0,
        "usage": {{"input_tokens": 0, "output_tokens": 0}},
        "modelUsage": {{}},
        "api_error_status": 429,
        "result": "Session limit reached",
    }}))
    raise SystemExit(1)
elif MODE == "malformed":
    print("{{not-json")
elif MODE == "invalid-schema":
    print(json.dumps({{"schema_version": "1.0", "findings": "none"}}))
elif MODE == "array-wrapper":
    print(json.dumps([{{"schema_version": "1.0", "findings": []}}]))
elif MODE == "ambiguous":
    print(json.dumps({{"schema_version": "1.0", "findings": []}}))
    print(json.dumps({{"schema_version": "1.0", "findings": []}}))
elif MODE == "non-utf8":
    sys.stdout.buffer.write(b"\\xff\\xfe")
elif MODE == "duplicate-key":
    print('{{"schema_version":"1.0","schema_version":"1.0","findings":[]}}')
elif MODE == "non-standard-number":
    print('{{"schema_version":"1.0","findings":[{{"schema_version":"1.0","finding_id":"F001","title":"Synthetic","explanation":"Synthetic","file_path":"src/example.py","severity":"medium","defect_category":"correctness","failure_mechanism":"Synthetic","confidence":NaN,"evidence":[{{"source_type":"file","reference":"src/example.py"}}]}}]}}')
elif MODE == "provider-error":
    print({SENSITIVE_STDERR!r}, file=sys.stderr)
    raise SystemExit(17)
elif MODE == "configuration-error":
    print("configuration missing setting token=private", file=sys.stderr)
    raise SystemExit(2)
elif MODE == "internal-error":
    print("internal error token=private", file=sys.stderr)
    raise SystemExit(70)
elif MODE == "oversized":
    sys.stdout.write("x" * 100000)
    sys.stdout.flush()
elif MODE == "oversized-stderr":
    sys.stderr.write("x" * 100000)
    sys.stderr.flush()
elif MODE == "timeout":
    child = subprocess.Popen([sys.executable, "-c", "import time; time.sleep(30)"])
    if CHILD_PID_PATH:
        with open(CHILD_PID_PATH, "w", encoding="utf-8") as stream:
            stream.write(str(child.pid))
            stream.flush()
            os.fsync(stream.fileno())
    time.sleep(30)
elif MODE == "grandchild-pipe":
    child = subprocess.Popen([sys.executable, "-c", "import time; time.sleep(30)"])
    if CHILD_PID_PATH:
        with open(CHILD_PID_PATH, "w", encoding="utf-8") as stream:
            stream.write(str(child.pid))
            stream.flush()
            os.fsync(stream.fileno())
else:
    print("internal error unknown mode", file=sys.stderr)
    raise SystemExit(70)
"""
    executable.write_text(textwrap.dedent(source), encoding="utf-8")
    executable.chmod(0o700)
    return executable


def _invocation(
    root: Path,
    executable: Path,
    *,
    condition: str = "baseline",
    profile_name: str = "baseline",
    profile_content: str = SENSITIVE_MARKER,
    timeout_seconds: float = 2.0,
    retain_raw_output: bool = False,
    settings: ReviewerSettings | None = None,
    maximum_stdout_bytes: int = 1_000_000,
    maximum_stderr_bytes: int = 64_000,
    seed: int = 42,
    total_token_limit: int = 24_000,
) -> tuple[ReviewerSubprocessAdapter, AdapterInvocation]:
    reviewer_settings = settings or _settings()
    build = _build(
        root,
        condition=condition,
        profile_name=profile_name,
        profile_content=profile_content,
        settings=reviewer_settings,
        seed=seed,
        total_token_limit=total_token_limit,
    )
    manifest = parse_manifest_bytes(build.manifest_bytes)
    execution_root = root / "adapter-cwd"
    execution_root.mkdir()
    adapter = ReviewerSubprocessAdapter(
        AdapterConfiguration(
            executable=str(executable),
            review_arguments=("run", "{model}"),
            working_directory=execution_root.resolve(),
            maximum_stdout_bytes=maximum_stdout_bytes,
            maximum_stderr_bytes=maximum_stderr_bytes,
        )
    )

    invocation = AdapterInvocation(
        build=build,
        profile=ProfileIdentity(
            manifest.profile_template.name,
            manifest.profile_template.version,
            manifest.profile_template.digest,
        ),
        reviewer_settings=reviewer_settings,
        output_schema_version="1.0",
        timeout_seconds=timeout_seconds,
        metadata=AdapterRunMetadata(
            run_id=manifest.run_id,
            experiment_id="experiment-synthetic-one",
            request_id=manifest.request_id,
            condition=manifest.condition,
            repetition=manifest.repetition,
            attempt=1,
        ),
        capabilities=adapter.probe(),
        trace_policy=TracePolicy(
            repository_root=root.resolve(),
            raw_trace_root=PurePosixPath("artifacts/provider-traces"),
            retain_raw_output=retain_raw_output,
        ),
    )
    return adapter, invocation


def test_probe_records_freeze_ready_version_capabilities_and_executable_digest(
    tmp_path: Path,
) -> None:
    executable = _fake_executable(tmp_path, "empty")
    working_directory = tmp_path / "probe-cwd"
    working_directory.mkdir()
    adapter = ReviewerSubprocessAdapter(
        AdapterConfiguration(
            executable=str(executable),
            review_arguments=("run", "{model}"),
            working_directory=working_directory.resolve(),
        )
    )

    capabilities = adapter.probe()

    assert capabilities.adapter_version == ADAPTER_VERSION
    assert capabilities.executable_version == "codex-cli 0.147.0"
    assert capabilities.capabilities == (
        "stdin-request-v1",
        "structured-reviewer-output-v1",
    )
    assert capabilities.review_arguments == ("run", "{model}")
    assert capabilities.version_arguments == ("--version",)
    assert capabilities.probe_timeout_seconds == 10
    assert capabilities.maximum_stdout_bytes == 1_000_000
    assert capabilities.maximum_stderr_bytes == 64_000
    assert capabilities.working_directory_policy == "explicit-empty-directory-v1"
    assert capabilities.environment_policy == "minimal-allowlist-v1"
    assert capabilities.termination_policy == "new-session-term-kill-v1"
    assert capabilities.executable_digest.startswith("sha256:")
    assert capabilities.content_digest == canonical_digest(
        {key: value for key, value in capabilities.to_dict().items() if key != "content_digest"}
    )


def test_validated_evaluation_configuration_resolves_adapter_and_trace_policy(
    tmp_path: Path,
) -> None:
    config = load_config(REPOSITORY / "config.example.toml")
    working_directory = tmp_path / config.adapter.working_directory
    working_directory.mkdir(parents=True)

    process = configuration_from_evaluation(config, tmp_path.resolve())
    trace = trace_policy_from_evaluation(config, tmp_path.resolve(), retain_raw_output=True)

    assert process.executable == "codex"
    assert process.review_arguments == (
        "exec",
        "--ephemeral",
        "--ignore-user-config",
        "--ignore-rules",
        "--sandbox",
        "read-only",
        "--skip-git-repo-check",
        "--model",
        "{model}",
        "-",
    )
    assert process.working_directory == working_directory
    assert trace.raw_trace_root == PurePosixPath("artifacts/provider-traces")
    trace.validate()


def test_probe_accepts_claude_style_version_output(tmp_path: Path) -> None:
    executable = _fake_executable(tmp_path, "claude-version")
    working_directory = tmp_path / "probe-cwd"
    working_directory.mkdir()
    adapter = ReviewerSubprocessAdapter(
        AdapterConfiguration(
            executable=str(executable),
            review_arguments=("run", "{model}"),
            working_directory=working_directory.resolve(),
        )
    )

    assert adapter.probe().executable_version == "2.1.224 (Claude Code)"


def test_probe_fails_closed_for_multiline_version_output(tmp_path: Path) -> None:
    executable = _fake_executable(tmp_path, "bad-version")
    working_directory = tmp_path / "probe-cwd"
    working_directory.mkdir()
    adapter = ReviewerSubprocessAdapter(
        AdapterConfiguration(
            executable=str(executable),
            review_arguments=("run", "{model}"),
            working_directory=working_directory.resolve(),
        )
    )

    with pytest.raises(AdapterConfigurationError):
        adapter.probe()


def test_success_parses_one_structured_object_and_retains_prose_only_in_raw_trace(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("SYNTHETIC_PROVIDER_SECRET", "must-not-cross")
    executable = _fake_executable(tmp_path, "success")
    adapter, invocation = _invocation(tmp_path, executable, retain_raw_output=True)

    outcome = adapter.invoke(invocation)

    assert outcome.succeeded
    assert outcome.failure is None
    assert not outcome.retryable
    assert outcome.exit_status == 0
    assert outcome.stderr_classification == "none"
    assert outcome.reviewer_output is not None
    assert [finding.finding_id for finding in outcome.reviewer_output.findings] == ["F001"]
    assert outcome.raw_trace.stdout_path is not None
    stdout_path = tmp_path / outcome.raw_trace.stdout_path
    stderr_path = tmp_path / cast(PurePosixPath, outcome.raw_trace.stderr_path)
    assert b"Reviewer preamble" in stdout_path.read_bytes()
    assert b"Reviewer preamble" not in repr(outcome).encode()
    assert stat.S_IMODE(stdout_path.stat().st_mode) == 0o600
    assert stat.S_IMODE(stderr_path.stat().st_mode) == 0o600


def test_empty_findings_is_success_not_invalid_output(tmp_path: Path) -> None:
    executable = _fake_executable(tmp_path, "empty")
    adapter, invocation = _invocation(tmp_path, executable)

    outcome = adapter.invoke(invocation)

    assert outcome.succeeded
    assert outcome.reviewer_output is not None
    assert outcome.reviewer_output.findings == ()


def test_standard_user_environment_is_available_for_provider_login(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("USER", "adapter-user")
    monkeypatch.setenv("LOGNAME", "adapter-login")
    monkeypatch.setenv("SHELL", "/bin/adapter-shell")
    executable = _fake_executable(tmp_path, "required-user-env")
    adapter, invocation = _invocation(tmp_path, executable)

    outcome = adapter.invoke(invocation)

    assert outcome.succeeded


def test_claude_json_envelope_preserves_output_usage_and_cost(tmp_path: Path) -> None:
    executable = _fake_executable(tmp_path, "claude-json")
    adapter, invocation = _invocation(tmp_path, executable)

    outcome = adapter.invoke(invocation)

    assert outcome.succeeded
    assert outcome.reviewer_output is not None
    assert outcome.reviewer_output.findings == ()
    assert outcome.provider_request_id == "provider-request-123"
    assert outcome.input_tokens == 315
    assert outcome.cached_input_tokens == 200
    assert outcome.output_tokens == 22
    assert outcome.total_cost_usd == 0.03125
    assert outcome.provider == "anthropic"


def test_trace_retention_failure_preserves_claude_attempt_metadata(tmp_path: Path) -> None:
    executable = _fake_executable(tmp_path, "claude-json")
    adapter, invocation = _invocation(tmp_path, executable, retain_raw_output=True)
    outside = tmp_path / "outside"
    outside.mkdir()
    artifacts = tmp_path / "artifacts"
    artifacts.mkdir()
    (artifacts / "provider-traces").symlink_to(outside, target_is_directory=True)

    outcome = adapter.invoke(invocation)

    assert outcome.failure == "adapter_error"
    assert outcome.validation_errors == ("TRACE_RETENTION_FAILED",)
    assert outcome.provider == "anthropic"
    assert outcome.provider_request_id == "provider-request-123"
    assert (outcome.input_tokens, outcome.cached_input_tokens, outcome.output_tokens) == (
        315,
        200,
        22,
    )
    assert outcome.total_cost_usd == 0.03125
    assert not list(outside.iterdir())


def test_claude_json_envelope_preserves_cost_for_invalid_reviewer_output(
    tmp_path: Path,
) -> None:
    executable = _fake_executable(tmp_path, "claude-json-invalid-result")
    adapter, invocation = _invocation(tmp_path, executable)

    outcome = adapter.invoke(invocation)

    assert outcome.failure == "invalid_output"
    assert outcome.provider_request_id == "provider-request-invalid"
    assert outcome.input_tokens == 10
    assert outcome.output_tokens == 3
    assert outcome.total_cost_usd == 0.0425


def test_claude_json_nonzero_envelope_preserves_provider_metadata(tmp_path: Path) -> None:
    executable = _fake_executable(tmp_path, "claude-json-provider-error")
    adapter, invocation = _invocation(tmp_path, executable)

    outcome = adapter.invoke(invocation)

    assert outcome.failure == "adapter_error"
    assert outcome.validation_errors == ("PROCESS_NONZERO",)
    assert outcome.provider_request_id == "provider-request-rate-limit"
    assert outcome.input_tokens == 0
    assert outcome.cached_input_tokens == 0
    assert outcome.output_tokens == 0
    assert outcome.total_cost_usd == 0


def test_exit_zero_stderr_does_not_discard_valid_structured_output(tmp_path: Path) -> None:
    executable = _fake_executable(tmp_path, "success-stderr")
    adapter, invocation = _invocation(tmp_path, executable)

    outcome = adapter.invoke(invocation)

    assert outcome.succeeded
    assert outcome.reviewer_output is not None
    assert outcome.reviewer_output.findings == ()
    assert outcome.stderr_classification == "none"
    assert outcome.raw_trace.stderr_digest != sha256_digest(b"")


@pytest.mark.parametrize(
    ("mode", "error"),
    [
        ("malformed", "OUTPUT_JSON_INVALID"),
        ("invalid-schema", "OUTPUT_SCHEMA_INVALID"),
        ("array-wrapper", "OUTPUT_JSON_INVALID"),
        ("ambiguous", "OUTPUT_JSON_INVALID"),
        ("non-utf8", "OUTPUT_ENCODING_INVALID"),
        ("duplicate-key", "OUTPUT_JSON_INVALID"),
        ("non-standard-number", "OUTPUT_JSON_INVALID"),
    ],
)
def test_invalid_output_is_never_interpreted_as_no_findings(
    tmp_path: Path, mode: str, error: str
) -> None:
    executable = _fake_executable(tmp_path, mode)
    adapter, invocation = _invocation(tmp_path, executable)

    outcome = adapter.invoke(invocation)

    assert not outcome.succeeded
    assert outcome.reviewer_output is None
    assert outcome.failure == "invalid_output"
    assert outcome.retryable
    assert outcome.validation_errors == (error,)
    assert outcome.to_dict()["failure"] == "invalid_output"


@pytest.mark.parametrize(
    ("mode", "failure", "stderr_classification", "retryable"),
    [
        ("provider-error", "provider_error", "provider", True),
        ("configuration-error", "configuration_error", "configuration", False),
        ("internal-error", "adapter_error", "internal", False),
    ],
)
def test_nonzero_failures_are_machine_classified_without_stderr_disclosure(
    tmp_path: Path,
    mode: str,
    failure: str,
    stderr_classification: str,
    retryable: bool,
) -> None:
    executable = _fake_executable(tmp_path, mode)
    adapter, invocation = _invocation(
        tmp_path, executable, retain_raw_output=mode == "provider-error"
    )

    outcome = adapter.invoke(invocation)

    assert outcome.failure == failure
    assert outcome.stderr_classification == stderr_classification
    assert outcome.retryable is retryable
    assert outcome.reviewer_output is None
    assert "synthetic-secret-value" not in repr(outcome)
    if mode == "provider-error":
        assert outcome.raw_trace.stderr_path is not None
        retained = tmp_path / outcome.raw_trace.stderr_path
        assert SENSITIVE_STDERR.encode() in retained.read_bytes()
        assert stat.S_IMODE(retained.stat().st_mode) == 0o600


def test_oversized_output_is_bounded_and_permanent(tmp_path: Path) -> None:
    executable = _fake_executable(tmp_path, "oversized")
    adapter, invocation = _invocation(
        tmp_path,
        executable,
        maximum_stdout_bytes=512,
        maximum_stderr_bytes=128,
    )

    outcome = adapter.invoke(invocation)

    assert outcome.failure == "adapter_error"
    assert not outcome.retryable
    assert outcome.validation_errors == ("OUTPUT_LIMIT_EXCEEDED", "STDOUT_LIMIT_EXCEEDED")
    assert outcome.raw_trace.truncated


def test_oversized_stderr_identifies_the_exceeded_stream(tmp_path: Path) -> None:
    executable = _fake_executable(tmp_path, "oversized-stderr")
    adapter, invocation = _invocation(
        tmp_path,
        executable,
        maximum_stdout_bytes=512,
        maximum_stderr_bytes=128,
    )

    outcome = adapter.invoke(invocation)

    assert outcome.failure == "adapter_error"
    assert not outcome.retryable
    assert outcome.validation_errors == ("OUTPUT_LIMIT_EXCEEDED", "STDERR_LIMIT_EXCEEDED")
    assert outcome.raw_trace.truncated


def test_timeout_terminates_the_process_group_and_is_retryable(tmp_path: Path) -> None:
    child_pid_path = tmp_path / "child.pid"
    executable = _fake_executable(tmp_path, "timeout", child_pid_path=child_pid_path)
    adapter, invocation = _invocation(tmp_path, executable, timeout_seconds=0.2)
    started = time.monotonic()

    outcome = adapter.invoke(invocation)

    assert time.monotonic() - started < 3
    assert outcome.failure == "timeout"
    assert outcome.retryable
    assert outcome.stderr_classification == "timeout"
    assert outcome.validation_errors == ("PROCESS_TIMEOUT",)
    assert child_pid_path.is_file()
    child_pid = int(child_pid_path.read_text(encoding="utf-8"))
    deadline = time.monotonic() + 2
    while time.monotonic() < deadline:
        try:
            os.kill(child_pid, 0)
        except ProcessLookupError:
            break
        time.sleep(0.02)
    else:
        pytest.fail("timed-out adapter child process was not terminated")


def test_timeout_remains_authoritative_after_direct_child_exits(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    grandchild_pid_path = tmp_path / "grandchild.pid"
    executable = _fake_executable(tmp_path, "grandchild-pipe", child_pid_path=grandchild_pid_path)
    adapter, invocation = _invocation(tmp_path, executable, timeout_seconds=1.0)
    captures: list[adapter_module._ProcessCapture] = []
    original_capture = adapter._capture

    def record_capture(
        arguments: tuple[str, ...], input_bytes: bytes, timeout_seconds: float
    ) -> adapter_module._ProcessCapture:
        capture = original_capture(arguments, input_bytes, timeout_seconds)
        captures.append(capture)
        return capture

    monkeypatch.setattr(adapter, "_capture", record_capture)
    started = time.monotonic()

    outcome = adapter.invoke(invocation)

    assert time.monotonic() - started < 2.5
    assert len(captures) == 1
    assert captures[0].timed_out is True
    assert captures[0].exit_status == 0
    assert outcome.failure == "timeout"
    assert outcome.retryable
    assert outcome.exit_status == 0
    assert outcome.stderr_classification == "timeout"
    assert outcome.validation_errors == ("PROCESS_TIMEOUT",)
    assert grandchild_pid_path.is_file()
    grandchild_pid = int(grandchild_pid_path.read_text(encoding="utf-8"))
    deadline = time.monotonic() + 1
    while time.monotonic() < deadline:
        try:
            os.kill(grandchild_pid, 0)
        except ProcessLookupError:
            break
        time.sleep(0.02)
    else:
        pytest.fail("adapter grandchild process was not terminated")


@pytest.mark.skipif(os.name == "nt", reason="POSIX process group termination")
def test_termination_clamps_sleep_when_grace_expires(monkeypatch: pytest.MonkeyPatch) -> None:
    process = Mock(spec=subprocess.Popen)
    process.pid = 12345
    process.poll.return_value = None
    timestamps = iter((0.0, 0.49, 0.51, 0.51))
    monkeypatch.setattr(time, "monotonic", lambda: next(timestamps))
    sleep = Mock()
    killpg = Mock()
    monkeypatch.setattr(time, "sleep", sleep)
    monkeypatch.setattr(os, "killpg", killpg)

    adapter_module._terminate_process(process)

    sleep.assert_called_once_with(0.0)
    assert [call.args for call in killpg.call_args_list] == [
        (process.pid, signal.SIGTERM),
        (process.pid, 0),
        (process.pid, signal.SIGKILL),
    ]
    process.wait.assert_called_once_with(timeout=adapter_module._TERMINATION_GRACE_SECONDS)


def test_profile_text_and_repository_filenames_never_become_arguments(
    tmp_path: Path,
) -> None:
    executable = _fake_executable(tmp_path, "empty")
    adapter, invocation = _invocation(tmp_path, executable)

    outcome = adapter.invoke(invocation)

    assert outcome.succeeded
    assert not (tmp_path / "adapter-cwd" / "adapter-shell-injection").exists()
    assert not (tmp_path / "adapter-cwd" / "adapter-pwned").exists()


def test_changed_executable_is_rejected_before_invocation(tmp_path: Path) -> None:
    executable = _fake_executable(tmp_path, "empty")
    adapter, invocation = _invocation(tmp_path, executable)
    executable.write_text("#!/bin/sh\nexit 99\n", encoding="utf-8")
    executable.chmod(0o700)

    outcome = adapter.invoke(invocation)

    assert outcome.failure == "configuration_error"
    assert outcome.exit_status is None
    assert outcome.validation_errors == ("EXECUTABLE_CHANGED",)


def test_changed_arguments_and_nonempty_working_directory_fail_before_invocation(
    tmp_path: Path,
) -> None:
    executable = _fake_executable(tmp_path, "empty")
    adapter, invocation = _invocation(tmp_path, executable)
    changed = ReviewerSubprocessAdapter(
        AdapterConfiguration(
            executable=str(executable),
            review_arguments=("different", "{model}"),
            working_directory=(tmp_path / "adapter-cwd").resolve(),
        )
    )
    changed_outcome = changed.invoke(invocation)
    assert changed_outcome.failure == "configuration_error"
    assert changed_outcome.validation_errors == ("PROCESS_CONTROLS_CHANGED",)

    (tmp_path / "adapter-cwd" / "unexpected-private-file").write_text("private", encoding="utf-8")
    unsafe_outcome = adapter.invoke(invocation)
    assert unsafe_outcome.failure == "configuration_error"
    assert unsafe_outcome.validation_errors == ("WORKING_DIRECTORY_UNSAFE",)


def test_invocation_must_match_approved_manifest_identity(tmp_path: Path) -> None:
    executable = _fake_executable(tmp_path, "empty")
    adapter, invocation = _invocation(tmp_path, executable)

    with pytest.raises(AdapterConfigurationError, match="reviewer settings"):
        adapter.invoke(replace(invocation, reviewer_settings=_settings(model="other-model")))
    with pytest.raises(AdapterConfigurationError, match="profile identity"):
        adapter.invoke(
            replace(invocation, profile=replace(invocation.profile, digest=f"sha256:{'0' * 64}"))
        )
    with pytest.raises(AdapterConfigurationError, match="run metadata"):
        adapter.invoke(
            replace(
                invocation,
                metadata=replace(invocation.metadata, request_id="request-other"),
            )
        )


def test_paired_calls_differ_only_in_approved_profile_fields(tmp_path: Path) -> None:
    executable = _fake_executable(tmp_path, "empty", expected_marker="Candidate profile")
    adapter, baseline = _invocation(tmp_path / "baseline", executable)
    _candidate_adapter, candidate = _invocation(
        tmp_path / "candidate",
        executable,
        condition="candidate",
        profile_name="candidate",
        profile_content="Candidate profile",
    )

    ensure_paired_invocations(baseline, candidate)
    with pytest.raises(AdapterConfigurationError, match="not invariant"):
        ensure_paired_invocations(
            baseline, replace(candidate, timeout_seconds=candidate.timeout_seconds + 1)
        )
    _seed_adapter, different_seed = _invocation(
        tmp_path / "different-seed",
        executable,
        condition="candidate",
        profile_name="candidate",
        profile_content="Candidate profile",
        seed=43,
    )
    with pytest.raises(AdapterConfigurationError, match="not invariant"):
        ensure_paired_invocations(baseline, different_seed)
    _policy_adapter, different_policy = _invocation(
        tmp_path / "different-policy",
        executable,
        condition="candidate",
        profile_name="candidate",
        profile_content="Candidate profile",
        total_token_limit=25_000,
    )
    assert baseline.build.bundle_digest == different_policy.build.bundle_digest
    with pytest.raises(AdapterConfigurationError, match="not invariant"):
        ensure_paired_invocations(baseline, different_policy)
    _bounded_adapter, different_bounds = _invocation(
        tmp_path / "different-bounds",
        executable,
        condition="candidate",
        profile_name="candidate",
        profile_content="Candidate profile",
        maximum_stdout_bytes=999_999,
    )
    with pytest.raises(AdapterConfigurationError, match="not invariant"):
        ensure_paired_invocations(baseline, different_bounds)
    assert adapter.probe() == baseline.capabilities


def test_changed_process_controls_are_rejected_before_invocation(tmp_path: Path) -> None:
    executable = _fake_executable(tmp_path, "oversized")
    _probe_adapter, invocation = _invocation(tmp_path, executable)
    changed = ReviewerSubprocessAdapter(
        AdapterConfiguration(
            executable=str(executable),
            review_arguments=("run", "{model}"),
            working_directory=(tmp_path / "adapter-cwd").resolve(),
            maximum_stdout_bytes=128,
            maximum_stderr_bytes=128,
        )
    )

    outcome = changed.invoke(invocation)

    assert outcome.failure == "configuration_error"
    assert outcome.exit_status is None
    assert outcome.validation_errors == ("PROCESS_CONTROLS_CHANGED",)


def test_trace_policy_rejects_wrong_class_and_symlinked_parent(tmp_path: Path) -> None:
    executable = _fake_executable(tmp_path, "empty")
    adapter, invocation = _invocation(tmp_path, executable, retain_raw_output=True)
    with pytest.raises(AdapterConfigurationError, match="artifact policy"):
        adapter.invoke(
            replace(
                invocation,
                trace_policy=replace(
                    invocation.trace_policy,
                    raw_trace_root=PurePosixPath("reports/aggregate"),
                ),
            )
        )
    with pytest.raises(AdapterConfigurationError, match="artifact policy"):
        adapter.invoke(
            replace(
                invocation,
                trace_policy=replace(
                    invocation.trace_policy,
                    raw_trace_root=PurePosixPath("artifacts/provider-traces/../outside"),
                ),
            )
        )

    outside = tmp_path / "outside"
    outside.mkdir()
    artifacts = tmp_path / "artifacts"
    artifacts.mkdir()
    (artifacts / "provider-traces").symlink_to(outside, target_is_directory=True)
    outcome = adapter.invoke(invocation)
    assert outcome.failure == "adapter_error"
    assert outcome.validation_errors == ("TRACE_RETENTION_FAILED",)
    assert not list(outside.iterdir())
