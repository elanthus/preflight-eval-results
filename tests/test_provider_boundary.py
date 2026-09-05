from __future__ import annotations

from pathlib import Path

import pytest

from tests.test_adapter import _fake_executable, _invocation


@pytest.mark.parametrize("condition", ["baseline", "candidate"])
def test_actual_provider_stdin_excludes_scorer_identity_and_labels(
    tmp_path: Path, condition: str
) -> None:
    capture = tmp_path / "provider-stdin.bin"
    executable = _fake_executable(tmp_path, "empty", expected_marker="Review carefully.")
    source = executable.read_text()
    source = source.replace(
        "request = sys.stdin.buffer.read()",
        "request = sys.stdin.buffer.read()\n"
        f"with open({str(capture)!r}, 'wb') as capture:\n    capture.write(request)",
    )
    executable.write_text(source)
    # Probe after instrumenting, so executable-digest validation remains active.
    adapter, invocation = _invocation(
        tmp_path,
        executable,
        condition=condition,
        profile_name=condition,
        profile_content="Review carefully.",
    )
    result = adapter.invoke(invocation)
    assert result.succeeded
    actual = capture.read_bytes()
    assert actual
    assert b"Review carefully." in actual
    for forbidden in (
        b"synthetic-adapter-case",
        b"request-adapter-",
        b"run-adapter-",
        b'"case_id"',
        b'"snapshot"',
        b'"condition"',
        b'"gold"',
        b"baseline",
        b"candidate",
        b"vulnerable",
        b"fixed",
    ):
        assert forbidden not in actual, forbidden
