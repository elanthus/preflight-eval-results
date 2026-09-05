"""Public PR regressions: observable contract, error and performance boundaries."""

from __future__ import annotations

import json
import random
import subprocess
from dataclasses import replace
from pathlib import Path
from typing import Any, cast
from unittest.mock import patch

import pytest
import tiktoken

from preflight_evals import adapter, bundle, corpus_split, execution
from preflight_evals.canonical import canonical_digest, canonical_json_bytes, sha256_digest
from preflight_evals.contract_models import parse_typed_contract
from preflight_evals.curator_models import CaseRecord
from preflight_evals.errors import ExecutionError, ExitCode, SchemaError
from preflight_evals.report import AggregateReport, render_markdown
from preflight_evals.reviewer_models import PromptManifest
from preflight_evals.run_models import RunRecord
from preflight_evals.schema import ContractName, validate_contract
from tests.test_report import _redigest
from tests.test_statistics import _inputs

ROOT = Path(__file__).resolve().parents[1]
FIXTURES = ROOT / "tests/fixtures/contracts"


def _document(name: str, variant: str = "full") -> dict[str, Any]:
    return cast(dict[str, Any], json.loads((FIXTURES / name / f"{variant}.json").read_text()))


def _classify(document: dict[str, Any]) -> adapter.AdapterOutcome:
    payload = json.dumps(document).encode()
    capture = adapter._ProcessCapture(payload, b"", 0, False, False, False, False, 1.0)
    trace = adapter.RawTraceRecord(None, sha256_digest(payload), None, sha256_digest(b""), False)
    return adapter._classify_capture(capture, trace, cast(PromptManifest, None))


def _envelope() -> dict[str, Any]:
    return {
        "type": "result",
        "subtype": "success",
        "is_error": False,
        "uuid": "synthetic-billed-failure",
        "total_cost_usd": 0.125,
        "usage": {"input_tokens": 12, "output_tokens": 4},
        "structured_output": {"schema_version": "1.0", "findings": []},
    }


@pytest.mark.parametrize("failure", ["provider_error", "wrong_shape", "malformed_result"])
def test_billed_invalid_envelopes_keep_provider_metadata(failure: str) -> None:
    document = _envelope()
    if failure == "provider_error":
        document.update(is_error=True, subtype="error_during_execution")
    elif failure == "wrong_shape":
        document["structured_output"] = []
    else:
        document.pop("structured_output")
        document["result"] = "{malformed JSON"
    outcome = _classify(document)
    assert outcome.failure == "invalid_output"
    assert outcome.provider == "anthropic"
    assert outcome.provider_request_id == "synthetic-billed-failure"
    assert outcome.total_cost_usd == 0.125
    assert (outcome.input_tokens, outcome.output_tokens) == (12, 4)


@pytest.mark.parametrize("enveloped", [False, True])
def test_lone_surrogate_is_invalid_output_before_record_digest(enveloped: bool) -> None:
    output = _document("reviewer-output")
    output["findings"][0]["title"] = "invalid \ud800"
    document = _envelope() if enveloped else output
    if enveloped:
        document["structured_output"] = output
    outcome = _classify(document)
    assert outcome.failure == "invalid_output"
    assert outcome.validation_errors == ("OUTPUT_ENCODING_INVALID",)
    assert outcome.reviewer_output is None
    if enveloped:
        assert outcome.total_cost_usd == 0.125


def test_unknown_contract_has_sanitized_schema_error() -> None:
    sensitive_name = "unknown-private-contract"
    with pytest.raises(SchemaError) as caught:
        parse_typed_contract(cast(ContractName, sensitive_name), {})
    assert caught.value.exit_code == ExitCode.SCHEMA
    assert sensitive_name not in str(caught.value)


@pytest.mark.parametrize("latency", [0, 1, 2000, 0.0, 1.0, 1.125])
def test_digest_preserves_integral_and_fractional_latency(latency: int | float) -> None:
    document = _document("run-record")
    document["monotonic_latency_ms"] = latency
    document.pop("content_digest")
    document["content_digest"] = canonical_digest(document)
    model = RunRecord.from_dict(document)
    assert model.canonical_bytes() == canonical_json_bytes(document)
    assert isinstance(model.monotonic_latency_ms, float)
    changed = replace(model, monotonic_latency_ms=99.5)
    assert changed.to_dict()["monotonic_latency_ms"] == 99.5


@pytest.mark.parametrize(
    "href",
    [
        "javascript:alert",
        "data:text/html,attack",
        "http://example.org/x",
        "file:///tmp/x",
        "https://example.org/a b",
        "https://example.org/[x]",
    ],
)
def test_investigation_links_reject_unsafe_or_malformed_urls(href: str) -> None:
    document = _document("aggregate-report")
    document["visibility"] = "private"
    document["investigation_links"] = [{"run_id": "run-" + "a" * 32, "href": href}]
    with pytest.raises(SchemaError):
        AggregateReport.from_dict(_redigest(document))


def test_investigation_link_accepts_https() -> None:
    document = _document("aggregate-report")
    document["visibility"] = "private"
    document["investigation_links"] = [
        {"run_id": "run-" + "a" * 32, "href": "https://example.org/runs/1?view=trace"}
    ]
    report = AggregateReport.from_dict(_redigest(document))
    assert "https://example.org/runs/1?view=trace" in render_markdown(report.canonical_bytes())


def test_uri_format_is_checked_at_schema_boundary() -> None:
    document = _document("catalog")
    validate_contract("catalog", document)
    document["source_evidence"] = "not a valid URI"
    with pytest.raises(SchemaError):
        validate_contract("catalog", document)


@pytest.mark.parametrize("variant", ["minimum", "full"])
def test_aggregate_fixture_boundaries(variant: str) -> None:
    document = _document("aggregate-report", variant)
    report = AggregateReport.from_dict(document)
    assert ("issue_discovery" in document) == (variant == "full")
    assert report.to_dict() == document
    if variant == "minimum":
        schema = json.loads((ROOT / "schemas/aggregate-report.schema.json").read_text())
        assert set(document) == set(schema["required"])


def _cases() -> tuple[CaseRecord, ...]:
    base = CaseRecord.from_dict(_document("case"))
    return tuple(replace(base, case_id=f"synthetic-split-{i}") for i in range(6))


def test_freeze_searches_once_and_generic_parser_still_checks_optimum() -> None:
    with patch.object(corpus_split, "_best_holdout", wraps=corpus_split._best_holdout) as search:
        split = corpus_split.freeze_corpus_split(
            _cases(), seed=10, holdout_count=2, locked_development=frozenset()
        )
        assert search.call_count == 1
        assert corpus_split.CorpusSplit.from_dict(split.to_dict()) == split
        assert search.call_count == 2
    # A checksum-correct artifact with a false optimum must still be rejected.
    document = split.to_dict()
    document["objective_score"] = split.objective_score + 1
    document.pop("content_digest")
    document["content_digest"] = canonical_digest(document)
    with pytest.raises(SchemaError, match="deterministic optimum"):
        parse_typed_contract("corpus-split", document)


@pytest.mark.parametrize("duplicate", [False, True])
def test_retry_recovery_wraps_incomplete_or_duplicate_records(duplicate: bool) -> None:
    source, records, _, _ = _inputs()
    # Only the preconditions needed to exercise terminal record coverage change.
    source = replace(
        source,
        schema_version="1.4",
        holdout_access_enabled=True,
        holdout_source=cast(Any, object()),
    )
    supplied = (*records, records[0]) if duplicate else records[:-1]
    assert source.adapter_capabilities is not None
    with pytest.raises(ExecutionError, match="terminal records") as caught:
        execution.freeze_retry_recovery_experiment(
            source,
            supplied,
            source.adapter_capabilities,
            maximum_attempts=1,
            code_revision="a" * 40,
            environment_lock_digest="sha256:" + "b" * 64,
            created_at=source.created_at,
            approved_at=source.created_at,
            approved_by="synthetic-operator",
            expected_provider_error_failures=1,
        )
    assert caught.value.exit_code == ExitCode.EXECUTION


def _candidate(text: str, kept: int, policy: str) -> str:
    marker = bundle._TRUNCATION_MARKER
    if policy == "head":
        return text[:kept] + marker
    tail = kept // 2
    return text[: (kept + 1) // 2] + marker + (text[-tail:] if tail else "")


@pytest.mark.parametrize("encoding", ["r50k_base", "cl100k_base", "o200k_base"])
@pytest.mark.parametrize("policy", ["head", "head_tail"])
def test_truncation_matches_exhaustive_oracle(encoding: str, policy: str) -> None:
    tokenizer = bundle._Tokenizer(
        encoding, "test", "per_file_utf8_sum_v1", tiktoken.get_encoding(encoding)
    )
    rng = random.Random(371)
    alphabet = "abCD09-_,. :\n\t漢é😀"
    texts = [",WXcGogG,.c:wbFrKm.:\ni1VfZ-/xn.,u", "hello <|endoftext|> world" * 4]
    texts.extend("".join(rng.choices(alphabet, k=100)) for _ in range(8))
    for text in texts:
        token_limit = tokenizer.count(bundle._TRUNCATION_MARKER) + rng.randrange(1, 20)
        byte_limit = rng.randrange(40, 150)

        def fits(value: str, byte_limit: int = byte_limit, token_limit: int = token_limit) -> bool:
            return len(value.encode()) <= byte_limit and tokenizer.count(value) <= token_limit

        expected = (
            text
            if fits(text)
            else next(
                _candidate(text, k, policy)
                for k in range(len(text), -1, -1)
                if fits(_candidate(text, k, policy))
            )
        )
        actual, _ = bundle._limit_text(
            text,
            tokenizer,
            byte_limit=byte_limit,
            token_limit=token_limit,
            policy=cast(bundle.TruncationPolicy, policy),
        )
        assert actual == expected


def test_large_head_truncation_avoids_full_candidate_scan() -> None:
    tokenizer = bundle._Tokenizer(
        "o200k_base", "test", "per_file_utf8_sum_v1", tiktoken.get_encoding("o200k_base")
    )
    text = "alpha beta gamma delta\n" * 5_000
    original = bundle._Tokenizer.count
    calls = 0

    def counted(self: bundle._Tokenizer, value: str) -> int:
        nonlocal calls
        calls += 1
        return original(self, value)

    with patch.object(bundle._Tokenizer, "count", counted):
        result, truncated = bundle._limit_text(
            text, tokenizer, byte_limit=len(text), token_limit=32, policy="head"
        )
    assert truncated and original(tokenizer, result) <= 32
    assert calls < 100  # Previously over 100,000 full candidate encodes.


def test_raw_artifacts_are_ignored() -> None:
    result = subprocess.run(
        ["git", "check-ignore", "artifacts/provider-trace.json"],
        cwd=ROOT,
        capture_output=True,
        text=True,
    )
    assert result.returncode == 0


def test_generic_split_parser_rejects_equal_score_wrong_tie_break() -> None:
    split = corpus_split.freeze_corpus_split(
        _cases(), seed=10, holdout_count=2, locked_development=frozenset()
    )
    chosen = set(split.ordered_holdout)
    replacement = next(item.case_id for item in split.assignments if item.case_id not in chosen)
    chosen.remove(split.ordered_holdout[0])
    chosen.add(replacement)
    # All six cases have identical strata: this different split has the same objective.
    document = split.to_dict()
    for assignment in cast(list[dict[str, Any]], document["assignments"]):
        assignment["role"] = "holdout" if assignment["case_id"] in chosen else "development"
    ordered = sorted(chosen, key=lambda value: corpus_split._order_key(split.seed, value))
    document["ordered_holdout"] = ordered
    document["ordered_holdout_checksum"] = corpus_split.ordered_holdout_checksum(ordered)
    document.pop("content_digest")
    document["content_digest"] = canonical_digest(document)
    with pytest.raises(SchemaError, match="deterministic optimum"):
        parse_typed_contract("corpus-split", document)
