from __future__ import annotations

import hashlib
import json
from copy import deepcopy
from dataclasses import replace
from pathlib import Path
from typing import Any, cast

import pytest

from preflight_evals.canonical import JsonValue, canonical_digest
from preflight_evals.errors import PolicyError, PreflightEvalsError, SchemaError
from preflight_evals.report import (
    AggregateReport,
    InvestigationLink,
    build_aggregate_report,
    render_markdown,
    validate_public_report,
)
from preflight_evals.reviewer_models import Finding, ReviewerOutput
from preflight_evals.run_models import ExperimentManifest, RunRecord
from preflight_evals.score import ScoringResult, score_experiment
from preflight_evals.scorer_models import GoldRecord
from preflight_evals.statistics import StatisticsResult, calculate_statistics
from tests.test_score import _adjudication as _mechanism_adjudication
from tests.test_statistics import _adjudication as _primary_adjudication
from tests.test_statistics import _inputs, _price_table

FIXTURES = Path(__file__).parent / "fixtures" / "report"
CONTRACT_FIXTURES = Path(__file__).parent / "fixtures" / "contracts" / "aggregate-report"


@pytest.fixture(scope="module")
def report_inputs() -> tuple[ExperimentManifest, StatisticsResult]:
    experiment, records, gold, scoring = _inputs()
    statistics = calculate_statistics(
        experiment,
        scoring,
        records,
        gold,
        _price_table(),
        provider="synthetic",
    )
    return experiment, statistics


def _public_report(
    inputs: tuple[ExperimentManifest, StatisticsResult],
    *,
    statistics: StatisticsResult | None = None,
) -> AggregateReport:
    experiment, default_statistics = inputs
    return build_aggregate_report(
        experiment,
        statistics or default_statistics,
        visibility="public",
        decision="revise",
        rationale="Synthetic evidence requires another profile revision.",
        minimum_public_cell_size=2,
        limitations=("Synthetic corpus only.", "Results do not establish broad generality."),
        exclusions=("External-setting cases were excluded.",),
    )


def _redigest(document: dict[str, Any]) -> dict[str, Any]:
    content = deepcopy(document)
    content.pop("report_id", None)
    content.pop("content_digest", None)
    digest = canonical_digest(cast(JsonValue, content))
    content["report_id"] = f"report-{digest.removeprefix('sha256:')[:32]}"
    content["content_digest"] = digest
    return content


def _mechanism_report_inputs() -> tuple[
    ExperimentManifest, StatisticsResult, ScoringResult, AggregateReport
]:
    experiment, original_records, _legacy_gold, legacy_scoring = _inputs()
    legacy_statistics = calculate_statistics(
        experiment,
        legacy_scoring,
        original_records,
        _legacy_gold,
        _price_table(),
        provider="synthetic",
    )
    legacy_report = build_aggregate_report(
        experiment,
        legacy_statistics,
        visibility="public",
        decision="revise",
        rationale="Synthetic evidence requires another profile revision.",
        minimum_public_cell_size=2,
    )

    gold_document = json.loads((Path(__file__).parent / "fixtures" / "gold-v2.json").read_text())
    gold = tuple(
        replace(GoldRecord.from_dict(gold_document), case_id=case.case_id)
        for case in experiment.cases
    )
    base_finding = next(
        finding
        for record in original_records
        if record.reviewer_output is not None
        for finding in record.reviewer_output.findings
    )
    supplemental_document = base_finding.to_dict()
    supplemental_document.update(
        {
            "finding_id": "F003",
            "title": "Synthetic supplemental defect",
            "file_path": "src/supplemental.py",
            "severity": "high",
            "defect_category": "security",
            "failure_mechanism": "Synthetic supplemental mechanism",
            "evidence": [{"source_type": "tool", "reference": "synthetic-check"}],
        }
    )
    supplemental_document.pop("start_line", None)
    supplemental_document.pop("end_line", None)
    supplemental = Finding.from_dict(supplemental_document)
    duplicate_document = supplemental.to_dict()
    duplicate_document["finding_id"] = "F004"
    duplicate = Finding.from_dict(duplicate_document)

    records: list[RunRecord] = []
    adjudications = []
    for record in original_records:
        planned = next(run for run in experiment.execution_order if run.run_id == record.run_id)
        output = record.reviewer_output
        findings = output.findings if output is not None else ()
        if output is not None and planned.snapshot == "fixed" and planned.condition == "candidate":
            output = ReviewerOutput(
                schema_version=output.schema_version,
                findings=(*findings, supplemental, duplicate),
            )
            assert record.identity is not None
            identity = replace(
                record.identity,
                reviewer_output_digest=canonical_digest(output.to_dict()),
            )
            draft = replace(record, reviewer_output=output, identity=identity, content_digest=None)
            record = replace(draft, content_digest=draft.digest_without_self())
            findings = output.findings
        records.append(record)

        for finding in findings:
            if planned.snapshot == "vulnerable":
                if finding.finding_id == "F002":
                    adjudications.append(_primary_adjudication(record.run_id))
                continue
            primary_decision = "match" if finding.finding_id == "F002" else "no_match"
            adjudications.append(
                _mechanism_adjudication(
                    record.run_id,
                    finding.finding_id,
                    primary_decision,
                    suffix=f"{record.run_id}-{finding.finding_id.lower()}-primary",
                )
            )
            adjudications.append(
                _mechanism_adjudication(
                    record.run_id,
                    finding.finding_id,
                    "match" if finding.finding_id in {"F003", "F004"} else "no_match",
                    suffix=f"{record.run_id}-{finding.finding_id.lower()}-supplemental",
                    mechanism_id="mechanism-supplemental",
                )
            )

    scoring = score_experiment(experiment, tuple(records), gold, tuple(adjudications))
    statistics = calculate_statistics(
        experiment,
        scoring,
        tuple(records),
        gold,
        _price_table(),
        provider="synthetic",
    )
    return experiment, statistics, scoring, legacy_report


def test_public_report_is_byte_stable_and_matches_json_snapshot(
    report_inputs: tuple[ExperimentManifest, StatisticsResult],
) -> None:
    first = _public_report(report_inputs)
    experiment, statistics = report_inputs
    second = build_aggregate_report(
        experiment,
        statistics,
        visibility="public",
        decision="revise",
        rationale="Synthetic evidence requires another profile revision.",
        minimum_public_cell_size=2,
        limitations=("Results do not establish broad generality.", "Synthetic corpus only."),
        exclusions=("External-setting cases were excluded.",),
    )

    assert second.canonical_bytes() == first.canonical_bytes()
    assert first.canonical_bytes() == (CONTRACT_FIXTURES / "full.json").read_bytes().removesuffix(
        b"\n"
    )
    document = first.to_dict()
    assert document["content_digest"] == canonical_digest(
        {
            key: value
            for key, value in document.items()
            if key not in {"report_id", "content_digest"}
        }
    )
    breakdowns = cast(dict[str, JsonValue], document["metrics"])["exploratory_breakdowns"]
    assert isinstance(breakdowns, list)
    assert breakdowns
    assert all(
        cast(int, cast(dict[str, JsonValue], item)["case_count"]) >= 2 for item in breakdowns
    )


def test_markdown_is_rendered_only_from_canonical_json_and_matches_snapshot(
    report_inputs: tuple[ExperimentManifest, StatisticsResult],
) -> None:
    report = _public_report(report_inputs)
    markdown = render_markdown(report.canonical_bytes())

    assert markdown == (FIXTURES / "public.md").read_text(encoding="utf-8")
    assert "Vulnerable lift | 0.5 (2/4) | [0.0, 1.0]" in markdown
    assert "Fixed false-positive increase | 0.5 (2/4) | [0.0, 1.0]" in markdown
    assert "Tokenizer-estimated input tokens: 32000.0" in markdown
    assert "Frozen worst-case budget: $1.920000" in markdown
    assert cast(str, report.to_dict()["content_digest"]) in markdown

    pretty = json.dumps(report.to_dict(), indent=2).encode()
    with pytest.raises(SchemaError, match="not canonical"):
        render_markdown(pretty)


def test_score_result_2_produces_byte_stable_mechanism_discovery_report() -> None:
    experiment, statistics, scoring, legacy_report = _mechanism_report_inputs()
    first = build_aggregate_report(
        experiment,
        statistics,
        visibility="public",
        decision="revise",
        rationale="Synthetic evidence requires another profile revision.",
        minimum_public_cell_size=2,
        scoring_result=scoring,
    )
    second = build_aggregate_report(
        experiment,
        statistics,
        visibility="public",
        decision="revise",
        rationale="Synthetic evidence requires another profile revision.",
        minimum_public_cell_size=2,
        scoring_result=ScoringResult.from_dict(scoring.to_dict()),
    )

    assert first.schema_version == "2.0"
    assert first.canonical_bytes() == second.canonical_bytes()
    assert hashlib.sha256(first.canonical_bytes()).hexdigest() == (
        "71d2a1c9eadd73307fae8acae5463158"  # pragma: allowlist secret
        "d0c37531b35368dbf464035a96447911"  # pragma: allowlist secret
    )
    assert AggregateReport.from_bytes(first.canonical_bytes()) == first
    document = cast(dict[str, Any], first.to_dict())
    discovery = document["mechanism_discovery"]
    assert discovery == cast(dict[str, Any], second.to_dict())["mechanism_discovery"]
    assert discovery["duplicate_findings_excluded"] == 4
    assert discovery["true_positive_findings"] == 4
    assert discovery["precision"] == 1.0
    assert discovery["unverified_mechanism_units"] == 4
    assert discovery["verified_mechanism_units"] == 4
    assert discovery["detected_present_units"] == 2
    assert discovery["missed_present_units"] == 2
    assert discovery["recall"] == 0.5
    assert discovery["f1"] == 2 / 3
    assert discovery["expected_mechanism_coverage"] == 1.0
    assert all(cell["case_count"] == 2 for cell in discovery["cells"])

    legacy = cast(dict[str, Any], legacy_report.to_dict())
    assert document["metrics"]["modes"] == legacy["metrics"]["modes"]
    assert document["decision"] == legacy["decision"]
    markdown = render_markdown(first.canonical_bytes())
    assert markdown == render_markdown(second.canonical_bytes())
    assert hashlib.sha256(markdown.encode()).hexdigest() == (
        "6d2595dd9cbe98a7c9764201a085c1b9"  # pragma: allowlist secret
        "d0d619e40ab7be6137ea9fce40cf5ed6"  # pragma: allowlist secret
    )
    assert "## Supplemental mechanism discovery" in markdown
    assert "do not change the primary paired decision" in markdown
    assert "Finding precision: 1.0 (4/4)" in markdown
    assert "Mechanism recall: 0.5 (2/4)" in markdown


def test_mechanism_discovery_public_cells_obey_minimum_case_size() -> None:
    experiment, statistics, scoring, _legacy_report = _mechanism_report_inputs()
    report = build_aggregate_report(
        experiment,
        statistics,
        visibility="public",
        decision="revise",
        rationale="Synthetic evidence requires another profile revision.",
        minimum_public_cell_size=2,
        scoring_result=scoring,
    )
    document = cast(dict[str, Any], report.to_dict())
    document["mechanism_discovery"]["cells"][0]["case_count"] = 1

    with pytest.raises(PolicyError, match="undersized discovery cell"):
        validate_public_report(document)
    with pytest.raises(SchemaError, match="mechanism-discovery cells"):
        AggregateReport.from_dict(_redigest(document))


def test_report_versions_reject_cross_version_mechanism_sections() -> None:
    experiment, statistics, scoring, legacy_report = _mechanism_report_inputs()
    version_two = cast(
        dict[str, Any],
        build_aggregate_report(
            experiment,
            statistics,
            visibility="public",
            decision="revise",
            rationale="Synthetic evidence requires another profile revision.",
            minimum_public_cell_size=2,
            scoring_result=scoring,
        ).to_dict(),
    )
    del version_two["mechanism_discovery"]
    with pytest.raises(SchemaError, match="required"):
        AggregateReport.from_dict(_redigest(version_two))

    version_one = cast(dict[str, Any], legacy_report.to_dict())
    version_one["mechanism_discovery"] = build_aggregate_report(
        experiment,
        statistics,
        visibility="public",
        decision="revise",
        rationale="Synthetic evidence requires another profile revision.",
        minimum_public_cell_size=2,
        scoring_result=scoring,
    ).to_dict()["mechanism_discovery"]
    with pytest.raises(SchemaError, match="not"):
        AggregateReport.from_dict(_redigest(version_one))


def test_missing_cost_is_explicitly_labeled(
    report_inputs: tuple[ExperimentManifest, StatisticsResult],
) -> None:
    _experiment, statistics = report_inputs
    unknown_cost = replace(
        statistics.cost,
        unknown_usage_or_price_runs=statistics.cost.completed_runs,
        known_terminal_cost_usd=None,
        actual_cost_usd=None,
        projected_remaining_cost_usd=None,
        projected_total_cost_usd=None,
    )
    report = _public_report(report_inputs, statistics=replace(statistics, cost=unknown_cost))

    document = cast(dict[str, Any], report.to_dict())
    assert document["decision"]["inputs"]["actual_cost_known"] is False
    markdown = render_markdown(report.canonical_bytes())
    assert markdown.count("Unknown (usage or matching dated price is incomplete)") == 2


def test_private_report_supports_only_opaque_frozen_run_links(
    report_inputs: tuple[ExperimentManifest, StatisticsResult],
) -> None:
    experiment, statistics = report_inputs
    run_id = experiment.execution_order[0].run_id
    link = InvestigationLink(run_id=run_id, href=f"https://example.invalid/runs/{run_id}")
    private = build_aggregate_report(
        experiment,
        statistics,
        visibility="private",
        decision="insufficient evidence",
        rationale="The synthetic run is not decision-quality evidence.",
        minimum_public_cell_size=5,
        investigation_links=(link,),
    )

    assert private.to_dict()["investigation_links"] == [{"run_id": run_id, "href": link.href}]
    assert f"[{run_id}]({link.href})" in render_markdown(private.canonical_bytes())

    with pytest.raises(PolicyError, match="investigation links"):
        build_aggregate_report(
            experiment,
            statistics,
            visibility="public",
            decision="reject",
            rationale="The evidence does not support adoption.",
            minimum_public_cell_size=2,
            investigation_links=(link,),
        )
    with pytest.raises(SchemaError, match="investigation link"):
        build_aggregate_report(
            experiment,
            statistics,
            visibility="private",
            decision="reject",
            rationale="The evidence does not support adoption.",
            minimum_public_cell_size=2,
            investigation_links=(
                InvestigationLink(run_id="run-reveals-private-case", href="private/run"),
            ),
        )


@pytest.mark.parametrize(
    ("mutation", "expected_error"),
    [
        ("case_id", PreflightEvalsError),
        ("path", PolicyError),
        ("source_sha", PolicyError),
        ("prompt", PreflightEvalsError),
        ("raw_findings", PreflightEvalsError),
        ("holdout_membership", PreflightEvalsError),
        ("undersized_cell", PolicyError),
        ("investigation_link", PreflightEvalsError),
    ],
)
def test_public_disclosure_rejects_every_sensitive_class(
    report_inputs: tuple[ExperimentManifest, StatisticsResult],
    mutation: str,
    expected_error: type[PreflightEvalsError],
) -> None:
    document = cast(dict[str, Any], _public_report(report_inputs).to_dict())
    if mutation == "case_id":
        document["case_id"] = "synthetic-repository-pr999-f001"
    elif mutation == "path":
        document["decision"]["rationale"] = "Evidence came from package/private_module.py."
    elif mutation == "source_sha":
        document["decision"]["rationale"] = "Source was " + "a" * 40 + "."
    elif mutation == "prompt":
        document["prompt"] = "private prompt contents"
    elif mutation == "raw_findings":
        document["raw_findings"] = ["private finding contents"]
    elif mutation == "holdout_membership":
        document["holdout_membership"] = ["synthetic-case"]
    elif mutation == "undersized_cell":
        document["metrics"]["exploratory_breakdowns"][0]["case_count"] = 1
    elif mutation == "investigation_link":
        document["investigation_links"] = [{"run_id": "run-" + "a" * 32, "href": "private/run"}]
    else:  # pragma: no cover - parametrization is exhaustive
        raise AssertionError(mutation)

    with pytest.raises(expected_error):
        AggregateReport.from_dict(_redigest(document))


def test_public_overall_and_eligibility_cells_must_meet_threshold(
    report_inputs: tuple[ExperimentManifest, StatisticsResult],
) -> None:
    experiment, statistics = report_inputs
    with pytest.raises(PolicyError, match="undersized overall cell"):
        build_aggregate_report(
            experiment,
            statistics,
            visibility="public",
            decision="revise",
            rationale="More evidence is required.",
            minimum_public_cell_size=3,
        )

    document = cast(dict[str, Any], _public_report(report_inputs).to_dict())
    document["corpus"]["eligibility_counts"] = [
        {"eligibility": "development", "count": 1},
        {"eligibility": "holdout", "count": 1},
    ]
    with pytest.raises(PolicyError, match="undersized eligibility cell"):
        AggregateReport.from_dict(_redigest(document))


def test_decision_taxonomy_and_evidence_relationships_fail_closed(
    report_inputs: tuple[ExperimentManifest, StatisticsResult],
) -> None:
    experiment, statistics = report_inputs
    with pytest.raises(SchemaError):
        build_aggregate_report(
            experiment,
            statistics,
            visibility="private",
            decision=cast(Any, "maybe"),
            rationale="Synthetic rationale.",
            minimum_public_cell_size=2,
        )

    document = cast(dict[str, Any], _public_report(report_inputs).to_dict())
    document["decision"]["inputs"]["invalid_outputs"] = 99
    with pytest.raises(SchemaError, match="decision inputs"):
        AggregateReport.from_dict(_redigest(document))


@pytest.mark.parametrize(
    ("mutation", "message"),
    [
        ("eligibility", "eligibility counts"),
        ("terminal_counts", "terminal counts"),
        ("completeness", "completeness fields"),
        ("mode_order", "analysis modes"),
        ("primary_intervals", "record is invalid"),
        ("primary_complete", "primary completeness"),
        ("quality_order", "quality conditions"),
        ("quality_counts", "quality counts"),
        ("valid_output_counts", "valid-output counts"),
        ("stability", "stability cells"),
        ("operation_order", "operation conditions"),
        ("operation_distribution", "operation distribution"),
        ("cost", "cost completeness"),
        ("cost_fields", "cost fields"),
        ("rate", "rate counts"),
        ("difference", "difference counts"),
        ("paired_relationship", "paired metric relationships"),
        ("discordance", "discordance counts"),
        ("breakdown_order", "breakdown modes"),
        ("negative_operation", "record is invalid"),
        ("missing_breakdown_interval", "record is invalid"),
    ],
)
def test_redigested_cross_field_forgeries_fail_closed(
    report_inputs: tuple[ExperimentManifest, StatisticsResult],
    mutation: str,
    message: str,
) -> None:
    document = cast(dict[str, Any], _public_report(report_inputs).to_dict())
    if mutation == "eligibility":
        document["corpus"]["eligibility_counts"][0]["count"] = 3
    elif mutation == "terminal_counts":
        document["completeness"]["terminal_status_counts"]["succeeded"] = 15
    elif mutation == "completeness":
        document["completeness"]["successful_runs"] = 15
    elif mutation == "mode_order":
        document["metrics"]["modes"][0], document["metrics"]["modes"][1] = (
            document["metrics"]["modes"][1],
            document["metrics"]["modes"][0],
        )
    elif mutation == "primary_intervals":
        del document["metrics"]["modes"][0]["intervals"]["net_useful_lift"]
        del document["decision"]["inputs"]["intervals"]["net_useful_lift"]
    elif mutation == "primary_complete":
        document["completeness"]["primary_analysis_complete"] = False
    elif mutation == "quality_order":
        document["metrics"]["quality"].reverse()
    elif mutation == "quality_counts":
        document["metrics"]["quality"][0]["category"]["total"] = 9
    elif mutation == "valid_output_counts":
        document["metrics"]["quality"][0]["valid_output"]["correct"] = 15
        document["metrics"]["quality"][0]["valid_output"]["total"] = 15
        document["metrics"]["quality"][0]["valid_output"]["value"] = 1.0
    elif mutation == "stability":
        document["metrics"]["repetition_stability"][0]["complete_cases"] = 1
    elif mutation == "operation_order":
        document["operations"].reverse()
    elif mutation == "operation_distribution":
        document["operations"][0]["latency_ms"]["source"] = "provider_reported"
    elif mutation == "cost":
        document["cost"]["completed_runs"] = 15
    elif mutation == "cost_fields":
        document["cost"]["unknown_usage_or_price_runs"] = 1
    elif mutation == "rate":
        document["metrics"]["modes"][1]["rates"]["fixed_baseline"]["positive"] = 1
    elif mutation == "difference":
        document["metrics"]["modes"][1]["differences"]["vulnerable_lift"]["numerator"] = 1
    elif mutation == "paired_relationship":
        vulnerable = document["metrics"]["modes"][1]["differences"]["vulnerable_lift"]
        vulnerable["baseline_positive"] = 1
        vulnerable["numerator"] = 3
        vulnerable["value"] = 0.75
    elif mutation == "discordance":
        document["metrics"]["modes"][1]["discordance"]["fixed"]["total_pairs"] = 5
    elif mutation == "breakdown_order":
        document["metrics"]["exploratory_breakdowns"][0]["modes"].reverse()
    elif mutation == "negative_operation":
        distribution = document["operations"][0]["latency_ms"]
        observations = distribution["observations"]
        distribution.update(
            {
                "minimum": -1.0,
                "median": -1.0,
                "p95": -1.0,
                "maximum": -1.0,
                "mean": -1.0,
                "total": -float(observations),
            }
        )
    elif mutation == "missing_breakdown_interval":
        del document["metrics"]["exploratory_breakdowns"][0]["modes"][0]["intervals"][
            "net_useful_lift"
        ]
    else:  # pragma: no cover - parametrization is exhaustive
        raise AssertionError(mutation)

    with pytest.raises(SchemaError, match=message):
        AggregateReport.from_dict(_redigest(document))


def test_parser_and_renderer_refuse_nonobject_nonfinite_and_empty_breakdown_inputs(
    report_inputs: tuple[ExperimentManifest, StatisticsResult],
) -> None:
    with pytest.raises(SchemaError, match="JSON is invalid"):
        AggregateReport.from_bytes(b"{")
    with pytest.raises(SchemaError, match="must contain an object"):
        AggregateReport.from_bytes(b"[]")

    nonfinite = cast(dict[str, Any], _public_report(report_inputs).to_dict())
    nonfinite["cost"]["actual_cost_usd"] = float("nan")
    with pytest.raises(SchemaError, match="noncanonical value"):
        AggregateReport.from_dict(nonfinite)

    without_breakdowns = cast(dict[str, Any], _public_report(report_inputs).to_dict())
    without_breakdowns["metrics"]["exploratory_breakdowns"] = []
    report = AggregateReport.from_dict(_redigest(without_breakdowns))
    assert "No breakdown met the disclosure threshold." in render_markdown(report.canonical_bytes())
