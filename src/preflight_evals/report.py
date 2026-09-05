"""Canonical aggregate reports and the public disclosure boundary."""

from __future__ import annotations

import json
import re
from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass
from typing import Any, Literal, cast

from preflight_evals.canonical import JsonValue, canonical_digest, canonical_json_bytes
from preflight_evals.discovery import build_mechanism_discovery
from preflight_evals.errors import PolicyError, SchemaError
from preflight_evals.run_models import ExperimentManifest
from preflight_evals.schema import validate_contract
from preflight_evals.score import ScoringResult
from preflight_evals.statistics import StatisticsResult

type ReportVisibility = Literal["private", "public"]
type DecisionValue = Literal["adopt", "revise", "reject", "insufficient evidence"]

_DECISIONS = frozenset({"adopt", "revise", "reject", "insufficient evidence"})
_STATUS_ORDER = (
    "succeeded",
    "invalid_output",
    "provider_error",
    "configuration_error",
    "adapter_error",
    "timeout",
)
_OPAQUE_RUN_ID = re.compile(r"run-[0-9a-f]{32}")
_REPORT_ID = re.compile(r"report-[0-9a-f]{32}")
_FULL_SHA = re.compile(r"(?<![0-9a-f])[0-9a-f]{40}(?![0-9a-f])")
_CASE_ID = re.compile(r"\b[a-z0-9]+(?:-[a-z0-9]+)*-pr[0-9]+-f[0-9]+\b")
_REPOSITORY_PATH = re.compile(
    r"(?<![:/])(?:^|[\s`'\"(])(?:\.?\.?/|(?:src|tests|docs|config|cases|prompts|schemas|"
    r"artifacts|reports|\.github)/)[^\s`'\"),;]+"
)
_GENERIC_PATH = re.compile(
    r"(?<![:/])(?:^|[\s`'\"(])(?:[A-Za-z0-9_.-]+/)+[A-Za-z0-9_.-]+"
    r"(?=$|[\s`'\"),;])"
)
_MEMBERSHIP_DISCLOSURE = re.compile(
    r"\bholdout\s+(?:case|cases|member|members|membership|assignment|assignments)\b",
    re.IGNORECASE,
)
_FORBIDDEN_PUBLIC_KEYS = frozenset(
    {
        "case_id",
        "case_ids",
        "commit",
        "commits",
        "finding",
        "findings",
        "href",
        "holdout_membership",
        "membership",
        "path",
        "paths",
        "prompt",
        "prompts",
        "pull_request",
        "raw_finding",
        "raw_findings",
        "run_id",
        "sha",
        "source_sha",
    }
)


@dataclass(frozen=True, slots=True)
class InvestigationLink:
    """Private-only link from one opaque frozen run ID to retained evidence."""

    run_id: str
    href: str


@dataclass(frozen=True, slots=True)
class AggregateReport:
    """Immutable canonical report validated through schema and semantic boundaries."""

    _canonical_bytes: bytes

    @property
    def schema_version(self) -> str:
        return cast(str, self.to_dict()["schema_version"])

    @classmethod
    def from_dict(cls, document: Mapping[str, Any]) -> AggregateReport:
        data = validate_contract("aggregate-report", dict(document))
        try:
            _validate_report_relationships(data)
            if data["visibility"] == "public":
                validate_public_report(data)
            canonical = canonical_json_bytes(cast(dict[str, JsonValue], data))
        except (TypeError, ValueError) as exc:
            raise SchemaError("aggregate report contains a noncanonical value") from exc
        return cls(canonical)

    @classmethod
    def from_bytes(cls, value: bytes) -> AggregateReport:
        try:
            document = json.loads(value)
        except (UnicodeError, json.JSONDecodeError) as exc:
            raise SchemaError("aggregate report JSON is invalid") from exc
        if not isinstance(document, Mapping):
            raise SchemaError("aggregate report JSON must contain an object")
        report = cls.from_dict(cast(Mapping[str, Any], document))
        if value != report.canonical_bytes():
            raise SchemaError("aggregate report JSON is not canonical")
        return report

    def to_dict(self) -> dict[str, JsonValue]:
        return cast(dict[str, JsonValue], json.loads(self._canonical_bytes))

    def canonical_bytes(self) -> bytes:
        return self._canonical_bytes


def build_aggregate_report(
    experiment: ExperimentManifest,
    statistics: StatisticsResult,
    *,
    visibility: ReportVisibility,
    decision: DecisionValue,
    rationale: str,
    minimum_public_cell_size: int,
    limitations: Sequence[str] = (),
    exclusions: Sequence[str] = (),
    protocol_deviations: Sequence[str] = (),
    investigation_links: Sequence[InvestigationLink] = (),
    issue_discovery: Mapping[str, JsonValue] | None = None,
    scoring_result: ScoringResult | None = None,
) -> AggregateReport:
    """Project frozen aggregate evidence into one content-addressed report."""

    experiment = ExperimentManifest.from_dict(experiment.to_dict())
    if (
        visibility not in {"private", "public"}
        or decision not in _DECISIONS
        or isinstance(minimum_public_cell_size, bool)
        or not 2 <= minimum_public_cell_size <= 1_000
        or experiment.content_digest is None
        or statistics.experiment_id != experiment.experiment_id
        or statistics.experiment_digest != experiment.content_digest
        or statistics.case_count != len(experiment.cases)
        or statistics.repetitions != experiment.repetitions
    ):
        raise SchemaError("aggregate report inputs do not match one frozen experiment")

    normalized_rationale = _narrative(rationale, field="decision rationale")
    normalized_limitations = _narratives(limitations, field="limitation")
    normalized_exclusions = _narratives(exclusions, field="exclusion")
    normalized_deviations = _narratives(protocol_deviations, field="protocol deviation")
    links = _investigation_links(experiment, investigation_links)
    if visibility == "public" and links:
        raise PolicyError("public aggregate reports cannot contain investigation links")
    if scoring_result is not None:
        planned_identities = {
            run.run_id: (run.case_id, run.snapshot, run.condition, run.repetition)
            for run in experiment.execution_order
        }
        scored_identities = {
            run.run_id: (run.case_id, run.snapshot, run.condition, run.repetition)
            for run in scoring_result.runs
        }
        if (
            scoring_result.schema_version != "2.0"
            or scoring_result.experiment_id != experiment.experiment_id
            or scoring_result.experiment_digest != experiment.content_digest
            or scoring_result.content_digest != statistics.score_result_digest
            or scored_identities != planned_identities
        ):
            raise SchemaError("mechanism discovery inputs do not match aggregate report inputs")

    status_counts = dict(statistics.terminal_status_counts)
    if set(status_counts) - set(_STATUS_ORDER) or any(
        isinstance(count, bool) or count < 0 for count in status_counts.values()
    ):
        raise SchemaError("aggregate report terminal status counts are invalid")
    ordered_status_counts = {status: status_counts.get(status, 0) for status in _STATUS_ORDER}
    completed_runs = sum(ordered_status_counts.values())
    cost = statistics.cost.to_dict()
    if (
        statistics.cost.completed_runs != completed_runs
        or statistics.cost.completed_runs + statistics.cost.unfinished_runs
        != experiment.planned_run_count
    ):
        raise SchemaError("aggregate report completeness does not match cost accounting")

    role_counts = [
        {"eligibility": role, "count": sum(case.role == role for case in experiment.cases)}
        for role in ("development", "holdout")
        if any(case.role == role for case in experiment.cases)
    ]
    modes = [mode.to_dict() for mode in statistics.modes]
    primary = next((mode for mode in statistics.modes if mode.mode == "primary"), None)
    if primary is None:
        raise SchemaError("aggregate report statistics omit the primary analysis")
    intervals = {name: interval.to_dict() for name, interval in primary.intervals}
    breakdowns = [
        breakdown.to_dict()
        for breakdown in statistics.exploratory_breakdowns
        if visibility == "private" or breakdown.case_count >= minimum_public_cell_size
    ]
    statistics_document = statistics.to_dict()
    prompt_digest = experiment.prompt_template.digest if experiment.prompt_template else None
    analysis_digest = experiment.analysis_plan.digest if experiment.analysis_plan else None
    adapter_digest = (
        experiment.adapter_capabilities.content_digest
        if experiment.adapter_capabilities is not None
        else None
    )
    reviewer_configuration_digest = canonical_digest(experiment.to_dict()["reviewer_config"])
    content: dict[str, JsonValue] = {
        "schema_version": "2.0" if scoring_result is not None else "1.0",
        "visibility": visibility,
        "minimum_public_cell_size": minimum_public_cell_size,
        "digests": {
            "experiment": experiment.content_digest,
            "statistics": canonical_digest(statistics_document),
            "score_result": statistics.score_result_digest,
            "case_manifest": experiment.case_manifest_checksum,
            "baseline_profile": experiment.baseline_profile.digest,
            "candidate_profile": experiment.candidate_profile.digest,
            "prompt_template": prompt_digest,
            "analysis_plan": analysis_digest,
            "reviewer_configuration": reviewer_configuration_digest,
            "adapter_capabilities": adapter_digest,
            "environment_lock": experiment.environment_lock_digest,
        },
        "corpus": {
            "eligible_cases": statistics.case_count,
            "eligibility_counts": cast(JsonValue, role_counts),
            "planned_runs": experiment.planned_run_count,
            "completed_runs": completed_runs,
            "repetitions": experiment.repetitions,
        },
        "protocol": {
            "snapshots": list(experiment.snapshot_set),
            "conditions": ["baseline", "candidate"],
            "paired_unit": "case",
            "invalid_output_policy": experiment.invalid_output_policy,
            "interval_method": statistics_document["interval_method"],
        },
        "completeness": {
            "all_planned_runs_terminal": (
                completed_runs == experiment.planned_run_count
                and statistics.cost.unfinished_runs == 0
            ),
            "primary_analysis_complete": primary.complete,
            "successful_runs": ordered_status_counts["succeeded"],
            "invalid_outputs": ordered_status_counts["invalid_output"],
            "other_failed_outputs": sum(
                count
                for status, count in ordered_status_counts.items()
                if status not in {"succeeded", "invalid_output"}
            ),
            "unfinished_runs": statistics.cost.unfinished_runs,
            "terminal_status_counts": cast(JsonValue, ordered_status_counts),
        },
        "metrics": {
            "modes": cast(JsonValue, modes),
            "quality": [item.to_dict() for item in statistics.quality],
            "repetition_stability": [item.to_dict() for item in statistics.repetition_stability],
            "exploratory_breakdowns": cast(JsonValue, breakdowns),
        },
        "operations": [item.to_dict() for item in statistics.operations],
        "cost": {key: value for key, value in cost.items() if key != "price_source"},
        "decision": {
            "value": decision,
            "rationale": normalized_rationale,
            "inputs": {
                "primary_analysis_complete": primary.complete,
                "vulnerable_lift": primary.vulnerable_lift.to_dict(),
                "fixed_false_positive_increase": (primary.fixed_false_positive_increase.to_dict()),
                "net_useful_lift": primary.net_useful_lift.to_dict(),
                "intervals": cast(JsonValue, intervals),
                "invalid_outputs": ordered_status_counts["invalid_output"],
                "actual_cost_known": statistics.cost.actual_cost_usd is not None,
            },
        },
        "limitations": list(normalized_limitations),
        "exclusions": list(normalized_exclusions),
        "protocol_deviations": list(normalized_deviations),
        "investigation_links": [{"run_id": link.run_id, "href": link.href} for link in links],
    }
    if issue_discovery is not None:
        content["issue_discovery"] = dict(issue_discovery)
    if scoring_result is not None:
        content["mechanism_discovery"] = build_mechanism_discovery(scoring_result)
    digest = canonical_digest(content)
    content["report_id"] = f"report-{digest.removeprefix('sha256:')[:32]}"
    content["content_digest"] = digest
    return AggregateReport.from_dict(cast(dict[str, Any], content))


def validate_public_report(document: Mapping[str, Any]) -> None:
    """Reject sensitive fields, values, links, and undersized public cells."""

    if document.get("visibility") != "public":
        raise PolicyError("public disclosure validation requires public report mode")
    threshold = document.get("minimum_public_cell_size")
    if isinstance(threshold, bool) or not isinstance(threshold, int) or not 2 <= threshold <= 1_000:
        raise PolicyError("public aggregate report disclosure threshold is invalid")
    corpus = _mapping(document.get("corpus"), field="public corpus")
    if _integer(corpus.get("eligible_cases"), field="eligible cases") < threshold:
        raise PolicyError("public aggregate report contains an undersized overall cell")
    for item in _sequence(corpus.get("eligibility_counts"), field="eligibility counts"):
        count = _integer(_mapping(item, field="eligibility count").get("count"), field="count")
        if count < threshold:
            raise PolicyError("public aggregate report contains an undersized eligibility cell")
    metrics = _mapping(document.get("metrics"), field="public metrics")
    for item in _sequence(metrics.get("exploratory_breakdowns"), field="exploratory breakdowns"):
        count = _integer(_mapping(item, field="breakdown").get("case_count"), field="count")
        if count < threshold:
            raise PolicyError("public aggregate report contains an undersized breakdown cell")
    if "mechanism_discovery" in document:
        discovery = _mapping(document["mechanism_discovery"], field="mechanism discovery")
        for item in _sequence(discovery["cells"], field="mechanism discovery cells"):
            cell = _mapping(item, field="mechanism discovery cell")
            if _integer(cell["case_count"], field="case count") < threshold:
                raise PolicyError("public aggregate report contains an undersized discovery cell")
    if _sequence(document.get("investigation_links"), field="investigation links"):
        raise PolicyError("public aggregate report contains private investigation links")
    _scan_public_value(document)


def render_markdown(canonical_report_json: bytes) -> str:
    """Render deterministic Markdown exclusively from canonical aggregate JSON."""

    report = AggregateReport.from_bytes(canonical_report_json)
    document = report.to_dict()
    corpus = _mapping(document["corpus"], field="corpus")
    protocol = _mapping(document["protocol"], field="protocol")
    completeness = _mapping(document["completeness"], field="completeness")
    metrics = _mapping(document["metrics"], field="metrics")
    decision = _mapping(document["decision"], field="decision")
    cost = _mapping(document["cost"], field="cost")
    modes = [_mapping(item, field="mode") for item in _sequence(metrics["modes"], field="modes")]
    primary = next(item for item in modes if item["mode"] == "primary")
    differences = _mapping(primary["differences"], field="differences")
    intervals = _mapping(primary["intervals"], field="intervals")
    operations = [
        _mapping(item, field="operations")
        for item in _sequence(document["operations"], field="operations")
    ]
    all_operations = next(item for item in operations if item["condition"] == "all")

    lines = [
        "# Aggregate evaluation report",
        "",
        "## Decision",
        "",
        f"**{_decision_label(cast(str, decision['value']))}.** "
        f"{_markdown_text(cast(str, decision['rationale']))}",
        "",
        "## Corpus and protocol",
        "",
        f"- Eligible cases: {corpus['eligible_cases']}",
        f"- Planned runs: {corpus['planned_runs']}",
        f"- Completed runs: {corpus['completed_runs']}",
        f"- Repetitions per cell: {corpus['repetitions']}",
        f"- Snapshots: {', '.join(cast(list[str], protocol['snapshots']))}",
        f"- Conditions: {', '.join(cast(list[str], protocol['conditions']))}",
        f"- Primary paired unit: {protocol['paired_unit']}",
        f"- Invalid-output policy: {protocol['invalid_output_policy']}",
        "",
        "## Paired results",
        "",
        "| Metric | Exact difference | 95% interval |",
        "| --- | ---: | ---: |",
    ]
    for key, label in (
        ("vulnerable_lift", "Vulnerable lift"),
        ("fixed_false_positive_increase", "Fixed false-positive increase"),
        ("net_useful_lift", "Net useful lift"),
    ):
        difference = _mapping(differences[key], field=key)
        interval = _mapping(intervals[key], field=key)
        lines.append(
            f"| {label} | {_number(difference['value'])} "
            f"({difference['numerator']}/{difference['denominator']}) | "
            f"{_interval(interval)} |"
        )

    if "mechanism_discovery" in document:
        discovery = _mapping(document["mechanism_discovery"], field="mechanism discovery")
        lines.extend(
            [
                "",
                "## Supplemental mechanism discovery",
                "",
                "These supplemental metrics are exploratory and do not change the primary "
                "paired decision.",
                "",
                "- Precision unit: nonduplicate finding per run",
                "- Recall unit: condition/snapshot/case/mechanism, with repetitions collapsed",
                f"- Finding precision: {_number(discovery['precision'])} "
                f"({discovery['true_positive_findings']}/{discovery['precision_denominator']})",
                f"- Mechanism recall: {_number(discovery['recall'])} "
                f"({discovery['detected_present_units']}/{discovery['recall_denominator']})",
                f"- F1: {_number(discovery['f1'])}",
                "- Expected-mechanism coverage: "
                f"{_number(discovery['expected_mechanism_coverage'])} "
                f"({discovery['resolved_mechanism_units']}/"
                f"{discovery['verified_mechanism_units']})",
                f"- Unresolved mechanism units: {discovery['unresolved_mechanism_units']}",
                f"- Unverified mechanism units excluded: {discovery['unverified_mechanism_units']}",
                "",
                "| Condition | Snapshot | Cases | Finding TP / FP / unresolved | "
                "Mechanism detected / missed / unresolved / unverified | Precision | Recall | "
                "F1 | Coverage |",
                "| --- | --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: |",
            ]
        )
        for value in _sequence(discovery["cells"], field="mechanism discovery cells"):
            cell = _mapping(value, field="mechanism discovery cell")
            lines.append(
                f"| {cell['condition']} | {cell['snapshot']} | {cell['case_count']} | "
                f"{cell['true_positive_findings']} / {cell['false_positive_findings']} / "
                f"{cell['unresolved_findings']} | {cell['detected_present_units']} / "
                f"{cell['missed_present_units']} / {cell['unresolved_mechanism_units']} / "
                f"{cell['unverified_mechanism_units']} | {_number(cell['precision'])} | "
                f"{_number(cell['recall'])} | {_number(cell['f1'])} | "
                f"{_number(cell['expected_mechanism_coverage'])} |"
            )

    lines.extend(
        [
            "",
            "## Fixed-control impact",
            "",
            _fixed_control_summary(differences, intervals),
            "",
            "## Completeness and stability",
            "",
            f"- All planned runs terminal: {_yes_no(completeness['all_planned_runs_terminal'])}",
            f"- Primary analysis complete: {_yes_no(completeness['primary_analysis_complete'])}",
            f"- Invalid outputs: {completeness['invalid_outputs']}",
            f"- Other failed outputs: {completeness['other_failed_outputs']}",
            "",
            "| Snapshot | Condition | Complete cases | Unresolved cases | "
            "Discordant cases | Mean within-case variance |",
            "| --- | --- | ---: | ---: | ---: | ---: |",
        ]
    )
    for item in _sequence(metrics["repetition_stability"], field="stability"):
        stability = _mapping(item, field="stability")
        lines.append(
            f"| {stability['snapshot']} | {stability['condition']} | "
            f"{stability['complete_cases']} | {stability['unresolved_cases']} | "
            f"{stability['discordant_cases']} | "
            f"{_number(stability['mean_within_case_variance'])} |"
        )

    latency = _mapping(all_operations["latency_ms"], field="latency")
    input_tokens = _mapping(all_operations["provider_input_tokens"], field="input tokens")
    output_tokens = _mapping(all_operations["provider_output_tokens"], field="output tokens")
    estimated_input_tokens = _mapping(
        all_operations["tokenizer_estimated_input_tokens"], field="estimated input tokens"
    )
    lines.extend(
        [
            "",
            "## Operations and cost",
            "",
            f"- Latency median / p95 (ms): {_number(latency['median'])} / "
            f"{_number(latency['p95'])}",
            f"- Provider input tokens: {_number(input_tokens['total'])}",
            f"- Provider output tokens: {_number(output_tokens['total'])}",
            f"- Tokenizer-estimated input tokens: {_number(estimated_input_tokens['total'])}",
            f"- Actual cost: {_money_or_unknown(cost['actual_cost_usd'])}",
            f"- Projected total cost: {_money_or_unknown(cost['projected_total_cost_usd'])}",
            f"- Frozen worst-case budget: {_money_or_unknown(cost['frozen_worst_case_cost_usd'])}",
            f"- Price table: {_markdown_text(cast(str, cost['price_table_version']))} "
            f"(effective {cost['price_effective_date']})",
            "",
            "## Aggregate breakdowns",
            "",
        ]
    )
    breakdowns = _sequence(metrics["exploratory_breakdowns"], field="breakdowns")
    if breakdowns:
        lines.extend(
            [
                "| Dimension | Value | Cases | Vulnerable lift | Fixed false-positive increase |",
                "| --- | --- | ---: | ---: | ---: |",
            ]
        )
        for item in breakdowns:
            breakdown = _mapping(item, field="breakdown")
            breakdown_modes = [
                _mapping(mode, field="breakdown mode")
                for mode in _sequence(breakdown["modes"], field="breakdown modes")
            ]
            breakdown_primary = next(mode for mode in breakdown_modes if mode["mode"] == "primary")
            breakdown_differences = _mapping(
                breakdown_primary["differences"], field="breakdown differences"
            )
            vulnerable = _mapping(breakdown_differences["vulnerable_lift"], field="vulnerable lift")
            fixed = _mapping(
                breakdown_differences["fixed_false_positive_increase"], field="fixed impact"
            )
            lines.append(
                f"| {_markdown_text(cast(str, breakdown['dimension']))} | "
                f"{_markdown_text(cast(str, breakdown['value']))} | {breakdown['case_count']} | "
                f"{_number(vulnerable['value'])} | {_number(fixed['value'])} |"
            )
    else:
        lines.append("No breakdown met the disclosure threshold.")

    if "issue_discovery" in document:
        discovery = _mapping(document["issue_discovery"], field="issue discovery")
        lines.extend(
            [
                "",
                "## Exploratory valid-issue discovery",
                "",
                f"- Model finding instances reviewed: {discovery['total_findings']}",
                f"- Valid finding instances: {discovery['valid_finding_instances']}",
                f"- Deduplicated valid issues: {discovery['unique_valid_issues']}",
                f"- Known-issue matches: {discovery['known_issue_instances']}",
                "- Additional valid issue instances: "
                f"{discovery['additional_valid_issue_instances']}",
                "- Deduplicated additional valid issues: "
                f"{discovery['unique_additional_valid_issues']}",
                f"- False-positive findings: {discovery['false_positive_findings']}",
                "- Repaired-mechanism false positives: "
                f"{discovery['repaired_mechanism_false_positives']}",
                f"- Other false-positive findings: {discovery['other_false_positive_findings']}",
                "- Valid code issue instances / unique: "
                f"{discovery['valid_code_issue_instances']} / "
                f"{discovery['unique_valid_code_issues']}",
                "- Valid documentation issue instances / unique: "
                f"{discovery['valid_documentation_issue_instances']} / "
                f"{discovery['unique_valid_documentation_issues']}",
                "- Code / documentation false positives: "
                f"{discovery['code_false_positive_findings']} / "
                f"{discovery['documentation_false_positive_findings']}",
                f"- Uncertain findings: {discovery['uncertain_findings']}",
                f"- Resolved finding precision: {_number(discovery['resolved_precision'])}",
                f"- False-positive rate: {_number(discovery['false_positive_rate'])}",
                "",
                "| Condition | Snapshot | Findings | Valid instances | Unique valid issues | "
                "Additional valid | False positives | Precision |",
                "| --- | --- | ---: | ---: | ---: | ---: | ---: | ---: |",
            ]
        )
        for value in _sequence(discovery["cells"], field="issue discovery cells"):
            cell = _mapping(value, field="issue discovery cell")
            lines.append(
                f"| {cell['condition']} | {cell['snapshot']} | {cell['total_findings']} | "
                f"{cell['valid_finding_instances']} | {cell['unique_valid_issues']} | "
                f"{cell['additional_valid_issue_instances']} | "
                f"{cell['false_positive_findings']} | "
                f"{_number(cell['resolved_precision'])} |"
            )

    _append_narrative_section(lines, "Limitations", document["limitations"])
    _append_narrative_section(lines, "Exclusions", document["exclusions"])
    _append_narrative_section(lines, "Protocol deviations", document["protocol_deviations"])
    links = _sequence(document["investigation_links"], field="investigation links")
    if links:
        lines.extend(["", "## Private investigation links", ""])
        for item in links:
            link = _mapping(item, field="investigation link")
            lines.append(f"- [{link['run_id']}]({link['href']})")
    lines.extend(["", f"Report digest: `{document['content_digest']}`", ""])
    return "\n".join(lines)


def _validate_report_relationships(document: Mapping[str, Any]) -> None:
    content = dict(document)
    report_id = content.pop("report_id")
    digest = content.pop("content_digest")
    expected_digest = canonical_digest(cast(dict[str, JsonValue], content))
    if digest != expected_digest or report_id != f"report-{expected_digest[7:39]}":
        raise SchemaError("aggregate report identity does not match its content")
    if not isinstance(report_id, str) or _REPORT_ID.fullmatch(report_id) is None:
        raise SchemaError("aggregate report identity is invalid")
    corpus = _mapping(document["corpus"], field="corpus")
    counts = [
        _mapping(item, field="eligibility count")
        for item in _sequence(corpus["eligibility_counts"], field="eligibility counts")
    ]
    expected_roles = [
        role
        for role in ("development", "holdout")
        if role in {item["eligibility"] for item in counts}
    ]
    if [item["eligibility"] for item in counts] != expected_roles or sum(
        _integer(item["count"], field="count") for item in counts
    ) != corpus["eligible_cases"]:
        raise SchemaError("aggregate report eligibility counts do not match the corpus")
    completeness = _mapping(document["completeness"], field="completeness")
    statuses = _mapping(completeness["terminal_status_counts"], field="terminal statuses")
    if (
        set(statuses) != set(_STATUS_ORDER)
        or sum(cast(int, count) for count in statuses.values()) != corpus["completed_runs"]
    ):
        raise SchemaError("aggregate report terminal counts do not match completeness")
    if (
        completeness["successful_runs"] != statuses["succeeded"]
        or completeness["invalid_outputs"] != statuses["invalid_output"]
        or completeness["other_failed_outputs"]
        != sum(
            cast(int, count)
            for status, count in statuses.items()
            if status not in {"succeeded", "invalid_output"}
        )
        or corpus["completed_runs"] + completeness["unfinished_runs"] != corpus["planned_runs"]
        or completeness["all_planned_runs_terminal"] != (completeness["unfinished_runs"] == 0)
    ):
        raise SchemaError("aggregate report completeness fields are inconsistent")
    metrics = _mapping(document["metrics"], field="metrics")
    modes = [_mapping(item, field="mode") for item in _sequence(metrics["modes"], field="modes")]
    if [mode["mode"] for mode in modes] != ["primary", "pessimistic", "optimistic"]:
        raise SchemaError("aggregate report analysis modes are incomplete or unordered")
    primary = modes[0]
    if set(_mapping(primary["intervals"], field="primary intervals")) != {
        "vulnerable_lift",
        "fixed_false_positive_increase",
        "net_useful_lift",
    }:
        raise SchemaError("aggregate report primary intervals are incomplete")
    if completeness["primary_analysis_complete"] != primary["complete"]:
        raise SchemaError("aggregate report primary completeness is inconsistent")
    _validate_metric_relationships(modes)
    quality = [
        _mapping(item, field="quality") for item in _sequence(metrics["quality"], field="quality")
    ]
    if [item["condition"] for item in quality] != ["all", "baseline", "candidate"]:
        raise SchemaError("aggregate report quality conditions are incomplete or unordered")
    for item in quality:
        for field in ("valid_output", "acceptable_path", "category", "mechanism", "severity"):
            _validate_accuracy(_mapping(item[field], field="quality counts"))
    if (
        quality[0]["valid_output"]["total"] != corpus["completed_runs"]
        or quality[1]["valid_output"]["total"] * 2 != corpus["completed_runs"]
        or quality[2]["valid_output"]["total"] * 2 != corpus["completed_runs"]
    ):
        raise SchemaError("aggregate report valid-output counts do not match completeness")
    stability = [
        _mapping(item, field="stability")
        for item in _sequence(metrics["repetition_stability"], field="stability")
    ]
    expected_cells = [
        ("vulnerable", "baseline"),
        ("vulnerable", "candidate"),
        ("fixed", "baseline"),
        ("fixed", "candidate"),
    ]
    if (
        [(item["snapshot"], item["condition"]) for item in stability] != expected_cells
        or any(item["case_count"] != corpus["eligible_cases"] for item in stability)
        or any(item["repetitions"] != corpus["repetitions"] for item in stability)
        or any(
            item["complete_cases"] + item["unresolved_cases"] != item["case_count"]
            for item in stability
        )
    ):
        raise SchemaError("aggregate report stability cells are inconsistent")
    operations = [
        _mapping(item, field="operations")
        for item in _sequence(document["operations"], field="operations")
    ]
    if [item["condition"] for item in operations] != ["all", "baseline", "candidate"]:
        raise SchemaError("aggregate report operation conditions are incomplete or unordered")
    _validate_operations(operations, completed_runs=cast(int, corpus["completed_runs"]))
    cost = _mapping(document["cost"], field="cost")
    if (
        cost["completed_runs"] != corpus["completed_runs"]
        or cost["unfinished_runs"] != completeness["unfinished_runs"]
    ):
        raise SchemaError("aggregate report cost completeness is inconsistent")
    _validate_cost(cost)
    decision = _mapping(document["decision"], field="decision")
    inputs = _mapping(decision["inputs"], field="decision inputs")
    differences = _mapping(primary["differences"], field="primary differences")
    if (
        inputs["primary_analysis_complete"] != primary["complete"]
        or inputs["vulnerable_lift"] != differences["vulnerable_lift"]
        or inputs["fixed_false_positive_increase"] != differences["fixed_false_positive_increase"]
        or inputs["net_useful_lift"] != differences["net_useful_lift"]
        or inputs["intervals"] != primary["intervals"]
        or inputs["invalid_outputs"] != completeness["invalid_outputs"]
        or inputs["actual_cost_known"] != (cost["actual_cost_usd"] is not None)
    ):
        raise SchemaError("aggregate report decision inputs do not match aggregate evidence")
    for breakdown in _sequence(metrics["exploratory_breakdowns"], field="breakdowns"):
        item = _mapping(breakdown, field="breakdown")
        breakdown_modes = [
            _mapping(mode, field="breakdown mode")["mode"]
            for mode in _sequence(item["modes"], field="breakdown modes")
        ]
        if breakdown_modes != ["primary", "pessimistic", "optimistic"]:
            raise SchemaError("aggregate report breakdown modes are incomplete or unordered")
        _validate_metric_relationships(
            [
                _mapping(mode, field="breakdown mode")
                for mode in _sequence(item["modes"], field="breakdown modes")
            ]
        )
    if "issue_discovery" in document:
        _validate_issue_discovery(_mapping(document["issue_discovery"], field="issue discovery"))
    if document["schema_version"] == "2.0":
        _validate_mechanism_discovery(
            _mapping(document["mechanism_discovery"], field="mechanism discovery"),
            expected_case_count=cast(int, corpus["eligible_cases"]),
        )


_MECHANISM_COUNT_FIELDS = (
    "finding_instances",
    "duplicate_findings_excluded",
    "unverified_findings_excluded",
    "unrelated_findings_excluded",
    "true_positive_findings",
    "false_positive_findings",
    "unresolved_findings",
    "precision_denominator",
    "verified_mechanism_units",
    "resolved_mechanism_units",
    "unresolved_mechanism_units",
    "unverified_mechanism_units",
    "expected_present_units",
    "detected_present_units",
    "missed_present_units",
    "recall_denominator",
    "expected_absent_units",
    "unexpected_claim_units",
    "clear_absence_units",
)


def _validate_mechanism_discovery(
    discovery: Mapping[str, Any], *, expected_case_count: int
) -> None:
    cells = [
        _mapping(item, field="mechanism discovery cell")
        for item in _sequence(discovery["cells"], field="mechanism discovery cells")
    ]
    expected_cells = [
        ("baseline", "vulnerable"),
        ("baseline", "fixed"),
        ("candidate", "vulnerable"),
        ("candidate", "fixed"),
    ]
    if (
        [(item["condition"], item["snapshot"]) for item in cells] != expected_cells
        or discovery["case_count"] != expected_case_count
        or any(item["case_count"] != expected_case_count for item in cells)
    ):
        raise SchemaError("aggregate report mechanism-discovery cells are incomplete or unordered")
    for item in [discovery, *cells]:
        _validate_mechanism_counts(item)
    for field in _MECHANISM_COUNT_FIELDS:
        if discovery[field] != sum(cast(int, item[field]) for item in cells):
            raise SchemaError("aggregate report mechanism-discovery totals do not match its cells")


def _validate_mechanism_counts(value: Mapping[str, Any]) -> None:
    finding_instances = _integer(value["finding_instances"], field="finding instances")
    true_positive = _integer(value["true_positive_findings"], field="true positives")
    false_positive = _integer(value["false_positive_findings"], field="false positives")
    unresolved_findings = _integer(value["unresolved_findings"], field="unresolved findings")
    unverified_findings = _integer(
        value["unverified_findings_excluded"], field="unverified findings"
    )
    unrelated_findings = _integer(value["unrelated_findings_excluded"], field="unrelated findings")
    precision_denominator = true_positive + false_positive
    expected_precision = true_positive / precision_denominator if precision_denominator else None
    detected = _integer(value["detected_present_units"], field="detected units")
    missed = _integer(value["missed_present_units"], field="missed units")
    recall_denominator = detected + missed
    expected_recall = detected / recall_denominator if recall_denominator else None
    expected_f1 = (
        2 * expected_precision * expected_recall / (expected_precision + expected_recall)
        if expected_precision is not None
        and expected_recall is not None
        and expected_precision + expected_recall
        else 0.0
        if expected_precision == 0.0 and expected_recall == 0.0
        else None
    )
    verified = _integer(value["verified_mechanism_units"], field="verified units")
    resolved = _integer(value["resolved_mechanism_units"], field="resolved units")
    unresolved = _integer(value["unresolved_mechanism_units"], field="unresolved units")
    present = _integer(value["expected_present_units"], field="present units")
    absent = _integer(value["expected_absent_units"], field="absent units")
    unexpected = _integer(value["unexpected_claim_units"], field="unexpected claims")
    clear_absence = _integer(value["clear_absence_units"], field="clear absences")
    expected_coverage = resolved / verified if verified else None
    if (
        finding_instances
        != true_positive
        + false_positive
        + unresolved_findings
        + unverified_findings
        + unrelated_findings
        or value["precision_denominator"] != precision_denominator
        or value["precision"] != expected_precision
        or value["recall_denominator"] != recall_denominator
        or value["recall"] != expected_recall
        or value["f1"] != expected_f1
        or verified != resolved + unresolved
        or resolved != present + absent
        or present != detected + missed
        or absent != unexpected + clear_absence
        or value["expected_mechanism_coverage"] != expected_coverage
    ):
        raise SchemaError("aggregate report mechanism-discovery counts are inconsistent")


def _validate_issue_discovery(discovery: Mapping[str, Any]) -> None:
    cells = [
        _mapping(item, field="issue discovery cell")
        for item in _sequence(discovery["cells"], field="issue discovery cells")
    ]
    expected_cells = [
        ("baseline", "vulnerable"),
        ("baseline", "fixed"),
        ("candidate", "vulnerable"),
        ("candidate", "fixed"),
    ]
    if [(item["condition"], item["snapshot"]) for item in cells] != expected_cells:
        raise SchemaError("aggregate report issue-discovery cells are incomplete or unordered")
    _validate_discovery_counts(discovery)
    for item in cells:
        _validate_discovery_counts(item)
    for field in (
        "total_findings",
        "valid_finding_instances",
        "known_issue_instances",
        "additional_valid_issue_instances",
        "false_positive_findings",
        "repaired_mechanism_false_positives",
        "other_false_positive_findings",
        "code_finding_instances",
        "documentation_finding_instances",
        "valid_code_issue_instances",
        "valid_documentation_issue_instances",
        "code_false_positive_findings",
        "documentation_false_positive_findings",
        "uncertain_findings",
    ):
        if discovery[field] != sum(cast(int, item[field]) for item in cells):
            raise SchemaError("aggregate report issue-discovery totals do not match its cells")


def _validate_discovery_counts(value: Mapping[str, Any]) -> None:
    total = _integer(value["total_findings"], field="discovery total findings")
    valid = _integer(value["valid_finding_instances"], field="discovery valid findings")
    known = _integer(value["known_issue_instances"], field="discovery known findings")
    additional = _integer(
        value["additional_valid_issue_instances"], field="discovery additional findings"
    )
    false_positives = _integer(
        value["false_positive_findings"], field="discovery false-positive findings"
    )
    repaired_false_positives = _integer(
        value["repaired_mechanism_false_positives"],
        field="discovery repaired-mechanism false positives",
    )
    other_false_positives = _integer(
        value["other_false_positive_findings"], field="discovery other false positives"
    )
    uncertain = _integer(value["uncertain_findings"], field="discovery uncertain findings")
    unique_valid = _integer(value["unique_valid_issues"], field="discovery unique issues")
    unique_known = _integer(value["unique_known_issues"], field="discovery unique known issues")
    unique_additional = _integer(
        value["unique_additional_valid_issues"], field="discovery unique additional issues"
    )
    code_findings = _integer(value["code_finding_instances"], field="discovery code findings")
    documentation_findings = _integer(
        value["documentation_finding_instances"], field="discovery documentation findings"
    )
    valid_code = _integer(value["valid_code_issue_instances"], field="discovery valid code issues")
    unique_valid_code = _integer(
        value["unique_valid_code_issues"], field="discovery unique valid code issues"
    )
    valid_documentation = _integer(
        value["valid_documentation_issue_instances"],
        field="discovery valid documentation issues",
    )
    unique_valid_documentation = _integer(
        value["unique_valid_documentation_issues"],
        field="discovery unique valid documentation issues",
    )
    code_false_positives = _integer(
        value["code_false_positive_findings"], field="discovery code false positives"
    )
    documentation_false_positives = _integer(
        value["documentation_false_positive_findings"],
        field="discovery documentation false positives",
    )
    resolved = total - uncertain
    expected_precision = valid / resolved if resolved else None
    expected_false_positive_rate = false_positives / resolved if resolved else None
    if (
        valid != known + additional
        or total != valid + false_positives + uncertain
        or false_positives != repaired_false_positives + other_false_positives
        or total != code_findings + documentation_findings + uncertain
        or valid != valid_code + valid_documentation
        or unique_valid != unique_valid_code + unique_valid_documentation
        or false_positives != code_false_positives + documentation_false_positives
        or unique_valid != unique_known + unique_additional
        or unique_known > known
        or unique_additional > additional
        or value["resolved_precision"] != expected_precision
        or value["false_positive_rate"] != expected_false_positive_rate
    ):
        raise SchemaError("aggregate report issue-discovery counts are inconsistent")


def _validate_metric_relationships(modes: Sequence[Mapping[str, Any]]) -> None:
    for mode in modes:
        rates = _mapping(mode["rates"], field="rates")
        for rate in rates.values():
            counts = _mapping(rate, field="rate")
            total = counts["positive"] + counts["negative"] + counts["unresolved"]
            expected_value = (
                counts["positive"] / counts["total"]
                if counts["total"] and not counts["unresolved"]
                else None
            )
            if counts["total"] != total or counts["value"] != expected_value:
                raise SchemaError("aggregate report rate counts are inconsistent")
        differences = _mapping(mode["differences"], field="differences")
        for difference in differences.values():
            item = _mapping(difference, field="difference")
            expected_value = (
                item["numerator"] / item["denominator"]
                if item["denominator"] and not item["unresolved"]
                else None
            )
            if (
                item["numerator"] != item["candidate_positive"] - item["baseline_positive"]
                or item["value"] != expected_value
            ):
                raise SchemaError("aggregate report difference counts are inconsistent")
        vulnerable = _mapping(differences["vulnerable_lift"], field="vulnerable lift")
        fixed = _mapping(differences["fixed_false_positive_increase"], field="fixed increase")
        net = _mapping(differences["net_useful_lift"], field="net useful lift")
        if (
            vulnerable["baseline_positive"] != rates["vulnerable_baseline"]["positive"]
            or vulnerable["candidate_positive"] != rates["vulnerable_candidate"]["positive"]
            or vulnerable["denominator"] != rates["vulnerable_baseline"]["total"]
            or fixed["baseline_positive"] != rates["fixed_baseline"]["positive"]
            or fixed["candidate_positive"] != rates["fixed_candidate"]["positive"]
            or fixed["denominator"] != rates["fixed_baseline"]["total"]
            or net["candidate_positive"]
            != rates["vulnerable_candidate"]["positive"] + rates["fixed_baseline"]["positive"]
            or net["baseline_positive"]
            != rates["vulnerable_baseline"]["positive"] + rates["fixed_candidate"]["positive"]
            or net["numerator"] != vulnerable["numerator"] - fixed["numerator"]
            or net["denominator"] != vulnerable["denominator"]
            or net["unresolved"] != vulnerable["unresolved"] + fixed["unresolved"]
            or mode["complete"]
            != all(_mapping(rate, field="rate")["unresolved"] == 0 for rate in rates.values())
        ):
            raise SchemaError("aggregate report paired metric relationships are inconsistent")
        for discordance in _mapping(mode["discordance"], field="discordance").values():
            item = _mapping(discordance, field="discordance cell")
            total = sum(
                item[field]
                for field in (
                    "both_positive",
                    "candidate_only",
                    "baseline_only",
                    "both_negative",
                    "unresolved",
                )
            )
            if item["total_pairs"] != total:
                raise SchemaError("aggregate report discordance counts are inconsistent")


def _validate_accuracy(item: Mapping[str, Any]) -> None:
    denominator = item["correct"] + item["incorrect"]
    expected_value = item["correct"] / denominator if denominator else None
    if item["total"] != denominator + item["unresolved"] or item["value"] != expected_value:
        raise SchemaError("aggregate report quality counts are inconsistent")


def _validate_operations(operations: Sequence[Mapping[str, Any]], *, completed_runs: int) -> None:
    expected_sources = {
        "latency_ms": "measured",
        "provider_input_tokens": "provider_reported",
        "provider_cached_input_tokens": "provider_reported",
        "provider_output_tokens": "provider_reported",
        "provider_reasoning_tokens": "provider_reported",
        "tokenizer_estimated_input_tokens": "tokenizer_estimate",
    }
    for operation in operations:
        expected = completed_runs if operation["condition"] == "all" else completed_runs // 2
        for field, source in expected_sources.items():
            distribution = _mapping(operation[field], field="operation distribution")
            observations = distribution["observations"]
            numeric = [
                distribution[name]
                for name in ("minimum", "median", "p95", "maximum", "mean", "total")
            ]
            if (
                distribution["source"] != source
                or observations + distribution["missing"] != expected
                or (observations == 0 and any(value is not None for value in numeric))
                or (observations > 0 and any(value is None for value in numeric))
                or any(value is not None and value < 0 for value in numeric)
                or (
                    observations > 0
                    and not (
                        distribution["minimum"]
                        <= distribution["median"]
                        <= distribution["p95"]
                        <= distribution["maximum"]
                    )
                )
                or (
                    observations > 0
                    and distribution["mean"] != distribution["total"] / observations
                )
            ):
                raise SchemaError("aggregate report operation distribution is inconsistent")


def _validate_cost(cost: Mapping[str, Any]) -> None:
    amounts = [
        cost[field]
        for field in (
            "known_terminal_cost_usd",
            "actual_cost_usd",
            "projected_remaining_cost_usd",
            "projected_total_cost_usd",
            "frozen_worst_case_cost_usd",
        )
    ]
    expected_total = (
        cost["actual_cost_usd"] + cost["projected_remaining_cost_usd"]
        if cost["actual_cost_usd"] is not None and cost["projected_remaining_cost_usd"] is not None
        else None
    )
    if (
        any(value is not None and value < 0 for value in amounts)
        or cost["provider_usage_runs"] > cost["completed_runs"]
        or cost["unknown_usage_or_price_runs"] > cost["completed_runs"]
        or (cost["actual_cost_usd"] is not None)
        != (cost["unknown_usage_or_price_runs"] == 0 and cost["unaccounted_retry_attempts"] == 0)
        or (
            cost["actual_cost_usd"] is not None
            and cost["actual_cost_usd"] != cost["known_terminal_cost_usd"]
        )
        or cost["projected_total_cost_usd"] != expected_total
    ):
        raise SchemaError("aggregate report cost fields are inconsistent")


def _scan_public_value(value: object, location: tuple[str, ...] = ()) -> None:
    if isinstance(value, Mapping):
        for key, item in value.items():
            if not isinstance(key, str) or key.lower() in _FORBIDDEN_PUBLIC_KEYS:
                raise PolicyError("public aggregate report contains a sensitive field")
            _scan_public_value(item, (*location, key))
    elif isinstance(value, Sequence) and not isinstance(value, str | bytes | bytearray):
        for item in value:
            _scan_public_value(item, location)
    elif isinstance(value, str) and (
        _FULL_SHA.search(value)
        or _CASE_ID.search(value)
        or _REPOSITORY_PATH.search(value)
        or _MEMBERSHIP_DISCLOSURE.search(value)
        or (location[-1:] not in {("model",), ("provider",)} and _GENERIC_PATH.search(value))
    ):
        raise PolicyError("public aggregate report contains a sensitive value")


def _investigation_links(
    experiment: ExperimentManifest, links: Sequence[InvestigationLink]
) -> tuple[InvestigationLink, ...]:
    planned = {run.run_id for run in experiment.execution_order}
    unique: dict[str, InvestigationLink] = {}
    for link in links:
        if (
            not isinstance(link, InvestigationLink)
            or _OPAQUE_RUN_ID.fullmatch(link.run_id) is None
            or link.run_id not in planned
            or not link.href
            or len(link.href) > 2_000
            or any(ord(character) < 32 for character in link.href)
            or any(character in link.href for character in '\\[]()<>"')
            or link.run_id in unique
        ):
            raise SchemaError("aggregate report investigation link is invalid")
        unique[link.run_id] = link
    return tuple(unique[run_id] for run_id in sorted(unique))


def _narrative(value: str, *, field: str) -> str:
    if (
        not isinstance(value, str)
        or not value.strip()
        or value != value.strip()
        or len(value) > 2_000
        or any(ord(character) < 32 for character in value)
    ):
        raise SchemaError(f"aggregate report {field} is invalid")
    return value


def _narratives(values: Iterable[str], *, field: str) -> tuple[str, ...]:
    normalized = tuple(sorted({_narrative(value, field=field) for value in values}))
    if len(normalized) > 100:
        raise SchemaError(f"aggregate report {field} list is too large")
    return normalized


def _mapping(value: object, *, field: str) -> Mapping[str, Any]:
    if not isinstance(value, Mapping) or not all(isinstance(key, str) for key in value):
        raise SchemaError(f"aggregate report {field} is invalid")
    return cast(Mapping[str, Any], value)


def _sequence(value: object, *, field: str) -> Sequence[Any]:
    if not isinstance(value, Sequence) or isinstance(value, str | bytes | bytearray):
        raise SchemaError(f"aggregate report {field} is invalid")
    return value


def _integer(value: object, *, field: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        raise SchemaError(f"aggregate report {field} is invalid")
    return value


def _number(value: object) -> str:
    if value is None:
        return "Unknown"
    if isinstance(value, bool) or not isinstance(value, int | float):
        raise SchemaError("aggregate report numeric value is invalid")
    return str(value)


def _interval(interval: Mapping[str, Any]) -> str:
    if interval["lower"] is None or interval["upper"] is None:
        return "Unknown"
    return f"[{_number(interval['lower'])}, {_number(interval['upper'])}]"


def _fixed_control_summary(differences: Mapping[str, Any], intervals: Mapping[str, Any]) -> str:
    impact = _mapping(
        differences["fixed_false_positive_increase"], field="fixed false-positive increase"
    )
    interval = _mapping(
        intervals["fixed_false_positive_increase"], field="fixed false-positive interval"
    )
    return (
        "Candidate minus baseline fixed-control false positives: "
        f"{_number(impact['value'])} ({impact['numerator']}/{impact['denominator']}), "
        f"95% interval {_interval(interval)}."
    )


def _yes_no(value: object) -> str:
    if not isinstance(value, bool):
        raise SchemaError("aggregate report boolean value is invalid")
    return "yes" if value else "no"


def _money_or_unknown(value: object) -> str:
    if value is None:
        return "Unknown (usage or matching dated price is incomplete)"
    if isinstance(value, bool) or not isinstance(value, int | float):
        raise SchemaError("aggregate report cost is invalid")
    return f"${value:.6f}"


def _decision_label(value: str) -> str:
    labels = {
        "adopt": "Adopt",
        "revise": "Revise",
        "reject": "Reject",
        "insufficient evidence": "Insufficient evidence",
    }
    try:
        return labels[value]
    except KeyError as exc:
        raise SchemaError("aggregate report decision is unsupported") from exc


def _markdown_text(value: str) -> str:
    return re.sub(r"([\\`*_{}\[\]()<>#+.!|])", r"\\\1", value)


def _append_narrative_section(lines: list[str], title: str, value: object) -> None:
    lines.extend(["", f"## {title}", ""])
    items = _sequence(value, field=title.lower())
    if not items:
        lines.append("None recorded.")
        return
    lines.extend(f"- {_markdown_text(cast(str, item))}" for item in items)
