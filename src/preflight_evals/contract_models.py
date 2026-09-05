"""Typed dispatch for every versioned contract."""

from __future__ import annotations

from collections.abc import Mapping
from pathlib import Path
from typing import Any, assert_never

from preflight_evals.adjudicate import AdjudicationPacket, DecisionBatch
from preflight_evals.attempt_metadata import AttemptMetadata
from preflight_evals.corpus_split import CorpusSplit
from preflight_evals.curator_models import CaseRecord, Catalog
from preflight_evals.m2_validation import M2AssessmentBatch
from preflight_evals.report import AggregateReport
from preflight_evals.reviewer_models import Finding, PromptManifest, ReviewerOutput
from preflight_evals.run_models import ExperimentManifest, RunRecord
from preflight_evals.schema import ContractName, load_contract_document
from preflight_evals.score import ScoringResult
from preflight_evals.scorer_models import AdjudicationRecord, GoldRecord, LeakagePolicy

type ContractModel = (
    CaseRecord
    | Catalog
    | GoldRecord
    | LeakagePolicy
    | Finding
    | ReviewerOutput
    | PromptManifest
    | RunRecord
    | AttemptMetadata
    | ExperimentManifest
    | AdjudicationRecord
    | AdjudicationPacket
    | DecisionBatch
    | ScoringResult
    | AggregateReport
    | M2AssessmentBatch
    | CorpusSplit
)


def parse_typed_contract(name: ContractName, document: Mapping[str, Any]) -> ContractModel:
    """Validate and convert one mapping to its immutable typed model."""

    if name == "case":
        return CaseRecord.from_dict(document)
    if name == "catalog":
        return Catalog.from_dict(document)
    if name == "gold":
        return GoldRecord.from_dict(document)
    if name == "leakage-policy":
        return LeakagePolicy.from_dict(document)
    if name == "finding":
        return Finding.from_dict(document)
    if name == "reviewer-output":
        return ReviewerOutput.from_dict(document)
    if name == "prompt-manifest":
        return PromptManifest.from_dict(document)
    if name == "run-record":
        return RunRecord.from_dict(document)
    if name == "attempt-metadata":
        return AttemptMetadata.from_dict(document)
    if name == "experiment":
        return ExperimentManifest.from_dict(document)
    if name == "adjudication":
        return AdjudicationRecord.from_dict(document)
    if name == "adjudication-packet":
        return AdjudicationPacket.from_dict(document)
    if name == "adjudication-decisions":
        return DecisionBatch.from_dict(document)
    if name == "score-result":
        return ScoringResult.from_dict(document)
    if name == "aggregate-report":
        return AggregateReport.from_dict(document)
    if name == "m2-finding-assessment":
        return M2AssessmentBatch.from_dict(document)
    if name == "corpus-split":
        return CorpusSplit.from_dict(document)
    assert_never(name)


def load_typed_contract(name: ContractName, path: Path) -> ContractModel:
    """Load one JSON/YAML contract through schema and typed-model boundaries."""

    return parse_typed_contract(name, load_contract_document(path))
