"""Disclosure-safe loading and validation for versioned contract documents."""

from __future__ import annotations

import json
from collections.abc import Mapping
from copy import deepcopy
from functools import cache
from importlib import resources
from importlib.resources.abc import Traversable
from pathlib import Path
from typing import Any, Literal, cast

import yaml
from jsonschema import FormatChecker, ValidationError, validators
from referencing import Registry, Resource

from preflight_evals.errors import SchemaError

type ContractName = Literal[
    "case",
    "catalog",
    "gold",
    "leakage-policy",
    "finding",
    "reviewer-output",
    "prompt-manifest",
    "run-record",
    "attempt-metadata",
    "experiment",
    "adjudication",
    "adjudication-packet",
    "adjudication-decisions",
    "score-result",
    "aggregate-report",
    "m2-finding-assessment",
    "corpus-split",
]

SCHEMA_VERSION = "1.0"
CONTRACT_NAMES: tuple[ContractName, ...] = (
    "case",
    "catalog",
    "gold",
    "leakage-policy",
    "finding",
    "reviewer-output",
    "prompt-manifest",
    "run-record",
    "attempt-metadata",
    "experiment",
    "adjudication",
    "adjudication-packet",
    "adjudication-decisions",
    "score-result",
    "aggregate-report",
    "m2-finding-assessment",
    "corpus-split",
)


def load_schema(path: Path) -> dict[str, Any]:
    """Load one JSON Schema object while keeping document content out of failures."""

    return _load_json_object(path, kind="schema")


def _load_json_object(path: Path | Traversable, *, kind: str) -> dict[str, Any]:
    try:
        with path.open("r", encoding="utf-8") as stream:
            document = json.load(stream)
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise SchemaError(f"could not load {kind} from {path.name!r}") from exc
    if not isinstance(document, dict):
        raise SchemaError(f"{kind} {path.name!r} must contain a JSON object")
    return cast(dict[str, Any], document)


def _schema_resource(name: ContractName) -> Path | Traversable:
    packaged = resources.files("preflight_evals").joinpath("schemas", f"{name}.schema.json")
    if packaged.is_file():
        return packaged
    repository_schema = Path(__file__).resolve().parents[2] / "schemas" / f"{name}.schema.json"
    if repository_schema.is_file():
        return repository_schema
    raise SchemaError(f"contract schema {name!r} is unavailable")


@cache
def _cached_contract_schema(name: ContractName) -> dict[str, Any]:
    """Load and meta-validate one bundled contract schema for internal use."""

    schema = _load_json_object(_schema_resource(name), kind="schema")
    try:
        validator_type = validators.validator_for(schema)
        validator_type.check_schema(schema)
    except Exception as exc:  # jsonschema exposes validator-specific schema errors
        raise SchemaError(f"contract schema {name!r} is invalid") from exc
    return schema


def load_contract_schema(name: ContractName) -> dict[str, Any]:
    """Return an isolated copy of one bundled, meta-validated contract schema."""

    return deepcopy(_cached_contract_schema(name))


@cache
def _contract_registry() -> Registry[Any]:
    registry: Registry[Any] = Registry()
    for name in CONTRACT_NAMES:
        schema = _cached_contract_schema(name)
        identifier = schema.get("$id")
        if not isinstance(identifier, str):
            raise SchemaError(f"contract schema {name!r} has no identifier")
        registry = registry.with_resource(identifier, Resource.from_contents(schema))
    return registry


def _validation_location(error: ValidationError) -> str:
    parts = [str(part) for part in error.absolute_path]
    return ".".join(parts) if parts else "root"


def validate_contract(name: ContractName, document: object) -> dict[str, Any]:
    """Validate *document* without including instance values in public failures."""

    schema = _cached_contract_schema(name)
    validator_type = validators.validator_for(schema)
    validator = validator_type(
        schema,
        registry=_contract_registry(),
        format_checker=FormatChecker(),
    )
    errors = sorted(
        validator.iter_errors(cast(Any, document)),
        key=lambda error: (tuple(str(part) for part in error.absolute_path), str(error.validator)),
    )
    if errors:
        error = errors[0]
        rule = str(error.validator) if error.validator is not None else "contract"
        location = _validation_location(error)
        raise SchemaError(
            f"{name} record is invalid at {location!r}; it does not satisfy rule {rule!r}"
        )
    if not isinstance(document, dict):  # kept explicit for a stable typed return
        raise SchemaError(f"{name} record must contain an object")
    return cast(dict[str, Any], document)


def load_contract_document(path: Path) -> dict[str, Any]:
    """Load one JSON or safe-YAML object without disclosing source content."""

    try:
        with path.open(encoding="utf-8") as stream:
            if path.suffix.lower() == ".json":
                document = json.load(stream)
            elif path.suffix.lower() in {".yaml", ".yml"}:
                document = yaml.safe_load(stream)
            else:
                raise SchemaError(f"contract file {path.name!r} has an unsupported extension")
    except SchemaError:
        raise
    except (OSError, UnicodeError, json.JSONDecodeError, yaml.YAMLError) as exc:
        raise SchemaError(f"could not load contract from {path.name!r}") from exc
    if not isinstance(document, Mapping) or not all(isinstance(key, str) for key in document):
        raise SchemaError(f"contract {path.name!r} must contain an object")
    return dict(document)


def load_and_validate_contract(name: ContractName, path: Path) -> dict[str, Any]:
    """Load and validate one contract document through the common safe boundary."""

    return validate_contract(name, load_contract_document(path))
