"""Common error types with disclosure-safe rendering."""

from __future__ import annotations

from dataclasses import dataclass
from enum import IntEnum


class ExitCode(IntEnum):
    """Stable process exit codes for operator-facing failures."""

    OK = 0
    CONFIGURATION = 2
    SCHEMA = 3
    POLICY = 4
    MATERIALIZATION = 5
    BUNDLING = 6
    LEAKAGE = 7
    EXECUTION = 8
    INTERNAL = 70


@dataclass(slots=True)
class PreflightEvalsError(Exception):
    """A failure whose public message contains no source values or raw artifacts."""

    public_message: str
    exit_code: ExitCode

    def __str__(self) -> str:
        return self.public_message


class ConfigurationError(PreflightEvalsError):
    """Raised for malformed or unsafe configuration."""

    def __init__(self, public_message: str) -> None:
        super().__init__(public_message, ExitCode.CONFIGURATION)


class SchemaError(PreflightEvalsError):
    """Raised when a schema cannot be loaded safely."""

    def __init__(self, public_message: str) -> None:
        super().__init__(public_message, ExitCode.SCHEMA)


class PolicyError(PreflightEvalsError):
    """Raised when an artifact policy invariant is violated."""

    def __init__(self, public_message: str) -> None:
        super().__init__(public_message, ExitCode.POLICY)


class MaterializationError(PreflightEvalsError):
    """Raised when an exact snapshot cannot be created safely."""

    def __init__(self, public_message: str) -> None:
        super().__init__(public_message, ExitCode.MATERIALIZATION)


class BundleError(PreflightEvalsError):
    """Raised when reviewer context cannot be bundled safely and deterministically."""

    def __init__(self, public_message: str) -> None:
        super().__init__(public_message, ExitCode.BUNDLING)


class LeakageError(PreflightEvalsError):
    """Raised when a reviewer request cannot cross the leakage boundary safely."""

    audit_bytes: bytes

    def __init__(self, public_message: str, *, audit_bytes: bytes = b"") -> None:
        super().__init__(public_message, ExitCode.LEAKAGE)
        self.audit_bytes = audit_bytes


class ExecutionError(PreflightEvalsError):
    """Raised when a frozen experiment cannot plan, execute, or resume safely."""

    def __init__(self, public_message: str) -> None:
        super().__init__(public_message, ExitCode.EXECUTION)
