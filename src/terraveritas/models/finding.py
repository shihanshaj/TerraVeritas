"""Normalized scanner evidence model.

A Finding represents one scanner's opinion about one check against one
resource. Findings are evidence, not verdicts — the oracle (not this module)
decides whether a repair is correct. Different scanners are free to disagree;
nothing here merges or reconciles their outputs.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from enum import StrEnum
from typing import Any


class FindingOutcome(StrEnum):
    """What the scanner concluded about this specific check, on this resource."""

    FAILED = "failed"
    PASSED = "passed"
    SKIPPED = "skipped"


class ScanStatus(StrEnum):
    """Outcome of attempting to run a scanner at all, independent of findings.

    A scan can fail in ways that have nothing to do with the Terraform being
    correct or incorrect. Those failure modes must stay visible, not be
    silently swallowed into an empty finding list.
    """

    SUCCESS = "success"
    TIMEOUT = "timeout"
    SCANNER_NOT_FOUND = "scanner_not_found"
    EXECUTION_ERROR = "execution_error"
    OUTPUT_PARSE_ERROR = "output_parse_error"
    INVALID_TARGET = "invalid_target"
    TARGET_UNPARSEABLE = "target_unparseable"
    """The scanner ran and produced well-formed output, but every file in the
    target could not be parsed as IaC (e.g. broken HCL). Distinct from
    OUTPUT_PARSE_ERROR (the scanner's own stdout was malformed) and from a
    genuine empty-findings SUCCESS (the files parsed but had no issues) —
    conflating this with either would let an unparseable config silently
    report as "clean"."""


@dataclass(frozen=True, slots=True)
class Finding:
    """One normalized scanner finding.

    `raw_evidence` always retains the scanner's original finding fragment
    verbatim, so normalization can never destroy information the oracle
    might later need.
    """

    scanner_name: str
    scanner_version: str
    rule_id: str
    outcome: FindingOutcome
    file_path: str
    description: str
    raw_evidence: dict[str, Any]
    scan_timestamp: datetime
    severity: str | None = None
    resource_id: str | None = None
    resource_type: str | None = None
    line_start: int | None = None
    line_end: int | None = None


@dataclass(frozen=True, slots=True)
class ParsedScanOutput:
    """What an adapter's `_parse_output` extracts from raw scanner stdout.

    Kept separate from ScanResult because parsing happens before the final
    ScanStatus is known — the base adapter decides SUCCESS vs
    TARGET_UNPARSEABLE by looking at both fields together.
    """

    findings: list[Finding] = field(default_factory=list)
    unparseable_files: list[str] = field(default_factory=list)


@dataclass(frozen=True, slots=True)
class ScanResult:
    """The full result of one scanner invocation against one target directory.

    Always returned by an adapter's `scan()` — never raised as an exception
    for expected failure modes (missing binary, timeout, unparseable output).
    Callers branch on `status`; `findings` is only meaningful when
    `status == ScanStatus.SUCCESS`.
    """

    scanner_name: str
    scanner_version: str
    target_path: str
    status: ScanStatus
    findings: list[Finding] = field(default_factory=list)
    unparseable_files: list[str] = field(default_factory=list)
    command: list[str] = field(default_factory=list)
    started_at: datetime | None = None
    finished_at: datetime | None = None
    exit_code: int | None = None
    error_message: str | None = None
