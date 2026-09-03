"""Deterministic, non-network scanner test double.

Used only to exercise ScannerAdapter's shared execution/error-handling logic
(timeout, missing binary, non-zero exit, unparseable output) without
depending on a real scanner binary being installed or on network I/O. Not a
stand-in for Checkov/Trivy/KICS integration tests, which run the real
executable against real fixtures.
"""

from __future__ import annotations

import json
import sys
from datetime import datetime
from pathlib import Path
from typing import Any

from terraveritas.models.finding import Finding, FindingOutcome, ParsedScanOutput
from terraveritas.scanners.base import ScannerAdapter


class FakeScannerAdapter(ScannerAdapter):
    """A scanner adapter whose subprocess behavior is fully controlled by the test.

    `python_expr` is executed via `python -c`, so tests can make the "scanner"
    print canned JSON, sleep past a timeout, or exit non-zero — all without
    touching the filesystem beyond the target directory check, and without
    depending on shell built-ins that differ across platforms.
    """

    def __init__(
        self,
        name: str,
        python_expr: str,
        *,
        executable: str | None = None,
        success_exit_codes: frozenset[int] = frozenset({0}),
    ) -> None:
        self.name = name
        self.executable = executable if executable is not None else sys.executable
        self._python_expr = python_expr
        self._success_exit_codes = success_exit_codes

    def _get_version(self) -> str:
        return "fake-1.0"

    def _build_command(self, target_dir: Path) -> list[str]:
        return [self.executable, "-c", self._python_expr]

    def _is_success_exit_code(self, returncode: int) -> bool:
        return returncode in self._success_exit_codes

    def _parse_output(self, stdout: str, *, scan_timestamp: datetime) -> ParsedScanOutput:
        raw = json.loads(stdout)
        if isinstance(raw, dict):
            payload: list[dict[str, Any]] = raw.get("findings", [])
            unparseable_files: list[str] = raw.get("unparseable_files", [])
        else:
            payload = raw
            unparseable_files = []
        findings = [
            Finding(
                scanner_name=self.name,
                scanner_version="fake-1.0",
                rule_id=item["rule_id"],
                outcome=FindingOutcome(item["outcome"]),
                file_path=item["file_path"],
                description=item["description"],
                raw_evidence=item,
                scan_timestamp=scan_timestamp,
                resource_id=item.get("resource_id"),
            )
            for item in payload
        ]
        return ParsedScanOutput(findings=findings, unparseable_files=unparseable_files)
