"""Terse factories for building synthetic Finding/ScanResult objects in tests.

The differential engine operates purely on already-parsed Finding objects,
so these unit tests construct evidence directly rather than invoking a real
scanner — real-scanner coverage is provided separately by
test_scanner_diff_checkov_integration.py.
"""

from __future__ import annotations

from datetime import UTC, datetime

from terraveritas.models.finding import Finding, FindingOutcome, ScanResult, ScanStatus

_TS = datetime(2026, 1, 1, tzinfo=UTC)


def finding(
    rule_id: str,
    resource_id: str | None,
    outcome: FindingOutcome = FindingOutcome.FAILED,
    *,
    resource_type: str | None = None,
    scanner_name: str = "checkov",
    description: str = "",
) -> Finding:
    if resource_type is None and resource_id and "." in resource_id:
        resource_type = resource_id.split(".")[-2]
    return Finding(
        scanner_name=scanner_name,
        scanner_version="test",
        rule_id=rule_id,
        outcome=outcome,
        file_path="main.tf",
        description=description,
        raw_evidence={},
        scan_timestamp=_TS,
        resource_id=resource_id,
        resource_type=resource_type,
    )


def scan_result(
    findings: list[Finding],
    *,
    scanner_name: str = "checkov",
    status: ScanStatus = ScanStatus.SUCCESS,
) -> ScanResult:
    return ScanResult(
        scanner_name=scanner_name,
        scanner_version="test",
        target_path="/fixture",
        status=status,
        findings=findings,
    )
