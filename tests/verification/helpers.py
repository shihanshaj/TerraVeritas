"""Terse factories for oracle tests: InvariantResult and DifferentialResult."""

from __future__ import annotations

from datetime import UTC, datetime

from terraveritas.models.diff import (
    DifferentialResult,
    NewFinding,
    PersistentFinding,
    RelocatedFinding,
    RemovedFinding,
)
from terraveritas.models.finding import Finding, FindingOutcome
from terraveritas.models.invariant import InvariantResult, InvariantStatus

_TS = datetime(2026, 1, 1, tzinfo=UTC)


def invariant_result(
    status: InvariantStatus,
    *,
    resource_address: str = "aws_s3_bucket.data",
    violated_conditions: list[str] | None = None,
    reason: str = "",
    invariant_id: str = "S3_PUBLIC_ACCESS_EXPOSURE",
) -> InvariantResult:
    return InvariantResult(
        invariant_id=invariant_id,
        resource_address=resource_address,
        status=status,
        violated_conditions=violated_conditions or [],
        reason=reason or status.value,
    )


def finding(
    rule_id: str, resource_id: str, outcome: FindingOutcome = FindingOutcome.FAILED
) -> Finding:
    return Finding(
        scanner_name="checkov",
        scanner_version="test",
        rule_id=rule_id,
        outcome=outcome,
        file_path="main.tf",
        description="",
        raw_evidence={},
        scan_timestamp=_TS,
        resource_id=resource_id,
    )


def differential_with_removed(
    resource_id: str, *, now_passes: bool = True, scanner_name: str = "checkov"
) -> DifferentialResult:
    return DifferentialResult(
        scanner_name=scanner_name,
        removed=[
            RemovedFinding(
                before=finding("CKV_AWS_20", resource_id),
                resource_still_present_in_after=now_passes,
                same_identity_now_passes=now_passes,
            )
        ],
        persistent=[],
        new=[],
        relocated=[],
    )


def differential_with_persistent(
    resource_id: str, *, scanner_name: str = "checkov"
) -> DifferentialResult:
    return DifferentialResult(
        scanner_name=scanner_name,
        removed=[],
        persistent=[
            PersistentFinding(
                before=finding("CKV_AWS_20", resource_id),
                after=finding("CKV_AWS_20", resource_id),
            )
        ],
        new=[],
        relocated=[],
    )


def differential_with_new(resource_id: str, *, scanner_name: str = "checkov") -> DifferentialResult:
    return DifferentialResult(
        scanner_name=scanner_name,
        removed=[],
        persistent=[],
        new=[NewFinding(after=finding("CKV_AWS_99", resource_id))],
        relocated=[],
    )


def differential_with_relocated(
    before_id: str, after_id: str, *, scanner_name: str = "checkov"
) -> DifferentialResult:
    return DifferentialResult(
        scanner_name=scanner_name,
        removed=[],
        persistent=[],
        new=[],
        relocated=[
            RelocatedFinding(
                before=finding("CKV_AWS_20", before_id),
                after=finding("CKV_AWS_20", after_id),
                note="test",
            )
        ],
    )
