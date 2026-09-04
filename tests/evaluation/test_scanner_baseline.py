"""Tests for compute_scanner_only_baseline.

Includes a direct regression test for the bug found during
docs/scanner_only_baseline_comparison.md's own construction: an earlier
version of the broad rule set included CKV2_AWS_6 ("no Block Public Access
resource"), which produced FIX_REJECTED on cases already independently
confirmed genuinely safe -- absence of a hardening control is not itself
evidence of exposure.
"""

from __future__ import annotations

from datetime import UTC, datetime

from terraveritas.evaluation.scanner_baseline import compute_scanner_only_baseline
from terraveritas.models.baseline import BaselineConclusion
from terraveritas.models.diff import DifferentialResult, NewFinding
from terraveritas.models.finding import Finding, FindingOutcome, ScanResult, ScanStatus


def _finding(rule_id: str, outcome: FindingOutcome) -> Finding:
    return Finding(
        scanner_name="checkov",
        scanner_version="3.3.16",
        rule_id=rule_id,
        outcome=outcome,
        file_path="/main.tf",
        description=rule_id,
        raw_evidence={},
        scan_timestamp=datetime.now(UTC),
        resource_id="aws_s3_bucket.data",
        resource_type="aws_s3_bucket",
    )


def _scan(findings: list[Finding]) -> ScanResult:
    return ScanResult(
        scanner_name="checkov",
        scanner_version="3.3.16",
        target_path="/fixture",
        status=ScanStatus.SUCCESS,
        findings=findings,
    )


def _empty_differential(*, new: list[Finding] | None = None) -> DifferentialResult:
    return DifferentialResult(
        scanner_name="checkov",
        removed=[],
        persistent=[],
        new=[NewFinding(after=f) for f in (new or [])],
        relocated=[],
    )


def test_narrow_accepted_when_reported_rule_clears() -> None:
    after = _scan([_finding("CKV_AWS_145", FindingOutcome.PASSED)])
    result = compute_scanner_only_baseline(
        rule_id="CKV_AWS_20", after_scan=after, differential=_empty_differential()
    )
    assert result.narrow_conclusion == BaselineConclusion.FIX_ACCEPTED


def test_narrow_rejected_when_reported_rule_still_fails() -> None:
    after = _scan([_finding("CKV_AWS_20", FindingOutcome.FAILED)])
    result = compute_scanner_only_baseline(
        rule_id="CKV_AWS_20", after_scan=after, differential=_empty_differential()
    )
    assert result.narrow_conclusion == BaselineConclusion.FIX_REJECTED


def test_narrow_no_finding_to_check_when_no_rule_reported() -> None:
    after = _scan([])
    result = compute_scanner_only_baseline(
        rule_id=None, after_scan=after, differential=_empty_differential()
    )
    assert result.narrow_conclusion == BaselineConclusion.NO_FINDING_TO_CHECK


def test_narrow_flags_new_findings_even_with_no_reported_rule() -> None:
    new_finding = _finding("CKV_AWS_300", FindingOutcome.FAILED)
    after = _scan([new_finding])
    result = compute_scanner_only_baseline(
        rule_id="N/A", after_scan=after, differential=_empty_differential(new=[new_finding])
    )
    assert result.narrow_conclusion == BaselineConclusion.NO_FINDING_TO_CHECK_BUT_NEW_FINDINGS


def test_narrow_accepted_with_new_findings_when_something_new_also_appears() -> None:
    new_finding = _finding("CKV_AWS_300", FindingOutcome.FAILED)
    after = _scan([_finding("CKV_AWS_20", FindingOutcome.PASSED), new_finding])
    result = compute_scanner_only_baseline(
        rule_id="CKV_AWS_20",
        after_scan=after,
        differential=_empty_differential(new=[new_finding]),
    )
    assert result.narrow_conclusion == BaselineConclusion.FIX_ACCEPTED_WITH_NEW_FINDINGS


def test_broad_rejected_when_a_different_actual_grant_rule_still_fails() -> None:
    """The originally-reported rule (CKV_AWS_20) cleared, but a DIFFERENT
    actual-grant rule (CKV_AWS_70, an untouched public policy) still fails
    -- exactly the real phase2_case_b_partial_fix / phase3_case_b_partial_fix
    shape. The narrow baseline misses this; the broad one must not."""
    after = _scan(
        [
            _finding("CKV_AWS_20", FindingOutcome.PASSED),
            _finding("CKV_AWS_70", FindingOutcome.FAILED),
        ]
    )
    result = compute_scanner_only_baseline(
        rule_id="CKV_AWS_20", after_scan=after, differential=_empty_differential()
    )
    assert result.narrow_conclusion == BaselineConclusion.FIX_ACCEPTED
    assert result.broad_conclusion == BaselineConclusion.FIX_REJECTED
    assert "CKV_AWS_70" in result.broad_reason


def test_broad_not_fooled_by_absence_of_hardening_control() -> None:
    """Regression test for the exact bug found while building
    docs/scanner_only_baseline_comparison.md: CKV2_AWS_6 ("no Block Public
    Access resource exists") is a hardening-control-absent advisory, not
    evidence of an actual grant. A genuinely fixed case (private ACL, no
    policy at all) that simply never added a BPA resource must still read
    as ACCEPTED on the broad baseline."""
    after = _scan(
        [
            _finding("CKV_AWS_20", FindingOutcome.PASSED),
            _finding("CKV2_AWS_6", FindingOutcome.FAILED),
        ]
    )
    result = compute_scanner_only_baseline(
        rule_id="CKV_AWS_20", after_scan=after, differential=_empty_differential()
    )
    assert result.broad_conclusion == BaselineConclusion.FIX_ACCEPTED
